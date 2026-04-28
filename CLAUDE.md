# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

MeshCore Internet-Spiegel: a server that bridges multiple MeshCore LoRa mesh "islands" over WebSocket, plus a server-side **Software-Companion** that acts as a full MeshCore participant (own Ed25519 identity, no LoRa hardware) by injecting/receiving packets through the bridge.

Single-user self-host on `cassius` (10.0.2.71), reverse-proxied by an existing Traefik2 stack. Production URL: `https://meshcore.dumke.me`.

## Repo layout

This is a monorepo with two installable Python packages plus firmware and ops:

| Path                          | Contents                                             |
|-------------------------------|------------------------------------------------------|
| `server/bridge/`              | `meshcore-bridge` package — FastAPI app, WS bridge, DB, web UI |
| `server/companion/`           | `meshcore-companion` package — virtual MeshCore node (crypto, packet codec, service) |
| `protocol/WIRE.md`            | Repeater↔Server wire spec (CBOR over WS-binary)      |
| `firmware/`                   | PlatformIO project (Phase 2, mostly skeleton)        |
| `ops/`                        | `Dockerfile`, `docker-compose.example.yaml`, sample configs |
| `tools/spiegel-ctl`           | Admin CLI hitting the bridge's admin API             |
| `docs/adr/`                   | ADRs (numbered)                                      |

The two packages share runtime state: `meshcore_bridge.web.app.build_app()` instantiates `CompanionService` from `meshcore_companion.service` and wires it to the bridge `Router` via an inject callback. `meshcore_companion.service` imports `meshcore_bridge.db` lazily to avoid circular imports — see the `per-file-ignores` in `pyproject.toml`.

## Common commands

Run from repo root unless noted.

```bash
# Install both packages editable + dev tools
pip install -e "./server/bridge[dev]" -e "./server/companion[dev]"

# Run the server on :8000 (loads MESHCORE_CONFIG yaml if set, else defaults)
python -m meshcore_bridge

# Tests — full suite (UI tests excluded by default via pytest -m 'not ui')
pytest

# Single test file / case
pytest server/bridge/tests/test_router.py
pytest server/bridge/tests/test_router.py::test_forward_within_scope -v

# UI/Playwright tests (opt-in; needs `pip install -e "./server/bridge[ui-test]"` + `playwright install chromium`)
pytest -m ui server/bridge/tests/ui/ --browser chromium

# Lint + types
ruff check .
ruff format .
mypy server/bridge/src        # strict; see [tool.mypy] in pyproject.toml
mypy server/companion/src

# Alembic migrations (run from server/bridge/ — alembic.ini lives there)
cd server/bridge
alembic revision --autogenerate -m "describe change"
alembic upgrade head
alembic downgrade -1
```

`pytest` uses `asyncio_mode = "auto"` and `filterwarnings = ["error", ...]` — warnings fail tests unless explicitly ignored in `pyproject.toml`.

## Configuration & env

Config layering (see `meshcore_bridge.config`): YAML file pointed to by `MESHCORE_CONFIG` → env-var overrides with prefix `MESHCORE_` and nested delimiter `__` (e.g. `MESHCORE_BRIDGE__DEDUP__TTL_S=600`). Sample YAML lives at `ops/config-examples/app.yaml`.

Notable env vars:
- `MESHCORE_CONFIG` — path to YAML config
- `MESHCORE_DB_KEY_FILE` (preferred) or `MESHCORE_DB_KEY` — 32-byte master key for at-rest encryption of companion privkey seeds (XChaCha20-Poly1305). **Required** for the companion subsystem to start.
- `MESHCORE_DB_PATH` — SQLite path (Docker default `/data/meshcore.sqlite`)
- `MESHCORE_ALEMBIC_DIR` — override for the alembic dir lookup (image default: `/app/server/bridge/alembic`)
- `MESHCORE_BUILD_SHA` — cache-buster for `/static/` URLs

`SIGHUP` triggers a hot reload of `AppConfig` and the `PolicyEngine` (see `web/app.py` lifespan).

## Architecture

### FastAPI app composition (`server/bridge/src/meshcore_bridge/web/app.py`)

`build_app(cfg)` is the single composition root. The lifespan context creates and stores on `app.state`:
- `bridge_registry: ConnectionRegistry` — live `RepeaterConn` set, indexed by site UUID and scope
- `bridge_dedup: DedupCache` — LRU+TTL cache keyed by `payload_dedup_key` (hop-invariant: header + transport_codes + payload, *not* path_len/path_hashes)
- `bridge_policy: PolicyEngine` — token-bucket rate limiting + allow/deny default
- `bridge_traffic: TrafficLog` — bounded ring buffer of recent events for the admin UI / SSE
- `bridge_packet_spool: PacketSpool` — async writer of every routed packet into the `RawPacket` table for the inspector
- `bridge_router: Router` — combines the above; called from `bridge_ws.py` for each inbound `pkt`
- `companion_service: CompanionService | None` — only if `cfg.companion.enabled` *and* `cfg.db_key` resolved
- `companion_events: CompanionEventBus` — pub/sub bus that companion routes turn into SSE for the web UI
- `templates: Jinja2Templates` — with `localtime` filter and `asset_version`/`app_version` globals

Routers mounted: `health_routes`, `auth_routes`, `repeater_routes`, `bridge_ws`, `admin_routes` (+ `ui_router`), `companion_routes` (+ `ui_router` + `internal_router`).

### Bridge data plane

`bridge_ws.py` (`/api/v1/bridge`) handles the repeater WebSocket: validates `hello` frame against the DB (token bound to site, scope match), sends `helloack`, registers a `RepeaterConn`, then in a loop decodes binary frames into `wire.Frame` variants. `pkt` frames go to `Router.route_inbound()`. Heartbeat is server-driven (`hb` every `hb_iv` s, default 15; close 1011 after `3 * hb_iv` silence). Close codes 4400/4401/4403/4410/4426 are application-level errors.

`Router.route_inbound()` (see `bridge/router.py`) is the dedup + scope filter:
1. Compute hop-invariant `payload_dedup_key`.
2. If origin already had this key → drop (this happens normally when the same LoRa frame reaches multiple repeaters).
3. For each peer in the *same scope*: send if not yet in the seen-set; mark on send.

The companion plugs in here as a virtual repeater: `CompanionService` consumes packets via a hook on the router, and emits packets via the `inject` callback that fans out to all `RepeaterConn`s in the matching scope.

### Wire protocol (`meshcore_bridge.wire`)

CBOR-encoded WS-binary frames, ≤8192 bytes. Top-level map with `t` discriminator: `hello`, `helloack`, `pkt`, `hb`, `hback`, `flow`, `bye`. Full spec: `protocol/WIRE.md`. Frame types are pydantic-shaped dataclasses in `wire/frames.py`; `wire/codec.py` does encode/decode with explicit `FrameDecodeError`. Canonical CBOR is required so dedup hashes are stable.

### Companion (`server/companion/src/meshcore_companion/`)

`crypto.py` — Ed25519 + XChaCha20-Poly1305 per MeshCore spec.
`packet.py` — on-air packet codec (header, route type, transport codes, path, payload).
`node.py` — pure-functional packet helpers: advert encode/parse, group-text decrypt, ack-hash, LPP/repeater-stats parsing.
`storage.py` — `encrypt_seed` / `decrypt_seed` of identity Ed25519 seeds with the master `db_key`.
`service.py` — `CompanionService` orchestrates one or more identities: loads them at start, runs an advert ticker per identity, sniffs inbound packets (ADVERT → contact upsert; TXT_MSG → try-decrypt for each identity → persist), exposes `send_dm`/`send_channel`/etc. that build packets and call the injected scope-fanout. Emits SSE events through `EventNotifier`.

### Database

SQLAlchemy 2.0 async + aiosqlite. Models in `meshcore_bridge.db.models`. Schema bootstrap (`db/session.py:init_engine`) handles **three** states deterministically:

1. **Fresh DB** (no tables) → `Base.metadata.create_all` + `alembic stamp head`.
2. **Legacy DB** (tables exist, no `alembic_version`) → `create_all` (idempotent) + apply `_COLUMN_PATCHES` for retro-added columns + `_ensure_fts5` for the FTS5 virtual table & triggers + `alembic stamp head`. Patches must run **before** the stamp.
3. **Alembic-managed** (`alembic_version` exists) → `alembic upgrade head` only.

Alembic itself runs in a separate sync connection — running it inside the same async transaction deadlocks SQLite ("database is locked"). When adding a migration, also update `_COLUMN_PATCHES` if it adds a column to a table that exists in legacy DBs.

FTS5 (`companion_messages_fts`) is created by `_ensure_fts5` and migration `d7e2a9c1f4b8`; both paths are idempotent.

### Web UI

Server-rendered Jinja2 (`web/templates/*.html.j2`) with progressive enhancement (SSE for live traffic/events). Templates assume a Berlin display timezone via the `localtime` filter; client-side JS uses browser locale. The inspector and traffic views are admin-only.

## Conventions

- Python 3.12, strict types: `mypy --strict`, `disallow_any_unimported`, `warn_unreachable`. Pydantic v2 plugin enabled.
- Ruff config in root `pyproject.toml`. Per-file ignores already encode the pragmatic exceptions (WS handler length, app lifespan length, FastAPI `Depends` defaults). Don't widen them globally — add to `per-file-ignores` if needed.
- All datetimes are UTC in the DB; only the Jinja `localtime` filter converts to Europe/Berlin for rendering.
- Comments are German where they exist; code identifiers are English. Match the surrounding style.
- Logging is `structlog` via `meshcore_bridge.log.get_logger("name")`.

## Deployment

CI (`.github/workflows/ci.yml`) on push to `main` builds and publishes `ghcr.io/danst0/meshrepeat:latest` (+ `sha-<short>`, semver tags). Watchtower on cassius pulls automatically. The compose file mounts `./app.yaml:/config/app.yaml:ro` and a `db_key` Docker secret. **Never** start the container without a pre-existing `app.yaml` host file — Compose will silently create a phantom *directory* in its place.
