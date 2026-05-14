# Companion REST-API

Stand: v0.5.5. Basis-URL: `https://meshcore.dumke.me/api/v1/companion`.
Alle Antworten sind JSON, soweit nicht anders vermerkt. Datumsfelder sind
ISO-8601 mit UTC-Suffix.

## Authentifizierung

Zwei Wege; pro Request wird **erst** der `Authorization`-Header geprüft,
sonst die Session-Cookie aus dem Web-Login.

### Bearer-Token

```
Authorization: Bearer <token>
```

Token werden pro **Companion-Identity** ausgegeben (siehe
[Token-Verwaltung](#token-verwaltung)). Ein Token sperrt auf seine
Identity — Aufrufe gegen andere Identities liefern `403`. Der Klartext
wird **genau einmal** beim Erstellen zurückgegeben; Server speichert nur
`argon2id`-Hash und 4-Byte-`prefix`. Format: 32 ASCII (base32, 160 bit).

### Session-Cookie

Standard-Web-Login (`/login`). Cookie-Sessions haben keinen Identity-Lock
und impliziten Scope `*` (alle Companion-Aktionen für eigene
Identities). Einige Routen (Identity-Erstellung, Token-Mgmt,
User-Admin) sind **ausschließlich** per Cookie erreichbar.

## Scopes

Token-Scopes als CSV beim Erstellen festlegen, Default ist `read`:

| Scope   | Erlaubt |
|---------|---------|
| `read`  | alle GETs auf der gelockten Identity (Threads, DMs, Channels, Kontakte, Reachability, Karte, Suche, SSE-Stream) |
| `write` | DMs senden, Channel-Posts senden |
| `admin` | Identity-Einstellungen (Advert/Echo/Archive/Path-Hash-Mode), Channel- und Kontakt-Verwaltung, Telemetry/Login/Status/Probe-Requests |

Cookie-only (kein Token-Scope erreicht das):
- `POST /identities` — Identity-Erstellung
- `POST /identities/{id}/tokens`, `POST /tokens/{id}/revoke` — Token-Mgmt
- `POST /admin/identities/{id}/cleanup-coords` — User-Admin-Rolle
- `/api/v1/internal/...` — Loopback-only (127.0.0.1)

Fehlt der nötige Scope → `403 {"detail":"scope missing"}`. Spricht der
Token eine fremde Identity an → `403 {"detail":"identity locked"}`.

## Token-Verwaltung

Cookie-Login erforderlich.

### Token erstellen

```
POST /api/v1/companion/identities/{identity_id}/tokens
Content-Type: application/x-www-form-urlencoded

name=ha-bridge&scopes=read,write&expires_at=
```

Felder:
- `name` (req.) — Label, max. 64 Zeichen.
- `scopes` (opt.) — CSV aus `read`/`write`/`admin`, Default `read`.
- `expires_at` (opt.) — ISO-8601-Datetime; leer = nie.

Antwort enthält den Klartext **einmalig** als `token`:

```json
{
  "id": "…uuid…",
  "identity_id": "…uuid…",
  "name": "ha-bridge",
  "scopes": ["read", "write"],
  "created_at": "2026-05-14T16:30:00+00:00",
  "last_used_at": null,
  "revoked_at": null,
  "expires_at": null,
  "token": "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
}
```

### Token auflisten

```
GET /api/v1/companion/identities/{identity_id}/tokens
```

Liefert Liste ohne Klartext.

### Token revoken

```
POST /api/v1/companion/tokens/{token_id}/revoke
```

Idempotent. Setzt `revoked_at = now()`.

## Endpoint-Referenz

### `read`-Scope (GET)

| Route | Zweck |
|-------|-------|
| `GET /identities` | Eigene Identities (bei Token: nur die gelockte) |
| `GET /messages?limit=` | Letzte Nachrichten aller eigenen Identities |
| `GET /contacts` | Bekannte Peer-Identitäten |
| `GET /channels` | Eigene Gruppen-Channels |
| `GET /identities/{id}/threads` | DM- und Channel-Sidebar einer Identity |
| `GET /identities/{id}/dms/{peer_pubkey_hex}?limit=&before_ts=` | DM-History (Cursor-paginiert) |
| `GET /identities/{id}/contacts?limit=` | Kontakte einer Identity |
| `GET /identities/{id}/contacts/{peer_pubkey_hex}/login-state` | In-Memory Login-Status zu einem Peer |
| `GET /identities/{id}/contacts/{peer_pubkey_hex}/probes?limit=&since_hours=` | Link-Probe-History + Aggregate |
| `GET /identities/{id}/reachability?hours=` | Erreichbarkeits-Dashboard pro Kontakt |
| `GET /identities/{id}/map?hours=&include_outliers=` | Kontakte mit GPS-Pin |
| `GET /identities/{id}/channels/{channel_id}/messages?limit=&before_ts=` | Channel-History (Cursor-paginiert) |
| `GET /identities/{id}/search?q=&limit=` | FTS5-Volltextsuche |
| `GET /identities/{id}/stream` | SSE-Push (DM-/Channel-Empfang, Echo-Events) |

### `write`-Scope (POST)

| Route | Body (form-encoded) |
|-------|---------------------|
| `POST /messages/dm` | `identity_id`, `peer_pubkey_hex` (32-Byte hex), `text` |
| `POST /messages/channel` | `identity_id`, `channel_id`, `text` |

### `admin`-Scope (POST)

| Route | Body |
|-------|------|
| `POST /identities/{id}/advert` | — (sofortiger Advert in den Scope) |
| `POST /identities/{id}/archive` | — |
| `POST /identities/{id}/echo` | `enabled=true|false` |
| `POST /identities/{id}/path-hash-mode` | `mode=0|1|2` (1/2/3 Byte) |
| `POST /channels` | `identity_id`, `name`, `password` |
| `POST /channels/{channel_id}/favorite` | — (toggle) |
| `POST /identities/{id}/contacts` | `peer_pubkey_hex`, optional `peer_name`, `favorite` |
| `POST /contacts/{contact_id}/favorite` | — (toggle) |
| `POST /identities/{id}/contacts/{peer_pubkey_hex}/telemetry` | — |
| `POST /identities/{id}/contacts/{peer_pubkey_hex}/login` | optional `password` (Guest = leer) |
| `POST /identities/{id}/contacts/{peer_pubkey_hex}/status` | — |
| `POST /identities/{id}/contacts/{peer_pubkey_hex}/probe` | — |

### Cookie-only (kein Token)

| Route | Hinweis |
|-------|---------|
| `POST /identities` | Identity-Erstellung (kein Identity-Lock anwendbar) |
| `POST /admin/identities/{id}/cleanup-coords?dry_run=` | User-Rolle `admin` erforderlich |
| `POST /identities/{id}/tokens`, `GET …/tokens`, `POST /tokens/{id}/revoke` | Token-Mgmt |
| `POST /api/v1/internal/companion/{id}/scan` | Loopback-only (127.0.0.1) |

## Beispielablauf

```bash
# 1) Cookie-Login + Identity-Erstellung (Web-UI oder curl)
curl -c cookies.txt -d "email=u@x&password=…" https://meshcore.dumke.me/login
curl -b cookies.txt -d "name=Antonia&scope=public" \
     https://meshcore.dumke.me/api/v1/companion/identities
# → {"id": "<IDENT>", "pubkey_hex": "…"}

# 2) Token erzeugen (z. B. für HA-Bridge: read + write)
curl -b cookies.txt \
     -d "name=ha-bridge&scopes=read,write" \
     https://meshcore.dumke.me/api/v1/companion/identities/<IDENT>/tokens
# → {"token": "ABCD…32CHARS", ...}

# 3) Token nutzen — DM senden
curl -H "Authorization: Bearer ABCD…32CHARS" \
     -d "identity_id=<IDENT>&peer_pubkey_hex=<32B_HEX>&text=Hallo" \
     https://meshcore.dumke.me/api/v1/companion/messages/dm

# 4) Threads pollen
curl -H "Authorization: Bearer ABCD…32CHARS" \
     https://meshcore.dumke.me/api/v1/companion/identities/<IDENT>/threads
```

## Fehlercodes

| Status | Bedeutung |
|--------|-----------|
| 401 | Token unbekannt, abgelaufen, revoked — oder weder Cookie noch Bearer vorhanden |
| 403 | `scope missing` oder `identity locked` |
| 404 | Identity/Contact/Channel gehört nicht zum aufrufenden User |
| 409 | Companion-Service nicht geladen / Identity nicht aktiv |
| 422 | Ungültige Eingabe (z. B. unbekannter Scope, kaputter pubkey, schlechtes ISO-Datum) |
| 503 | Companion-Service nicht verfügbar (kein `db_key`) |
