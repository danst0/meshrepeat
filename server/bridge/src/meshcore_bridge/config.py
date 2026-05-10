"""Application configuration.

Layered: YAML file (via ``MESHCORE_CONFIG`` env) → environment variables
override individual fields. Pydantic-Settings handles parsing and
validation.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"  # noqa: S104  - intentional bind on all interfaces inside container
    port: int = 8000


class DedupConfig(BaseModel):
    ttl_s: int = 300
    lru_capacity: int = 100_000


class PolicyConfig(BaseModel):
    default: Literal["allow", "deny"] = "allow"
    rate_limit_pkts_per_s: int = 50
    rate_limit_burst: int = 200


class BridgeConfig(BaseModel):
    ws_path: str = "/api/v1/bridge"
    max_frame_bytes: int = 8192
    heartbeat_interval_s: int = 15
    heartbeat_timeout_s: int = 45
    reconnect_grace_s: int = 30
    dedup: DedupConfig = DedupConfig()
    policy: PolicyConfig = PolicyConfig()


class SignupConfig(BaseModel):
    enabled: bool = True
    require_email_verification: bool = True


class Argon2Config(BaseModel):
    time_cost: int = 3
    memory_cost_kib: int = 65_536
    parallelism: int = 4


class SmtpConfig(BaseModel):
    enabled: bool = False
    host: str = ""
    port: int = 587
    username: str = ""
    password: str = ""
    sender: str = "noreply@meshcore.dumke.me"
    use_tls: bool = False  # implicit TLS (port 465)
    starttls: bool = True  # explicit STARTTLS (port 587)


class WebConfig(BaseModel):
    base_url: str = "https://meshcore.dumke.me"
    session_cookie_name: str = "meshcore_sid"
    session_idle_timeout_days: int = 7
    signup: SignupConfig = SignupConfig()
    argon2: Argon2Config = Argon2Config()
    smtp: SmtpConfig = SmtpConfig()


class CompanionConfig(BaseModel):
    enabled: bool = True
    # 50 h Default folgt der Community-Etiquette (mc-radar: max. 1 Flood-Advert
    # pro 50 h). Kürzere Intervalle helfen zwar Path-Caches, fluten aber das
    # ganze Mesh und werden öffentlich als Misconfiguration gelistet.
    advert_interval_s: int = 180_000
    # Auto-Probe-Loop: schickt eine "[probe]"-DM an jeden Favoriten-Kontakt
    # alle N Sekunden, persistiert ACK/Loss in companion_link_probes. 0 = aus.
    # Vorsicht: jede Probe ist eine echte LoRa-DM mit ACK — Default lieber
    # konservativ, der User kann es per app.yaml hochziehen.
    probe_interval_s: int = 0


class TranslationConfig(BaseModel):
    """Optionale Auto-Übersetzung eingehender Companion-Nachrichten.

    Engine ist ein lokales Ollama (default ``http://localhost:11434``).
    Bei ``enabled=True`` ruft der CompanionService nach jedem persistierten
    eingehenden Text einen Hintergrund-Task, der das Result als
    ``translated_text``/``language`` in companion_messages schreibt und
    per SSE-Event ``message_translated`` nachreicht. Die clientseitige
    Anzeige wird im Browser per Checkbox an-/ausgeschaltet.
    """

    enabled: bool = False
    base_url: str = "http://localhost:11434"
    model: str = "llama3.1:8b"
    target_lang: str = "de"
    target_lang_label: str = "Deutsch"
    timeout_s: float = 20.0
    # Texte unterhalb dieser Länge (z.B. "Thx", "👍") werden nicht übersetzt.
    min_chars: int = 3
    # Schutz gegen lange Posts — wir kappen Übersetzung statt das LLM zu
    # belasten. Mesh-Texte sind eh ≤ ~200 Bytes.
    max_chars: int = 800
    # Wie oft der Batch-Loop alle noch nicht übersetzten Nachrichten
    # nachholt. Default 1 h. ``0`` deaktiviert den Batch — dann läuft
    # ausschließlich der Live-Pfad und Backlog bleibt liegen.
    batch_interval_s: int = 3600
    # Live-Übersetzung läuft auch noch N Sekunden nach dem letzten
    # SSE-Disconnect, damit Reload/Tab-Wechsel die Übersetzung nicht
    # in den Batch-Modus kippt.
    live_grace_s: float = 120.0


class StorageConfig(BaseModel):
    sqlite_path: Path = Path("/data/meshcore.sqlite")


class LoggingConfig(BaseModel):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    format: Literal["json", "console"] = "json"


class MetricsConfig(BaseModel):
    enabled: bool = False
    bind: str = "127.0.0.1:9090"


class AppConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MESHCORE_",
        env_nested_delimiter="__",
        env_file=None,
        extra="ignore",
    )

    server: ServerConfig = ServerConfig()
    bridge: BridgeConfig = BridgeConfig()
    web: WebConfig = WebConfig()
    companion: CompanionConfig = CompanionConfig()
    translation: TranslationConfig = TranslationConfig()
    storage: StorageConfig = StorageConfig()
    logging: LoggingConfig = LoggingConfig()
    metrics: MetricsConfig = MetricsConfig()

    db_key: Annotated[bytes, Field(default=b"")] = b""
    """Master-Key for at-rest encryption (companion privkeys etc.).

    Loaded from ``MESHCORE_DB_KEY_FILE`` (preferred) or ``MESHCORE_DB_KEY``.
    Empty until ``load()`` resolves it.
    """

    @classmethod
    def load(cls, yaml_path: Path | str | None = None) -> AppConfig:
        """Load YAML (if given), apply env overrides, resolve secret files."""
        path = Path(yaml_path) if yaml_path else _config_path_from_env()
        data: dict[str, Any] = {}
        if path is not None and path.exists():
            with path.open("r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f) or {}
            if not isinstance(loaded, dict):
                raise ValueError(f"Config file {path} must be a mapping at top level")
            data = loaded

        cfg = cls(**data)
        cfg.db_key = _resolve_db_key()
        return cfg


def _config_path_from_env() -> Path | None:
    raw = os.environ.get("MESHCORE_CONFIG")
    return Path(raw) if raw else None


def _resolve_db_key() -> bytes:
    """Load ``db_key`` from file (preferred) or env var."""
    file_path = os.environ.get("MESHCORE_DB_KEY_FILE")
    if file_path:
        path = Path(file_path)
        if path.exists():
            return path.read_bytes().strip()
    inline = os.environ.get("MESHCORE_DB_KEY")
    if inline:
        return inline.encode("utf-8").strip()
    return b""
