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
    # Pause zwischen zwei aufeinanderfolgenden Batch-Calls, damit ein
    # großer Backlog Ollama nicht in Burst-Modus zwingt.
    per_call_delay_s: float = 0.3
    # Nach N aufeinanderfolgenden Transient-Fehlern (5xx/Timeout) bricht
    # der Batch-Run ab und probiert es beim nächsten Tick neu.
    max_consecutive_errors: int = 5
    # Timeout des Pre-flight Health-Checks (GET /v1/models) vor jedem
    # Batch-Run. Ein hängender LLM-Server soll den Loop nicht blockieren.
    health_check_timeout_s: float = 2.0


class AiAgentConfig(BaseModel):
    """Globale Defaults und Hard-Limits für den KI-Agent pro Companion.

    Pro Identity aktivierbar über die DB-Tabelle ``companion_ai_agents``
    und das UI auf der Companion-Detail-Seite. Diese Config setzt nur
    den Rahmen (Limits, Tick-Rate, Ollama-Endpoint), den die UI-Validierung
    und der Service-Loop einhalten müssen.

    Ollama-URL fällt per Default auf den :class:`TranslationConfig`-Endpoint
    zurück (``ollama_base_url=None``) — fast immer das gleiche lokale
    Ollama, kein Grund, es doppelt zu konfigurieren.
    """

    enabled: bool = True
    """Master-Schalter. Wenn ``False``, wird der Service-Loop nie gestartet,
    egal was in der DB steht."""
    min_interval_s: int = 3600
    """Unteres Limit für ``CompanionAiAgent.interval_s`` — Schutz vor
    versehentlichem Hochfrequenz-Posting (Spam-Wirkung im Mesh)."""
    max_interval_s: int = 86_400
    """Oberes Limit (1x/Tag). Größere Intervalle wären kein Bug, geben aber
    dem Slider in der UI eine sinnvolle Skala."""
    max_prompt_chars: int = 2000
    """Hard-Cap auf ``system_prompt``. Ollama-Tokens werden gegen das Modell-
    Context-Window gerechnet; 2 k Zeichen ≈ 600 Tokens bei deutscher Mischung
    und lassen genug Raum für die Channel-History."""
    max_message_chars: int = 140
    """LoRa-pragmatisches Byte-Limit für die generierte Antwort. Wird vom
    Sanitizer hart durchgesetzt."""
    dm_rate_cap_per_hour: int = 30
    """Absolutes Maximum für ``CompanionAiAgent.dm_rate_per_hour``. Auch
    wenn der User in der UI mehr eintippen würde, kappen wir hier."""
    tick_granularity_s: int = 60
    """Schritt des ``_ai_agent_loop``. Bestimmt, wie schnell der Loop auf
    Config-Änderungen (DB-Updates aus dem UI) reagiert."""
    ollama_base_url: str | None = None
    """Optionaler Override. ``None`` = ``translation.base_url`` benutzen."""
    ollama_model_default: str = "llama3.1:8b"
    """Default-Modell, das die UI als Platzhalter zeigt, wenn die Identity
    noch keine eigene Modell-Auswahl hat."""
    ollama_timeout_s: float = 90.0
    """Per-Versuch-Timeout für den Ollama-Call. Großzügig dimensioniert,
    weil Cold-Loads eines 8B-Modells leicht 60 bis 80 s brauchen können."""
    ollama_max_attempts: int = 3
    """Gesamtanzahl Versuche pro LLM-Call (= 1 Initial + (n-1) Retries).
    Greift bei Timeout und 5xx-Fehlern; 4xx fließt nicht in den Retry-Pfad."""
    ollama_retry_backoff_s: float = 2.0
    """Basis für exponentielles Back-off: Wartezeit zwischen Versuch ``i``
    und ``i+1`` ist ``base * 2**i`` (z.B. 2 s, 4 s, 8 s …)."""


class HomeAssistantSettings(BaseModel):
    """Lese-Zugang zur Home-Assistant-REST-API.

    Token kommt nicht aus dem YAML, sondern aus
    ``MESHCORE_HA_TOKEN_FILE`` (bevorzugt) oder ``MESHCORE_HA_TOKEN``
    — gleiches Muster wie ``db_key``, damit das Geheimnis als
    Docker-Secret bzw. .env-File ausserhalb der versionierten Config
    lebt.
    """

    enabled: bool = False
    base_url: str = ""
    timeout_s: float = 10.0
    verify_ssl: bool = True


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
    ai_agent: AiAgentConfig = AiAgentConfig()
    homeassistant: HomeAssistantSettings = HomeAssistantSettings()
    storage: StorageConfig = StorageConfig()
    logging: LoggingConfig = LoggingConfig()
    metrics: MetricsConfig = MetricsConfig()

    db_key: Annotated[bytes, Field(default=b"")] = b""
    """Master-Key for at-rest encryption (companion privkeys etc.).

    Loaded from ``MESHCORE_DB_KEY_FILE`` (preferred) or ``MESHCORE_DB_KEY``.
    Empty until ``load()`` resolves it.
    """

    ha_token: Annotated[str, Field(default="")] = ""
    """Long-Lived Access Token für Home Assistant.

    Loaded from ``MESHCORE_HA_TOKEN_FILE`` (preferred) or ``MESHCORE_HA_TOKEN``.
    Leer wenn HA nicht konfiguriert ist.
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
        cfg.ha_token = _resolve_ha_token()
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


def _resolve_ha_token() -> str:
    """Load Home-Assistant token from file (preferred) or env var."""
    file_path = os.environ.get("MESHCORE_HA_TOKEN_FILE")
    if file_path:
        path = Path(file_path)
        if path.exists():
            return path.read_text(encoding="utf-8").strip()
    inline = os.environ.get("MESHCORE_HA_TOKEN")
    if inline:
        return inline.strip()
    return ""
