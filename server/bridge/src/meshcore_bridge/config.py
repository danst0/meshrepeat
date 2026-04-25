"""Application configuration.

Layered: YAML file (via ``MESHCORE_CONFIG`` env) → environment variables
override individual fields. Pydantic-Settings handles parsing and
validation.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, Literal

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
    advert_interval_s: int = 3600


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
        data: dict[str, object] = {}
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
