# Phase-0-Skelett. Wird in Phase 1 vervollständigt, sobald ein
# Python-Entry-Module existiert.

FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Source-Layout: wir kopieren beide Sub-Packages getrennt rein,
# damit Layer-Caching auf pyproject.toml-Ebene greift.
COPY server/bridge/pyproject.toml /app/server/bridge/pyproject.toml
COPY server/companion/pyproject.toml /app/server/companion/pyproject.toml

# Dependencies-Install (Phase 1: echte Lock-Datei via uv oder pip-tools)
RUN pip install \
    "fastapi>=0.115" \
    "uvicorn[standard]>=0.30" \
    "websockets>=13" \
    "cbor2>=5.6" \
    "pydantic>=2.8" \
    "pydantic-settings>=2.4" \
    "argon2-cffi>=23" \
    "cryptography>=43" \
    "pynacl>=1.5" \
    "aiosqlite>=0.20" \
    "sqlalchemy>=2.0" \
    "alembic>=1.13" \
    "structlog>=24" \
    "prometheus-client>=0.21" \
    "typer>=0.12" \
    "PyYAML>=6.0"

COPY server/bridge/src /app/server/bridge/src
COPY server/companion/src /app/server/companion/src
COPY tools /app/tools

ENV PYTHONPATH=/app/server/bridge/src:/app/server/companion/src

EXPOSE 8000

# Entry-Point wird in Phase 1 implementiert (meshcore_bridge.app:main)
CMD ["python", "-m", "meshcore_bridge"]
