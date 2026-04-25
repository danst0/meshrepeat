FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Layer-Caching: Dependencies vor dem Source-Code installieren.
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
    "PyYAML>=6.0" \
    "jinja2>=3.1" \
    "python-multipart>=0.0.9" \
    "itsdangerous>=2.2"

COPY server/bridge /app/server/bridge
COPY server/companion /app/server/companion
COPY ops/config-examples/app.yaml /config/app.yaml
# tools/ (CLI-Helfer wie meshcore-spiegel-ctl) folgt in Phase 3

ENV PYTHONPATH=/app/server/bridge/src:/app/server/companion/src \
    MESHCORE_CONFIG=/config/app.yaml \
    MESHCORE_DB_PATH=/data/meshcore.sqlite

RUN useradd --create-home --shell /usr/sbin/nologin app \
    && mkdir -p /data \
    && chown -R app:app /data /app /config
USER app

EXPOSE 8000

CMD ["python", "-m", "meshcore_bridge"]
