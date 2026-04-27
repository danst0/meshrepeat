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

# Pakete installieren, damit importlib.metadata.version("meshcore-bridge")
# funktioniert (App-Version im Footer + Cache-Bust für /static/-URLs).
# --no-deps weil Runtime-Deps oben schon liegen.
RUN pip install --no-deps ./server/bridge ./server/companion

# Optionaler Build-SHA-Cache-Bust: CI kann ARG MESHCORE_BUILD_SHA setzen,
# wir reichen das als ENV durch (überschreibt asset_version).
ARG MESHCORE_BUILD_SHA=""
ENV MESHCORE_BUILD_SHA=$MESHCORE_BUILD_SHA \
    MESHCORE_CONFIG=/config/app.yaml \
    MESHCORE_DB_PATH=/data/meshcore.sqlite

RUN useradd --create-home --shell /usr/sbin/nologin app \
    && mkdir -p /data \
    && chown -R app:app /data /app /config
USER app

EXPOSE 8000

# Container-Healthcheck: liveness via /healthz (kein curl im Image, daher
# Python urllib). Watchtower/Traefik können daran "unhealthy" erkennen.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3).status==200 else 1)" \
      || exit 1

CMD ["python", "-m", "meshcore_bridge"]
