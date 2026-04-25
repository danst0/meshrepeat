# Deployment auf cassius

Ziel-Pfad: `/home/danst/dockers/meshcore/`

Image: `ghcr.io/danst0/meshrepeat:latest` (gebaut von
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) auf jedem
Push nach `main` und für jeden semver-Tag).

## Voraussetzungen (bereits vorhanden auf cassius)

- Traefik2-Stack (`/home/danst/dockers/traefik2/`) läuft.
- Externes Docker-Netzwerk `traefik_proxy` existiert.
- DNS-Challenge via IONOS, certResolver `default`. Wildcard `*.dumke.me`
  abgedeckt.
- Watchtower zieht Container mit
  `com.centurylinklabs.watchtower.enable=true` automatisch.
- DNS: `meshcore.dumke.me` zeigt auf cassius.

## Erst-Setup

```bash
ssh cassius
mkdir -p /home/danst/dockers/meshcore/secrets
cd /home/danst/dockers/meshcore

# Compose aus dem Repo holen (oder per Clone)
curl -fsSL https://raw.githubusercontent.com/danst0/meshrepeat/main/ops/docker-compose.example.yaml \
  -o docker-compose.yaml

# Optional: eigene App-Config (sonst wird die im Image gebackene genutzt)
curl -fsSL https://raw.githubusercontent.com/danst0/meshrepeat/main/ops/config-examples/app.yaml \
  -o app.yaml

# Master-Key für DB-At-Rest-Encryption (XChaCha20-Poly1305 für Privkeys)
openssl rand -hex 32 > secrets/db_key
chmod 600 secrets/db_key

# Erst-Login bei GHCR (Public-Image ist auch ohne Login zugänglich; nötig
# nur falls das Repo private ist)
# echo "$GHCR_PAT" | docker login ghcr.io -u danst0 --password-stdin

docker compose pull
docker compose up -d
docker compose logs -f
```

## Updates

Per Watchtower automatisch oder manuell:

```bash
cd /home/danst/dockers/meshcore
docker compose pull
docker compose up -d
```

CI tagged automatisch:
- `latest` und `sha-<short>` für jeden Push auf `main`
- `vX.Y.Z`, `X.Y.Z`, `X.Y` für jeden git-Tag `vX.Y.Z`

## Logs & Inspektion

```bash
docker compose logs -f app
docker exec -it meshcore-app /bin/sh
sqlite3 /var/lib/docker/volumes/meshcore_app_data/_data/meshcore.sqlite ".tables"
```

## Lokaler Build (ohne CI)

Für Entwicklung auf der eigenen Maschine:

```bash
cd ops
docker build -t meshrepeat:dev -f Dockerfile ..
```

In dem Fall die `image:`-Zeile in einem lokalen Compose-File durch
`build: { context: .., dockerfile: ops/Dockerfile }` ersetzen.
