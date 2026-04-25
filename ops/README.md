# Deployment auf cassius

Ziel-Pfad: `/home/danst/dockers/meshcore/`

## Voraussetzungen (bereits vorhanden auf cassius)

- Traefik2-Stack (`/home/danst/dockers/traefik2/`) läuft.
- Externes Docker-Netzwerk `traefik_proxy` existiert.
- DNS-Challenge via IONOS, certResolver `default`. Wildcard `*.dumke.me`
  ist abgedeckt.
- Watchtower picked Container mit `com.centurylinklabs.watchtower.enable=true`
  automatisch für Image-Updates auf.

## Initial-Setup

```bash
ssh cassius
sudo mkdir -p /home/danst/dockers/meshcore
sudo chown danst:danst /home/danst/dockers/meshcore
cd /home/danst/dockers/meshcore

# Repo-Inhalt ablegen — entweder Clone oder rsync
# (Phase 0: nur die ops/ + Sources werden gebraucht)

# Secret für DB-Verschlüsselung erzeugen (32 Byte hex)
mkdir -p secrets
openssl rand -hex 32 > secrets/db_key
chmod 600 secrets/db_key

# Optional: app.yaml aus config-examples/ ableiten und anpassen
cp ops/config-examples/app.yaml ops/config-examples/app.yaml.local
```

DNS-Eintrag für `meshcore.dumke.me` → cassius (A-Record auf
öffentlichen Cassius-Endpoint, Standard-Workflow im IONOS-Panel).

## Stack starten

```bash
cd /home/danst/dockers/meshcore/ops
docker compose up -d --build
docker compose logs -f app
```

## WebSocket via Traefik

WebSocket über HTTP-Router funktioniert in Traefik out-of-the-box —
`Connection: Upgrade` wird transparent durchgereicht, kein Subprotocol
oder spezielles Label nötig. Der WebSocket-Pfad `/api/v1/bridge`
landet beim selben Router wie HTTP-Traffic.

Falls in späteren Phasen separater Idle-Timeout für WS-Verbindungen
nötig ist, können die auskommentierten `meshcore-ws`-Labels in
`docker-compose.yml` aktiviert werden.

## Update-Workflow

```bash
cd /home/danst/dockers/meshcore
git pull
cd ops
docker compose up -d --build
```

Watchtower macht **kein** automatisches Update auf den `app`-Container,
weil das Image lokal aus dem Source-Tree gebaut wird (kein Registry-
Tag). Updates passieren manuell via `git pull && compose up -d --build`.

## Logs & Inspektion

```bash
docker compose logs -f app                 # App-Logs (JSON)
docker exec -it meshcore-app /bin/sh       # Shell im Container
sqlite3 /var/lib/docker/volumes/meshcore_app_data/_data/meshcore.sqlite
```
