# ADR 005: Single-Container-Deployment für v1

Datum: 2026-04-25
Status: accepted

## Kontext

Bridge-Daemon, Web-Backend und Companion-Service sind drei logische
Komponenten. Sie können getrennt oder zusammen laufen. Das Briefing
sieht Companion explizit als In-Process-Plugin der Bridge vor.

## Entscheidung

In v1 läuft **ein** Python-Container (`app`) mit Bridge-Daemon,
Web-Backend (FastAPI) und Companion-Service in einem gemeinsamen
asyncio-Event-Loop. TLS und Routing übernimmt der **existierende
Traefik2-Stack** auf cassius — wir hängen uns nur via Labels und das
externe Netzwerk `traefik_proxy` ein. Persistenz: Named-Volume mit
SQLite-Datei.

Compose-Services (in `ops/docker-compose.yml`):

- `app` — Bridge + Web + Companion (uvicorn als Entrypoint).
- volume `app_data` — SQLite + sonstige persistente Daten.
- secret `db_key` — Master-Key für DB-At-Rest-Encryption (Privkeys etc.).

Pfad auf cassius: `/home/danst/dockers/meshcore/`.

## Folgen

### Vorteile

- In-Process-Companion-API ist trivial (kein RPC zwischen Containern).
- Ein Python-Image, ein systemd-Lifecycle, einfaches Logging.
- SQLite reicht für Phase 1-4.

### Nachteile

- Skalierung horizontal nicht möglich — bei höherer Last muss
  Architektur überarbeitet werden (eigener Bridge-Container,
  Postgres, Redis-Pub/Sub für Companion-Bridge-IPC).
- Bridge-Restart restartet auch das Web-UI und umgekehrt.

## Migrationspfad

Sobald Postgres oder Redis nötig wird, kann `app` aufgeteilt werden:
`web`, `bridge`, `companion` als drei Container, IPC über lokales
TCP oder Unix-Socket.

## Verworfen

- **Drei Container ab Tag 1**: zusätzliche IPC-Komplexität ohne
  konkreten Bedarf in v1.
