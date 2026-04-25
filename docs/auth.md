# Auth & Onboarding

Status: **Draft v0.1** (Phase 0)

## Akteure

| Rolle           | Beschreibung                                                  |
|-----------------|---------------------------------------------------------------|
| `admin`         | Globale Verwaltung (du). Kann alles sehen, User sperren, Pools moderieren. |
| `owner`         | Repeater-Betreiber mit Web-Account. Verwaltet eigene Repeater, Tokens, Pools, Companion-Identitäten. |
| `repeater`      | Hardware-Node mit Bearer-Token. Kein eigener User-Account.    |
| `companion`     | Software-Identität, gehört zu einem `owner`. Mehrere pro User möglich. |

User-Tabelle hat ein einziges Feld `role`. Es gibt **keine** getrennte
Auth-Datenbank für Admin und Owner — Rollen-Check erfolgt im Web-Backend.

## Web-User-Lifecycle

1. **Self-Signup**: User registriert sich auf `https://meshcore.dumke.me/signup`
   mit E-Mail und Passwort.
2. **E-Mail-Verifikation**: Server schickt Token-Link, gültig 24 h.
3. **Login**: Session-Cookie (HTTPOnly, Secure, SameSite=Strict),
   serverseitig in der DB gespeichert. Idle-Timeout 7 Tage.
4. **Passwort-Hash**: argon2id (Standard-Parameter aus `argon2-cffi`).

Keine OAuth/SSO in v1 — kann später nachgerüstet werden.

## Repeater-Onboarding

```
┌─────────┐        ┌──────────────┐        ┌──────────┐        ┌──────────┐
│ Owner   │        │ Web-UI       │        │ Phone    │        │ Repeater │
│         │        │ (FastAPI)    │        │ MeshCore │        │ T-Beam   │
└────┬────┘        └──────┬───────┘        │   App    │        └────┬─────┘
     │                    │                └─────┬────┘             │
     │ 1) login           │                      │                  │
     ├───────────────────►│                      │                  │
     │ 2) "neuer Repeater"│                      │                  │
     ├───────────────────►│                      │                  │
     │  scope: pool:xy    │                      │                  │
     │ 3) site_id, token  │                      │                  │
     │◄───────────────────┤                      │                  │
     │                    │                      │                  │
     │ 4) Token kopieren, MeshCore-App öffnen,                      │
     │    eigenen Repeater als Admin auswählen                      │
     │ 5) Admin-DM senden:                                          │
     │    set bridge.host meshcore.dumke.me                         │
     │    set bridge.token <TOKEN>                                  │
     │    set bridge.site  <SITE_ID>                                │
     │    set bridge.scope <pool:xy|public>                         │
     │    bridge enable                                             │
     │                    │                      │     LoRa-DM      │
     │                    │                      ├─────────────────►│
     │                    │                      │                  │
     │                    │                      │             6) NVS-Write,
     │                    │                      │                Reboot-Bridge-Task
     │                    │                      │                  │
     │                    │                      │       wss://     │
     │                    │◄────────────────────────────────────────┤
     │                    │   hello{site,tok,scope}                 │
     │                    │                      │                  │
     │                    │   helloack           │                  │
     │                    ├────────────────────────────────────────►│
     │ 7) UI: "verbunden" │                      │                  │
     │◄───────────────────┤                      │                  │
```

### MeshCore-Admin-CLI-Erweiterungen (Phase 2)

Neue Befehle im Repeater-CLI (nutzbar via Phone-App-Admin-DM, signiert
mit Admin-Pubkey wie alle anderen `set`-Befehle):

| Befehl                       | Wirkung                                            |
|------------------------------|----------------------------------------------------|
| `set bridge.host <host>`     | Hostname/Domain des Bridge-Servers                 |
| `set bridge.port <port>`     | Default 443                                        |
| `set bridge.path <path>`     | Default `/api/v1/bridge`                           |
| `set bridge.token <token>`   | Bearer-Token (nicht zurücklesbar, nur write+hash)  |
| `set bridge.site <uuid>`     | Site-ID als UUID-String                            |
| `set bridge.scope <s>`       | `public` oder `pool:<uuid>`                        |
| `bridge enable` / `disable`  | Verbindung an/aus                                  |
| `bridge status`              | Verbindungs-Status, Reconnect-Counter, letzter Fehler |

Persistenz: NVS-Namespace `mcbridge`. Token wird beim Setzen gespeichert;
beim `get` wird nur SHA-256-Prefix geloggt, nicht der Token selbst.

### Token-Format

- Generierung: 160 Bit Entropie (`secrets.token_bytes(20)`).
- Encoding: base32 (RFC 4648 ohne Padding) → 32 Zeichen, lesbar in
  LoRa-DMs, kein Sonderzeichen-Problem.
- Speicherung serverseitig: `argon2id(token)` plus 32-Bit-Prefix als
  Index für Lookup.
- Bindung: jeder Token gehört zu **genau einer** `site_id`. Site-ID
  wird beim Anlegen erzeugt (UUIDv4) und ist permanent.
- Rotation: Owner kann neuen Token erzeugen → alter wird `revoked_at`
  gesetzt. Repeater muss neu konfiguriert werden, sonst Auth-Fehler
  4410 (Gone) beim nächsten Reconnect.

## TLS-Trust auf dem Repeater

- ISRG Root X1 (`isrgrootx1.pem`) als Compile-Zeit-Konstante in der FW
  einkompiliert (`firmware/src/certs/isrg_root_x1.h`).
- ISRG Root X2 als Fallback ebenfalls einkompiliert.
- Hostname-Verifikation gegen `bridge.host`.
- Bei Cert-Wechsel von Let's Encrypt auf eine andere CA: FW-Update
  notwendig. Risiko akzeptiert (sehr seltenes Ereignis).

## Companion-Identitäten

Ein User kann beliebig viele Companion-Identitäten anlegen. Pro
Identität:

| Feld         | Typ        | Bemerkung                                           |
|--------------|------------|-----------------------------------------------------|
| `id`         | uuid       | Datenbank-PK                                        |
| `user_id`    | fk users   | Owner                                               |
| `name`       | text       | Display-Name (frei wählbar)                         |
| `pubkey`     | bytes(32)  | Ed25519                                             |
| `privkey`    | bytes(64)  | Ed25519 (verschlüsselt at-rest, Schlüssel s.u.)     |
| `scope`      | text       | `public` oder `pool:<uuid>`                         |
| `created_at` | timestamp  |                                                     |
| `archived_at`| timestamp? | weiche Löschung; Identität wird nicht mehr gepostet |

Privat-Keys werden in der DB **verschlüsselt** abgelegt (XChaCha20-Poly1305
mit pro-Container-Master-Key aus `MESHCORE_DB_KEY` im `.env`,
HKDF-abgeleitet pro Identity-ID). Master-Key liegt im Docker-Secret bzw.
im `.env` mit `chmod 600`. Backup-Strategie: Phase 5.

Identitäten dürfen ihren Scope ändern (Migration zwischen Pools), aber
ihr Pubkey bleibt stabil — andernfalls verliert der Mesh den Adressaten.

## Threat-Model (knapp)

| Bedrohung                                           | Mitigation                                |
|-----------------------------------------------------|-------------------------------------------|
| Mitlesen WS-Traffic                                  | TLS                                       |
| Token-Diebstahl aus DB                              | Argon2id-Hash, kein Klartext              |
| Token-Diebstahl vom Repeater (NVS-Dump)             | akzeptiert; Owner muss bei Verlust rotieren |
| Repeater-Spoofing (anderer Token, gleiche Site)     | Token↔Site-Bindung in DB                  |
| LoRa-Sniff der Admin-DM mit Token                   | MeshCore-Admin-DM ist AES-128 + HMAC      |
| Phishing per Web-UI                                 | Standard-CSRF + SameSite-Cookies          |
| Companion-Privkey-Leck                              | At-rest-Encryption                        |
| Brute-Force gegen Token (online)                    | Rate-Limit pro IP + pro `site_id`         |

Out of Scope für v1: Hardware-HSM, Reproducible Builds der FW,
Bug-Bounty, Audit.
