# Wire-Protokoll Repeater ↔ Server

Status: **Draft v0.1** (Phase 0)
Geltungsbereich: WebSocket-Verbindung zwischen einem MeshCore-Repeater
mit Custom-Firmware (`WifiTcpBridge`-Subclass) und dem zentralen
Bridge-Daemon auf `meshcore.dumke.me`.

## Transport

- **URL**: `wss://meshcore.dumke.me/api/v1/bridge`
- **TLS**: TLS 1.2+, Server-Cert via Let's Encrypt (ISRG Root X1).
  Repeater pinnt ISRG Root X1 als Compile-Zeit-Konstante in der FW.
- **Reverse-Proxy**: bestehender Traefik2-Stack auf cassius. WebSocket
  wird transparent durchgereicht (kein Sonder-Label), `Connection: Upgrade`-
  Handling übernimmt Traefik. Routing-Labels: siehe
  `ops/docker-compose.yml`.
- **Subprotokoll**: kein WS-Subprotocol-Header. Frame-Typ steht im
  CBOR-Body.
- **Frame-Modus**: WebSocket **binary** frames. Kein Fragmentieren auf
  Anwendungsebene; ein WS-Frame = ein Wire-Frame.

## Frame-Body: CBOR

Jeder WS-Binary-Frame trägt ein einzelnes top-level CBOR-Map mit
Schlüssel `t` (Type-Tag, kurzer ASCII-String) und typabhängigen
Feldern. Map-Keys sind ASCII-Kurznamen (Bandbreitenoptimierung).

**Größenlimit**: 8192 Bytes pro WS-Frame. Bridge schließt Verbindung
mit Code 1009 ("Message too big") bei Überschreitung.

**Encoding**: kanonisches CBOR (RFC 8949 §4.2.1) — deterministische
Map-Reihenfolge, kürzeste Integer-Encoding. Ermöglicht stabile
Hashes.

## Frame-Typen

### `hello` — Repeater → Server (erste Nachricht)

```cbor
{
  "t":      "hello",
  "site":   <bytes 16>,        ; site_id (UUID v4 als 16-Byte-bytes)
  "tok":    <text>,            ; Bearer-Token (opaque, base32, 32 chars)
  "fw":     <text>,            ; Firmware-Version "v0.3.1"
  "proto":  1,                 ; Protokollversion (1)
  "scope":  <text>,            ; "public" oder "pool:<uuid>"
  "caps":   [<text>, ...]      ; optionale Capability-Tags, z.B. "rssi","snr"
}
```

Server validiert: `tok` existiert und ist nicht widerrufen, `tok` ist
gebunden an `site`, `scope` matched die Datenbank.

### `helloack` — Server → Repeater

```cbor
{
  "t":          "helloack",
  "proto":      1,
  "policy_ep":  <uint>,        ; Policy-Epoche (für Hot-Reload)
  "srv_time":   <uint>,        ; Unix-Sekunden, dient als Zeit-Sync-Hint
  "max_bytes":  <uint>,        ; max Frame-Body-Größe (immer 8192 in v1)
  "hb_iv":      <uint>         ; Heartbeat-Intervall in Sekunden (default 15)
}
```

Bei Auth-Fehler: WS-Close mit Code 4401 (Unauthorized) und Reason-Phrase.
Bei Scope-Mismatch: 4403 (Forbidden). Bei Token-Revoked: 4410 (Gone).

### `pkt` — beidseitig

```cbor
{
  "t":     "pkt",
  "raw":   <bytes>,            ; komplettes On-Air-MeshCore-Paket (Header + Path + Payload)
  "rssi":  <int|null>,         ; nur up: RSSI in dBm
  "snr":   <int|null>,         ; nur up: SNR ×4
  "rxts":  <uint|null>         ; nur up: Repeater-RX-Zeitstempel ms seit Boot
}
```

Server tagged das Paket intern mit `site` und `scope` der Verbindung
und routet entsprechend.

**Dedup-Schlüssel** (server-seitig): SHA-256 über `raw` ohne SNR-Anhang
(Bytes 0..N-1 außer letztem SNR-Byte; siehe `MeshCore::Packet::writeTo()`).
Server hält pro Schlüssel ein `seen_sites: set[uuid]` mit TTL 5 Minuten,
LRU-Cap 100k. Ein Paket wird nur an Sites im **gleichen Scope**
weitergeleitet, deren UUID **nicht** in `seen_sites` ist.

### `hb` / `hback` — Heartbeat

```cbor
{ "t": "hb",    "seq": <uint>, "ts": <uint> }
{ "t": "hback", "seq": <uint> }
```

Sender ist immer der Server (alle `hb_iv` Sekunden, default 15 s).
Repeater antwortet zeitnah mit `hback` und gleicher `seq`. Keine
Antwort innerhalb von `3 * hb_iv` → Server schließt mit 1011.
Repeater nutzen das als Liveness-Signal; eigenes Heartbeating optional
via WebSocket-Ping/Pong.

### `flow` — Server → Repeater (Backpressure)

```cbor
{ "t": "flow", "pause_ms": <uint> }
```

Server signalisiert dem Repeater, für `pause_ms` Millisekunden keine
weiteren `pkt`-Frames mehr Richtung Server zu senden. Frames werden
serverseitig nicht in eine unbegrenzte Queue geworfen — bei Überlauf
einer Bridge-Inbox wird `flow` an den lautesten Repeater gesendet.

### `bye` — beidseitig

```cbor
{ "t": "bye", "reason": <text> }
```

Geordneter Disconnect. Sender folgt mit WS-Close 1000.

### `cfg_get` / `cfg_set` (reserviert, nicht in v1 implementiert)

Frame-Typen `"cfg_get"`, `"cfg_set"`, `"cfg_ok"`, `"cfg_err"`
sind reserviert für zukünftige Server→Repeater-Konfiguration über
den Bridge-Kanal (z.B. Logging-Level zur Laufzeit ändern). In v1
nicht implementiert; Server lehnt mit 4400 ab.

## Auth-Flow (zusammenfassend, Details: `docs/auth.md`)

```
Repeater                                      Server
    │  TLS-Handshake (Server-Cert ISRG)         │
    ├──────────────────────────────────────────►│
    │  hello { site, tok, scope, fw, proto }   │
    ├──────────────────────────────────────────►│
    │                                           │  Token-Lookup (DB)
    │                                           │  Bind-Check site↔tok
    │                                           │  Scope-Match
    │  helloack { proto, hb_iv, ... }           │
    │◄──────────────────────────────────────────┤
    │  ─── operativer Datenfluss ───            │
    │  pkt up                                   │  hb (alle 15 s)
    │  hback                                    │  pkt down
    ...
```

## Reconnect-Verhalten

Repeater bei Verbindungsabbruch: exponentielles Backoff
1 → 2 → 4 → 8 → 16 → 32 → 60 s mit ±20% Jitter, bei Erfolg Reset.
Bei Close-Code in `4xxx` (Application-Error): kein Backoff-Reset, sondern
Backoff-Maximum (60 s) und Logging — Konfigurationsfehler.

## Versionierung

`proto` ist ein monotoner Integer. Server akzeptiert `proto >= 1`. Bei
Inkompatibilität antwortet Server mit `helloack` und niedrigerer
unterstützter Version, oder schließt mit 4426 (Upgrade Required).

## Beispiel-Session (CBOR Diagnostic Notation)

Siehe `protocol/examples/handshake.cbor.txt`.

## Sicherheits-Hinweise

- Token sind opaque, **niemals** im Klartext loggen — nur SHA-256-Hash.
- Token-Rotation: Owner kann via Web-UI einen neuen Token erzeugen,
  der alte wird sofort revoked. Repeater muss neu konfiguriert werden.
- Replay: TLS schützt vor Replay; Server merkt sich keine Nonces.
- Site-Spoofing: `site` aus dem `hello`-Frame wird gegen die
  Token-Bindung in der DB verifiziert. Manipulation = Auth-Fail.
