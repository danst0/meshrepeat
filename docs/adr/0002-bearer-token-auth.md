# ADR 002: Bearer-Token statt mTLS-Client-Cert

Datum: 2026-04-25
Status: accepted

## Kontext

Ursprünglich war mTLS mit pro-Repeater-Client-Cert geplant
(CN = site_id, eigene CA auf cassius). Mit der Anforderung, Repeater
über das **Web-UI** zu registrieren und den Auth-Credential per LoRa-DM
über die existierende MeshCore-Admin-CLI zu setzen (Q5'/Q8), passt mTLS
nicht mehr: ein x509-Client-Cert über LoRa-DM zu schicken ist
unverhältnismäßig — Cert + Key zusammen sind ~1.5 kB, müssten in
mehreren Admin-DMs übertragen werden.

## Entscheidung

Repeater authentisieren sich mit einem **Bearer-Token**, übermittelt
im `hello`-WebSocket-Frame. Der Token wird beim Anlegen eines Repeaters
in der Web-UI generiert (160 Bit Entropie, base32-encoded, 32 Zeichen)
und per Admin-LoRa-DM auf den Repeater geschrieben (`set bridge.token`).

Server-seitige TLS-Authentifikation läuft weiterhin über das
Let's-Encrypt-Server-Cert (siehe ADR 001), Repeater pinnt ISRG Root X1.

## Folgen

### Vorteile

- 32 ASCII-Zeichen passen in einen einzelnen MeshCore-Admin-DM-Payload
  (max ~200 B).
- Keine eigene CA-Logistik, keine Cert-Renewal-Pipeline.
- Token-Rotation = simpler DB-Eintrag, kein Cert-Re-Issue.
- Owner können selbständig in der Web-UI Tokens neu erzeugen.

### Nachteile

- Bei DB-Kompromittierung sind Token-Hashes (Argon2id) zu cracken
  potenziell denkbar; mTLS-Privkeys im Server (ohne Cracking) wären
  dort kein Faktor. Mitigiert durch starkes Argon2id-Profil und
  niedrige Token-Werte (Repeater-Identität ist nicht hochwertvoll).
- Kein automatisches "Cert-Pinning"-Feature — wir vertrauen TLS-Trust
  über ISRG.

## Verworfen

- **mTLS**: siehe Kontext.
- **JWT**: Ablaufzeit-Logik unnötig kompliziert für long-lived
  Repeater-Tokens; Revocation bei JWT problematisch.
- **HMAC-Challenge-Response**: pseudo-Challenge ohne Replay-Schutz
  bringt nichts über TLS.
