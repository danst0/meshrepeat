# ADR 007: N Companion-Identitäten pro User

Datum: 2026-04-25
Status: accepted

## Kontext

Q14 wurde initial mit "ein Companion pro User" (b) beantwortet,
direkt danach präzisiert: ein User soll mehrere Identitäten/Keys
verwalten können.

## Entscheidung

User → Companion-Identität ist 1:N. Jede Identität hat:

- eigenes Ed25519-Keypair (persistent in DB, Privkey at-rest verschlüsselt)
- eigenen Display-Namen
- eigenen Scope (`public` oder `pool:<uuid>`)
- eigene Nachrichten-Historie und Kontaktliste

Datenbank-Schema-Sketch (siehe `ops/sql/schema.sql` in Phase 1):

```sql
CREATE TABLE users (
  id UUID PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','owner')),
  email_verified_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL
);

CREATE TABLE companion_identities (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id),
  name TEXT NOT NULL,
  pubkey BLOB(32) NOT NULL UNIQUE,
  privkey_enc BLOB NOT NULL,        -- XChaCha20-Poly1305(privkey)
  scope TEXT NOT NULL,              -- 'public' or 'pool:<uuid>'
  created_at TIMESTAMP NOT NULL,
  archived_at TIMESTAMP
);
```

REST/CLI-API listet, erzeugt, archiviert Identitäten. Senden einer
DM oder Channel-Nachricht erfordert Auswahl der absendenden
Identität.

## Folgen

### Vorteile

- Personae-Trennung (z.B. "Alice privat" vs. "Alice technische Notdienste").
- Pro Pool eine eigene Identität möglich, wenn der User Pubkey-
  Verlinkung über Pools nicht möchte.
- Skalierbar — keine Limit-Logik nötig.

### Nachteile

- UI muss Identity-Picker an jeder relevanten Stelle haben.
- Storage wächst linear mit Identitäten — vernachlässigbar.
- Companion-Bridge-API muss pro Identity adressierbar sein
  (Identity-ID als Tag in jedem Paket-Inject-Call).

## Verworfen

- **Eine Identität pro User**: User-Anforderung explizit dagegen.
