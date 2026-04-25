# ADR 003: Hybrid-Mesh-Modell (public + private pools)

Datum: 2026-04-25
Status: accepted

## Kontext

Drei Optionen für Multi-User-Datenmodell standen zur Wahl
(Q12):

- α) Gemeinsames Mesh — alle User-Repeater bilden ein einziges Mesh.
- β) Isolierte Meshes — pro User ein eigener, abgeschotteter Mesh.
- γ) Hybrid — pro Repeater wählbar.

User hat γ entschieden.

## Entscheidung

Jeder Repeater bekommt beim Anlegen einen `scope`:

- `public` — Teil eines globalen, gemeinsamen MeshCore-Spiegels.
- `pool:<uuid>` — Teil eines Private-Pools, den der Owner anlegt.
  Andere User können auf Einladung beitreten (Phase 3+).

Bridge-Routing: ein eingehendes Paket wird ausschließlich an
Repeater im **gleichen** Scope weitergeleitet. Public und Private
sind hart getrennt — kein Crossover.

Companion-Identitäten haben einen Scope (siehe ADR 007); ein User
kann mehrere Identitäten anlegen, eine pro Scope an dem er teilnimmt
(oder mehrere im gleichen Scope, wenn er getrennte Personae will).

## Folgen

### Vorteile

- Owner können privaten Familien-/Vereins-Mesh fahren ohne öffentlichen
  Verkehr.
- Public-Mesh erlaubt das ursprüngliche Internet-Spiegel-Konzept.
- Datenbank-Schema bleibt schlank: ein `scope`-Feld pro Entität.

### Nachteile

- Routing-Code muss pro-Paket den Scope auflösen — minimaler Overhead.
- Hot-Switch zwischen Pools braucht klare Semantik (wir definieren:
  Repeater-Disconnect, Re-Configure, Reconnect; keine Live-Migration
  in v1).
- Pool-Memberships von Owner-Accounts (wer darf einem Pool beitreten?)
  öffnen einen Berechtigungs-Layer — Phase 3+.

## Verworfen

- α) Pure Public — eingeschränkt für Privat-Anwendungsfälle.
- β) Pure Private — eliminiert den Internet-Spiegel-Aspekt komplett.
