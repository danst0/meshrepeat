"""End-to-End: eingehende DM wird im Hintergrund übersetzt, Felder
landen in companion_messages, ``message_translated`` wird emittiert."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from meshcore_bridge.db import CompanionContact, CompanionMessage
from meshcore_companion import service as svc_mod
from meshcore_companion.crypto import LocalIdentity
from meshcore_companion.node import CompanionNode
from meshcore_companion.translator import Translation, TranslatorConfig


def _cfg() -> TranslatorConfig:
    return TranslatorConfig(
        base_url="http://stub.local",
        model="stub",
        target_lang="de",
        target_lang_label="Deutsch",
        timeout_s=5.0,
        min_chars=3,
        max_chars=800,
    )


async def _add_contact(sessionmaker, identity_id, peer_pubkey: bytes) -> None:
    async with sessionmaker() as db:
        db.add(
            CompanionContact(
                identity_id=identity_id,
                peer_pubkey=peer_pubkey,
                peer_name="nl peer",
                last_seen_at=datetime.now(UTC),
            )
        )
        await db.commit()


async def _wait_translation_tasks(svc, timeout_s: float = 2.0) -> None:
    """Warte, bis alle laufenden Übersetzungs-Tasks abgeschlossen sind."""
    pending = list(svc._translation_tasks)
    if not pending:
        return
    await asyncio.wait_for(asyncio.gather(*pending, return_exceptions=True), timeout=timeout_s)


@pytest.mark.asyncio
async def test_inbound_dm_triggers_translation(
    service_env, monkeypatch: pytest.MonkeyPatch
) -> None:
    svc, sessionmaker, user_id, _sent = service_env

    # Translator stubben — wir wollen kein Ollama im Testlauf.
    async def fake_translate(text: str, cfg: TranslatorConfig) -> Translation | None:
        assert cfg.target_lang == "de"
        return Translation(language="nl", translated_text="Wie ist der Chef?")

    monkeypatch.setattr(svc_mod, "translate", fake_translate)

    # Notify-Sink, der alle Events sammelt.
    events: list[tuple] = []

    async def notify(identity_id, event):  # type: ignore[no-untyped-def]
        events.append((identity_id, event))

    svc.notify = notify
    svc.translation = _cfg()

    # Identity + Peer-Contact aufsetzen.
    me = await svc.add_identity(user_id=user_id, name="Antonia", scope="public")
    sender = CompanionNode(LocalIdentity.generate())
    await _add_contact(sessionmaker, me.id, sender.pub_key)

    # Eingehende NL-DM einliefern.
    pkt = sender.make_dm(peer_pubkey=me.pubkey, text="Wie is de baas?", timestamp=int(time.time()))
    await svc.on_inbound_packet(raw=pkt.encode(), scope="public")

    # Auf Hintergrund-Translator warten.
    await _wait_translation_tasks(svc)

    # DB-Row sollte language + translated_text gesetzt haben.
    async with sessionmaker() as db:
        row = (
            await db.execute(select(CompanionMessage).where(CompanionMessage.identity_id == me.id))
        ).scalar_one()
        assert row.text == "Wie is de baas?"
        assert row.language == "nl"
        assert row.translated_text == "Wie ist der Chef?"
        assert row.translated_at is not None

    # Zwei Events erwartet: das initiale "dm" + ein "message_translated".
    types = [evt.get("type") for _, evt in events]
    assert "dm" in types
    assert "message_translated" in types
    translated_evt = next(evt for _, evt in events if evt.get("type") == "message_translated")
    assert translated_evt["language"] == "nl"
    assert translated_evt["translated_text"] == "Wie ist der Chef?"


@pytest.mark.asyncio
async def test_inbound_dm_no_translation_when_disabled(
    service_env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Ohne svc.translation soll keine Übersetzung passieren — auch wenn
    der Stub erreichbar wäre, wird er gar nicht erst aufgerufen."""
    svc, sessionmaker, user_id, _sent = service_env

    called = False

    async def fake_translate(text, cfg):  # type: ignore[no-untyped-def]
        nonlocal called
        called = True
        return Translation(language="nl", translated_text="x")

    monkeypatch.setattr(svc_mod, "translate", fake_translate)

    me = await svc.add_identity(user_id=user_id, name="Antonia", scope="public")
    sender = CompanionNode(LocalIdentity.generate())
    await _add_contact(sessionmaker, me.id, sender.pub_key)

    pkt = sender.make_dm(peer_pubkey=me.pubkey, text="Wie is de baas?", timestamp=int(time.time()))
    await svc.on_inbound_packet(raw=pkt.encode(), scope="public")
    await _wait_translation_tasks(svc)

    assert called is False
    async with sessionmaker() as db:
        row = (
            await db.execute(select(CompanionMessage).where(CompanionMessage.identity_id == me.id))
        ).scalar_one()
        assert row.translated_text is None
        assert row.language is None


@pytest.mark.asyncio
async def test_translation_skipped_keeps_row_clean(
    service_env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Wenn translate() None liefert (z.B. Skip-Heuristik oder Fehler),
    bleibt das Row unverändert und es gibt kein zusätzliches Event."""
    svc, sessionmaker, user_id, _sent = service_env

    async def fake_translate(text, cfg):  # type: ignore[no-untyped-def]
        return None

    monkeypatch.setattr(svc_mod, "translate", fake_translate)

    events: list[tuple] = []

    async def notify(identity_id, event):  # type: ignore[no-untyped-def]
        events.append((identity_id, event))

    svc.notify = notify
    svc.translation = _cfg()

    me = await svc.add_identity(user_id=user_id, name="Antonia", scope="public")
    sender = CompanionNode(LocalIdentity.generate())
    await _add_contact(sessionmaker, me.id, sender.pub_key)

    pkt = sender.make_dm(peer_pubkey=me.pubkey, text="Hallo", timestamp=int(time.time()))
    await svc.on_inbound_packet(raw=pkt.encode(), scope="public")
    await _wait_translation_tasks(svc)

    async with sessionmaker() as db:
        row = (
            await db.execute(select(CompanionMessage).where(CompanionMessage.identity_id == me.id))
        ).scalar_one()
        assert row.translated_text is None
        assert row.translated_at is None

    types = [evt.get("type") for _, evt in events]
    assert "message_translated" not in types
