"""End-to-End: eingehende DM wird im Hintergrund übersetzt, Felder
landen in companion_messages, ``message_translated`` wird emittiert."""

from __future__ import annotations

import asyncio
import contextlib
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


@pytest.mark.asyncio
async def test_inbound_dm_skipped_when_no_listener(
    service_env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Wenn ``is_listener_active`` False liefert (kein Browser-Tab offen),
    läuft der Live-Pfad nicht. Der Batch-Loop muss das später nachholen."""
    svc, sessionmaker, user_id, _sent = service_env

    called = False

    async def fake_translate(text, cfg):  # type: ignore[no-untyped-def]
        nonlocal called
        called = True
        return Translation(language="nl", translated_text="x")

    monkeypatch.setattr(svc_mod, "translate", fake_translate)

    svc.translation = _cfg()
    svc.is_listener_active = lambda: False

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
        assert row.text == "Wie is de baas?"
        assert row.translated_text is None
        assert row.translated_at is None


@pytest.mark.asyncio
async def test_batch_loop_translates_pending_rows(
    service_env, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``_translation_batch_loop`` holt Rows mit translated_text=NULL nach."""
    svc, sessionmaker, user_id, _sent = service_env

    async def fake_translate(text, cfg):  # type: ignore[no-untyped-def]
        return Translation(language="nl", translated_text=f"DE:{text}")

    monkeypatch.setattr(svc_mod, "translate", fake_translate)

    events: list[tuple] = []

    async def notify(identity_id, event):  # type: ignore[no-untyped-def]
        events.append((identity_id, event))

    svc.notify = notify
    svc.translation = _cfg()
    # Listener ist offline → Live-Pfad läuft nicht; nur der Batch zählt.
    svc.is_listener_active = lambda: False

    me = await svc.add_identity(user_id=user_id, name="Antonia", scope="public")
    sender = CompanionNode(LocalIdentity.generate())
    await _add_contact(sessionmaker, me.id, sender.pub_key)

    # Zwei Inbound-DMs einliefern — beide bleiben unübersetzt. Timestamps
    # auseinanderhalten, sonst greift dm_retry_dedup und verwirft den zweiten.
    base_ts = int(time.time())
    for offset, txt in enumerate(("Wie is de baas?", "Tot ziens")):
        pkt = sender.make_dm(peer_pubkey=me.pubkey, text=txt, timestamp=base_ts + offset)
        await svc.on_inbound_packet(raw=pkt.encode(), scope="public")
    await _wait_translation_tasks(svc)

    async with sessionmaker() as db:
        rows = list(
            (
                await db.execute(
                    select(CompanionMessage).where(CompanionMessage.identity_id == me.id)
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 2
        assert all(r.translated_text is None for r in rows)

    # Batch-Loop mit kurzer Tickrate manuell anstoßen, dann nach einem
    # Durchlauf (≈ Initial-Pause + Verarbeitung) wieder stoppen.
    svc.translation = TranslatorConfig(
        base_url="http://stub.local",
        model="stub",
        target_lang="de",
        target_lang_label="Deutsch",
        timeout_s=5.0,
        min_chars=3,
        max_chars=800,
        batch_interval_s=1,  # 1 s Initial-Pause, schneller Test
    )
    task = asyncio.create_task(svc._translation_batch_loop())
    # Genug Zeit für eine Iteration: Initial-Pause + zwei Übersetzungen.
    await asyncio.sleep(2.0)
    svc._stop.set()
    try:
        await asyncio.wait_for(task, timeout=2.0)
    except TimeoutError:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
    finally:
        svc._stop.clear()

    async with sessionmaker() as db:
        rows = list(
            (
                await db.execute(
                    select(CompanionMessage).where(CompanionMessage.identity_id == me.id)
                )
            )
            .scalars()
            .all()
        )
        assert len(rows) == 2
        for r in rows:
            assert r.translated_text == f"DE:{r.text}"
            assert r.translated_at is not None
            assert r.language == "nl"

    types = [evt.get("type") for _, evt in events]
    assert types.count("message_translated") == 2
