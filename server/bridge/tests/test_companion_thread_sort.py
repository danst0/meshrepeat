"""Sort-Reihenfolge der DM-Sidebar (/threads → renderDmList)."""

from __future__ import annotations

from meshcore_bridge.web.companion_routes import _sort_dm_threads


def _row(
    *,
    name: str,
    last_ts: str | None,
    last_text: str | None = None,
    favorite: bool = False,
) -> dict[str, object]:
    return {
        "id": name,
        "peer_pubkey_hex": name + "00",
        "peer_name": name,
        "favorite": favorite,
        "node_type": None,
        "last_ts": last_ts,
        "last_text": last_text,
        "last_direction": "in" if last_text else None,
    }


def test_sort_dms_with_messages_above_advert_only_contacts() -> None:
    """Kontakt mit echter DM (älteres ts) muss vor reinem Advert-Kontakt
    mit aktuellerem last_seen stehen."""
    rows = [
        _row(name="advert_recent", last_ts="2026-05-02T10:00:00+00:00"),
        _row(name="dm_old", last_ts="2026-04-01T10:00:00+00:00", last_text="hi"),
        _row(name="advert_older", last_ts="2026-04-30T10:00:00+00:00"),
        _row(name="dm_recent", last_ts="2026-05-01T10:00:00+00:00", last_text="ja"),
    ]
    _sort_dm_threads(rows)
    assert [r["id"] for r in rows] == [
        "dm_recent",
        "dm_old",
        "advert_recent",
        "advert_older",
    ]


def test_sort_favorites_above_everything() -> None:
    """Favorit ohne DM steht vor nicht-favoritem Kontakt mit DM."""
    rows = [
        _row(name="dm_plain", last_ts="2026-05-02T10:00:00+00:00", last_text="hi"),
        _row(name="fav_advert", last_ts="2026-04-01T10:00:00+00:00", favorite=True),
        _row(name="advert", last_ts="2026-05-01T10:00:00+00:00"),
    ]
    _sort_dm_threads(rows)
    assert [r["id"] for r in rows] == ["fav_advert", "dm_plain", "advert"]


def test_sort_inside_group_by_last_ts_desc() -> None:
    rows = [
        _row(name="c", last_ts="2026-05-01T10:00:00+00:00", last_text="x"),
        _row(name="a", last_ts="2026-05-03T10:00:00+00:00", last_text="x"),
        _row(name="b", last_ts="2026-05-02T10:00:00+00:00", last_text="x"),
    ]
    _sort_dm_threads(rows)
    assert [r["id"] for r in rows] == ["a", "b", "c"]


def test_sort_handles_missing_ts() -> None:
    rows = [
        _row(name="no_ts", last_ts=None),
        _row(name="with_ts", last_ts="2026-05-02T10:00:00+00:00"),
    ]
    _sort_dm_threads(rows)
    assert [r["id"] for r in rows] == ["with_ts", "no_ts"]
