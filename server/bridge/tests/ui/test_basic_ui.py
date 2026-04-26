"""Playwright-Smoke-Tests. Aktivieren mit ``pytest -m ui tests/ui/``.

Diese Tests sind absichtlich knapp gehalten — sie sichern Frontend-Boot,
Static-Assets und Mobile-Toggle ab. Detaillierte Flows (DM-Senden,
Pagination, Suche, SSE) folgen iterativ, sobald die Test-Infrastruktur
in CI stabil ist.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.ui


def test_login_page_loads_and_static_css(live_server: str, page) -> None:
    page.goto(f"{live_server}/login")
    assert page.title()  # Title-Block "Login — MeshCore Spiegel"
    # Static-CSS muss eingebunden sein
    css_links = page.locator('link[rel="stylesheet"]').all()
    hrefs = [el.get_attribute("href") for el in css_links]
    assert any("/static/app.css" in (h or "") for h in hrefs)


def test_signup_creates_user_and_lands_on_dashboard(live_server: str, page) -> None:
    page.goto(f"{live_server}/signup")
    page.fill('input[name="email"]', "ui@example.com")
    page.fill('input[name="password"]', "longenoughpw1!")
    page.click('button[type="submit"]')
    # require_email_verification=false → direkt eingeloggt → Dashboard
    page.wait_for_url(f"{live_server}/dashboard", timeout=10_000)
    assert "Dashboard" in page.content()


def test_mobile_toggle_threads_to_conv(live_server: str, browser) -> None:
    """Auf einem 375x667-Viewport (iPhone-SE) sollte ``.messenger`` per
    data-mobile-view zwischen Threads und Conv toggeln. Der konkrete
    Klick-Pfad braucht eine Identity + Login — wir checken hier nur, dass
    Default ``data-mobile-view="threads"`` gesetzt ist und der
    .conv-back-Button existiert."""
    ctx = browser.new_context(viewport={"width": 375, "height": 667})
    page = ctx.new_page()
    page.goto(f"{live_server}/signup")
    page.fill('input[name="email"]', "mobile@example.com")
    page.fill('input[name="password"]', "longenoughpw1!")
    page.click('button[type="submit"]')
    page.wait_for_url(f"{live_server}/dashboard", timeout=10_000)
    # Companion-Index → Identity anlegen
    page.goto(f"{live_server}/companion/")
    page.fill('input[name="name"]', "Mobile-Test")
    page.click('button[type="submit"]')
    # Detail-Seite öffnen (erste Identity)
    detail_link = page.locator("a", has_text="öffnen").first
    detail_link.click()
    # Tab "Chats" hat eine .messenger Card mit data-mobile-view="threads"
    messenger = page.locator(".messenger")
    assert messenger.get_attribute("data-mobile-view") == "threads"
    back_btn = page.locator(".conv-back")
    assert back_btn.count() == 1
    ctx.close()
