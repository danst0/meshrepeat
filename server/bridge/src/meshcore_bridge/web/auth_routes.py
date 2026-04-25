"""Auth-Routen: Signup, Login, Logout, E-Mail-Verifikation."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from meshcore_bridge.auth.email import (
    ConsoleEmailSender,
    EmailSender,
    consume_token,
    issue_token,
)
from meshcore_bridge.auth.passwords import hash_password, verify_password
from meshcore_bridge.auth.sessions import (
    create_session,
    decode_cookie,
    destroy_session,
    encode_cookie,
)
from meshcore_bridge.config import AppConfig
from meshcore_bridge.db import User
from meshcore_bridge.web.deps import current_user_optional, get_config, get_db

router = APIRouter()
_email_sender: EmailSender = ConsoleEmailSender()

MIN_PASSWORD_LEN = 12


def _templates(request: Request) -> Jinja2Templates:
    templates = getattr(request.app.state, "templates", None)
    if templates is None:
        raise RuntimeError("templates not attached to app.state")
    return templates  # type: ignore[no-any-return]


def _set_session_cookie(
    response: Response, *, sid: bytes, cfg: AppConfig
) -> None:
    response.set_cookie(
        cfg.web.session_cookie_name,
        encode_cookie(sid),
        max_age=cfg.web.session_idle_timeout_days * 86_400,
        httponly=True,
        secure=cfg.web.base_url.startswith("https://"),
        samesite="strict",
        path="/",
    )


def _clear_session_cookie(response: Response, cfg: AppConfig) -> None:
    response.delete_cookie(cfg.web.session_cookie_name, path="/")


@router.get("/", response_class=HTMLResponse)
async def index(
    request: Request,
    user: User | None = Depends(current_user_optional),
    cfg: AppConfig = Depends(get_config),
) -> HTMLResponse:
    return _templates(request).TemplateResponse(
        request,
        "index.html.j2",
        {"user": user, "host": cfg.web.base_url.split("://", 1)[-1]},
    )


@router.get("/signup", response_class=HTMLResponse)
async def signup_form(
    request: Request,
    user: User | None = Depends(current_user_optional),
) -> HTMLResponse:
    return _templates(request).TemplateResponse(
        request, "signup.html.j2", {"user": user, "email": None, "flash": None}
    )


@router.post("/signup", response_model=None)
async def signup_submit(
    request: Request,
    response: Response,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    db: AsyncSession = Depends(get_db),
    cfg: AppConfig = Depends(get_config),
) -> HTMLResponse | RedirectResponse:
    if not cfg.web.signup.enabled:
        return _templates(request).TemplateResponse(
            request,
            "signup.html.j2",
            {
                "user": None,
                "email": email,
                "flash": {"kind": "error", "message": "Signup deaktiviert."},
            },
            status_code=403,
        )

    email = email.strip().lower()
    if len(password) < MIN_PASSWORD_LEN:
        return _templates(request).TemplateResponse(
            request,
            "signup.html.j2",
            {
                "user": None,
                "email": email,
                "flash": {"kind": "error", "message": "Passwort muss mind. 12 Zeichen haben."},
            },
            status_code=400,
        )
    existing = (
        await db.execute(select(User).where(User.email == email))
    ).scalar_one_or_none()
    if existing is not None:
        return _templates(request).TemplateResponse(
            request,
            "signup.html.j2",
            {
                "user": None,
                "email": email,
                "flash": {"kind": "error", "message": "Diese E-Mail ist schon registriert."},
            },
            status_code=400,
        )

    user = User(email=email, password_hash=hash_password(password), role="owner")
    db.add(user)
    await db.commit()

    if cfg.web.signup.require_email_verification:
        token = await issue_token(db, user_id=user.id, purpose="email_verify")
        verify_url = f"{cfg.web.base_url}/verify-email?token={token}"
        await _email_sender.send(
            to=email,
            subject="MeshCore Spiegel — E-Mail bestätigen",
            body=f"Bestätige deine E-Mail unter: {verify_url}",
        )
        return _templates(request).TemplateResponse(
            request,
            "login.html.j2",
            {
                "user": None,
                "email": email,
                "flash": {
                    "kind": "ok",
                    "message": "Account angelegt. Bitte E-Mail prüfen und Bestätigungslink öffnen.",
                },
            },
        )

    sid = await create_session(db, user_id=user.id, user_agent=request.headers.get("user-agent"))
    redirect = RedirectResponse(url="/dashboard", status_code=303)
    _set_session_cookie(redirect, sid=sid, cfg=cfg)
    return redirect


@router.get("/verify-email", response_class=HTMLResponse)
async def verify_email(
    request: Request,
    token: str,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    user_id = await consume_token(db, token=token, purpose="email_verify")
    if user_id is None:
        return _templates(request).TemplateResponse(
            request,
            "verify_email.html.j2",
            {
                "user": None,
                "success": False,
                "message": "Token ungültig oder abgelaufen.",
                "flash": None,
            },
            status_code=400,
        )
    user = await db.get(User, user_id)
    if user is not None:
        from datetime import UTC, datetime

        user.email_verified_at = datetime.now(UTC)
        await db.commit()
    return _templates(request).TemplateResponse(
        request,
        "verify_email.html.j2",
        {"user": None, "success": True, "message": "E-Mail bestätigt.", "flash": None},
    )


@router.get("/login", response_class=HTMLResponse)
async def login_form(
    request: Request,
    user: User | None = Depends(current_user_optional),
) -> HTMLResponse:
    return _templates(request).TemplateResponse(
        request, "login.html.j2", {"user": user, "email": None, "flash": None}
    )


@router.post("/login", response_model=None)
async def login_submit(
    request: Request,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    db: AsyncSession = Depends(get_db),
    cfg: AppConfig = Depends(get_config),
) -> HTMLResponse | RedirectResponse:
    email = email.strip().lower()
    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if user is None or not verify_password(user.password_hash, password):
        return _templates(request).TemplateResponse(
            request,
            "login.html.j2",
            {
                "user": None,
                "email": email,
                "flash": {"kind": "error", "message": "E-Mail oder Passwort falsch."},
            },
            status_code=401,
        )
    if cfg.web.signup.require_email_verification and user.email_verified_at is None:
        return _templates(request).TemplateResponse(
            request,
            "login.html.j2",
            {
                "user": None,
                "email": email,
                "flash": {
                    "kind": "error",
                    "message": "E-Mail noch nicht bestätigt — bitte Bestätigungslink öffnen.",
                },
            },
            status_code=403,
        )
    sid = await create_session(db, user_id=user.id, user_agent=request.headers.get("user-agent"))
    redirect = RedirectResponse(url="/dashboard", status_code=303)
    _set_session_cookie(redirect, sid=sid, cfg=cfg)
    return redirect


@router.post("/logout")
async def logout(
    request: Request,
    db: AsyncSession = Depends(get_db),
    cfg: AppConfig = Depends(get_config),
) -> RedirectResponse:
    cookie_value = request.cookies.get(cfg.web.session_cookie_name)
    if cookie_value:
        sid = decode_cookie(cookie_value)
        if sid is not None:
            await destroy_session(db, sid)
    redirect = RedirectResponse(url="/", status_code=303)
    _clear_session_cookie(redirect, cfg)
    return redirect


def set_email_sender(sender: EmailSender) -> None:
    """For tests: swap the email sender."""
    global _email_sender
    _email_sender = sender
