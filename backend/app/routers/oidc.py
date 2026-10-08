"""Anmelden ueber OIDC: Weiterleitung zum Dienst und Rueckkehr mit dem Code.

Beides sind Seitenaufrufe des Browsers, keine API-Aufrufe. Fehler gehen deshalb als Weiterleitung auf die
Anmeldeseite zurueck (``/?sso_error=<kennung>``), nicht als JSON.
"""

from __future__ import annotations

import logging
import secrets

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, Response

from ..deps import DbSession
from ..security import create_oidc_flow_token, decode_oidc_flow_token
from ..services import oidc, sitzung
from ..services.settings_service import AppSettings, load_settings

logger = logging.getLogger("nexbeat.oidc")

router = APIRouter(prefix="/api/auth/oidc", tags=["auth"])

FLOW_COOKIE = "nexbeat_oidc"
FLOW_PATH = "/api/auth/oidc"


def redirect_uri(settings: AppSettings, request: Request) -> str:
    """Muss genau so beim Dienst eingetragen sein. Hinter einem Proxy gehoert die Adresse unter "System" hinein."""
    base = settings.public_url or str(request.base_url).rstrip("/")
    return f"{base}{FLOW_PATH}/callback"


def _forget_flow(request: Request, response: Response) -> None:
    # Pfad und Secure wie beim Setzen, sonst bleibt das echte Cookie liegen.
    response.delete_cookie(
        FLOW_COOKIE, path=FLOW_PATH, secure=sitzung.cookie_secure(request), httponly=True, samesite="lax"
    )


def _back(request: Request, code: str) -> RedirectResponse:
    response = RedirectResponse(f"/?sso_error={code}", status_code=303)
    _forget_flow(request, response)
    return response


@router.get("/login", include_in_schema=False)
async def start(request: Request, db: DbSession) -> Response:
    settings = load_settings(db)
    if not settings.oidc_ready:
        return _back(request, "sso_disabled")
    try:
        document = await oidc.discover(settings.text("oidc_issuer"))
    except oidc.OidcError as error:
        logger.warning("Sign-in could not start: %s", error)
        return _back(request, error.code)
    flow = oidc.new_flow()
    target = oidc.authorize_url(document, settings, redirect_uri(settings, request), flow)
    response = RedirectResponse(target, status_code=303)
    response.set_cookie(
        FLOW_COOKIE,
        create_oidc_flow_token(flow),
        max_age=600,
        path=FLOW_PATH,
        httponly=True,
        samesite="lax",
        secure=sitzung.cookie_secure(request),
    )
    return response


@router.get("/callback", include_in_schema=False)
async def callback(
    request: Request, db: DbSession, code: str | None = None, state: str | None = None, error: str | None = None
) -> Response:
    settings = load_settings(db)
    if not settings.oidc_ready:
        return _back(request, "sso_disabled")
    raw = request.cookies.get(FLOW_COOKIE)
    flow = decode_oidc_flow_token(raw) if raw else None
    if error:
        logger.info("The provider refused the sign-in: %s", error)
        return _back(request, "sso_denied" if error == "access_denied" else "sso_failed")
    if flow is None or not code or not state or not secrets.compare_digest(flow.state, state):
        return _back(request, "sso_failed")
    try:
        identity = await oidc.complete(settings, redirect_uri(settings, request), code, flow)
        user = oidc.sign_in(db, settings, identity)
    except oidc.OidcError as failure:
        logger.warning("OIDC sign-in failed: %s", failure)
        return _back(request, failure.code)
    response = RedirectResponse("/", status_code=303)
    _forget_flow(request, response)
    sitzung.remember_device(response, request, user)
    # Die Seite holt sich beim Laden mit dem Cookie ihren Zugangs-Token, siehe ``POST /api/auth/refresh``.
    sitzung.start(response, request, user)
    return response
