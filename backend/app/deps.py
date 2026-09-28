"""Wiederverwendbare Pruefungen: angemeldet? Admin?"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_db
from .meldungen import fehler, meldung
from .middleware import set_actor
from .models import ApiKey, User
from .security import decode_token
from .services import api_keys, sitzung

_bearer = HTTPBearer(auto_error=False)

DbSession = Annotated[Session, Depends(get_db)]


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=meldung("not_signed_in", "Not signed in."),
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    db: DbSession,
) -> User:
    """Das Konto hinter einem Sitzungs-Token oder einem API-Token.

    Ein API-Token nimmt einen eigenen Weg: Pruefsumme statt Unterschrift, und ``sitzung.still_valid``
    gilt fuer ihn nicht. Ein Passwortwechsel laesst Anbindungen also weiterlaufen, wie in Nexview;
    ein stillgelegtes Konto sperrt sie mit.
    """
    unauthorized = _unauthorized()
    if credentials is None:
        raise unauthorized
    if api_keys.looks_like_key(credentials.credentials):
        key = api_keys.redeem(db, credentials.credentials)
        if key is None:
            raise unauthorized
        if not api_keys.allows(key, request.method):
            raise fehler("api_key_read_only", "This API token may only read.", 403)
        request.state.api_key = key
        set_actor(f"{key.user.username} (token {key.preview})")
        return key.user
    content = decode_token(credentials.credentials, "access")
    if content is None:
        raise unauthorized
    user = db.get(User, content.user_id)
    if user is None or not user.is_active or not sitzung.still_valid(content, user):
        raise unauthorized
    set_actor(user.username)
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def key_of_request(request: Request) -> ApiKey | None:
    """Der API-Token, mit dem diese Anfrage kam, oder ``None`` bei einer Sitzung im Browser."""
    return getattr(request.state, "api_key", None)


def require_session(request: Request, user: CurrentUser) -> User:
    """Nur mit einer Sitzung im Browser, nie mit einem API-Token.

    ⚠️ Fuer Token-Verwaltung und Passwort: Ein Token, der sich selbst weitere Token ausstellt, ueberlebte
    jeden Widerruf; und ein Skript hat an einem Passwort nichts zu suchen.
    """
    if key_of_request(request) is not None:
        raise fehler("api_key_not_here", "This needs a sign-in in the browser, not an API token.", 403)
    return user


SessionUser = Annotated[User, Depends(require_session)]


def require_admin(user: CurrentUser) -> User:
    if not user.is_admin:
        raise fehler("admins_only", "This action is reserved for administrators.", 403)
    return user


AdminUser = Annotated[User, Depends(require_admin)]


def has_any_user(db: Session) -> bool:
    return db.scalar(select(User.id).limit(1)) is not None
