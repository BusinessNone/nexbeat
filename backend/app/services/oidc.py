"""Anmeldung ueber einen OIDC-Dienst (Entra, Keycloak, Google ...), Authorization-Code-Fluss mit PKCE.

Der Dienst weist nur nach, wer da ist. Ob jemand hinein darf, entscheidet nexbeat: Die Adresse muss zu einer
der erlaubten Domaenen gehoeren. Danach laeuft alles wie bei einem Passwort-Konto, die Sitzung entsteht in
``sitzung.start``.

⚠️ Zugeordnet wird ueber ``(issuer, sub)``. Die Adresse dient nur dem ersten Zusammenfuehren mit einem Konto,
das es schon gibt, und nur, wenn sie zu einer erlaubten Domaene gehoert.

⚠️ Mehrmandanten-Aussteller (``common``, ``organizations``) sind abgelehnt: Dort stellt jeder beliebige
Mandant Tokens aus, und die Adresse darin ist nichts wert. Fuer Entra gehoert die Mandanten-ID in den Aussteller.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx
import jwt
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import __version__
from ..models import Role, User, UserIdentity, utcnow
from ..schemas import USERNAME_PATTERN
from ..security import OidcFlow
from . import http
from .mail import valid_address
from .settings_service import AppSettings
from .tokens import normalize_email

logger = logging.getLogger("nexbeat.oidc")

#: Wer ohne Passwort angelegt wird, bekommt diesen Wert. Er ist kein bcrypt-Hash, also passt kein Passwort.
NO_PASSWORD = "!oidc"
_ALGORITHMS = ["RS256", "RS384", "RS512", "PS256", "ES256", "ES384"]
_ENTRA = "https://login.microsoftonline.com/"
_CACHE_SECONDS = 3600
_discovery: dict[str, tuple[float, dict[str, Any]]] = {}
_keys: dict[str, tuple[float, dict[str, Any]]] = {}


class OidcError(Exception):
    """``code`` ist die Kennung, die die Anmeldeseite uebersetzt (``login.sso.<code>``)."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass(frozen=True)
class Identity:
    issuer: str
    subject: str
    email: str
    name: str


def reset_cache() -> None:
    _discovery.clear()
    _keys.clear()


def _secure(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme == "https" or (parsed.scheme == "http" and parsed.hostname in ("localhost", "127.0.0.1"))


async def _get_json(url: str) -> dict[str, Any]:
    try:
        response = await http.client("oidc").get(url)
        response.raise_for_status()
        data = response.json()
    except (httpx.HTTPError, ValueError) as error:
        raise OidcError("sso_unavailable", f"{url}: {error}") from error
    if not isinstance(data, dict):
        raise OidcError("sso_unavailable", f"{url}: not an object")
    return data


async def discover(issuer: str) -> dict[str, Any]:
    cached = _discovery.get(issuer)
    if cached and cached[0] > time.monotonic():
        return cached[1]
    if "{" in issuer or re.search(r"/(common|organizations|consumers)(/|$)", issuer):
        raise OidcError("sso_issuer_multitenant", issuer)
    if not _secure(issuer):
        raise OidcError("sso_unavailable", "issuer is not https")
    document = await _get_json(f"{issuer}/.well-known/openid-configuration")
    if str(document.get("issuer", "")).rstrip("/") != issuer:
        raise OidcError("sso_issuer_mismatch", f"{document.get('issuer')!r} != {issuer!r}")
    for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not isinstance(document.get(field), str) or not _secure(document[field]):
            raise OidcError("sso_unavailable", f"discovery document lacks a secure {field}")
    _discovery[issuer] = (time.monotonic() + _CACHE_SECONDS, document)
    return document


def new_flow() -> OidcFlow:
    return OidcFlow(
        state=secrets.token_urlsafe(24), nonce=secrets.token_urlsafe(24), verifier=secrets.token_urlsafe(48)
    )


def authorize_url(document: dict[str, Any], settings: AppSettings, redirect_uri: str, flow: OidcFlow) -> str:
    challenge = base64.urlsafe_b64encode(hashlib.sha256(flow.verifier.encode("ascii")).digest()).rstrip(b"=").decode()
    query = urlencode(
        {
            "client_id": settings.text("oidc_client_id"),
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": "openid email profile",
            "state": flow.state,
            "nonce": flow.nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    separator = "&" if "?" in document["authorization_endpoint"] else "?"
    return f"{document['authorization_endpoint']}{separator}{query}"


async def _signing_keys(uri: str, *, refresh: bool = False) -> dict[str, Any]:
    cached = _keys.get(uri)
    if cached and cached[0] > time.monotonic() and not refresh:
        return cached[1]
    data = await _get_json(uri)
    _keys[uri] = (time.monotonic() + _CACHE_SECONDS, data)
    return data


async def _verify(id_token: str, document: dict[str, Any], settings: AppSettings, nonce: str) -> dict[str, Any]:
    try:
        kid = jwt.get_unverified_header(id_token).get("kid")
    except jwt.PyJWTError as error:
        raise OidcError("sso_failed", "id_token header") from error
    key = None
    for refresh in (False, True):
        for entry in (await _signing_keys(document["jwks_uri"], refresh=refresh)).get("keys", []):
            if isinstance(entry, dict) and entry.get("kid") == kid:
                try:
                    key = jwt.PyJWK(entry).key
                except jwt.PyJWTError:
                    key = None
                break
        if key is not None:
            break  # Ein unbekanntes ``kid`` ist oft ein neuer Schluessel: einmal frisch holen.
    if key is None:
        raise OidcError("sso_failed", "unknown signing key")
    try:
        claims = jwt.decode(
            id_token,
            key,
            algorithms=_ALGORITHMS,
            audience=settings.text("oidc_client_id"),
            issuer=settings.text("oidc_issuer"),
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as error:
        raise OidcError("sso_failed", f"id_token: {error}") from error
    if not isinstance(claims.get("nonce"), str) or not secrets.compare_digest(claims["nonce"], nonce):
        raise OidcError("sso_failed", "nonce")
    return claims


def _email_of(claims: dict[str, Any], issuer: str) -> str:
    verified = claims.get("email_verified")
    if verified is False or str(verified).lower() == "false":
        raise OidcError("sso_email_unverified")
    candidates = [claims.get("email")]
    if issuer.startswith(_ENTRA):
        # Entra schickt ``email`` nur, wenn es als optionale Angabe eingeschaltet ist. Der Anmeldename im
        # eigenen Mandanten ist dann der Ersatz.
        candidates += [claims.get("preferred_username"), claims.get("upn")]
    for value in candidates:
        if isinstance(value, str) and valid_address(normalize_email(value)):
            return normalize_email(value)
    raise OidcError("sso_email_missing")


async def complete(settings: AppSettings, redirect_uri: str, code: str, flow: OidcFlow) -> Identity:
    """Code gegen Token tauschen und das ID-Token pruefen."""
    issuer = settings.text("oidc_issuer")
    document = await discover(issuer)
    try:
        response = await http.client("oidc").post(
            document["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": settings.text("oidc_client_id"),
                "client_secret": settings.text("oidc_client_secret"),
                "code_verifier": flow.verifier,
            },
        )
    except httpx.HTTPError as error:
        raise OidcError("sso_unavailable", f"token endpoint: {error}") from error
    if response.status_code != 200:
        raise OidcError("sso_failed", f"token endpoint answered {response.status_code}")
    try:
        id_token = response.json().get("id_token")
    except (ValueError, AttributeError):
        id_token = None
    if not isinstance(id_token, str):
        raise OidcError("sso_failed", "no id_token")
    claims = await _verify(id_token, document, settings, flow.nonce)
    name = claims.get("name")
    return Identity(
        issuer=issuer,
        subject=str(claims["sub"]),
        email=_email_of(claims, issuer),
        name=name.strip() if isinstance(name, str) else "",
    )


def domain_allowed(settings: AppSettings, email: str) -> bool:
    return email.rpartition("@")[2] in settings.oidc_domains


def _free_username(db: Session, email: str) -> str:
    base = re.sub(r"[^A-Za-z0-9._-]", "", email.partition("@")[0])[:28].ljust(3, "_")
    candidate, number = base, 1
    while not re.match(USERNAME_PATTERN, candidate) or db.scalar(
        select(User.id).where(func.lower(User.username) == candidate.lower())
    ):
        number += 1
        candidate = f"{base[: 32 - len(str(number))]}{number}"
    return candidate


def _resolve(db: Session, settings: AppSettings, identity: Identity) -> User:
    if not domain_allowed(settings, identity.email):
        raise OidcError("sso_domain_not_allowed", identity.email.rpartition("@")[2])
    link = db.scalar(
        select(UserIdentity).where(UserIdentity.issuer == identity.issuer, UserIdentity.subject == identity.subject)
    )
    user = db.get(User, link.user_id) if link else None
    if user is None:
        user = db.scalar(select(User).where(User.email == identity.email))
        if user is None:
            if not settings.flag("oidc_auto_create"):
                raise OidcError("sso_no_account")
            user = User(
                seen_version=__version__,
                username=_free_username(db, identity.email),
                email=identity.email,
                password_hash=NO_PASSWORD,
                role=Role.user,
                display_name=identity.name or identity.email.partition("@")[0],
                language="",
                password_changed_at=utcnow(),
            )
            db.add(user)
            db.flush()
        db.add(UserIdentity(user_id=user.id, issuer=identity.issuer, subject=identity.subject))
    if not user.is_active:
        raise OidcError("sso_account_disabled")
    db.flush()
    return user


def sign_in(db: Session, settings: AppSettings, identity: Identity) -> User:
    """Das Konto zur Anmeldung finden oder anlegen. Zwei gleichzeitige Erstanmeldungen: die zweite liest nur."""
    for attempt in (1, 2):
        try:
            user = _resolve(db, settings, identity)
            user.last_login_at = utcnow()
            db.commit()
            return user
        except IntegrityError:
            db.rollback()
            if attempt == 2:
                raise OidcError("sso_failed", "account could not be created") from None
    raise OidcError("sso_failed")  # pragma: no cover


