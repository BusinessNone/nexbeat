"""Persoenliche API-Token, gebaut wie in Nexview.

⚠️ **Der Klartext existiert genau einmal**, in der Antwort aufs Anlegen. Danach gibt es nur noch die
Pruefsumme. Wer einen Token verliert, legt einen neuen an; wiederherstellen kann ihn niemand, auch der
Admin nicht.

Ein Token erbt die Rechte seines Kontos. Die einzige Abstufung ist "nur lesen": Dann gehen nur GET,
HEAD und OPTIONS. Das ist bei nexbeat zulaessig, weil kein GET etwas veraendert, was ein anderer sieht.
Eine Liste erlaubter Adressen muesste man bei jedem neuen Endpunkt pflegen, und wer das vergisst, macht
ein Loch statt einer Sperre.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import ApiKey, User, utcnow

logger = logging.getLogger("nexbeat.api_keys")

#: ⚠️ Kein Schmuck. Es trennt einen Token von einem Sitzungs-Token, ohne dass jemand raten muss, und
#: macht ihn fuer Scanner erkennbar, die Quelltext nach veroeffentlichten Geheimnissen absuchen.
PREFIX = "nxb_"
#: Bytes fuer ``token_urlsafe``, gibt rund 54 Zeichen.
LENGTH = 40
#: Damit die Liste im Profil eine Liste bleibt, keine Sicherheitsmassnahme.
MOST = 20
#: ``last_used_at`` wird nicht bei jeder Anfrage geschrieben. Ein Dashboard, das jede Minute fragt,
#: erzeugte sonst 1.440 Schreibvorgaenge am Tag fuer eine Angabe, die niemand minutengenau braucht.
REMEMBER_USE_AFTER = timedelta(minutes=15)
#: Methoden, die ein Token mit "nur lesen" benutzen darf.
READING = frozenset({"GET", "HEAD", "OPTIONS"})


class ApiKeyProblem(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400) -> None:
        super().__init__(code)
        self.code = code
        self.message = message
        self.status_code = status_code


def _digest(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def looks_like_key(raw: str) -> bool:
    """Billig und ohne Datenbank: Nur mit dem Praefix wird nachgesehen."""
    return raw.startswith(PREFIX)


def create(db: Session, user: User, *, name: str, read_only: bool) -> tuple[ApiKey, str]:
    """Einen Token anlegen. Gibt den Eintrag **und** den Klartext zurueck, den es nur hier gibt."""
    clean = name.strip()
    if not clean:
        raise ApiKeyProblem("api_key_needs_name", "An API token needs a name.")
    if db.scalar(select(ApiKey.id).where(ApiKey.user_id == user.id).limit(1).offset(MOST - 1)) is not None:
        raise ApiKeyProblem("api_key_too_many", f"An account can have at most {MOST} API tokens.")
    raw = PREFIX + secrets.token_urlsafe(LENGTH)
    key = ApiKey(
        user_id=user.id,
        name=clean[:80],
        token_hash=_digest(raw),
        # Genug zum Wiedererkennen, zu wenig zum Raten.
        preview=raw[: len(PREFIX) + 6],
        read_only=read_only,
    )
    db.add(key)
    db.commit()
    db.refresh(key)
    logger.info(
        "API token %r created for %r (%s)",
        key.name,
        user.username,
        "read-only" if read_only else "full rights of its owner",
    )
    return key, raw


def of_user(db: Session, user: User) -> list[ApiKey]:
    return list(db.scalars(select(ApiKey).where(ApiKey.user_id == user.id).order_by(ApiKey.created_at.desc())))


def all_keys(db: Session) -> list[ApiKey]:
    return list(db.scalars(select(ApiKey).order_by(ApiKey.created_at.desc())))


def revoke(db: Session, user: User, key_id: int) -> None:
    """Einen eigenen Token entfernen.

    ⚠️ Die Bedingung auf ``user_id`` ist der Schutz: Ohne sie koennte jeder mit einer geratenen Nummer
    fremde Token widerrufen.
    """
    key = db.scalar(select(ApiKey).where(ApiKey.id == key_id, ApiKey.user_id == user.id))
    if key is None:
        raise ApiKeyProblem("api_key_not_found", "This API token does not exist.", 404)
    db.delete(key)
    db.commit()
    logger.info("API token %r of %r revoked", key.name, user.username)


def redeem(db: Session, raw: str, now: datetime | None = None) -> ApiKey | None:
    """Den Token nachschlagen und seine Nutzung vermerken. ``None`` bei unbekanntem Token oder
    stillgelegtem Konto, der Aufrufer macht daraus ein 401."""
    key = db.scalar(select(ApiKey).where(ApiKey.token_hash == _digest(raw)))
    if key is None or key.user is None or not key.user.is_active:
        return None
    moment = now or utcnow()
    if key.last_used_at is None or moment - key.last_used_at >= REMEMBER_USE_AFTER:
        key.last_used_at = moment
        db.commit()
    return key


def allows(key: ApiKey, method: str) -> bool:
    return not key.read_only or method.upper() in READING
