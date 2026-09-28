"""API-Token: die eigenen anlegen, ansehen, widerrufen, und fuer Admins die Uebersicht."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..deps import AdminUser, DbSession, SessionUser
from ..meldungen import fehler
from ..models import ApiKey
from ..services import api_keys
from ..services.api_keys import ApiKeyProblem

router = APIRouter(tags=["api keys"])


class ApiKeyIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    read_only: bool = False


class ApiKeyOut(BaseModel):
    id: int
    name: str
    preview: str
    read_only: bool
    created_at: datetime
    last_used_at: datetime | None


class ApiKeyCreatedOut(ApiKeyOut):
    #: Der Klartext. Er steht nur in dieser einen Antwort.
    token: str


class ApiKeyOwnerOut(ApiKeyOut):
    user_id: int
    username: str


def _out(key: ApiKey) -> ApiKeyOut:
    return ApiKeyOut(
        id=key.id,
        name=key.name,
        preview=key.preview,
        read_only=key.read_only,
        created_at=key.created_at,
        last_used_at=key.last_used_at,
    )


def _problem(error: ApiKeyProblem) -> HTTPException:
    return fehler(error.code, error.message, error.status_code)


@router.get("/api/auth/me/keys", response_model=list[ApiKeyOut], summary="The signed-in account's API tokens")
def my_keys(user: SessionUser, db: DbSession) -> list[ApiKeyOut]:
    return [_out(key) for key in api_keys.of_user(db, user)]


@router.post(
    "/api/auth/me/keys",
    status_code=201,
    response_model=ApiKeyCreatedOut,
    summary="Create an API token; the token itself is only in this answer",
)
def create_key(payload: ApiKeyIn, user: SessionUser, db: DbSession) -> ApiKeyCreatedOut:
    try:
        key, raw = api_keys.create(db, user, name=payload.name, read_only=payload.read_only)
    except ApiKeyProblem as error:
        raise _problem(error) from error
    return ApiKeyCreatedOut(**_out(key).model_dump(), token=raw)


@router.delete("/api/auth/me/keys/{key_id}", status_code=204, summary="Revoke one of the account's API tokens")
def revoke_key(key_id: int, user: SessionUser, db: DbSession) -> None:
    try:
        api_keys.revoke(db, user, key_id)
    except ApiKeyProblem as error:
        raise _problem(error) from error


@router.get("/api/admin/api-keys", response_model=list[ApiKeyOwnerOut], summary="Every API token of this installation")
def every_key(_admin: AdminUser, db: DbSession) -> list[ApiKeyOwnerOut]:
    """⚠️ Nur ansehen. Widerrufen kann ein Token nur sein Besitzer; ein Admin legt im Notfall das Konto
    still, das sperrt dessen Token mit. So haelt es Nexview auch."""
    return [
        ApiKeyOwnerOut(**_out(key).model_dump(), user_id=key.user_id, username=key.user.username)
        for key in api_keys.all_keys(db)
    ]
