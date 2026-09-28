"""API-Token und die zugesagte Schnittstelle unter /api/v1."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db import SessionLocal
from app.models import ApiKey, LibraryArtist, MusicRequest, RequestStatus, User, utcnow
from app.services import api_keys
from tests.conftest import ARTIST, auth_headers, create_user


def _create(client: TestClient, headers: dict[str, str] | None = None, **body: Any) -> dict[str, Any]:
    response = client.post("/api/auth/me/keys", json={"name": "Dashboard", **body}, headers=headers or {})
    assert response.status_code == 201, response.text
    return response.json()


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _request(user_id: int, status: RequestStatus, **extra: Any) -> int:
    with SessionLocal() as db:
        row = MusicRequest(
            user_id=user_id,
            release_group_mbid=f"{len(db.scalars(select(MusicRequest.id)).all()):08d}-1111-4111-8111-111111111111",
            artist_mbid=ARTIST,
            title="Album",
            artist_name="Test Artist",
            status=status,
            **extra,
        )
        db.add(row)
        db.commit()
        return row.id


def _admin_id() -> int:
    with SessionLocal() as db:
        return db.scalars(select(User.id).where(User.username == "admin")).one()


def test_the_token_is_shown_once_and_stored_only_as_a_digest(admin_client: TestClient) -> None:
    created = _create(admin_client)
    assert created["token"].startswith("nxb_")
    assert len(created["token"]) > 50
    assert created["token"].startswith(created["preview"])

    listed = admin_client.get("/api/auth/me/keys").json()
    assert [key["name"] for key in listed] == ["Dashboard"]
    assert "token" not in listed[0]
    with SessionLocal() as db:
        stored = db.scalars(select(ApiKey)).one()
        assert created["token"] not in (stored.token_hash, stored.preview)


def test_a_token_signs_in_like_its_owner(admin_client: TestClient) -> None:
    token = _create(admin_client)["token"]
    me = admin_client.get("/api/v1/me", headers=_bearer(token)).json()
    assert me["account"]["username"] == "admin"
    assert me["key"] == {"name": "Dashboard", "read_only": False}
    assert me["may"] == ["request", "see_all", "decide"]
    # Auch der Innenteil nimmt ihn an, mit den Rechten des Kontos.
    assert admin_client.get("/api/settings", headers=_bearer(token)).status_code == 200


def test_a_browser_session_has_no_key_in_me(admin_client: TestClient) -> None:
    me = admin_client.get("/api/v1/me").json()
    assert me["key"] is None
    assert "decide" in me["may"]


def test_a_read_only_token_reads_but_never_writes(admin_client: TestClient) -> None:
    token = _create(admin_client, read_only=True)["token"]
    me = admin_client.get("/api/v1/me", headers=_bearer(token)).json()
    assert me["may"] == ["see_all"]

    waiting = _request(_admin_id(), RequestStatus.pending_approval)
    assert admin_client.get("/api/v1/admin/requests", headers=_bearer(token)).status_code == 200
    refused = admin_client.post(f"/api/v1/admin/requests/{waiting}/reject", json={}, headers=_bearer(token))
    assert refused.status_code == 403
    assert refused.json()["detail"]["code"] == "api_key_read_only"
    assert admin_client.put("/api/settings", json={"public_url": ""}, headers=_bearer(token)).status_code == 403
    with SessionLocal() as db:
        assert db.get(MusicRequest, waiting).status == RequestStatus.pending_approval


def test_a_writing_admin_token_turns_a_request_down(admin_client: TestClient) -> None:
    token = _create(admin_client)["token"]
    waiting = _request(_admin_id(), RequestStatus.pending_approval)
    response = admin_client.post(
        f"/api/v1/admin/requests/{waiting}/reject", json={"reason": "no"}, headers=_bearer(token)
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "rejected"


def test_a_user_token_may_not_decide(admin_client: TestClient) -> None:
    create_user("anna")
    headers = auth_headers(admin_client, "anna")
    token = _create(admin_client, headers)["token"]
    me = admin_client.get("/api/v1/me", headers=_bearer(token)).json()
    assert me["may"] == ["request"]
    assert admin_client.get("/api/v1/admin/requests", headers=_bearer(token)).status_code == 403


def test_a_token_cannot_manage_tokens_or_the_password(admin_client: TestClient) -> None:
    token = _create(admin_client)["token"]
    for method, path, body in (
        ("GET", "/api/auth/me/keys", None),
        ("POST", "/api/auth/me/keys", {"name": "Another"}),
        ("DELETE", "/api/auth/me/keys/1", None),
        ("POST", "/api/auth/me/password", {"current_password": "x", "new_password": "y" * 8}),
    ):
        response = admin_client.request(method, path, json=body, headers=_bearer(token))
        assert response.status_code == 403, (method, path, response.text)
        assert response.json()["detail"]["code"] == "api_key_not_here"


def test_revoking_ends_the_token_and_only_the_owner_may(admin_client: TestClient) -> None:
    created = _create(admin_client)
    create_user("anna")
    anna = auth_headers(admin_client, "anna")
    assert admin_client.delete(f"/api/auth/me/keys/{created['id']}", headers=anna).status_code == 404
    assert admin_client.get("/api/v1/me", headers=_bearer(created["token"])).status_code == 200

    assert admin_client.delete(f"/api/auth/me/keys/{created['id']}").status_code == 204
    assert admin_client.get("/api/v1/me", headers=_bearer(created["token"])).status_code == 401


def test_an_unknown_token_is_refused(client: TestClient) -> None:
    response = client.get("/api/v1/me", headers=_bearer("nxb_" + "a" * 54))
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "not_signed_in"


def test_a_deactivated_account_takes_its_tokens_along(admin_client: TestClient) -> None:
    user_id = create_user("anna")
    token = _create(admin_client, auth_headers(admin_client, "anna"))["token"]
    assert admin_client.patch(f"/api/users/{user_id}", json={"is_active": False}).status_code == 200
    assert admin_client.get("/api/v1/me", headers=_bearer(token)).status_code == 401


def test_deleting_an_account_deletes_its_tokens(admin_client: TestClient) -> None:
    user_id = create_user("anna")
    _create(admin_client, auth_headers(admin_client, "anna"))
    assert admin_client.delete(f"/api/users/{user_id}").status_code == 204
    with SessionLocal() as db:
        assert db.scalars(select(ApiKey)).all() == []


def test_a_password_change_leaves_tokens_working(admin_client: TestClient) -> None:
    create_user("anna")
    headers = auth_headers(admin_client, "anna")
    token = _create(admin_client, headers)["token"]
    changed = admin_client.post(
        "/api/auth/me/password",
        json={"current_password": "user-password-123", "new_password": "another-password-456"},
        headers=headers,
    )
    assert changed.status_code == 200, changed.text
    assert admin_client.get("/api/v1/me", headers=_bearer(token)).status_code == 200


def test_names_and_the_upper_limit(admin_client: TestClient) -> None:
    blank = admin_client.post("/api/auth/me/keys", json={"name": "   "})
    assert blank.json()["detail"]["code"] == "api_key_needs_name"
    for number in range(api_keys.MOST):
        _create(admin_client, name=f"Key {number}")
    too_many = admin_client.post("/api/auth/me/keys", json={"name": "One more"})
    assert too_many.status_code == 400
    assert too_many.json()["detail"]["code"] == "api_key_too_many"


def test_last_use_is_written_at_most_every_quarter_hour(admin_client: TestClient) -> None:
    token = _create(admin_client)["token"]
    start = utcnow()
    with SessionLocal() as db:
        assert api_keys.redeem(db, token, start) is not None
        assert api_keys.redeem(db, token, start + timedelta(minutes=5)).last_used_at == start
        later = start + api_keys.REMEMBER_USE_AFTER
        assert api_keys.redeem(db, token, later).last_used_at == later


def test_admins_see_every_token_but_nobody_else_does(admin_client: TestClient) -> None:
    create_user("anna")
    anna = auth_headers(admin_client, "anna")
    _create(admin_client, anna, name="Anna's script")
    _create(admin_client, name="Wall display", read_only=True)
    listed = admin_client.get("/api/admin/api-keys").json()
    assert {(key["username"], key["name"], key["read_only"]) for key in listed} == {
        ("anna", "Anna's script", False),
        ("admin", "Wall display", True),
    }
    assert admin_client.get("/api/admin/api-keys", headers=anna).status_code == 403


def test_the_dashboard_counts_everything_for_admins_and_the_own_for_users(admin_client: TestClient) -> None:
    anna = create_user("anna")
    admin = _admin_id()
    now = utcnow()
    _request(admin, RequestStatus.pending_approval)
    _request(anna, RequestStatus.pending_approval)
    _request(anna, RequestStatus.searching)
    _request(admin, RequestStatus.approved)
    _request(anna, RequestStatus.failed)
    _request(anna, RequestStatus.downloaded, completed_at=now - timedelta(days=2))
    _request(anna, RequestStatus.downloaded, completed_at=now - timedelta(days=9))
    _request(admin, RequestStatus.rejected)
    with SessionLocal() as db:
        db.add(LibraryArtist(mbid=ARTIST, lidarr_id=1, name="A", track_file_count=12, album_count=3))
        db.add(LibraryArtist(mbid="44444444-4444-4444-8444-444444444444", lidarr_id=2, name="B", album_count=2))
        db.commit()

    everything = admin_client.get("/api/v1/dashboard").json()
    assert everything["scope"] == "all"
    assert everything["requests"] == {"waiting": 2, "running": 2, "failed": 1, "done_last_7_days": 1}
    assert everything["library"] == {"artists": 2, "artists_with_music": 1, "albums": 5}
    assert everything["target"] is None
    assert everything["requests_enabled"] is False

    token = _create(admin_client, auth_headers(admin_client, "anna"), read_only=True)["token"]
    own = admin_client.get("/api/v1/dashboard", headers=_bearer(token)).json()
    assert own["scope"] == "mine"
    assert own["requests"] == {"waiting": 1, "running": 1, "failed": 1, "done_last_7_days": 1}
