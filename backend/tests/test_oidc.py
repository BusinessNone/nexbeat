"""Anmelden ueber OIDC, gegen einen Anmeldedienst aus Attrappen (Discovery, Schluessel, Token-Endpunkt)."""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db import SessionLocal
from app.models import User, UserIdentity
from app.services import http, oidc
from tests.conftest import USER_PASSWORD, create_user

TENANT = "11111111-2222-4333-8444-555555555555"
ISSUER = f"https://login.microsoftonline.com/{TENANT}/v2.0"
CLIENT_ID = "client-id-123"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwk(key: rsa.RSAPrivateKey, kid: str) -> dict[str, Any]:
    data = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    return {**data, "kid": kid, "use": "sig", "alg": "RS256"}


class FakeProvider:
    """Antwortet wie Entra. ``claims`` ersetzt Angaben im ID-Token, ``key`` den Schluessel, mit dem es unterschrieben wird."""

    def __init__(self) -> None:
        self.claims: dict[str, Any] = {}
        self.signing_key = KEY
        self.token_status = 200
        self.requests: list[httpx.Request] = []
        self.nonce = ""

    def id_token(self) -> str:
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "sub": "subject-1",
            "iat": now,
            "exp": now + 300,
            "nonce": self.nonce,
            "email": "lena@firma.example",
            "name": "Lena Muster",
            **self.claims,
        }
        return jwt.encode(claims, self.signing_key, algorithm="RS256", headers={"kid": "k1"})

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url)
        base = f"https://login.microsoftonline.com/{TENANT}"
        if url.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": ISSUER,
                    "authorization_endpoint": f"{base}/oauth2/v2.0/authorize",
                    "token_endpoint": f"{base}/oauth2/v2.0/token",
                    "jwks_uri": f"{base}/discovery/v2.0/keys",
                },
            )
        if url.endswith("/discovery/v2.0/keys"):
            return httpx.Response(200, json={"keys": [_jwk(KEY, "k1")]})
        if url.endswith("/oauth2/v2.0/token"):
            if self.token_status != 200:
                return httpx.Response(self.token_status, json={"error": "invalid_grant"})
            return httpx.Response(200, json={"id_token": self.id_token(), "access_token": "unused"})
        raise AssertionError(f"Unexpected request to the fake provider: {url}")


@pytest.fixture(autouse=True)
def fresh_discovery() -> Iterator[None]:
    oidc.reset_cache()
    yield
    oidc.reset_cache()


@pytest.fixture
def provider() -> FakeProvider:
    fake = FakeProvider()
    http.use_transport(httpx.MockTransport(fake))
    return fake


def configure(admin_client: TestClient, **extra: Any) -> None:
    response = admin_client.put(
        "/api/settings",
        json={
            "oidc_enabled": True,
            "oidc_issuer": ISSUER,
            "oidc_client_id": CLIENT_ID,
            "oidc_client_secret": "the-client-secret",
            "oidc_allowed_domains": "firma.example",
            **extra,
        },
    )
    assert response.status_code == 200, response.text


def sign_in(client: TestClient, provider: FakeProvider) -> httpx.Response:
    """Beide Schritte des Browsers: hin zum Dienst, mit dessen Code zurueck."""
    start = client.get("/api/auth/oidc/login", follow_redirects=False)
    assert start.status_code == 303, start.text
    query = parse_qs(urlparse(start.headers["location"]).query)
    provider.nonce = query["nonce"][0]
    return client.get(
        "/api/auth/oidc/callback", params={"code": "the-code", "state": query["state"][0]}, follow_redirects=False
    )


def error_of(response: httpx.Response) -> str:
    assert response.status_code == 303
    return parse_qs(urlparse(response.headers["location"]).query)["sso_error"][0]


def users() -> list[User]:
    with SessionLocal() as session:
        return list(session.scalars(select(User).order_by(User.id)))


def test_config_offers_sso_only_when_complete(client: TestClient, admin_client: TestClient) -> None:
    assert client.get("/api/config").json()["oidc_enabled"] is False
    # An, aber ohne erlaubte Domaene: Das reicht nicht, die Schaltflaeche bleibt weg.
    admin_client.put("/api/settings", json={"oidc_enabled": True, "oidc_issuer": ISSUER, "oidc_client_id": CLIENT_ID, "oidc_client_secret": "x"})
    assert client.get("/api/config").json()["oidc_enabled"] is False
    admin_client.put("/api/settings", json={"oidc_allowed_domains": "@Firma.example, firma.example"})
    config = client.get("/api/config").json()
    assert config["oidc_enabled"] is True
    assert admin_client.get("/api/settings").json()["oidc_allowed_domains"] == "firma.example"


def test_secret_never_leaves_the_server_and_domains_are_checked(admin_client: TestClient) -> None:
    configure(admin_client)
    shown = admin_client.get("/api/settings").json()
    assert shown["oidc_client_secret_set"] is True
    assert "the-client-secret" not in json.dumps(shown)
    bad = admin_client.put("/api/settings", json={"oidc_allowed_domains": "not a domain!"})
    assert bad.status_code == 422


def test_first_sign_in_creates_a_user_and_a_session(admin_client: TestClient, provider: FakeProvider) -> None:
    configure(admin_client)
    browser = TestClient(admin_client.app)
    done = sign_in(browser, provider)
    assert done.status_code == 303 and done.headers["location"] == "/"
    assert "nexbeat_refresh" in done.cookies

    created = [user for user in users() if user.email == "lena@firma.example"]
    assert len(created) == 1
    user = created[0]
    assert (user.username, user.display_name, user.is_admin, user.is_active) == ("lena", "Lena Muster", False, True)
    assert user.password_hash == oidc.NO_PASSWORD

    # Die Seite holt sich den Zugang wie nach jedem Neuladen aus dem Cookie.
    token = browser.post("/api/auth/refresh").json()["access_token"]
    me = browser.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
    assert me["email"] == "lena@firma.example" and me["is_admin"] is False

    # Mit dem Kennzeichen kein Passwort-Login, auch nicht mit dem Platzhalter.
    for password in (oidc.NO_PASSWORD, "", "lena"):
        attempt = browser.post("/api/auth/login", json={"login": "lena", "password": password or "x" * 12})
        assert attempt.status_code == 401


def test_second_sign_in_reuses_the_account(admin_client: TestClient, provider: FakeProvider) -> None:
    configure(admin_client)
    sign_in(TestClient(admin_client.app), provider)
    # Die Adresse wechselt, ``sub`` bleibt: Es ist derselbe Mensch.
    provider.claims = {"email": "lena.muster@firma.example"}
    done = sign_in(TestClient(admin_client.app), provider)
    assert done.headers["location"] == "/"
    assert len([user for user in users() if not user.is_admin]) == 1
    with SessionLocal() as session:
        assert len(list(session.scalars(select(UserIdentity)))) == 1


def test_existing_account_with_the_same_address_is_linked(admin_client: TestClient, provider: FakeProvider) -> None:
    create_user("lena", email="lena@firma.example")
    configure(admin_client)
    assert sign_in(TestClient(admin_client.app), provider).headers["location"] == "/"
    assert len([user for user in users() if user.email == "lena@firma.example"]) == 1
    with SessionLocal() as session:
        link = session.scalars(select(UserIdentity)).one()
        assert session.get(User, link.user_id).username == "lena"
    # Das Passwort des Kontos gilt weiter.
    assert TestClient(admin_client.app).post("/api/auth/login", json={"login": "lena", "password": USER_PASSWORD}).status_code == 200


def test_username_collision_gets_a_number(admin_client: TestClient, provider: FakeProvider) -> None:
    create_user("lena", email="other@example.com")
    configure(admin_client)
    sign_in(TestClient(admin_client.app), provider)
    assert "lena2" in [user.username for user in users()]


def test_other_domains_are_turned_away(admin_client: TestClient, provider: FakeProvider) -> None:
    configure(admin_client)
    provider.claims = {"email": "mallory@evil.example"}
    assert error_of(sign_in(TestClient(admin_client.app), provider)) == "sso_domain_not_allowed"
    # Auch ein Lookalike, das nur mit der erlaubten Domaene endet.
    provider.claims = {"email": "mallory@notfirma.example"}
    assert error_of(sign_in(TestClient(admin_client.app), provider)) == "sso_domain_not_allowed"
    assert len(users()) == 1


def test_linked_user_loses_access_when_the_domain_is_removed(admin_client: TestClient, provider: FakeProvider) -> None:
    configure(admin_client)
    sign_in(TestClient(admin_client.app), provider)
    configure(admin_client, oidc_allowed_domains="andere.example")
    assert error_of(sign_in(TestClient(admin_client.app), provider)) == "sso_domain_not_allowed"


def test_without_auto_create_only_existing_accounts_get_in(admin_client: TestClient, provider: FakeProvider) -> None:
    configure(admin_client, oidc_auto_create=False)
    assert error_of(sign_in(TestClient(admin_client.app), provider)) == "sso_no_account"
    create_user("lena", email="lena@firma.example")
    assert sign_in(TestClient(admin_client.app), provider).headers["location"] == "/"


def test_deactivated_account_stays_out(admin_client: TestClient, provider: FakeProvider) -> None:
    create_user("lena", email="lena@firma.example", is_active=False)
    configure(admin_client)
    assert error_of(sign_in(TestClient(admin_client.app), provider)) == "sso_account_disabled"


@pytest.mark.parametrize(
    ("claims", "key", "expected"),
    [
        ({"aud": "someone-else"}, None, "sso_failed"),
        ({"iss": "https://login.microsoftonline.com/other-tenant/v2.0"}, None, "sso_failed"),
        ({"exp": int(time.time()) - 60}, None, "sso_failed"),
        ({"nonce": "not-the-nonce"}, None, "sso_failed"),
        ({}, OTHER_KEY, "sso_failed"),
        ({"email_verified": False}, None, "sso_email_unverified"),
        ({"email": None}, None, "sso_email_missing"),
    ],
)
def test_bad_id_tokens_are_refused(
    admin_client: TestClient, provider: FakeProvider, claims: dict[str, Any], key: Any, expected: str
) -> None:
    configure(admin_client)
    provider.claims = claims
    if key is not None:
        provider.signing_key = key
    real_nonce = provider.id_token

    def with_nonce() -> str:
        # Eine Probe soll am erwarteten Mangel scheitern, nicht daran, dass die Nonce fehlt.
        if "nonce" not in claims:
            provider.claims = {**claims, "nonce": provider.nonce}
        return real_nonce()

    provider.id_token = with_nonce  # type: ignore[method-assign]
    assert error_of(sign_in(TestClient(admin_client.app), provider)) == expected
    assert [user.email for user in users()] == ["admin@example.com"]


def test_entra_without_email_claim_uses_the_sign_in_name(admin_client: TestClient, provider: FakeProvider) -> None:
    configure(admin_client)
    provider.claims = {"email": None, "preferred_username": "lena@firma.example"}
    assert sign_in(TestClient(admin_client.app), provider).headers["location"] == "/"


def test_state_must_match_and_flow_cookie_is_needed(admin_client: TestClient, provider: FakeProvider) -> None:
    configure(admin_client)
    browser = TestClient(admin_client.app)
    browser.get("/api/auth/oidc/login", follow_redirects=False)
    forged = browser.get("/api/auth/oidc/callback", params={"code": "c", "state": "forged"}, follow_redirects=False)
    assert error_of(forged) == "sso_failed"
    # Ohne den Weg ueber /login gibt es kein Cookie, ein fertiger Link allein oeffnet nichts.
    assert error_of(TestClient(admin_client.app).get("/api/auth/oidc/callback", params={"code": "c", "state": "s"}, follow_redirects=False)) == "sso_failed"
    assert [user.email for user in users()] == ["admin@example.com"]


def test_authorize_redirect_carries_pkce_and_exact_redirect_uri(admin_client: TestClient, provider: FakeProvider) -> None:
    configure(admin_client, public_url="https://music.firma.example")
    start = TestClient(admin_client.app).get("/api/auth/oidc/login", follow_redirects=False)
    target = urlparse(start.headers["location"])
    query = parse_qs(target.query)
    assert target.netloc == "login.microsoftonline.com"
    assert query["code_challenge_method"] == ["S256"] and query["code_challenge"][0]
    assert query["redirect_uri"] == ["https://music.firma.example/api/auth/oidc/callback"]
    assert query["client_id"] == [CLIENT_ID] and query["response_type"] == ["code"]
    assert "HttpOnly" in start.headers["set-cookie"]


def test_provider_error_and_token_failure_go_back_to_the_login_page(admin_client: TestClient, provider: FakeProvider) -> None:
    configure(admin_client)
    browser = TestClient(admin_client.app)
    browser.get("/api/auth/oidc/login", follow_redirects=False)
    denied = browser.get("/api/auth/oidc/callback", params={"error": "access_denied"}, follow_redirects=False)
    assert error_of(denied) == "sso_denied"
    provider.token_status = 400
    assert error_of(sign_in(TestClient(admin_client.app), provider)) == "sso_failed"


def test_disabled_sso_does_nothing(client: TestClient, provider: FakeProvider) -> None:
    assert error_of(client.get("/api/auth/oidc/login", follow_redirects=False)) == "sso_disabled"
    assert error_of(client.get("/api/auth/oidc/callback", params={"code": "c", "state": "s"}, follow_redirects=False)) == "sso_disabled"
    assert provider.requests == []


@pytest.mark.parametrize("issuer", ["https://login.microsoftonline.com/common/v2.0", "https://login.microsoftonline.com/organizations/v2.0"])
def test_multi_tenant_issuers_are_refused(admin_client: TestClient, provider: FakeProvider, issuer: str) -> None:
    configure(admin_client, oidc_issuer=issuer)
    assert error_of(admin_client.get("/api/auth/oidc/login", follow_redirects=False)) == "sso_issuer_multitenant"
    checked = admin_client.post("/api/settings/test/oidc", json={})
    assert checked.status_code == 502 and checked.json()["detail"]["code"] == "sso_issuer_multitenant"


def test_issuer_check_endpoint(admin_client: TestClient, provider: FakeProvider) -> None:
    assert admin_client.post("/api/settings/test/oidc", json={}).json()["detail"]["code"] == "oidc_issuer_missing"
    assert admin_client.post("/api/settings/test/oidc", json={"issuer": ISSUER}).json() == {"ok": True}


def test_only_admins_may_change_sso_settings(admin_client: TestClient) -> None:
    create_user("lena")
    from tests.conftest import auth_headers

    headers = auth_headers(admin_client, "lena")
    assert admin_client.put("/api/settings", json={"oidc_enabled": True}, headers=headers).status_code == 403
    assert admin_client.post("/api/settings/test/oidc", json={}, headers=headers).status_code == 403


