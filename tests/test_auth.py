"""Tests for tokens, password hashing, roles, and the FastAPI auth dependencies."""

import pytest

from netra_common.security import (
    ROLE_ADMIN,
    ROLE_ANALYST,
    TokenError,
    has_role,
    hash_password,
    issue_token,
    require_secret,
    verify_password,
    verify_token,
)

SECRET = "s" * 48
OTHER_SECRET = "t" * 48


# --- Tokens -----------------------------------------------------------------------

def test_token_round_trip():
    token, expires = issue_token("priya", ROLE_ANALYST, SECRET, 3600, now=1_000)
    principal = verify_token(token, SECRET, now=1_500)
    assert (principal.username, principal.role, principal.expires_at) == ("priya", ROLE_ANALYST, 4_600)
    assert expires == 4_600


def test_expired_token_is_rejected():
    token, _ = issue_token("priya", ROLE_ANALYST, SECRET, 60, now=1_000)
    with pytest.raises(TokenError, match="expired"):
        verify_token(token, SECRET, now=1_060)


def test_token_signed_with_another_secret_is_rejected():
    token, _ = issue_token("priya", ROLE_ANALYST, OTHER_SECRET, 3600)
    with pytest.raises(TokenError, match="signature"):
        verify_token(token, SECRET)


def test_role_cannot_be_escalated_by_editing_the_payload():
    import base64
    import json

    token, _ = issue_token("priya", ROLE_ANALYST, SECRET, 3600)
    body, signature = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    payload["role"] = ROLE_ADMIN
    forged_body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    with pytest.raises(TokenError):
        verify_token(f"{forged_body}.{signature}", SECRET)


@pytest.mark.parametrize("garbage", ["", "no-dot", "a.b.c", "!!!.???", None])
def test_malformed_tokens_are_rejected(garbage):
    with pytest.raises(TokenError):
        verify_token(garbage, SECRET)


def test_short_or_missing_secret_is_refused():
    for bad in ("", "short"):
        with pytest.raises(RuntimeError, match="NETRA_AUTH_SECRET"):
            require_secret(bad)
        with pytest.raises(RuntimeError):
            issue_token("priya", ROLE_ANALYST, bad, 60)


def test_unknown_role_cannot_be_issued():
    with pytest.raises(ValueError):
        issue_token("priya", "superuser", SECRET, 60)


# --- Passwords --------------------------------------------------------------------

def test_password_hash_verifies_and_is_salted():
    first, second = hash_password("correct horse battery", 1_000), hash_password("correct horse battery", 1_000)
    assert first != second
    assert verify_password("correct horse battery", first)
    assert not verify_password("correct horse batterY", first)


@pytest.mark.parametrize("stored", ["", "plaintext", "md5$1$x$y", "pbkdf2_sha256$notanumber$x$y"])
def test_unrecognised_hashes_never_verify(stored):
    assert not verify_password("anything", stored)


# --- Roles ------------------------------------------------------------------------

def test_admin_outranks_analyst():
    assert has_role(ROLE_ADMIN, ROLE_ANALYST)
    assert has_role(ROLE_ANALYST, ROLE_ANALYST)
    assert not has_role(ROLE_ANALYST, ROLE_ADMIN)
    assert not has_role("stranger", ROLE_ANALYST)


# --- FastAPI dependencies ---------------------------------------------------------

@pytest.fixture
def client(monkeypatch):
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from netra_common.config import settings
    from netra_common.fastapi_auth import require_role

    monkeypatch.setattr(settings, "NETRA_AUTH_SECRET", SECRET)
    app = fastapi.FastAPI()

    @app.get("/analyst")
    def analyst_only(p=fastapi.Depends(require_role(ROLE_ANALYST))):
        return {"user": p.username}

    @app.get("/admin")
    def admin_only(p=fastapi.Depends(require_role(ROLE_ADMIN))):
        return {"user": p.username}

    return TestClient(app)


def bearer(username, role, secret=SECRET):
    return {"Authorization": f"Bearer {issue_token(username, role, secret, 3600)[0]}"}


def test_no_token_is_401_with_bearer_challenge(client):
    res = client.get("/analyst")
    assert res.status_code == 401
    assert res.headers["www-authenticate"] == "Bearer"


def test_forged_token_is_401(client):
    assert client.get("/analyst", headers=bearer("priya", ROLE_ANALYST, OTHER_SECRET)).status_code == 401


def test_analyst_can_read_but_not_administer(client):
    headers = bearer("priya", ROLE_ANALYST)
    assert client.get("/analyst", headers=headers).json() == {"user": "priya"}
    res = client.get("/admin", headers=headers)
    assert res.status_code == 403
    assert "admin role" in res.json()["detail"]


def test_admin_can_do_both(client):
    headers = bearer("root", ROLE_ADMIN)
    assert client.get("/analyst", headers=headers).status_code == 200
    assert client.get("/admin", headers=headers).status_code == 200
