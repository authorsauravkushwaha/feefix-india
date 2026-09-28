"""Security & auth layer — accounts, sessions, ownership, rate limits, headers."""

from __future__ import annotations

PROFILE = {
    "domicile_state": "West Bengal",
    "category": "general",
    "annual_family_income": 200000,
    "course_level": "ug",
    "gender": "female",
}


def _register(client, email="student@example.com", password="S3cure!Pass", name="Asha"):
    return client.post("/api/auth/register",
                       json={"email": email, "password": password, "name": name})


# ---- registration & login --------------------------------------------------- #
def test_register_and_login_roundtrip(client):
    r = _register(client)
    assert r.status_code == 200
    token = r.json()["token"]

    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["user"]["email"] == "student@example.com"

    # login again → new token, same account
    r2 = client.post("/api/auth/login",
                     json={"email": "student@example.com", "password": "S3cure!Pass"})
    assert r2.status_code == 200 and r2.json()["token"] != token


def test_password_never_stored_in_plaintext(client, tmp_path):
    _register(client, password="TopSecret123")
    db_bytes = (tmp_path / "test.db").read_bytes()
    assert b"TopSecret123" not in db_bytes


def test_wrong_password_and_unknown_email_are_indistinguishable(client):
    _register(client)
    r1 = client.post("/api/auth/login",
                     json={"email": "student@example.com", "password": "wrongwrong"})
    r2 = client.post("/api/auth/login",
                     json={"email": "nobody@example.com", "password": "wrongwrong"})
    assert r1.status_code == 401 == r2.status_code
    assert r1.json()["detail"] == r2.json()["detail"]


def test_register_validations(client):
    assert client.post("/api/auth/register", json={
        "email": "not-an-email", "password": "longenoughpw"}).status_code == 422
    assert client.post("/api/auth/register", json={
        "email": "x@y.co", "password": "short"}).status_code == 422
    _register(client)
    assert _register(client).status_code == 422  # duplicate email


def test_logout_revokes_token(client):
    token = _register(client).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert client.post("/api/auth/logout", headers=headers).json()["revoked"] is True
    assert client.get("/api/auth/me", headers=headers).status_code == 401


def test_login_rate_limited(client):
    _register(client)
    ok = 0
    for i in range(12):
        r = client.post("/api/auth/login",
                        json={"email": "student@example.com", "password": "nope-nope"})
        if r.status_code == 429:
            break
        ok += 1
    assert ok <= 10  # AUTH_LIMIT = 10 attempts / 5 min per IP+account


# ---- session linking & ownership -------------------------------------------- #
def _signup_and_link(client, sid):
    token = _register(client).json()["token"]
    r = client.post("/api/auth/link-session", json={"session_id": sid},
                    headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200 and r.json()["linked"] is True
    return token


def test_anonymous_data_follows_login(client):
    sid = "wiz-session-001"
    client.put(f"/api/students/{sid}/profile", json={"profile": PROFILE})
    token = _signup_and_link(client, sid)

    # session now owned → anonymous access is refused
    assert client.get(f"/api/students/{sid}/profile").status_code == 403
    # owner gets it back with the token
    r = client.get(f"/api/students/{sid}/profile",
                   headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["profile"]["domicile_state"] == "West Bengal"


def test_owner_session_returned_on_next_login(client):
    sid = "wiz-session-002"
    client.put(f"/api/students/{sid}/profile", json={"profile": PROFILE})
    _signup_and_link(client, sid)

    r = client.post("/api/auth/login",
                    json={"email": "student@example.com", "password": "S3cure!Pass"})
    assert r.json()["session_id"] == sid  # second device picks up "their" session


def test_fresh_anonymous_sessions_stay_open(client):
    sid = "totally-anon"
    assert client.get(f"/api/students/{sid}/profile").status_code == 200
    assert client.put(f"/api/students/{sid}/profile",
                      json={"profile": PROFILE}).status_code == 200


def test_other_account_cannot_read(client):
    sid = "wiz-session-003"
    client.put(f"/api/students/{sid}/profile", json={"profile": PROFILE})
    _signup_and_link(client, sid)

    token2 = _register(client, email="other@example.com").json()["token"]
    assert client.get(f"/api/students/{sid}/profile",
                      headers={"Authorization": f"Bearer {token2}"}).status_code == 403


# ---- export & erasure --------------------------------------------------------- #
def test_export_and_delete_account(client):
    sid = "wiz-session-004"
    client.put(f"/api/students/{sid}/profile", json={"profile": PROFILE})
    client.put(f"/api/tracker/{sid}/sv-mcm-wb", json={"status": "applied"})
    token = _signup_and_link(client, sid)
    headers = {"Authorization": f"Bearer {token}"}

    exp = client.get("/api/auth/export", headers=headers)
    assert exp.status_code == 200
    body = exp.json()
    assert body["sessions"][sid]["profile"]["domicile_state"] == "West Bengal"
    assert body["sessions"][sid]["tracker"]["sv-mcm-wb"]["status"] == "applied"

    assert client.delete("/api/auth/account", headers=headers).json()["deleted"] is True
    assert client.get("/api/auth/me", headers=headers).status_code == 401
    # data is gone — session reads now behave anonymous-empty again
    assert client.get(f"/api/students/{sid}/profile").json()["profile"] is None


# ---- transport security ------------------------------------------------------ #
def test_security_headers_present(client):
    r = client.get("/api/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["Cache-Control"] == "no-store"
    assert r.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
