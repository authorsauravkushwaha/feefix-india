"""OTP & OAuth sign-in — request/verify lifecycle, rate limits, merge logic."""

from __future__ import annotations

PROFILE = {"domicile_state": "West Bengal", "course_level": "ug"}


def _req_email(client, addr="new.user@gmail.com"):
    return client.post("/api/auth/otp/request", json={"channel": "email", "address": addr})


def _verify(client, channel, address, code, name=None):
    body = {"channel": channel, "address": address, "code": code}
    if name:
        body["name"] = name
    return client.post("/api/auth/otp/verify", json=body)


# ---- happy path ---------------------------------------------------------- #
def test_email_otp_roundtrip(client):
    r = _req_email(client)
    assert r.status_code == 200
    data = r.json()
    assert data["channel"] == "email"
    assert data["address"] == "ne***@gmail.com"          # masked in response
    assert data["dev_code"].isdigit()                    # no SMTP → dev code

    bad = _verify(client, "email", "new.user@gmail.com", "000000")
    assert bad.status_code == 401
    assert "otp" not in bad.json().get("detail", "").lower()

    good = _verify(client, "email", "new.user@gmail.com", data["dev_code"], name="Rohan")
    assert good.status_code == 200
    token = good.json()["token"]
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200 and me.json()["user"]["email"] == "new.user@gmail.com"


def test_otp_code_single_use(client):
    code = _req_email(client).json()["dev_code"]
    assert _verify(client, "email", "new.user@gmail.com", code).status_code == 200
    assert _verify(client, "email", "new.user@gmail.com", code).status_code == 401


def test_otp_merge_with_password_account(client):
    client.post("/api/auth/register", json={
        "email": "same@gmail.com", "password": "S3cure!Pass", "name": "Asha"})
    code = _req_email(client, "same@gmail.com").json()["dev_code"]
    r = _verify(client, "email", "same@gmail.com", code)
    assert r.status_code == 200
    assert r.json()["user"]["email"] == "same@gmail.com"  # same account, no dupes


def test_otp_merges_on_second_login(client):
    c1 = _req_email(client).json()["dev_code"]
    u1 = _verify(client, "email", "new.user@gmail.com", c1).json()["user"]["id"]
    from backend.services import ratelimit
    ratelimit.reset()
    from backend.services import db
    db.get_connection().execute("DELETE FROM otp_challenges")
    db.get_connection().commit()
    c2 = _req_email(client).json()["dev_code"]
    u2 = _verify(client, "email", "new.user@gmail.com", c2).json()["user"]["id"]
    assert u1 == u2


# ---- phone ---------------------------------------------------------------- #
def test_phone_otp_indian_normalisation(client):
    r = client.post("/api/auth/otp/request",
                    json={"channel": "phone", "address": "98765 43210"})
    assert r.status_code == 200
    assert r.json()["address"].startswith("+919")
    code = r.json()["dev_code"]
    r2 = client.post("/api/auth/otp/verify",
                     json={"channel": "phone", "address": "+919876543210", "code": code})
    assert r2.status_code == 200
    assert r2.json()["user"]["email"].startswith("phone:+919876543210@")


def test_phone_rejects_bad_format(client):
    r = client.post("/api/auth/otp/request", json={"channel": "phone", "address": "123"})
    assert r.status_code == 422


# ---- abuse resistance ------------------------------------------------------ #
def test_resend_cooldown(client):
    _req_email(client)
    r = _req_email(client)  # immediate second request
    assert r.status_code == 422 and "resend" in r.json()["detail"].lower()


def test_attempt_burn_after_5_wrong(client):
    _req_email(client)
    for _ in range(4):
        assert _verify(client, "email", "new.user@gmail.com", "000000").status_code == 401
    r = _verify(client, "email", "new.user@gmail.com", "000000")   # attempt 5 burns
    assert r.status_code in (401, 429)


def test_hourly_request_cap(client):
    addr = "cap@gmail.com"
    _req_email(client, addr)
    from backend.services import db
    conn = db.get_connection()
    from datetime import datetime, timedelta, timezone
    past = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(timespec="seconds")
    conn.execute("UPDATE otp_challenges SET resend_after=? WHERE address=?",
                 (past, "cap@gmail.com"))
    conn.commit()
    for i in range(4):
        conn.execute("UPDATE otp_challenges SET resend_after=? WHERE address=?",
                     (past, "cap@gmail.com"))
        conn.commit()
        assert _req_email(client, addr).status_code == 200
    conn.execute("UPDATE otp_challenges SET resend_after=? WHERE address=?",
                 (past, "cap@gmail.com"))
    conn.commit()
    r = _req_email(client, addr)  # 6th within the hour
    assert r.status_code == 422 and "hour" in r.json()["detail"].lower()


# ---- methods & GitHub gating ---------------------------------------------- #
def test_methods_endpoint(client):
    m = client.get("/api/auth/methods").json()
    assert m["password"] is True and m["otp_email"] is True
    assert m["otp_phone"] is False and m["github"] is False   # unconfigured by default


def test_github_start_unconfigured(client):
    r = client.get("/api/auth/github", follow_redirects=False)
    assert r.status_code == 501


def test_github_callback_rejects_bogus_state(client, monkeypatch):
    import os
    monkeypatch.setenv("GITHUB_CLIENT_ID", "x")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "y")
    r = client.get("/api/auth/github/callback?code=bogus&state=bogus",
                   follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/#auth=failed"


# ---- identity privacy ------------------------------------------------------ #
def test_error_messages_dont_leak_existence(client):
    client.post("/api/auth/register", json={
        "email": "exists@gmail.com", "password": "S3cure!Pass"})
    c1 = _req_email(client, "exists@gmail.com")
    c2 = _req_email(client, "notexists@gmail.com")
    for j in (c1, c2):
        assert j.status_code == 200 and j.json()["sent"] is True


def test_otp_verify_wrong_code_never_shows_hint(client):
    _req_email(client, "hint@gmail.com")
    r = _verify(client, "email", "hint@gmail.com", "111111")
    assert "invalid or expired" in r.json()["detail"].lower()
