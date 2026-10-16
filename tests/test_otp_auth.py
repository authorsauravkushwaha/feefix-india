"""OTP & OAuth sign-in — request/verify lifecycle, rate limits, merge logic.

Delivery itself (SMTP, Twilio, MSG91, Fast2SMS, Vonage, Brevo, Resend, the
webhook transport, and the "no gateway configured" answers) is covered in
``test_otp_delivery.py``. What is pinned *here* is the challenge lifecycle a
student goes through: normalisation of what they type, expiry, attempt
burning, single use, resend/cooldown answers, per-destination caps, account
merging, and the no-enumeration property of the error messages.

Outside production the demo echo is on by default (a laptop has no gateway), so
these tests read ``dev_code`` — and one of them asserts that production, which
has no such luxury, never does.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

PROFILE = {"domicile_state": "West Bengal", "course_level": "ug"}


def _req_email(client, addr="new.user@gmail.com"):
    return client.post("/api/auth/otp/request", json={"channel": "email", "address": addr})


def _verify(client, channel, address, code, name=None):
    body = {"channel": channel, "address": address, "code": code}
    if name:
        body["name"] = name
    return client.post("/api/auth/otp/verify", json=body)


def _forget_send_history():
    """Time-travel past the cooldown/hours windows without sleeping."""
    from backend.services import db, otp
    otp._ensure_schema()
    conn = db.get_connection()
    conn.execute("DELETE FROM otp_sends")
    conn.execute("DELETE FROM otp_challenges")
    conn.commit()


def _age_the_last_send(minutes: int = 10) -> None:
    from backend.services import db, otp
    otp._ensure_schema()
    stamp = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat(timespec="seconds")
    conn = db.get_connection()
    conn.execute("UPDATE otp_sends SET created_at=?", (stamp,))
    conn.execute("UPDATE otp_challenges SET created_at=?, expires_at=?",
                 (stamp, stamp))
    conn.commit()


# ---- happy path ---------------------------------------------------------- #
def test_email_otp_roundtrip(client):
    r = _req_email(client)
    assert r.status_code == 200
    data = r.json()
    assert data["channel"] == "email"
    assert data["address"] == "ne***@gmail.com"          # masked in response
    assert data["dev_code"].isdigit()                    # no SMTP → labelled demo
    assert data["demo"] is True and data["delivered"] is False
    assert data["via"] == "console"
    assert "Demo mode" in data["message"]                # never silent about it

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


def test_code_formatting_from_a_paste_is_accepted(client):
    """SMS autofill and pasted email bodies bring spaces and dashes along."""
    code = _req_email(client).json()["dev_code"]
    spaced = f"{code[:3]} {code[3:]}"
    assert _verify(client, "email", "new.user@gmail.com", spaced).status_code == 200


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
    _forget_send_history()               # as if the student came back tomorrow
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


@pytest.mark.parametrize("typed", [
    "+91 98765 43210",        # international, spaced
    "0091 9876543210",        # international, 00 prefix
    "09876543210",            # trunk prefix
    "9876543210",             # bare Indian mobile
    "+919876543210",          # already canonical
])
def test_phone_normalisation_variants_are_one_destination(client, typed, monkeypatch, tmp_path):
    from backend.services import otp as otp_svc
    monkeypatch.setattr(otp_svc, "OTP_OUTBOX", tmp_path / "outbox.jsonl")
    r = client.post("/api/auth/otp/request", json={"channel": "phone", "address": typed})
    assert r.status_code == 200, r.json()
    assert r.json()["address"] == "+919****10"           # one masked destination
    assert otp_svc.normalize("phone", typed) == "+919876543210"


def test_phone_rejects_bad_format(client):
    r = client.post("/api/auth/otp/request", json={"channel": "phone", "address": "123"})
    assert r.status_code == 422


def test_unknown_channel_is_rejected_before_any_work(client):
    r = client.post("/api/auth/otp/request", json={"channel": "sms", "address": "x@y.com"})
    assert r.status_code == 422


def test_unparseable_destination_is_a_401_not_a_500(client):
    """Regression: the "bad destination" branch raised ``NameError`` inside the
    handler, so a malformed address on /verify was a 500."""
    for channel, address in (("email", "not-an-email"), ("phone", "+91abc")):
        r = _verify(client, channel, address, "123456")
        assert r.status_code == 401, r.text
        assert "invalid or expired" in r.json()["detail"].lower()


# ---- abuse resistance ------------------------------------------------------ #
def test_resend_cooldown_answers_429_with_retry_after(client):
    _req_email(client)
    r = _req_email(client)  # immediate second request
    assert r.status_code == 429 and "resend" in r.json()["detail"].lower()
    assert 0 < int(r.headers["Retry-After"]) <= 300


def test_attempt_burn_after_5_wrong(client):
    _req_email(client)
    for i in range(4):
        r = _verify(client, "email", "new.user@gmail.com", "000000")
        assert r.status_code == 401
        assert f"{4 - i} attempt" in r.json()["detail"]      # the student can count
    r = _verify(client, "email", "new.user@gmail.com", "000000")   # 5th burns the code
    assert r.status_code == 429 and "wrong codes" in r.json()["detail"].lower()
    # …and the (unknown) right code is dead too
    assert _verify(client, "email", "new.user@gmail.com", "000000").status_code == 401


def test_expired_code_answers_410(client):
    code = _req_email(client).json()["dev_code"]
    from backend.services import db
    conn = db.get_connection()
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(timespec="seconds")
    conn.execute("UPDATE otp_challenges SET expires_at=?", (past,))
    conn.commit()
    r = _verify(client, "email", "new.user@gmail.com", code)
    assert r.status_code == 410 and "expired" in r.json()["detail"].lower()


def test_hourly_request_cap(client):
    addr = "cap@gmail.com"
    _req_email(client, addr)
    for _ in range(4):
        _age_the_last_send()
        assert _req_email(client, addr).status_code == 200
    _age_the_last_send()
    r = _req_email(client, addr)  # 6th within the hour
    assert r.status_code == 429 and "hour" in r.json()["detail"].lower()


def test_daily_cap_is_per_destination(client, monkeypatch):
    monkeypatch.setenv("FEEFIX_OTP_DAILY_CAP", "3")
    monkeypatch.setenv("FEEFIX_OTP_PER_HOUR", "20")
    addr = "daily@gmail.com"
    for _ in range(3):
        _age_the_last_send()
        assert _req_email(client, addr).status_code == 200
    _age_the_last_send()
    assert _req_email(client, addr).status_code == 429
    # another destination is untouched (an attacker cannot starve a victim)
    assert _req_email(client, "other@gmail.com").status_code == 200


# ---- methods & GitHub gating ---------------------------------------------- #
def test_methods_endpoint_reports_the_doors_and_the_delivery_path(client):
    m = client.get("/api/auth/methods").json()
    assert m["password"] is True
    # Outside production both code doors are *usable* (console demo), and the
    # response says explicitly that nothing real is carrying the code.
    assert m["otp_email"] is True and m["otp_phone"] is True
    assert m["delivery"]["demo_mode"] is True
    assert m["delivery"]["email"] == {"provider": None, "real": False,
                                     "demo": True, "usable": True}
    assert m["github"] is False                   # unconfigured by default


def test_methods_endpoint_in_production_closes_the_doors(client, monkeypatch):
    monkeypatch.setenv("FEEFIX_ENV", "production")
    m = client.get("/api/auth/methods").json()
    assert m["otp_email"] is False and m["otp_phone"] is False
    assert m["delivery"]["demo_mode"] is False and m["delivery"]["dev_inbox"] is False
    assert m["password"] is True                  # password sign-in still works


def test_github_start_unconfigured(client):
    r = client.get("/api/auth/github", follow_redirects=False)
    assert r.status_code == 501


def test_github_callback_rejects_bogus_state(client, monkeypatch):
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


def test_wrong_code_never_reveals_whether_the_account_exists(client):
    """Same wording, same status, for an address with an account and without.

    The attempts-left hint is a property of the challenge (which the caller just
    created), not of the account — so it is identical on both sides, and an
    attacker learns nothing about who is registered.
    """
    client.post("/api/auth/register", json={
        "email": "has.account@gmail.com", "password": "S3cure!Pass"})
    from backend.services import ratelimit
    ratelimit.reset()
    _req_email(client, "has.account@gmail.com")
    r1 = _verify(client, "email", "has.account@gmail.com", "111111")
    _forget_send_history()
    _req_email(client, "no.account@gmail.com")
    r2 = _verify(client, "email", "no.account@gmail.com", "111111")
    assert r1.status_code == r2.status_code == 401
    assert r1.json()["detail"] == r2.json()["detail"]
    assert "attempt" in r1.json()["detail"]       # actionable, not a hint about accounts
