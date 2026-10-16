"""OTP *delivery* — the message must actually reach the student's device.

The regression this suite exists for: sign-in codes were generated and handed
straight back to the browser ("dev_code") with a console fallback, so a
deployment could show a code that no phone ever received, and nothing in the
product said so. These tests pin the replacement contract:

* a configured gateway (SMTP, Brevo, Resend, Twilio, MSG91, Fast2SMS, Vonage,
  webhook) is the path a code takes, and the code in the delivered message is
  the code that verifies;
* the console fallback is development-only, is *labelled* a demo, and its code
  is never written to a log or an API response in production;
* with no gateway in production the endpoint fails closed (503) instead of
  pretending to have sent something;
* a delivery failure is reported honestly (502 + audit) and can be retried
  without the student's hourly budget being spent on a message nobody got;
* the counters that cap spending (per hour / per day / resend cooldown) count
  sends that really happened, not challenges that have already expired.

No network is used: SMTP is a fake transport and the HTTPS providers are
exercised by stubbing the one function that opens the socket.
"""

from __future__ import annotations

import json
import smtplib
import ssl
from datetime import datetime, timedelta, timezone

import pytest

from backend.services import otp as otp_svc

EMAIL = "student@gmail.com"
PHONE = "+919876543210"


# --------------------------------------------------------------------------- #
# fakes & helpers
# --------------------------------------------------------------------------- #
class _FakeSMTP:
    """Records what the SMTP provider actually handed to the relay."""

    instances: list["_FakeSMTP"] = []
    #: Whether the relay advertises STARTTLS (Gmail/587 does; a local MailHog
    #: or a plain port-25 smarthost may not).
    supports_starttls = True

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port, self.timeout, self.context = host, port, timeout, context
        self.messages = []
        self.user = None
        self.password = None
        self.started_tls = False
        self.closed = False
        _FakeSMTP.instances.append(self)

    # context-manager + smtplib surface used by the provider
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = True
        return False

    def ehlo(self):
        return 250, b"ok"

    def has_extn(self, name):
        return name.lower() == "starttls" and self.supports_starttls

    def starttls(self, context=None):
        self.started_tls = True
        return 220, b"go ahead"

    def login(self, user, password):
        self.user, self.password = user, password

    def send_message(self, message):
        self.messages.append(message)

    @property
    def bodies(self) -> list[str]:
        return [m.get_content() if not m.is_multipart()
                else _first_text_part(m) for m in self.messages]


def _first_text_part(message) -> str:
    for part in message.walk():
        if part.get_content_type() == "text/plain":
            return part.get_content()
    return ""


class _FakeSMTPSSL(_FakeSMTP):
    """Same recorder, reached through the implicit-TLS constructor."""


def _install_smtp(monkeypatch) -> None:
    _FakeSMTP.instances = []
    monkeypatch.setattr(otp_svc.smtplib, "SMTP", _FakeSMTP)
    monkeypatch.setattr(otp_svc.smtplib, "SMTP_SSL", _FakeSMTPSSL)


@pytest.fixture()
def smtp_env(monkeypatch):
    """A Gmail-shaped SMTP configuration (spaced app password included)."""
    monkeypatch.setenv("OTP_SMTP_HOST", "smtp.gmail.com")
    monkeypatch.setenv("OTP_SMTP_PORT", "587")
    monkeypatch.setenv("OTP_SMTP_USER", "no-reply@feefix.in")
    monkeypatch.setenv("OTP_SMTP_PASS", "abcd efgh ijkl mnop")   # Gmail shows spaces
    monkeypatch.setenv("OTP_SMTP_FROM", "no-reply@feefix.in")
    _install_smtp(monkeypatch)
    return _FakeSMTP


@pytest.fixture()
def production(monkeypatch):
    monkeypatch.setenv("FEEFIX_ENV", "production")


def _send(client, channel="email", address=EMAIL):
    return client.post("/api/auth/otp/request", json={"channel": channel, "address": address})


def _verify(client, code, channel="email", address=EMAIL, name=None):
    body = {"channel": channel, "address": address, "code": code}
    if name:
        body["name"] = name
    return client.post("/api/auth/otp/verify", json=body)


def _code_in(blob) -> str:
    """Pull the 6-digit code out of whatever a gateway was handed.

    Asserting on the *delivered* payload (not on a `dev_code` echo) is the whole
    point: a real gateway must never see a different code from the one that
    verifies, and nothing may be echoed to the browser when delivery worked.
    """
    import re as _re

    text = blob if isinstance(blob, str) else json.dumps(blob)
    match = _re.search(r"\b(\d{6})\b", text)
    assert match, f"no 6-digit code found in {text[:200]}"
    return match.group(1)


def _fake_http(monkeypatch, outcome, calls):
    """Stub the single function that opens a provider socket."""
    def _post(url, payload, headers=None, *, form=False, timeout=None):
        calls.append({"url": url, "payload": payload, "headers": headers or {},
                      "form": form})
        status, body = outcome(len(calls), calls[-1])
        return status, body if isinstance(body, str) else json.dumps(body)
    monkeypatch.setattr(otp_svc, "_post_json", _post)


def _sends_table():
    from backend.services import db
    return db.get_connection()


def _forget_send_history():
    """Pretend an hour passed: the caps are time-windowed, not permanent."""
    from backend.services import db
    conn = db.get_connection()
    conn.execute("DELETE FROM otp_sends")
    conn.execute("DELETE FROM otp_challenges")
    conn.commit()


# ===================================================================== SMTP ==
def test_smtp_delivers_the_code_to_the_mailbox(client, smtp_env):
    r = _send(client)
    assert r.status_code == 200
    body = r.json()
    assert body["via"] == "smtp" and body["delivered"] is True
    assert body["demo"] is False and "dev_code" not in body      # nothing echoed
    assert body["address"] == "st***@gmail.com"                  # still masked

    assert len(smtp_env.instances) == 1
    server = smtp_env.instances[0]
    assert server.host == "smtp.gmail.com" and server.port == 587
    assert server.started_tls is True
    assert server.user == "no-reply@feefix.in"
    assert server.password == "abcdefghijklmnop"                 # spaces stripped
    assert len(server.messages) == 1
    message = server.messages[0]
    assert message["To"] == EMAIL
    assert "FeeFix" in str(message["From"])
    text = _first_text_part(message)
    assert "verification code" in text
    code = "".join(ch for ch in text.split("code is", 1)[1].split()[0] if ch.isdigit())
    assert len(code) == 6
    # the delivered code is the code that signs in — end to end
    assert _verify(client, code).status_code == 200


def test_smtp_html_alternative_is_present(client, smtp_env):
    _send(client)
    message = smtp_env.instances[0].messages[0]
    assert message.is_multipart()
    types = {part.get_content_type() for part in message.walk()}
    assert {"text/plain", "text/html"} <= types


def test_smtp_port_465_uses_implicit_tls(client, smtp_env, monkeypatch):
    monkeypatch.setenv("OTP_SMTP_PORT", "465")
    assert _send(client).status_code == 200
    server = _FakeSMTP.instances[0]
    assert isinstance(server, _FakeSMTPSSL)
    assert server.started_tls is False          # the connection is already TLS
    assert isinstance(server.context, ssl.SSLContext)


def test_starttls_auto_still_delivers_to_a_relay_without_tls(client, smtp_env, monkeypatch):
    """Local relays (MailHog, a port-25 smarthost) often have no STARTTLS.

    `auto` is the explicit opt-in that keeps development working; the default
    (`required`) would refuse rather than send a code in the clear.
    """
    monkeypatch.setenv("OTP_SMTP_STARTTLS", "auto")

    class NoTLS(_FakeSMTP):
        supports_starttls = False

    monkeypatch.setattr(otp_svc.smtplib, "SMTP", NoTLS)
    assert _send(client).json()["delivered"] is True
    assert _FakeSMTP.instances[0].started_tls is False


def test_starttls_required_refuses_a_relay_without_tls(client, smtp_env, monkeypatch, production):
    class NoTLS(_FakeSMTP):
        supports_starttls = False

    monkeypatch.setattr(otp_svc.smtplib, "SMTP", NoTLS)
    r = _send(client)
    assert r.status_code == 502
    assert "dev_code" not in json.dumps(r.json())


def test_transient_smtp_failure_is_retried_once(client, smtp_env, monkeypatch):
    attempts = {"n": 0}

    class Flaky(_FakeSMTP):
        def send_message(self, message):
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise smtplib.SMTPServerDisconnected("connection reset")
            return super().send_message(message)

    monkeypatch.setattr(otp_svc.smtplib, "SMTP", Flaky)
    r = _send(client)
    assert r.status_code == 200 and r.json()["via"] == "smtp"
    assert attempts["n"] == 2                   # one retry, then success


def test_authentication_failure_is_reported_in_words(client, smtp_env, monkeypatch):
    calls = {"n": 0}

    class RefusesLogin(_FakeSMTP):
        def login(self, user, password):
            calls["n"] += 1
            raise smtplib.SMTPAuthenticationError(535, b"bad credentials")

    monkeypatch.setattr(otp_svc.smtplib, "SMTP", RefusesLogin)
    body = _send(client).json()                 # dev fallback keeps the demo usable
    assert body["demo"] is True and body["delivered"] is False
    assert "app password" in body["delivery"]["error"]
    assert calls["n"] == 1                      # a wrong password is not retried


def test_production_smtp_failure_answers_502_and_never_echoes(client, smtp_env,
                                                              monkeypatch, production):
    class Broken(_FakeSMTP):
        def send_message(self, message):
            raise smtplib.SMTPException("relay said no")

    monkeypatch.setattr(otp_svc.smtplib, "SMTP", Broken)
    r = _send(client)
    assert r.status_code == 502
    assert "dev_code" not in json.dumps(r.json())
    # the failed send must not consume the student's budget: the next attempt
    # is not told to wait, it is told the relay is down again
    assert _send(client).status_code == 502


# ============================================================ console/demo ==
def test_console_fallback_is_labelled_and_never_claims_delivery(client, monkeypatch, tmp_path):
    outbox = tmp_path / "otp_outbox.jsonl"
    monkeypatch.setattr(otp_svc, "OTP_OUTBOX", outbox)
    body = _send(client).json()
    assert body["delivered"] is False and body["demo"] is True
    assert body["via"] == "console"
    assert "Demo mode" in body["message"] and "instead of being sent" in body["message"]
    assert body["dev_code"].isdigit() and len(body["dev_code"]) == 6
    entry = json.loads(outbox.read_text(encoding="utf-8").splitlines()[-1])
    assert entry["address"] == EMAIL and entry["code"] == body["dev_code"]


def test_dev_echo_can_be_turned_off_even_outside_production(client, monkeypatch, tmp_path):
    monkeypatch.setattr(otp_svc, "OTP_OUTBOX", tmp_path / "outbox.jsonl")
    monkeypatch.setenv("FEEFIX_OTP_DEV_ECHO", "0")
    r = _send(client)
    assert r.status_code == 503
    assert "OTP_SMTP_HOST" in r.json()["detail"]      # operator-actionable
    assert "dev_code" not in json.dumps(r.json())


def test_per_channel_dev_echo_switch(client, monkeypatch, tmp_path):
    monkeypatch.setattr(otp_svc, "OTP_OUTBOX", tmp_path / "outbox.jsonl")
    monkeypatch.setenv("FEEFIX_OTP_DEV_ECHO_PHONE", "0")
    assert _send(client, "email").json()["demo"] is True
    assert _send(client, "phone", PHONE).status_code == 503


def test_production_never_echoes_a_code(client, production, monkeypatch, tmp_path):
    outbox = tmp_path / "outbox.jsonl"
    monkeypatch.setattr(otp_svc, "OTP_OUTBOX", outbox)
    r = _send(client)
    assert r.status_code == 503
    assert not outbox.exists()                    # nothing landed in a file either
    assert otp_svc.dev_echo_enabled("email") is False
    assert client.get("/api/auth/otp/dev-inbox").status_code == 404


def test_production_refuses_to_boot_with_the_demo_echo_on(monkeypatch):
    """A production deploy that asks for codes in the response is a misconfig."""
    from backend.main import create_app
    from backend.services.secrets import SecretHygieneError

    monkeypatch.setenv("FEEFIX_ENV", "production")
    monkeypatch.setenv("FEEFIX_OTP_DEV_ECHO", "1")
    with pytest.raises(SecretHygieneError):
        create_app()


def test_dev_inbox_lists_codes_for_the_developer(client, monkeypatch, tmp_path):
    monkeypatch.setattr(otp_svc, "OTP_OUTBOX", tmp_path / "otp_outbox.jsonl")
    code = _send(client).json()["dev_code"]
    r = client.get(f"/api/auth/otp/dev-inbox?address={EMAIL}")
    assert r.status_code == 200
    assert r.json()["entries"][0]["code"] == code
    assert client.get("/api/auth/otp/dev-inbox?address=nobody@gmail.com").json()["entries"] == []


# ======================================================= HTTPS SMS gateways ==
def _json_ok(payload):
    return 200, payload


def test_twilio_payload_and_success(client, monkeypatch):
    monkeypatch.setenv("OTP_TWILIO_SID", "AC" + "0" * 32)
    monkeypatch.setenv("OTP_TWILIO_TOKEN", "t" * 32)
    monkeypatch.setenv("OTP_TWILIO_FROM", "+15005550006")
    calls: list[dict] = []
    _fake_http(monkeypatch, lambda n, c: _json_ok({"sid": "SM123"}), calls)

    body = _send(client, "phone", PHONE).json()
    assert body["via"] == "twilio" and body["delivered"] is True
    call = calls[0]
    assert call["url"].endswith("/Accounts/AC" + "0" * 32 + "/Messages.json")
    assert call["form"] is True
    assert call["payload"]["To"] == PHONE and call["payload"]["From"] == "+15005550006"
    assert call["headers"]["Authorization"].startswith("Basic ")
    code = _code_in(call["payload"]["Body"])
    assert "dev_code" not in body                # a real SMS is not echoed
    assert _verify(client, code, "phone", PHONE).status_code == 200


def test_twilio_messaging_service_replaces_from(client, monkeypatch):
    monkeypatch.setenv("OTP_TWILIO_SID", "AC" + "1" * 32)
    monkeypatch.setenv("OTP_TWILIO_TOKEN", "t" * 32)
    monkeypatch.setenv("OTP_TWILIO_MESSAGING_SERVICE_SID", "MG" + "2" * 32)
    calls: list[dict] = []
    _fake_http(monkeypatch, lambda n, c: _json_ok({"sid": "SM1"}), calls)
    assert _send(client, "phone", PHONE).status_code == 200
    assert calls[0]["payload"]["MessagingServiceSid"].startswith("MG")
    assert "From" not in calls[0]["payload"]


def test_twilio_error_body_is_surfaced_to_the_operator(client, monkeypatch, production):
    monkeypatch.setenv("OTP_TWILIO_SID", "AC" + "0" * 32)
    monkeypatch.setenv("OTP_TWILIO_TOKEN", "t" * 32)
    monkeypatch.setenv("OTP_TWILIO_FROM", "+15005550006")
    calls: list[dict] = []
    _fake_http(monkeypatch, lambda n, c: (400, {"code": 21608,
                                                "message": "The number is unverified"}), calls)
    r = _send(client, "phone", PHONE)
    assert r.status_code == 502
    assert "dev_code" not in json.dumps(r.json())
    from backend.services import db
    rows = db.get_connection().execute(
        "SELECT detail FROM audit_log WHERE action='otp.send_failed.phone'").fetchall()
    assert rows and "unverified" in rows[-1]["detail"]


def test_msg91_flow_payload(client, monkeypatch):
    monkeypatch.setenv("OTP_MSG91_AUTH_KEY", "k" * 24)
    monkeypatch.setenv("OTP_MSG91_TEMPLATE_ID", "feefix_login")
    calls: list[dict] = []
    _fake_http(monkeypatch, lambda n, c: _json_ok({"type": "success",
                                                   "message": "Message sent"}), calls)
    body = _send(client, "phone", PHONE).json()
    assert body["via"] == "msg91" and body["delivered"] is True
    call = calls[0]
    assert call["url"].endswith("/api/v5/flow/")
    assert call["headers"]["authkey"] == "k" * 24
    recipient = call["payload"]["recipients"][0]
    assert recipient["mobiles"] == "919876543210"          # MSG91 wants no '+'
    code = _code_in(call["payload"])
    assert "dev_code" not in body
    assert _verify(client, code, "phone", PHONE).status_code == 200


def test_msg91_error_inside_a_200_is_not_a_delivery(client, monkeypatch, production):
    monkeypatch.setenv("OTP_MSG91_AUTH_KEY", "k" * 24)
    monkeypatch.setenv("OTP_MSG91_TEMPLATE_ID", "feefix_login")
    calls: list[dict] = []
    _fake_http(monkeypatch, lambda n, c: _json_ok({"type": "error",
                                                   "message": "Template not found"}), calls)
    r = _send(client, "phone", PHONE)
    assert r.status_code == 502


def test_fast2sms_requires_an_indian_number(client, monkeypatch, production):
    monkeypatch.setenv("OTP_FAST2SMS_KEY", "f" * 24)
    calls: list[dict] = []
    _fake_http(monkeypatch, lambda n, c: _json_ok({"return": True}), calls)
    r = _send(client, "phone", "+14155552671")
    assert r.status_code == 502
    assert calls == []                                    # nothing was sent anywhere


def test_fast2sms_quick_route_payload(client, monkeypatch):
    monkeypatch.setenv("OTP_FAST2SMS_KEY", "f" * 24)
    calls: list[dict] = []
    _fake_http(monkeypatch, lambda n, c: _json_ok({"return": True,
                                                   "message": ["sms-id"]}), calls)
    body = _send(client, "phone", PHONE).json()
    assert body["via"] == "fast2sms"
    assert calls[0]["payload"]["numbers"] == "9876543210"
    code = _code_in(calls[0]["payload"]["message"])
    assert "dev_code" not in body
    assert _verify(client, code, "phone", PHONE).status_code == 200


def test_fast2sms_return_false_with_200_is_a_failure(client, monkeypatch, production):
    monkeypatch.setenv("OTP_FAST2SMS_KEY", "f" * 24)
    calls: list[dict] = []
    _fake_http(monkeypatch, lambda n, c: _json_ok({"return": False,
                                                   "message": "Invalid API key"}), calls)
    assert _send(client, "phone", PHONE).status_code == 502


def test_vonage_status_zero_is_success_and_nonzero_is_not(client, monkeypatch, production):
    monkeypatch.setenv("OTP_VONAGE_API_KEY", "vk")
    monkeypatch.setenv("OTP_VONAGE_API_SECRET", "vs" * 8)
    calls: list[dict] = []
    _fake_http(monkeypatch, lambda n, c: _json_ok(
        {"messages": [{"status": "0", "message-id": "abc"}]}), calls)
    assert _send(client, "phone", PHONE).json()["via"] == "vonage"
    calls.clear()
    _fake_http(monkeypatch, lambda n, c: _json_ok(
        {"messages": [{"status": "7", "error-text": "Bad credentials"}]}), calls)
    _forget_send_history()
    r = _send(client, "phone", PHONE)
    assert r.status_code == 502


def test_sms_webhook_posts_json_with_bearer_token(client, monkeypatch):
    monkeypatch.setenv("OTP_SMS_WEBHOOK_URL", "https://sms.example.com/send")
    monkeypatch.setenv("OTP_SMS_WEBHOOK_TOKEN", "s" * 24)
    calls: list[dict] = []
    _fake_http(monkeypatch, lambda n, c: _json_ok({"ok": True}), calls)
    body = _send(client, "phone", PHONE).json()
    assert body["via"] == "webhook"
    assert calls[0]["url"] == "https://sms.example.com/send"
    assert calls[0]["headers"]["Authorization"] == "Bearer " + "s" * 24
    assert calls[0]["payload"]["to"] == PHONE
    assert "dev_code" not in body
    assert _verify(client, calls[0]["payload"]["code"], "phone", PHONE).status_code == 200


def test_sms_webhook_5xx_is_retried_then_reported(client, monkeypatch):
    monkeypatch.setenv("OTP_SMS_WEBHOOK_URL", "https://sms.example.com/send")
    calls: list[dict] = []
    _fake_http(monkeypatch, lambda n, c: (503, "upstream down"), calls)
    body = _send(client, "phone", PHONE).json()     # dev: labelled demo, not silence
    assert body["demo"] is True and body["delivered"] is False
    assert len(calls) == 2                          # retried once
    assert "upstream down" in body["delivery"]["error"]


def test_explicit_provider_must_be_configured(client, monkeypatch, production):
    monkeypatch.setenv("OTP_SMS_PROVIDER", "twilio")     # chosen, but no credentials
    monkeypatch.setenv("OTP_FAST2SMS_KEY", "f" * 24)     # the other gateway is ready
    calls: list[dict] = []
    _fake_http(monkeypatch, lambda n, c: _json_ok({"return": True}), calls)
    r = _send(client, "phone", PHONE)
    assert r.status_code == 503 and calls == []          # never silently swaps
    assert otp_svc.delivery_status("phone")["provider"] is None


# ======================================================== HTTPS email gateways
def test_brevo_mail_payload(client, monkeypatch):
    monkeypatch.setenv("OTP_BREVO_API_KEY", "b" * 24)
    monkeypatch.setenv("OTP_SMTP_FROM", "no-reply@feefix.in")
    calls: list[dict] = []
    _fake_http(monkeypatch, lambda n, c: _json_ok({"messageId": "<1@brevo>"}), calls)
    body = _send(client).json()
    assert body["via"] == "brevo" and body["delivered"] is True
    call = calls[0]
    assert call["url"] == "https://api.brevo.com/v3/smtp/email"
    assert call["headers"]["api-key"] == "b" * 24
    assert call["payload"]["to"] == [{"email": EMAIL}]
    code = _code_in(call["payload"]["textContent"])
    assert "dev_code" not in body
    assert _verify(client, code).status_code == 200


def test_resend_mail_payload(client, monkeypatch):
    monkeypatch.setenv("OTP_RESEND_API_KEY", "r" * 24)
    calls: list[dict] = []
    _fake_http(monkeypatch, lambda n, c: _json_ok({"id": "abc-123"}), calls)
    body = _send(client).json()
    assert body["via"] == "resend" and body["delivered"] is True
    assert calls[0]["url"] == "https://api.resend.com/emails"
    assert calls[0]["headers"]["Authorization"] == "Bearer " + "r" * 24
    assert _verify(client, _code_in(calls[0]["payload"]["text"])).status_code == 200


def test_email_webhook_payload(client, monkeypatch):
    monkeypatch.setenv("OTP_EMAIL_WEBHOOK_URL", "https://mail.example.com/send")
    calls: list[dict] = []
    _fake_http(monkeypatch, lambda n, c: _json_ok({"ok": True}), calls)
    body = _send(client).json()
    assert body["via"] == "webhook" and body["delivered"] is True
    assert "dev_code" not in body
    assert _verify(client, calls[0]["payload"]["code"]).status_code == 200


def test_http_provider_requires_https(client, monkeypatch):
    """A credential-carrying call must never be downgraded to plaintext."""
    from backend.services import otp as svc
    with pytest.raises(ValueError):
        svc._post_json("http://sms.example.com/send", {"to": PHONE})


# ============================================================== readiness ====
def test_methods_reports_which_gateway_delivers(client, monkeypatch):
    body = client.get("/api/auth/methods").json()
    assert body["delivery"]["email"]["demo"] is True        # dev fallback
    assert body["delivery"]["email"]["real"] is False
    assert body["delivery"]["demo_mode"] is True
    monkeypatch.setenv("OTP_SMTP_HOST", "smtp.gmail.com")
    body = client.get("/api/auth/methods").json()
    assert body["delivery"]["email"] == {"provider": "smtp", "real": True,
                                        "demo": False, "usable": True}
    assert body["delivery"]["phone"]["real"] is False


def test_health_endpoint_answers_was_it_really_sent(client, monkeypatch):
    monkeypatch.setenv("OTP_TWILIO_SID", "AC" + "0" * 32)
    monkeypatch.setenv("OTP_TWILIO_TOKEN", "t" * 32)
    monkeypatch.setenv("OTP_TWILIO_FROM", "+15005550006")
    otp = client.get("/api/health").json()["otp_delivery"]
    assert otp["phone"]["provider"] == "twilio" and otp["phone"]["real"] is True
    assert otp["email"]["provider"] is None


# ============================================================ spend & abuse ==
def test_resend_cooldown_is_429_with_retry_after(client, monkeypatch, tmp_path):
    monkeypatch.setattr(otp_svc, "OTP_OUTBOX", tmp_path / "outbox.jsonl")
    assert _send(client).status_code == 200
    r = _send(client)
    assert r.status_code == 429
    assert "resend" in r.json()["detail"].lower()
    assert 0 < int(r.headers["Retry-After"]) <= otp_svc.RESEND_COOLDOWN_S


def test_hourly_cap_counts_real_sends_not_expired_challenges(client, monkeypatch, tmp_path):
    monkeypatch.setattr(otp_svc, "OTP_OUTBOX", tmp_path / "outbox.jsonl")
    monkeypatch.setenv("FEEFIX_OTP_DAILY_CAP", "50")
    conn = _sends_table()
    past = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat(timespec="seconds")
    for _ in range(otp_svc.REQ_PER_HOUR):
        assert _send(client).status_code == 200
        conn.execute("UPDATE otp_sends SET created_at=?", (past,))
        conn.execute("UPDATE otp_challenges SET created_at=?, expires_at=?",
                     (past, past))
        conn.commit()
    r = _send(client)
    assert r.status_code == 429 and "hour" in r.json()["detail"].lower()


def test_daily_cap_stops_a_pumping_attack(client, monkeypatch, tmp_path):
    monkeypatch.setattr(otp_svc, "OTP_OUTBOX", tmp_path / "outbox.jsonl")
    monkeypatch.setenv("FEEFIX_OTP_PER_HOUR", "20")
    monkeypatch.setenv("FEEFIX_OTP_DAILY_CAP", "3")
    conn = _sends_table()
    for i in range(3):
        assert _send(client).status_code == 200
        # back-date *this* send past the cooldown but inside the day
        stamp = (datetime.now(timezone.utc) - timedelta(minutes=5 + i)).isoformat(timespec="seconds")
        conn.execute("UPDATE otp_sends SET created_at=?", (stamp,))
        conn.execute("UPDATE otp_challenges SET created_at=?", (stamp,))
        conn.commit()
    r = _send(client)
    assert r.status_code == 429 and "today" in r.json()["detail"].lower()
    # a different number is unaffected — the cap is per destination
    assert _send(client, "phone", "+919000000001").status_code == 200


def test_a_failed_send_does_not_spend_the_budget(client, monkeypatch, tmp_path, production):
    monkeypatch.setattr(otp_svc, "OTP_OUTBOX", tmp_path / "outbox.jsonl")
    monkeypatch.setenv("OTP_SMS_WEBHOOK_URL", "https://sms.example.com/send")
    calls: list[dict] = []
    _fake_http(monkeypatch, lambda n, c: (500, "boom"), calls)
    assert _send(client, "phone", PHONE).status_code == 502
    assert _sends_table().execute("SELECT COUNT(*) AS n FROM otp_sends").fetchone()["n"] == 0
    # the gateway recovers → the student can sign in immediately (no cooldown)
    _fake_http(monkeypatch, lambda n, c: _json_ok({"ok": True}), calls)
    r = _send(client, "phone", PHONE)
    assert r.status_code == 200 and r.json()["delivered"] is True
