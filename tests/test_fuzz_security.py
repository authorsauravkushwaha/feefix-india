"""Property-based and adversarial tests — the part the old suite was missing.

The review's point #10: "217 passed" proved the code matched its own author's
assumptions, because every test was written by the same person as the code, and
the suite only walked the happy path. There was no fuzzing at all.

This module adds two kinds of tests that do not depend on knowing the answer in
advance:

* **Property-based (Hypothesis)** — invariants that must hold for *arbitrary*
  input: parsers are total, size caps hold for every string, sanitisers never
  emit a path separator, JSON-in-HTML encoders never emit a breakable character,
  rate limiters never exceed their own limit.
* **Adversarial/abuse cases** — the inputs a friendly test never types: NUL
  bytes, CRLF header injection, unicode confusables, deeply nested JSON, huge
  parameter sets, malformed multipart, oversized tokens.

Where a behaviour is *not* protected, the test documents it as observed rather
than asserting a wish (see the nesting/size notes below).
"""

from __future__ import annotations

import json
import math
import re

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from backend.services import auth as auth_svc
from backend.services import numerals, ratelimit, upload as upload_svc
from backend.services.limits import MAX_UPLOAD_BYTES, body_limit_bytes

SETTINGS = settings(max_examples=60, deadline=None,
                    suppress_health_check=[HealthCheck.function_scoped_fixture])

# Text that is hostile in ways Python strings normally are not: control chars,
# NULs, bidi overrides, lone surrogates avoided (JSON cannot carry them), and
# mixed scripts.
HOSTILE_TEXT = st.text(
    alphabet=st.characters(
        blacklist_categories=("Cs",),  # lone surrogates are not valid UTF-8
    ),
    max_size=200,
)
HOSTILE_BYTES = st.binary(max_size=256)
SAFE_FILENAMES = st.text(max_size=60)


# --------------------------------------------------------------------------- #
# parsers are total: never raise, always bounded
# --------------------------------------------------------------------------- #
@SETTINGS
@given(HOSTILE_TEXT)
def test_income_parser_is_total_and_bounded(text):
    """Any input at all → an int in range, or None. Never an exception."""
    result = numerals.parse_amount(text)
    assert result is None or (isinstance(result, int) and 0 <= result <= numerals.MAX_AMOUNT)


@SETTINGS
@given(HOSTILE_TEXT)
def test_digit_normalisation_is_total_and_idempotent(text):
    once = numerals.normalize_digits(text)
    assert numerals.normalize_digits(once) == once, "normalisation must be idempotent"


@SETTINGS
@given(st.integers(min_value=0, max_value=10 ** 9), st.sampled_from([1, 1000, 100000, 10 ** 7]))
def test_ascii_amounts_round_trip(value, multiplier):
    text = f"{value} " + {1: "", 1000: "thousand", 100000: "lakh", 10 ** 7: "crore"}[multiplier]
    expected = value * multiplier
    parsed = numerals.parse_amount(text)
    if expected > numerals.MAX_AMOUNT:
        assert parsed is None
    else:
        assert parsed == expected


@SETTINGS
@given(HOSTILE_TEXT)
def test_secret_scanner_never_crashes_and_redacts_boundedly(text):
    from agents.secret_scan import _redact, _scan_text

    findings = _scan_text("fuzz/whatever.py", text)
    assert isinstance(findings, list)
    for finding in findings:
        assert len(finding["snippet"]) <= 81
        assert "\n" not in finding["snippet"]


# The token shape the scanner must catch. Assembled at runtime (rather than
# written as a literal) so this test file does not itself look like a leak —
# see tests/test_secret_hygiene.py for why that matters.
_TOKEN_PREFIX = "ghp" + chr(95)
_TOKEN_BODY = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


@SETTINGS
@given(st.text(alphabet=_TOKEN_PREFIX + _TOKEN_BODY, min_size=40, max_size=80))
def test_scanner_finds_planted_provider_tokens(text):
    from agents.secret_scan import _scan_text

    if _TOKEN_PREFIX not in text:
        text = _TOKEN_PREFIX + text
    if not re.search(re.escape(_TOKEN_PREFIX) + r"[A-Za-z0-9]{36,}", text):
        return
    assert _scan_text("fuzz/leak.py", f'TOKEN = "{text}"')


# --------------------------------------------------------------------------- #
# uploads: the gate must hold for arbitrary input
# --------------------------------------------------------------------------- #
@SETTINGS
@given(SAFE_FILENAMES, HOSTILE_BYTES)
def test_upload_validation_is_total(filename, content):
    ok, reason = upload_svc.validate_upload(filename, content)
    assert isinstance(ok, bool) and isinstance(reason, str)
    if ok:
        ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
        assert f".{ext}" in (".pdf", ".png", ".jpg", ".jpeg")
        assert content and len(content) <= MAX_UPLOAD_BYTES


@SETTINGS
@given(SAFE_FILENAMES)
def test_sanitised_filenames_never_contain_traversal_or_separators(filename):
    cleaned = upload_svc.sanitize_filename(filename)
    assert "/" not in cleaned and "\\" not in cleaned
    assert ".." not in cleaned
    assert "\x00" not in cleaned
    assert not cleaned.startswith(".")
    assert 0 < len(cleaned) <= 128
    stored = upload_svc.safe_storage_name(filename)
    assert "/" not in stored and "\\" not in stored
    assert not stored.startswith(".")


@SETTINGS
@given(st.binary(max_size=32))
def test_magic_bytes_are_actually_checked(content):
    ok, _ = upload_svc.validate_upload("claim.pdf", content)
    assert ok is (content.startswith(b"%PDF-") and len(content) > 0)


@pytest.mark.parametrize(
    "filename",
    ["\x00.pdf", "a\x00b.pdf", "..%2f..%2fetc%2fpasswd.pdf", "con.pdf ", ".....pdf",
     "ﬁle.pdf", "file.pdf\x0aSet-Cookie: x=1"],
)
def test_nasty_filenames_are_neutralised(filename):
    stored = upload_svc.safe_storage_name(filename)
    assert re.fullmatch(r"[0-9a-f]{32}(\.(pdf|png|jpg|jpeg))?", stored), stored


# --------------------------------------------------------------------------- #
# auth: arbitrary tokens must be inert
# --------------------------------------------------------------------------- #
@SETTINGS
@given(HOSTILE_TEXT)
def test_arbitrary_tokens_never_resolve(token):
    assert auth_svc.resolve_token(token) is None


@SETTINGS
@given(st.text(max_size=64))
def test_password_verification_never_raises(password):
    from backend.services import passwords

    assert passwords.verify(password, "not-a-hash")[0] is False
    for stored in ("", "pbkdf2$", "pbkdf2$abc$def$ghi", "argon2id$broken", "x" * 500):
        assert passwords.verify(password, stored)[0] is False


@SETTINGS
@given(st.text(max_size=40))
def test_client_fingerprint_is_stable_and_short(value):
    class _Req:
        def __init__(self, headers):
            self.headers = headers

    first = auth_svc.client_fingerprint(_Req({"user-agent": value}))
    second = auth_svc.client_fingerprint(_Req({"user-agent": value}))
    assert first == second
    if first is not None:
        assert re.fullmatch(r"[0-9a-f]{16}", first)


def test_header_injection_in_user_agent_cannot_forge_a_session(client):
    """CRLF in a header must not become a header of its own."""
    r = client.get(
        "/api/schemes",
        headers={"User-Agent": "evil\r\nX-Injected: 1", "Authorization": "Bearer " + "A" * 40},
    )
    assert r.status_code == 200
    assert "x-injected" not in {k.lower() for k in r.headers}


# --------------------------------------------------------------------------- #
# rate limiter invariants
# --------------------------------------------------------------------------- #
@SETTINGS
@given(st.lists(st.integers(min_value=1, max_value=50), min_size=1, max_size=60))
def test_memory_limiter_never_exceeds_its_own_limit(labels):
    store = ratelimit.MemoryBackend()
    window = 60
    seen: dict[str, int] = {}
    for label in labels:
        ident = f"ip-{label}"
        allowed, retry = store.allow("global", ident, 5, window)
        seen[ident] = seen.get(ident, 0) + (1 if allowed else 0)
        assert seen[ident] <= 5
        if not allowed:
            assert retry > 0
    assert all(count <= 5 for count in seen.values())


@SETTINGS
@given(st.sampled_from(["/api/ask", "/api/chat", "/api/uploads/x", "/api/schemes", "/"]),
       st.sampled_from(["GET", "POST", "PUT", "DELETE"]))
def test_every_endpoint_class_has_a_finite_body_limit(path, method):
    limit = body_limit_bytes(method, path)
    assert 1024 <= limit <= 16_000_000


# --------------------------------------------------------------------------- #
# JSON-in-HTML encoder (the one place the server emits HTML)
# --------------------------------------------------------------------------- #
@SETTINGS
@given(HOSTILE_TEXT)
def test_handoff_json_encoder_neutralises_every_breakout(value):
    from backend.api.routes import _json_html_safe

    encoded = _json_html_safe({"user": {"name": value, "email": "a@b.co"}})
    for char in ("<", ">", "&", "\u2028", "\u2029"):
        assert char not in encoded, f"{char!r} survived the encoder"
    # …and it is still valid JSON with the exact original value.
    assert json.loads(encoded)["user"]["name"] == value


# --------------------------------------------------------------------------- #
# adversarial request shapes: must be refused, never crash
# --------------------------------------------------------------------------- #
def test_deeply_nested_json_does_not_crash_the_service(client):
    """Deep nesting is a known RecursionError shape — it must not 500-crash.

    Observed behaviour is recorded here rather than asserted away: a 4xx (or even
    a bounded 500 with an opaque body and a request id) is acceptable; a process
    crash or a stack trace in the response is not.
    """
    depth = 2000
    payload = ("[" * depth) + ("]" * depth)
    r = client.post(
        "/api/chat",
        content=payload.encode(),
        headers={"content-type": "application/json"},
    )
    assert r.status_code != 200
    assert "Traceback" not in r.text and "RecursionError" not in r.text
    if r.status_code >= 500:
        assert r.json().get("request_id")


def test_absurd_number_of_query_parameters_is_survivable(client):
    params = {f"q{i}": "x" * 20 for i in range(500)}
    r = client.get("/api/schemes", params=params)
    assert r.status_code in (200, 414, 422)


def test_very_long_url_path_is_a_404_not_a_crash(client):
    r = client.get("/api/schemes/" + "a" * 4000)
    assert r.status_code in (404, 414)


@pytest.mark.parametrize(
    "payload",
    [
        b"\x00\x01\x02",          # not JSON at all
        b"{}" * 5000,               # concatenated objects
        b"[1,2,3]",                 # right JSON, wrong shape
        b'{"message": null}',       # null where a string is required
        b'{"message": ' + b"1" * 3000 + b"}",  # oversized unquoted number
        b'{"message": "unterminated',          # truncated body
    ],
)
def test_malformed_bodies_get_a_4xx_never_a_5xx(client, payload):
    r = client.post("/api/chat", content=payload, headers={"content-type": "application/json"})
    assert 400 <= r.status_code < 500, f"unexpected {r.status_code} for {payload[:20]!r}"


@pytest.mark.parametrize(
    "payload",
    [
        b'{"message": "' + b"\\" * 50 + b'"}',              # 25 escaped backslashes
        b'{"message": "' + "👩‍👩‍👧‍👦".encode() + b'"}',          # ZWJ emoji sequence
        b'{"message": "' + rb"\u0000" + b'"}',               # NUL *inside* a string
    ],
)
def test_unusual_but_valid_bodies_never_produce_a_5xx(client, payload):
    """Valid JSON with hostile content is accepted (or refused) — never a 5xx."""
    r = client.post("/api/chat", content=payload, headers={"content-type": "application/json"})
    assert r.status_code < 500, f"unexpected {r.status_code} for {payload[:20]!r}"


def test_lone_surrogates_are_a_clean_422_not_a_500(client):
    """Regression for a fuzzer finding: a surrogate used to 500 in the renderer.

    ``json.loads`` produces lone surrogates from ``"\ud800"``; the value reached
    the response renderer, which raised ``UnicodeEncodeError``. Two layers now
    prevent it: schema validation (422) and a response class that can always
    encode (belt and braces).
    """
    r = client.post(
        "/api/chat",
        content=b'{"message": "\\ud800"}',
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 422, r.text
    # The error body is valid JSON, and the un-encodable character is replaced
    # (U+FFFD) rather than echoed verbatim — so the error response itself can
    # always be serialised.
    payload = r.json()
    assert payload["detail"]
    assert "\ud800" not in r.text
    assert "\ufffd" in r.text or "unicode" in r.text.lower()


def test_response_class_survives_unencodable_payloads():
    """Even if a surrogate reaches a response, rendering must not explode."""
    from backend.api.responses import SafeJSONResponse

    response = SafeJSONResponse(content={"echo": "\ud800"})
    assert b"ud800" in response.body.lower()
    assert response.body.decode("utf-8")  # valid UTF-8 bytes out


def test_wrong_content_type_is_rejected_cleanly(client):
    r = client.post("/api/chat", content=b"message=hi", headers={"content-type": "text/plain"})
    assert r.status_code in (400, 415, 422)


def test_unicode_confusables_do_not_become_a_different_scheme(client):
    """A look-alike scheme id is looked up and not found — never executed."""
    for scheme_id in ("sv-mcm-wb\u200b", "\u0455v-mcm-wb", "sv-mcm-wb/../admin", "sv%2fmcm-wb"):
        assert client.get(f"/api/schemes/{scheme_id}").status_code == 404


def test_nan_and_infinity_shaped_amounts_are_rejected():
    from backend.services.chat import parse_income

    for text in ("nan lakh", "inf crore", "1e309", "0x10 lakh", "２ lakh"):
        parsed = parse_income(text)
        assert parsed is None or isinstance(parsed, int)
        if isinstance(parsed, int):
            assert 0 <= parsed <= numerals.MAX_AMOUNT
    assert not math.isnan(float(0))  # sanity: nothing above produced a float


def test_random_fuzz_burst_of_endpoints_never_5xx(client):
    """A small deterministic 'monkey' over the read-only surface."""
    paths = ["/api/health", "/api/meta", "/api/stats", "/api/schemes", "/api/i18n/en",
             "/api/i18n/xx", "/api/tracker/does-not-exist", "/api/auth/methods"]
    for path in paths:
        r = client.get(path)
        assert r.status_code < 500, f"{path} → {r.status_code}"
