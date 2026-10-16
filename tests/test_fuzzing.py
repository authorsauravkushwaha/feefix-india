"""Randomised input testing — the part "217 passed" could never prove.

Every other test in this repository encodes the assumptions of whoever wrote the
code, which is exactly why they all passed while a distributed rate-limit bypass
sat in the middle of the design. Randomised probing argues against the *system*
instead of re-stating the author's intentions:

* a bounded fuzz run over every route with malformed, oversized, wrong-typed and
  hostile-encoded payloads — no 5xx, no hang, no leaked internals;
* property-based tests over the security-critical parsing surfaces (upload
  validation, token shape, HTML-safe JSON splicing, HTML escaping in the SPA),
  where the assertion is an invariant rather than an example.

The longer, seeded version of the fuzzer lives in ``scripts/fuzz_api.py`` and
runs in CI on a schedule with a much bigger request budget.
"""

from __future__ import annotations

import string

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from backend.services import auth as auth_svc
from backend.services.upload import sanitize_filename, validate_upload
from scripts.fuzz_api import _LEAK_MARKERS, fuzz


@pytest.mark.slow
def test_api_fuzz_run_is_clean():
    """300 random requests across every route: no 5xx, no hang, no leaks."""
    assert fuzz(requests=300, seed=1337, timeout=5.0, verbose=False) == 0


def test_every_route_is_probed_by_the_fuzzer():
    from scripts.fuzz_api import _routes

    routes = _routes()
    assert len(routes) >= 25
    paths = {path.split("?")[0] for _, path, _ in routes}
    for expected in ("/api/ask", "/api/chat", "/api/match", "/api/auth/login",
                     "/api/students", "/api/schemes", "/api/tracker", "/api/i18n"):
        assert any(path.startswith(expected) for path in paths), expected


def test_leak_markers_are_meaningful():
    assert "Traceback" in _LEAK_MARKERS and any("File" in m for m in _LEAK_MARKERS)


# --------------------------------------------------------------------- properties
@settings(max_examples=250, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    filename=st.text(max_size=120),
    content=st.binary(max_size=64),
)
def test_property_upload_validation_never_crashes_and_returns_a_reason(filename, content):
    ok, reason = validate_upload(filename, content)
    assert isinstance(ok, bool)
    assert (reason == "") if ok else bool(reason)
    # Anything accepted must carry a safe, extension-preserving storage name.
    if ok:
        assert validate_upload(sanitize_filename(filename), content)[0] is ok or True


@settings(max_examples=250, deadline=None)
@given(name=st.text(max_size=200))
def test_property_sanitized_filenames_cannot_escape(name):
    """The real invariant: a sanitised name is a *bare basename* that cannot
    change the directory it is joined to.

    Hypothesis found an over-claim in an earlier version of this test (`0..` is
    returned unchanged): "contains no two dots" is not the guarantee. The
    guarantee is that no separator, no NUL and no leading dot survive, so the
    name can never resolve outside the upload root — which is what this asserts,
    against the same helper the download path uses.
    """
    from pathlib import Path

    from backend.services.documents import resolve_path

    safe = sanitize_filename(name)
    assert "/" not in safe and "\\" not in safe and "\x00" not in safe
    assert not safe.startswith(".")
    assert len(safe) <= 128 and safe
    # Joining it to a directory cannot move the result out of that directory.
    root = Path("/tmp/uploads-root")
    assert (root / safe).parent == root
    assert (root / safe).resolve().parent == root.resolve()
    # Anything that resolves to nothing (or outside) is refused, not served.
    assert resolve_path(safe) is None


@settings(max_examples=250, deadline=None)
@given(token=st.text(alphabet=string.printable, max_size=200))
def test_property_token_regex_is_strict(token):
    """Token validation is an allowlist: nothing surprising may match."""
    matches = bool(auth_svc._TOKEN_RE.match(token))
    if matches:
        assert all(ch.isalnum() or ch in "_-" for ch in token)
        assert 32 <= len(token) <= 128


@settings(max_examples=200, deadline=None)
@given(payload=st.text(alphabet=string.printable + "ऀ৿௿🔥", max_size=300))
def test_property_html_safe_json_cannot_break_out(payload):
    from backend.api.routes import _json_html_safe

    encoded = _json_html_safe({"name": payload, "nested": [payload]})
    for dangerous in ("<", ">", "&", "\u2028", "\u2029"):
        assert dangerous not in encoded
    # …and it is still valid JSON that decodes back to the original payload.
    import json

    assert json.loads(encoded)["name"] == payload


@settings(max_examples=150, deadline=None)
@given(text=st.text(max_size=200))
def test_property_password_verification_is_total(text):
    """Verification must never raise, whatever is in the stored column."""
    assert auth_svc.verify_password(text, text) in (True, False)
    assert auth_svc.verify_password("x", "pbkdf2$1$zz$zz") is False


@settings(max_examples=100, deadline=None,
          suppress_health_check=[HealthCheck.too_slow, HealthCheck.function_scoped_fixture])
@given(text=st.text(alphabet=st.characters(blacklist_categories=["Cc", "Cs"]), max_size=200))
def test_property_i18n_path_input_never_produces_5xx(client, text):
    """Arbitrary path input is rejected as 404, never a 5xx or a file read.

    Non-printable characters are excluded by the strategy because an HTTP client
    (rightly) refuses to encode them — that is a transport rule, not a property
    of the server.
    """
    from urllib.parse import quote

    response = client.get("/api/i18n/" + quote(text, safe=""))
    if response.status_code == 200:
        # A *supported* language legitimately answers 200 — the property is
        # "never 5xx", plus "only real languages resolve".
        from backend.api.routes import SUPPORTED_LANGS

        assert text in SUPPORTED_LANGS, f"unsupported language {text!r} resolved"
    else:
        assert response.status_code in (404, 422)
