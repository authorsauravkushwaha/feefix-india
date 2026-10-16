"""Auth gate (``web/frontend/auth-gate.js``) — the UI must not fake a delivery.

The gate is browser code, so the assertions here are on its source: they pin the
contract that the rewrite exists to guarantee, the way ``test_clipboard_js.py``
pins the clipboard module's honesty. The behaviour of the thing it talks to is
tested for real in ``test_otp_delivery.py``.

Contract:
* the code is rendered as *text*, never spliced into HTML (`dev_code` came from
  the server, but a template literal is how the next injection starts);
* capabilities come from the server (`/api/auth/methods`), so a deployment with
  no gateway does not greet the student with a door that cannot open;
* a demo code is labelled as a demo (banner + chip + button copy), because
  "Sent!" over a code that was never sent is the bug being fixed;
* the resend/expiry countdowns follow the server's numbers instead of a
  hard-coded 40.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
GATE = (REPO / "web" / "frontend" / "auth-gate.js").read_text(encoding="utf-8")


def test_gate_asks_the_server_which_doors_are_open():
    assert "/api/auth/methods" in GATE
    assert "demo_mode" in GATE and "dev_inbox" in GATE
    # A closed door is disabled with the reason, not silently omitted.
    assert "offReason" in GATE and "Not available on this server" in GATE


def test_gate_renders_codes_as_text_never_as_html():
    assert "textContent = code" in GATE, "a code must never be spliced into HTML"
    offenders = [
        line.strip() for line in GATE.splitlines()
        if "innerHTML" in line and ("code" in line or "detail" in line)
    ]
    assert offenders == [], f"HTML built from a server value: {offenders}"


def test_demo_mode_is_labelled_everywhere_it_appears():
    assert '"DEMO"' in GATE                     # the chip next to the code
    assert "Demo mode:" in GATE                 # the banner at the top of the card
    assert "Show a demo code →" in GATE         # the button copy
    assert "instead of being sent" in GATE      # the banner sentence


def test_delivery_state_is_described_per_channel():
    assert "describeDelivery" in GATE
    for provider in ("smtp", "brevo", "resend", "twilio", "msg91", "fast2sms", "vonage"):
        assert provider in GATE, f"{provider} must be named to the student"


def test_countdowns_come_from_the_server_not_a_constant():
    assert "resend_in" in GATE and "ttl_s" in GATE
    # …and the old hard-coded default is gone (it desynced from the API).
    assert not re.search(r"seconds\s*=\s*40", GATE)
    assert "retryAfter" in GATE, "429s must drive the countdown too"


def test_expiry_returns_the_student_to_the_address_step():
    assert "backToAddress" in GATE and "expired" in GATE


def test_clipboard_courtesy_is_still_required_and_still_honest():
    """``test_clipboard_js.py`` asserts the phrasing; this pins the wiring."""
    assert "data-clip-note" in GATE
    assert "clearClipboard()" in GATE
    assert "convenience, not protection" in GATE
