"""Clipboard module behaviour — executed, not just grepped.

The old regression test only asserted that certain identifiers existed in
``secure-clipboard.js``. That proves nothing about behaviour, and the module's
documentation claimed a control it could not provide (malware reads the clipboard
long before a 20-second timer fires). This runs the real JavaScript in Node with
stub clipboard/DOM globals and checks what the module actually does.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
HARNESS = REPO / "tests" / "js" / "clipboard.test.mjs"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")


def test_clipboard_module_behaviour():
    result = subprocess.run(
        ["node", str(HARNESS)],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"clipboard tests failed:\n{result.stdout}\n{result.stderr}"
    assert "all clipboard tests passed" in result.stdout


def test_module_documents_that_it_is_not_a_security_control():
    source = (REPO / "web" / "frontend" / "secure-clipboard.js").read_text(encoding="utf-8")
    lowered = source.lower()
    for phrase in ("cannot stop", "not a security control", "limitations"):
        assert phrase in lowered, f"the module must be honest about '{phrase}'"
    # The old file claimed "clipboard-attack hardening"; that must be gone.
    assert "clipboard-attack hardening" not in lowered


def test_ui_states_the_limitation_to_the_user():
    gate = (REPO / "web" / "frontend" / "auth-gate.js").read_text(encoding="utf-8")
    assert "data-clip-note" in gate, "the OTP panes must disclose the limitation"
    assert "clearClipboard()" in gate
    assert "not protection" in gate.lower() or "convenience" in gate.lower()
