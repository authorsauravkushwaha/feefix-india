"""Deliberately FAKE credential samples, used to prove the secret scanner works.

.. warning::

   **Nothing in this file is a real credential.** Every value below is either a
   published documentation example or an invented string. They live in one file,
   under one name, so that:

   * the scanner can be allow-listed for exactly this path and nothing else;
   * a reviewer reading a diff here knows immediately what they are looking at;
   * nobody has to wonder whether a credential-shaped string elsewhere in the
   * test suite is real.

Why this file exists at all
---------------------------
``scripts/secret_scan.py`` runs in CI over every tracked file. A scanner that
always passes is worse than no scanner, because it produces confidence — so
``tests/test_security.py`` asserts it *detects* known-bad content and *ignores*
ordinary code. That assertion needs credential-shaped literals somewhere in the
repository, and putting them inline in a test file would mean either
allow-listing the whole test module (which would also suppress a real secret
pasted into it later) or breaking the literals up so they stop matching (which
would silently stop testing anything).

Isolating them here keeps the exemption as narrow as it can be: one path, one
reason, and the file's entire purpose is visible in its name.

If you add a sample, add it to ``DIRTY`` (must be caught) or ``CLEAN`` (must not
be), and extend the corresponding assertion in
``tests/test_security.py::TestSecretManagement::test_secret_scanner_actually_detects``.
"""

from __future__ import annotations

#: Extracted so tests that need to WRITE a credential-shaped string into a
#: throwaway repository can import it instead of inlining a literal. Inlining it
#: in ``tests/test_security.py`` made the scanner flag that file — correctly,
#: because it *is* a credential-shaped string in tracked content. This module is
#: the one path allow-listed for such literals, so the value belongs here.
AWS_EXAMPLE_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"

# ---------------------------------------------------------------------------
# Must be DETECTED. Each key is the filename the test writes the body to, so the
# extension is part of what is being exercised (``.pem`` is text and is the most
# common home for a private key — it must never be in a binary skip list).
# ---------------------------------------------------------------------------
DIRTY: dict[str, str] = {
    # AWS access key id — the canonical example from AWS documentation.
    "aws.py": f'K = "{AWS_EXAMPLE_KEY_ID}"',
    # GitHub personal access token (classic prefix). Invented suffix.
    "gh.py": 'K = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB"',
    # Database URL with an inline password. Invented.
    "db.py": 'K = "postgres://u:Sup3rS3cretPass@h:5432/d"',
    # PEM private key. Header/footer are the real markers; the body is filler.
    "key.pem": (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIBOgIBAAJBAKj34E0x8wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
        "-----END RSA PRIVATE KEY-----"
    ),
}

# ---------------------------------------------------------------------------
# Must NOT be detected. These are the strings that appear constantly in this
# codebase and would make the scanner noisy enough to be ignored — which is how
# a scanner gets removed.
# ---------------------------------------------------------------------------
CLEAN: dict[str, str] = {
    # Hash-format template with interpolation, not a literal secret.
    "auth.py": 'h = f"pbkdf2${i}${salt.hex()}${d.hex()}"',
    # Documentation naming a variable without assigning a value.
    "docs.md": "Set `FEEFIX_OTP_PEPPER` to a 32-byte value.",
    # A test password — high-entropy-looking but obviously a fixture.
    "test.py": '_register(client, password="TopSecret123")',
}

__all__ = ["DIRTY", "CLEAN", "AWS_EXAMPLE_KEY_ID"]
