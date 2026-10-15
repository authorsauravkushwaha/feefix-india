"""Centralized input-size and resource limits — the first line of defence.

Every user-supplied string is bounded *here* so that a single constant governs
both the pydantic request schemas and the service layer. Bounding input length
is what makes several classic denial-of-service classes non-viable on FeeFix:

* **Long-password DoS** — PBKDF2 cost grows with the secret's length, so the
  password is capped (and additionally pre-hashed, see ``services/auth.py``).
* **ReDoS** — no regex ever runs over an unbounded string; inputs are clipped
  before any ``re`` engine touches them.
* **Giant-payload DoS** — ``MAX_BODY_BYTES`` is enforced by request-body
  middleware before a handler parses anything.

These are deliberately generous for legitimate use and tiny for abuse.
"""

from __future__ import annotations

# -- credential / identity fields ------------------------------------------- #
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = 256          # passphrase-friendly, yet bounds KDF work
MAX_EMAIL_LEN = 254             # RFC 5321 practical maximum
MAX_NAME_LEN = 100
MAX_ADDRESS_LEN = 320           # email or E.164 phone destination

# -- free-text fields -------------------------------------------------------- #
MAX_MESSAGE_LEN = 2000          # chat turn
MAX_QUESTION_LEN = 1000         # grounded Q&A question
MAX_SEARCH_LEN = 200            # semantic / keyword search query

# -- identifiers ------------------------------------------------------------- #
MAX_SESSION_ID_LEN = 64
MAX_SCHEME_ID_LEN = 64
MAX_LANG_LEN = 8

# -- transport --------------------------------------------------------------- #
MAX_BODY_BYTES = 1_000_000      # 1 MB hard cap on any request body

# -- uploads (see services/upload.py) --------------------------------------- #
MAX_UPLOAD_BYTES = 2_000_000    # 2 MB per file
UPLOAD_ALLOWED_EXTS = frozenset({".pdf", ".png", ".jpg", ".jpeg"})
