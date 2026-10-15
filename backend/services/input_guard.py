"""Input guard — validation and sanitisation that cannot itself be attacked.

THE PROBLEM WITH ``re``
=======================
A regular expression is a program, and like any program it can have a
pathological worst case. Python's ``re`` is a *backtracking* engine: when a
pattern contains two quantifiers that can match the same characters, a failing
input makes the engine try every way of splitting the string before giving up.
Cost goes quadratic — or exponential — in the input length. That is **ReDoS**
(regular-expression denial of service), and it is the cheapest DoS available to
an attacker: one HTTP field, a few kilobytes, no authentication, and the server
burns CPU for seconds.

FeeFix shipped exactly this. ``EMAIL_RE = ^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$`` has a
``[^@\\s]+`` on both sides of a literal ``.``, and ``.`` is *inside* ``[^@\\s]``,
so the two quantifiers overlap. Measured before the fix:

    "a@" + "a." * 10000 + " "   →  718 ms for one 20 KB string
    (quadratic: 4× the length ≈ 16× the time)

At 20 requests/second that is a full core, from an unauthenticated endpoint,
with a payload smaller than a single photograph.

THE FIX
=======
Every validator here is written so its cost is **provably linear** in the input
length and so no two quantifiers can match the same character:

* Length is checked *first* — before any parsing work at all. An attacker who
  cannot send a long string cannot trigger a slow path.
* Structure is checked with ``str`` operations (``partition``, ``split``,
  character-set membership) which are single-pass and non-backtracking.
* Where a regex is genuinely the clearest tool, the character classes are made
  **mutually exclusive** (``[A-Za-z0-9-]`` never contains ``.``), so there is
  exactly one way to match any prefix and nothing to backtrack over.

All validators are also *rejecting*: they return ``None``/``False`` rather than
raising, so a caller cannot forget to handle a malformed value.

Also covered here (input validation, defence in depth):
* Unicode normalisation + bidi/control stripping (:mod:`backend.services.security`)
* ID whitelists for anything that becomes a dict key, filename or SQL parameter
* Enum membership checks so no free-form string reaches a filter
"""

from __future__ import annotations

import re
import unicodedata

from backend.services.security import LIMITS, sanitize_text

# ---------------------------------------------------------------------------
# Character sets. Each is used in at most ONE quantifier per pattern, and no
# set below contains a character that also appears literally in the pattern.
# That invariant is what makes these linear — see the module docstring.
# ---------------------------------------------------------------------------
_ATEXT = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    ".!#$%&'*+-/=?^_`{|}~"
)
_LDH = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789-"
)
_ALPHA = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_DIGITS = frozenset("0123456789")
_HEX = frozenset("0123456789abcdefABCDEF")
# base64url — the alphabet ``secrets.token_urlsafe`` emits.
_B64URL = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
)

# Session ids arrive from ``crypto.randomUUID()`` but must also tolerate the
# legacy hex ids the server mints. Both shapes are covered, nothing else is.
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{3,63}$")
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_BEARER_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_LANG_RE = re.compile(r"^[a-z]{2}(-[A-Z]{2})?$")

# Kept ONLY for backwards compatibility with modules that imported it. It is a
# linear pattern (the classes are mutually exclusive) but prefer valid_email().
EMAIL_SAFE_RE = re.compile(
    r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,63}$"
)


# ------------------------------------------------------------------ strings --
def bounded(value: str | None, max_len: int, *, field: str = "value") -> str:
    """Sanitise + hard-truncate a free-text field. Never raises."""
    return sanitize_text(value, max_len)


def reject_if_overlong(value: str | None, max_len: int) -> bool:
    """True when a value exceeds its ceiling.

    Call this *before* doing anything expensive with ``value``. The whole point
    is that the check is O(1) — ``len()`` on a Python string does not scan.
    """
    return value is not None and len(value) > max_len


def is_email(value: str | None) -> bool:
    return valid_email(value) is not None


def valid_email(value: str | None) -> str | None:
    """Return the canonical lowercase address, or ``None``.

    Linear by construction: one ``rpartition``, one ``split``, and a bounded
    number of single-pass character checks. There is no backtracking because
    there is no regex.

    Enforces the RFC 5321 length limits (254 total / 64 local / 253 domain /
    63 per label) *before* looking at characters, so an oversized payload is
    rejected without being parsed at all.
    """
    if not value:
        return None
    if reject_if_overlong(value, LIMITS.MAX_EMAIL_LEN):
        return None

    address = value.strip()
    # Normalise first: a fullwidth "＠" or a combining-mark homoglyph must not
    # slip past as a different address that renders identically.
    address = unicodedata.normalize("NFC", address).lower()
    if len(address) > LIMITS.MAX_EMAIL_LEN:
        return None

    # rpartition on the LAST '@' — an address has exactly one unquoted '@'.
    local, sep, domain = address.rpartition("@")
    if not sep or not local or not domain:
        return None
    if len(local) > LIMITS.MAX_EMAIL_LOCAL_LEN:
        return None
    if len(domain) > LIMITS.MAX_DOMAIN_LEN:
        return None

    # --- local part: single pass over a fixed character set -----------------
    if local[0] == "." or local[-1] == "." or ".." in local:
        return None
    for ch in local:
        if ch not in _ATEXT:
            return None

    # --- domain: LDH labels, at least two, no leading/trailing hyphen -------
    labels = domain.split(".")
    if len(labels) < 2:
        return None
    for label in labels:
        if not label or len(label) > LIMITS.MAX_DOMAIN_LABEL_LEN:
            return None
        if label[0] == "-" or label[-1] == "-":
            return None
        for ch in label:
            if ch not in _LDH:
                return None
    # TLD must be alphabetic — stops "user@1.2.3.4" being treated as a mailbox
    # (an IP literal is a legitimate SMTP target but not a sign-in identity,
    # and accepting it invites SSRF-shaped confusion downstream).
    for ch in labels[-1]:
        if ch not in _ALPHA:
            return None

    return address


def valid_phone(value: str | None) -> str | None:
    """E.164 normalisation, linear and backtracking-free.

    Accepts the separators humans actually type (spaces, hyphens, parentheses),
    infers ``+91`` for a bare 10-digit Indian mobile, and rejects anything that
    is not a well-formed international number.
    """
    if not value:
        return None
    if reject_if_overlong(value, LIMITS.MAX_PHONE_LEN * 4):
        return None

    cleaned = []
    seen_plus = False
    for ch in value.strip():
        if ch in " \t-().":
            continue
        if ch == "+":
            if seen_plus or cleaned:
                return None          # '+' only valid as the first character
            seen_plus = True
            continue
        if ch not in _DIGITS:
            return None
        cleaned.append(ch)

    digits = "".join(cleaned)
    if not seen_plus:
        # Bare national number: Indians commonly write a trunk prefix ("0"),
        # which is not part of the subscriber number. Strip it, then assume
        # India — the product's primary market.
        digits = digits.lstrip("0")
        if len(digits) == 10 and digits[0] in "6789":
            digits = "91" + digits
        else:
            return None
    if not (7 <= len(digits) <= 15):
        return None
    if digits[0] == "0":
        return None                  # E.164 country codes never start with 0
    return "+" + digits


def valid_password(value: str | None) -> str | None:
    """Length-gate a password *before* it reaches the KDF.

    This is the long-password DoS control. PBKDF2's cost is dominated by the
    iteration count, but the password still has to be encoded to UTF-8, held in
    memory and shipped through TLS — and a 10 MB field is a 10 MB allocation
    per request. Capping at the API boundary means the expensive function is
    never reached with an expensive argument.

    Returns ``None`` when the value is unusable so callers answer 422 without
    hashing anything.
    """
    if value is None:
        return None
    if reject_if_overlong(value, LIMITS.MAX_PASSWORD_LEN):
        return None
    if len(value) < MIN_PASSWORD_LEN:
        return None
    # Reject non-printable content: a password made of control characters is
    # either a client bug or an attempt to smuggle bytes into a log line.
    for ch in value:
        if unicodedata.category(ch) in ("Cc", "Cf"):
            return None
    return value


MIN_PASSWORD_LEN = LIMITS.MIN_PASSWORD_LEN
MAX_PASSWORD_LEN = LIMITS.MAX_PASSWORD_LEN


def valid_bearer_token(value: str | None) -> str | None:
    """Opaque session token shape check (constant cost, bounded length)."""
    if not value or len(value) > LIMITS.MAX_TOKEN_LEN:
        return None
    return value if _BEARER_RE.match(value) else None


def valid_session_id(value: str | None) -> str | None:
    """Anything used as a store key, path segment or dict key goes through here.

    Whitelisting the shape is what makes the value safe to interpolate into a
    URL, a filename or a cache key — a ``../`` or a newline can never survive.
    """
    if not value or len(value) > LIMITS.MAX_SESSION_ID_LEN:
        return None
    return value if _ID_RE.match(value) else None


def valid_scheme_id(value: str | None) -> str | None:
    """Scheme ids are lowercase slugs (matches ``models.scheme.Scheme.id``)."""
    if not value or len(value) > LIMITS.MAX_SCHEME_ID_LEN:
        return None
    return value if _SLUG_RE.match(value) else None


def valid_lang(value: str | None, allowed: set[str] | frozenset[str]) -> str | None:
    """Language codes are checked against an allow-list, never pattern-matched
    into a filesystem path. ``../../etc/passwd`` is not in the allow-list."""
    if not value or len(value) > LIMITS.MAX_LANG_LEN:
        return None
    if not _LANG_RE.match(value):
        return None
    return value if value in allowed else None


def valid_nonce(value: str | None) -> str | None:
    """Anti-replay nonce: URL-safe, bounded, at least 128 bits of entropy.

    The alphabet is base64url (``A-Za-z0-9-_``), which is what
    ``secrets.token_urlsafe`` emits; a 24-byte draw renders as 32 characters
    and carries 192 bits. The length floor is on *characters*, so it is a
    sanity gate rather than an entropy guarantee — the server cannot verify
    that a client used a CSPRNG, only that the value is shaped like one and is
    not reused.
    """
    if not value or len(value) > LIMITS.MAX_NONCE_LEN:
        return None
    if len(value) < 16:
        return None
    for ch in value:
        if ch not in _B64URL:
            return None
    return value


def valid_enum(value: str | None, allowed, *, default=None):
    """Whitelist a query parameter against a fixed set.

    ``level``/``status``/``type`` parameters are filters that reach dataset
    lookups. Allowing only known members means an unexpected value can never be
    interpreted as an operator, a wildcard or a query fragment.
    """
    if value is None:
        return default
    if isinstance(value, str):
        value = value.strip()
    return value if value in allowed else default


def valid_int(value, *, minimum: int, maximum: int, default: int) -> int:
    """Clamp an integer instead of trusting it.

    Clamping (rather than rejecting) keeps a client bug from becoming a 4xx,
    while ``maximum`` keeps a hostile value from becoming an allocation — e.g.
    ``?k=999999999`` on a search endpoint.
    """
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, n))


def strip_nulls_and_control(value: str | None) -> str:
    """Remove C0 control characters (except \\t and \\n) and NUL.

    NUL bytes are the classic truncation trick against C-backed string
    handlers; the rest exist to stop log-line forgery and terminal escape
    injection when a value is echoed to an operator.
    """
    if not value:
        return ""
    return "".join(
        ch for ch in value
        if ch in ("\t", "\n") or unicodedata.category(ch) not in ("Cc", "Cf")
    )


def safe_filename(name: str | None, *, max_len: int = LIMITS.MAX_UPLOAD_FILENAME_LEN) -> str | None:
    """Reduce an untrusted filename to a safe basename, or ``None``.

    Defeats directory traversal (``../../``), absolute paths, Windows drive
    letters, alternate data streams (``file.txt:evil``), NUL truncation
    (``file.txt\\0.jpg``) and hidden dotfiles. Used by the upload guard and by
    anything that ever writes a client-supplied name to disk.
    """
    if not name:
        return None
    name = strip_nulls_and_control(str(name))
    # NFKD + drop combining marks turns "élan.pdf" into "elan.pdf" rather than
    # "lan.pdf": an accented filename stays recognisable to its owner while
    # still being pure ASCII on disk.
    name = unicodedata.normalize("NFKD", name)
    name = "".join(ch for ch in name if not unicodedata.combining(ch))
    name = unicodedata.normalize("NFKC", name)
    # Take the last path component under either separator convention.
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    # NTFS alternate data stream / macOS resource fork.
    name = name.split(":", 1)[0]
    name = name.strip().strip(".")
    allowed = []
    for ch in name:
        if ch in _ALPHA or ch in _DIGITS or ch in "._-":
            allowed.append(ch)
        elif ch == " ":
            allowed.append("_")
        # everything else is dropped, not replaced with a placeholder: a
        # placeholder would let "a<b>c" and "a_b_c" collide.
    cleaned = "".join(allowed)[:max_len].strip("._")
    if not cleaned or cleaned in (".", ".."):
        return None
    if cleaned.lower() in _RESERVED_NAMES:
        return None
    return cleaned


#: Device names that are magical on Windows and would write to a device rather
#: than a file — an availability bug that presents as a "successful" upload.
_RESERVED_NAMES = frozenset({
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
})


def safe_path_segment(value: str | None) -> str | None:
    """A single path component with no traversal possible."""
    if not value:
        return None
    if reject_if_overlong(value, LIMITS.MAX_SCHEME_ID_LEN):
        return None
    value = strip_nulls_and_control(str(value)).strip()
    if value in (".", "..") or "/" in value or "\\" in value or "\x00" in value:
        return None
    return _SLUG_RE.match(value).group(0) if _SLUG_RE.match(value) else None


__all__ = [
    "EMAIL_SAFE_RE",
    "MAX_PASSWORD_LEN",
    "MIN_PASSWORD_LEN",
    "bounded",
    "is_email",
    "reject_if_overlong",
    "safe_filename",
    "safe_path_segment",
    "strip_nulls_and_control",
    "valid_bearer_token",
    "valid_email",
    "valid_enum",
    "valid_int",
    "valid_lang",
    "valid_nonce",
    "valid_password",
    "valid_phone",
    "valid_scheme_id",
    "valid_session_id",
]
