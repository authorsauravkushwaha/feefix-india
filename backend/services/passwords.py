"""Password hashing — Argon2id by default, PBKDF2 only as a migration path.

Why this module exists
----------------------
The previous implementation was PBKDF2-HMAC-SHA256 only, justified by a
"standard library only" rule. 600k iterations is OWASP-acceptable, but PBKDF2 is
*CPU-cheap to parallelise*: a GPU/ASIC attacker gets a large multiplier, and the
rule bought nothing except a self-imposed ceiling on cracking resistance.

Argon2id is memory-hard, so parallel hardware buys the attacker far less. This
module therefore:

* **Uses Argon2id** (``argon2-cffi``) with OWASP-recommended parameters —
  ``m=19456 KiB`` (19 MiB), ``t=2``, ``p=1``, 32-byte tag, 16-byte salt.
* **Migrates transparently.** Legacy ``pbkdf2$…`` rows still verify, and
  :func:`verify` reports ``needs_rehash=True`` so the caller can upgrade the
  stored hash on the next successful sign-in. Nothing breaks; nothing stays
  weak for users who log in again.
* **Fails closed when it matters.** ``FEEFIX_PASSWORD_ALGO=argon2id`` (the
  default when ``FEEFIX_ENV=production``) makes a deployment without
  ``argon2-cffi`` refuse to start rather than silently downgrade to PBKDF2.
  ``auto`` keeps local/dev/CI usable without the wheel.
* **Keeps the long-password DoS defence.** Both algorithms hash a fixed-size
  SHA-256 pre-image, so KDF cost is independent of password length; the password
  is length-capped earlier (``services/limits.py``).

Stored formats (single column, prefix-discriminated)::

    argon2id$argon2id$v=19$m=19456,t=2,p=1$<salt-b64>$<tag-b64>
    pbkdf2$600000$<salt-hex>$<digest-hex>          # legacy, verified then upgraded
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets

log = logging.getLogger("feefix.passwords")

# -- policy ------------------------------------------------------------------- #
PBKDF2_ITERATIONS = int(os.environ.get("FEEFIX_PBKDF2_ITERATIONS", "600000") or 600000)
ARGON2_TIME_COST = int(os.environ.get("FEEFIX_ARGON2_TIME_COST", "2") or 2)
ARGON2_MEMORY_KIB = int(os.environ.get("FEEFIX_ARGON2_MEMORY_KIB", "19456") or 19456)
ARGON2_PARALLELISM = int(os.environ.get("FEEFIX_ARGON2_PARALLELISM", "1") or 1)
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 16

ARGON2_PREFIX = "argon2id$"
PBKDF2_PREFIX = "pbkdf2$"


def _policy() -> str:
    """``argon2id`` (require it), ``pbkdf2`` (legacy), or ``auto`` (best available).

    An explicit ``FEEFIX_PASSWORD_ALGO`` always wins. Otherwise production
    demands Argon2id while other environments accept whatever is installed.
    """
    raw = (os.environ.get("FEEFIX_PASSWORD_ALGO") or "").strip().lower()
    if raw in ("argon2", "argon2id"):
        return "argon2id"
    if raw in ("pbkdf2", "pbkdf2_sha256"):
        return "pbkdf2"
    if raw not in ("", "auto"):
        log.warning("[passwords] unknown FEEFIX_PASSWORD_ALGO=%r — using auto", raw)
    if (os.environ.get("FEEFIX_ENV") or "").strip().lower() in ("prod", "production"):
        return "argon2id"
    return "auto"


def _argon2_hasher():  # noqa: ANN202 - argon2 type is optional at import time
    try:
        from argon2 import PasswordHasher
    except ImportError:
        return None
    return PasswordHasher(
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        salt_len=ARGON2_SALT_LEN,
    )


_HASHER = None
_HASHER_RESOLVED = False


def _hasher():  # noqa: ANN202
    global _HASHER, _HASHER_RESOLVED
    if not _HASHER_RESOLVED:
        _HASHER = _argon2_hasher()
        _HASHER_RESOLVED = True
    return _HASHER


def argon2_available() -> bool:
    return _hasher() is not None


def _is_production() -> bool:
    return (os.environ.get("FEEFIX_ENV") or "").strip().lower() in ("prod", "production")


def active_algorithm() -> str:
    """The algorithm new passwords are hashed with right now."""
    policy = _policy()
    if policy == "pbkdf2":
        if _is_production():
            raise RuntimeError(
                "FEEFIX_ENV=production cannot hash passwords with PBKDF2. "
                "Set FEEFIX_PASSWORD_ALGO=argon2id and install argon2-cffi. "
                "A CPU-cheap KDF is not an acceptable production default."
            )
        return "pbkdf2"
    if _hasher() is not None:
        return "argon2id"
    if policy == "argon2id":
        raise RuntimeError(
            "FEEFIX_PASSWORD_ALGO=argon2id (or FEEFIX_ENV=production) but 'argon2-cffi' "
            "is not installed. Install it (pip install 'argon2-cffi>=23.1') — refusing to "
            "silently downgrade password hashing to PBKDF2."
        )
    return "pbkdf2"


def describe() -> dict:
    """Non-secret description of the active policy (boot log / ``/api/meta``)."""
    try:
        algo = active_algorithm()
    except RuntimeError as exc:  # pragma: no cover - misconfiguration path
        return {"algorithm": "unavailable", "error": str(exc), "argon2_available": False}
    params: dict = {"algorithm": algo, "policy": _policy(), "argon2_available": argon2_available()}
    if algo == "argon2id":
        params |= {
            "memory_kib": ARGON2_MEMORY_KIB,
            "time_cost": ARGON2_TIME_COST,
            "parallelism": ARGON2_PARALLELISM,
        }
    else:
        params |= {"iterations": PBKDF2_ITERATIONS}
    return params


# -- primitives ---------------------------------------------------------------- #
def _prehash(password: str) -> bytes:
    """Fixed-size pre-image so KDF cost is independent of password length.

    A 100 MB "password" would otherwise force the KDF to chew megabytes on every
    pass — a trivial CPU-exhaustion DoS (see ``services/limits.py`` too).
    """
    return hashlib.sha256(password.encode("utf-8")).digest()


def _hash_argon2id(preimage: bytes) -> str:
    hasher = _hasher()
    if hasher is None:  # pragma: no cover - guarded by active_algorithm()
        raise RuntimeError("argon2-cffi is not installed")
    encoded = hasher.hash(preimage)
    return ARGON2_PREFIX + encoded.lstrip("$")


def _hash_pbkdf2(preimage: bytes) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", preimage, salt, PBKDF2_ITERATIONS)
    return f"{PBKDF2_PREFIX}{PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def hash_password(password: str) -> str:
    """Hash a password with the active algorithm."""
    preimage = _prehash(password)
    return _hash_argon2id(preimage) if active_algorithm() == "argon2id" else _hash_pbkdf2(preimage)


# -- verification -------------------------------------------------------------- #
def _verify_argon2id(preimage: bytes, stored: str) -> tuple[bool, bool]:
    hasher = _hasher()
    if hasher is None:
        # A row hashed with Argon2id cannot be verified without the library.
        # This is a configuration error, not a wrong password.
        log.error("[passwords] argon2-cffi missing — cannot verify an Argon2id row")
        return False, False
    encoded = "$" + stored[len(ARGON2_PREFIX):]
    from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

    try:
        hasher.verify(encoded, preimage)
    except VerifyMismatchError:
        return False, False
    except (VerificationError, InvalidHashError):
        return False, False
    except Exception:  # noqa: BLE001 - never leak a hashing error to the caller
        return False, False
    try:
        needs = hasher.check_needs_rehash(encoded)
    except Exception:  # noqa: BLE001
        needs = False
    return True, bool(needs)


def _verify_pbkdf2(password: str, stored: str) -> tuple[bool, bool]:
    try:
        scheme, iterations, salt_hex, digest_hex = stored.split("$")
        if scheme != "pbkdf2":
            return False, False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        iters = int(iterations)
    except Exception:  # noqa: BLE001 - malformed row ⇒ not a valid password
        return False, False
    actual = hashlib.pbkdf2_hmac("sha256", _prehash(password), salt, iters)
    # Legacy rows hashed the raw password instead of the pre-image.
    legacy = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
    ok = hmac.compare_digest(actual, expected) or hmac.compare_digest(legacy, expected)
    # A verified PBKDF2 row should be upgraded to Argon2id on the next sign-in.
    return ok, ok


def verify(password: str, stored: str | None) -> tuple[bool, bool]:
    """Return ``(verified, needs_rehash)`` — never raises on a malformed row."""
    if not stored or not isinstance(stored, str):
        return False, False
    if stored.startswith(ARGON2_PREFIX):
        return _verify_argon2id(_prehash(password), stored)
    if stored.startswith("$argon2"):
        # Branch format: raw PHC with its leading "$" intact.
        return _verify_argon2id(_prehash(password), ARGON2_PREFIX + stored[1:])
    if stored.startswith(PBKDF2_PREFIX):
        return _verify_pbkdf2(password, stored)
    return False, False


def needs_rehash(stored: str | None) -> bool:
    """Whether a stored hash should be rewritten (scheme or parameters)."""
    if not stored or not isinstance(stored, str):
        return True
    if stored.startswith(PBKDF2_PREFIX):
        return True
    if stored.startswith(ARGON2_PREFIX):
        return verify("__rehash_probe__", stored)[1] or not _argon2_params_current(stored)
    return True


def _argon2_params_current(stored: str) -> bool:
    """Compare the encoded parameters against the configured ones."""
    try:
        params = stored.split("$")[2]
        parsed = {
            key: int(value)
            for key, value in (part.split("=") for part in params.split(","))
        }
    except Exception:  # noqa: BLE001
        return False
    return (
        parsed.get("m") == ARGON2_MEMORY_KIB
        and parsed.get("t") == ARGON2_TIME_COST
        and parsed.get("p") == ARGON2_PARALLELISM
    )


#: A dummy hash so unknown-email logins still pay the KDF cost (no enumeration
#: by timing) without hashing on every request.
_DUMMY_HASH: str | None = None


def dummy_verify(password: str) -> bool:
    """Burn one KDF verification for unknown accounts. Always returns False.

    The dummy row uses the *active* algorithm. A PBKDF2 dummy next to an
    Argon2id real hash is a timing oracle: unknown emails finish on a different
    curve than known ones, which is user enumeration by response time.
    """
    global _DUMMY_HASH
    algo = active_algorithm()
    prefix = ARGON2_PREFIX if algo == "argon2id" else PBKDF2_PREFIX
    if _DUMMY_HASH is None or not _DUMMY_HASH.startswith(prefix):
        preimage = hashlib.sha256(b"feefix-dummy").digest()
        _DUMMY_HASH = _hash_argon2id(preimage) if algo == "argon2id" else _hash_pbkdf2(preimage)
    verify(password, _DUMMY_HASH)
    return False


def reset_for_tests() -> None:
    global _DUMMY_HASH, _HASHER, _HASHER_RESOLVED
    _DUMMY_HASH = None
    _HASHER = None
    _HASHER_RESOLVED = False
