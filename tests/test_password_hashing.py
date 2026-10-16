"""Password hashing: Argon2id by default, memory-hard, and *provably* upgrading.

The previous scheme was PBKDF2-HMAC-SHA256 at 600k iterations — OWASP-acceptable
but CPU-cheap to parallelise on GPUs/ASICs, and chosen only because of a
stdlib-only rule. These tests pin the replacements:

* new hashes are Argon2id (memory-hard) whenever ``argon2-cffi`` is installed;
* the remembered parameters are strong (time and memory cost, not just length);
* legacy PBKDF2 rows still verify and are **re-hashed on the next login**, so the
  weak scheme drains out of a live database without locking anyone out;
* the scrypt fallback is memory-hard too (never a silent downgrade to PBKDF2);
* the memory cost cannot be turned into a memory-exhaustion DoS: concurrent KDFs
  are bounded and excess callers are refused, not queued into OOM.
"""

from __future__ import annotations

import threading

import pytest

from backend.services import auth as auth_svc


def _argon2_installed() -> bool:
    return auth_svc.hash_backend() == "argon2id"


def test_new_passwords_use_argon2id_or_the_memory_hard_fallback():
    stored = auth_svc.hash_password("S3cure!Pass")
    if _argon2_installed():
        assert stored.startswith("$argon2id$"), stored[:16]
    else:  # pragma: no cover - depends on the environment
        assert stored.startswith("scrypt$")
    assert not stored.startswith("pbkdf2$"), "PBKDF2 must never hash a new password"
    assert auth_svc.verify_password("S3cure!Pass", stored)
    assert not auth_svc.verify_password("wrong-password", stored)


def test_argon2_parameters_are_recorded_in_the_hash():
    stored = auth_svc.hash_password("S3cure!Pass")
    if not _argon2_installed():  # pragma: no cover - environment-dependent
        pytest.skip("argon2-cffi not installed")
    # PHC string carries m=<memory in KiB>, t=<time cost>, p=<parallelism>.
    assert f"m={auth_svc.ARGON2_MEMORY_KIB}" in stored
    assert f"t={auth_svc.ARGON2_TIME_COST}" in stored
    assert auth_svc.ARGON2_MEMORY_KIB >= 19 * 1024, "OWASP floor is 19 MiB"
    assert auth_svc.ARGON2_TIME_COST >= 2


def test_salt_is_unique_per_hash():
    a = auth_svc.hash_password("same-password-here")
    b = auth_svc.hash_password("same-password-here")
    assert a != b, "identical passwords must not produce identical hashes"
    assert auth_svc.verify_password("same-password-here", a)
    assert auth_svc.verify_password("same-password-here", b)


def test_kdf_cost_is_length_independent():
    # Pre-hashing keeps the KDF cost constant even for a 100k-character input.
    short = auth_svc.hash_password("shortpw1")
    long_ = auth_svc.hash_password("L" * 100_000)
    assert auth_svc.verify_password("shortpw1", short)
    assert auth_svc.verify_password("L" * 100_000, long_)


def test_legacy_pbkdf2_rows_still_verify():
    legacy = auth_svc.legacy_pbkdf2_hash("S3cure!Pass")
    assert legacy.startswith("pbkdf2$")
    assert auth_svc.verify_password("S3cure!Pass", legacy)
    assert not auth_svc.verify_password("wrong-password", legacy)
    assert auth_svc.needs_rehash(legacy) is True


def test_login_upgrades_a_legacy_hash_in_place(client, tmp_path):
    from backend.services import db

    email, password = "legacy@example.com", "S3cure!Pass"
    assert client.post(
        "/api/auth/register", json={"email": email, "password": password}
    ).status_code == 200

    # Rewrite the row to the old format, exactly like a pre-upgrade database.
    legacy = auth_svc.legacy_pbkdf2_hash(password)
    conn = db.get_connection()
    conn.execute("UPDATE users SET password_hash=? WHERE email=?", (legacy, email))
    conn.commit()
    assert conn.execute(
        "SELECT password_hash FROM users WHERE email=?", (email,)
    ).fetchone()[0].startswith("pbkdf2$")

    assert client.post(
        "/api/auth/login", json={"email": email, "password": password}
    ).status_code == 200

    upgraded = conn.execute(
        "SELECT password_hash FROM users WHERE email=?", (email,)
    ).fetchone()[0]
    assert not upgraded.startswith("pbkdf2$"), "legacy hashes must be upgraded on login"
    assert auth_svc.verify_password(password, upgraded)
    # The upgrade is auditable, and the plaintext never appears anywhere.
    actions = [r[0] for r in conn.execute("SELECT action FROM audit_log").fetchall()]
    assert "auth.password_hash_upgraded" in actions
    assert password.encode() not in (tmp_path / "test.db").read_bytes()


def test_scrypt_fallback_is_memory_hard_and_not_pbkdf2(monkeypatch):
    monkeypatch.setattr(auth_svc, "_argon2_available", lambda: False)
    stored = auth_svc.hash_password("S3cure!Pass")
    assert stored.startswith("scrypt$")
    assert auth_svc.SCRYPT_N >= 2 ** 14, "scrypt N must be memory-hard (>=16 MiB)"
    assert auth_svc.verify_password("S3cure!Pass", stored)
    assert not auth_svc.verify_password("nope-nope-nope", stored)
    assert "pbkdf2" not in stored


def test_unknown_scheme_and_garbage_fail_closed():
    assert auth_svc.verify_password("x", "") is False
    assert auth_svc.verify_password("x", "md5$deadbeef") is False
    assert auth_svc.verify_password("x", "pbkdf2$not-an-int$a$b") is False
    assert auth_svc.verify_password("x", "$argon2id$broken") is False


def test_concurrent_kdf_work_is_bounded(monkeypatch):
    """Memory-hard hashing must not be turnable into a RAM-exhaustion DoS."""
    monkeypatch.setattr(auth_svc, "KDF_WAIT_S", 0.05)
    monkeypatch.setattr(auth_svc, "_KDF_SLOTS", threading.BoundedSemaphore(1))
    started = threading.Event()
    release = threading.Event()

    def hold():
        auth_svc._kdf_slot()
        started.set()
        release.wait(timeout=5)
        auth_svc._kdf_release()

    holder = threading.Thread(target=hold, daemon=True)
    holder.start()
    assert started.wait(timeout=5)

    with pytest.raises(auth_svc.AuthBusy):
        auth_svc.hash_password("S3cure!Pass")

    release.set()
    holder.join(timeout=5)


def test_hash_backend_note_is_honest_and_secret_free():
    note = auth_svc.hash_backend_note()
    assert ("argon2id" in note) or ("scrypt" in note and "argon2-cffi" in note)
    assert "PBKDF2" not in note
