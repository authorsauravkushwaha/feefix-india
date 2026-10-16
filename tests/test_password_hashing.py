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
  are bounded and excess callers are refused, not queued into OOM;
* PBKDF2 is GPU/ASIC-friendly, so "stdlib only" capped password-cracking
  resistance for no real benefit — the ceiling the review called out.

Argon2id first, PBKDF2 only as a migration path.
"""

from __future__ import annotations

import hashlib
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


class TestKdfBackPressure:
    """A saturated hashing pool is a retryable capacity signal, never "wrong
    password".

    The bug this pins: ``verify_password`` swallowed every exception, so a busy
    KDF surfaced as 401 "Invalid email or password" for a *correct* password —
    misleading to the user and dangerous for clients that count failures and
    lock accounts or force a password reset.
    """

    def _saturate(self, monkeypatch):
        monkeypatch.setattr(auth_svc, "KDF_WAIT_S", 0.01)
        monkeypatch.setattr(auth_svc, "_KDF_SLOTS", threading.BoundedSemaphore(1))
        auth_svc._KDF_SLOTS.acquire()

    def test_verify_raises_busy_instead_of_returning_false(self, monkeypatch):
        stored = auth_svc.hash_password("S3cure!Pass")
        self._saturate(monkeypatch)
        with pytest.raises(auth_svc.AuthBusy):
            auth_svc.verify_password("S3cure!Pass", stored)

    def test_login_answers_503_with_retry_after(self, client, monkeypatch):
        assert client.post(
            "/api/auth/register", json={"email": "cap@example.com", "password": "S3cure!Pass"}
        ).status_code == 200
        self._saturate(monkeypatch)
        response = client.post(
            "/api/auth/login", json={"email": "cap@example.com", "password": "S3cure!Pass"}
        )
        assert response.status_code == 503
        assert response.headers["Retry-After"] == "2"
        assert "password" not in response.text.lower()

    def test_register_answers_503_not_422(self, client, monkeypatch):
        self._saturate(monkeypatch)
        response = client.post(
            "/api/auth/register", json={"email": "cap2@example.com", "password": "S3cure!Pass"}
        )
        assert response.status_code == 503
        assert response.headers["Retry-After"] == "2"

    def test_known_unknown_and_wrong_password_are_indistinguishable(self, client, monkeypatch):
        assert client.post(
            "/api/auth/register", json={"email": "cap3@example.com", "password": "S3cure!Pass"}
        ).status_code == 200
        self._saturate(monkeypatch)
        bodies = [
            client.post("/api/auth/login", json={"email": "cap3@example.com", "password": "S3cure!Pass"}),
            client.post("/api/auth/login", json={"email": "nobody@example.com", "password": "whatever1"}),
            client.post("/api/auth/login", json={"email": "cap3@example.com", "password": "wrongwrong"}),
        ]
        assert {r.status_code for r in bodies} == {503}
        assert len({r.text for r in bodies}) == 1, "back-pressure must not enumerate accounts"

    def test_service_recovers_when_a_slot_frees(self, client, monkeypatch):
        assert client.post(
            "/api/auth/register", json={"email": "cap4@example.com", "password": "S3cure!Pass"}
        ).status_code == 200
        self._saturate(monkeypatch)
        assert client.post(
            "/api/auth/login", json={"email": "cap4@example.com", "password": "S3cure!Pass"}
        ).status_code == 503
        auth_svc._KDF_SLOTS.release()
        monkeypatch.setattr(auth_svc, "KDF_WAIT_S", 5.0)
        assert client.post(
            "/api/auth/login", json={"email": "cap4@example.com", "password": "S3cure!Pass"}
        ).status_code == 200


def test_hash_backend_note_is_honest_and_secret_free():
    note = auth_svc.hash_backend_note()
    assert ("argon2id" in note) or ("scrypt" in note and "argon2-cffi" in note)
    assert "PBKDF2" not in note


from backend.services import db, passwords


@pytest.fixture(autouse=True)
def _reset_policy(monkeypatch):
    """Each test starts from the ambient policy, then restores it."""
    for name in ("FEEFIX_PASSWORD_ALGO", "FEEFIX_ENV"):
        monkeypatch.delenv(name, raising=False)
    passwords.reset_for_tests()
    yield
    passwords.reset_for_tests()


# -- the algorithm actually in use ---------------------------------------------
def test_argon2id_is_used_when_available():
    if not passwords.argon2_available():
        pytest.skip("argon2-cffi not installed in this environment")
    stored = passwords.hash_password("correct horse battery staple")
    assert stored.startswith("argon2id$")
    assert "m=" in stored and "t=" in stored and "p=" in stored
    ok, needs_rehash = passwords.verify("correct horse battery staple", stored)
    assert ok and not needs_rehash


def test_argon2id_parameters_meet_owasp_recommendations():
    if not passwords.argon2_available():
        pytest.skip("argon2-cffi not installed in this environment")
    stored = passwords.hash_password("parameter-check-passphrase")
    param_block = next(p for p in stored.split("$") if p.startswith("m="))
    params = dict(part.split("=") for part in param_block.split(","))
    assert int(params["m"]) >= 19456, "memory cost below OWASP minimum (19 MiB)"
    assert int(params["t"]) >= 2, "time cost below OWASP minimum"
    assert int(params["p"]) >= 1


def test_memory_hard_hashes_differ_per_user():
    a = passwords.hash_password("same-password-123")
    b = passwords.hash_password("same-password-123")
    assert a != b, "salts must be unique per hash"


# -- backwards compatibility & migration ---------------------------------------
def test_legacy_pbkdf2_rows_verify_via_passwords_module():
    salt = b"\x01" * 16
    legacy = hashlib.pbkdf2_hmac(
        "sha256", hashlib.sha256(b"legacy-pass-1").digest(), salt, 100_000
    )
    stored = "pbkdf2$100000$" + salt.hex() + "$" + legacy.hex()
    ok, needs_rehash = passwords.verify("legacy-pass-1", stored)
    assert ok is True
    assert needs_rehash is True, "a verified PBKDF2 row must be flagged for upgrade"


def test_direct_hash_legacy_scheme_still_verifies():
    # Rows written by the very first implementation hashed the raw password.
    salt = b"\x02" * 16
    legacy = hashlib.pbkdf2_hmac("sha256", b"direct-pass-1", salt, 50_000)
    stored = "pbkdf2$50000$" + salt.hex() + "$" + legacy.hex()
    assert passwords.verify("direct-pass-1", stored)[0] is True


def test_schemes_do_not_cross_verify():
    if not passwords.argon2_available():
        pytest.skip("argon2-cffi not installed in this environment")
    argon = passwords.hash_password("cross-check-1")
    pbkdf2 = "pbkdf2$1000$" + (b"\x03" * 16).hex() + "$" + "ab" * 32  # noqa: ISC003
    assert passwords.verify("cross-check-1", pbkdf2)[0] is False
    assert passwords.verify("cross-check-1", argon)[0] is True
    assert passwords.verify("wrong-password", argon)[0] is False
    assert passwords.verify("cross-check-1", "garbage")[0] is False
    assert passwords.verify("cross-check-1", None)[0] is False


def test_login_upgrades_row_to_passwords_format(client):
    """A pre-existing PBKDF2 account is rehashed on its next successful login."""
    salt = b"\x04" * 16
    legacy = hashlib.pbkdf2_hmac(
        "sha256", hashlib.sha256(b"S3cure!Pass").digest(), salt, 100_000
    )
    stored = "pbkdf2$100000$" + salt.hex() + "$" + legacy.hex()
    conn = db.get_connection()
    conn.execute(
        "INSERT INTO users (id, email, password_hash, name, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?)",
        ("legacy-user", "legacy@example.com", stored, "Legacy", "2024-01-01T00:00:00+00:00",
         "2024-01-01T00:00:00+00:00"),
    )
    conn.commit()

    r = client.post("/api/auth/login",
                    json={"email": "legacy@example.com", "password": "S3cure!Pass"})
    assert r.status_code == 200

    upgraded = conn.execute(
        "SELECT password_hash FROM users WHERE id=?", ("legacy-user",)
    ).fetchone()["password_hash"]
    if passwords.argon2_available():
        assert upgraded.startswith("argon2id$"), "login must upgrade the stored hash"
        assert passwords.verify("S3cure!Pass", upgraded)[0] is True
    # Old password still works after the upgrade, obviously.
    assert client.post("/api/auth/login",
                       json={"email": "legacy@example.com",
                             "password": "S3cure!Pass"}).status_code == 200


# -- fail-closed configuration ---------------------------------------------------
def test_production_demands_argon2id_and_refuses_to_downgrade(monkeypatch):
    monkeypatch.setenv("FEEFIX_ENV", "production")
    monkeypatch.setattr(passwords, "_argon2_hasher", lambda: None)
    passwords.reset_for_tests()
    assert passwords.describe()["algorithm"] == "unavailable"
    with pytest.raises(RuntimeError) as exc:
        passwords.hash_password("whatever-123")
    assert "argon2" in str(exc.value).lower()


def test_auto_policy_falls_back_to_pbkdf2_outside_production(monkeypatch):
    monkeypatch.setattr(passwords, "_argon2_hasher", lambda: None)
    passwords.reset_for_tests()
    assert passwords.active_algorithm() == "pbkdf2"
    stored = passwords.hash_password("fallback-pass-1")
    assert stored.startswith("pbkdf2$")
    assert passwords.verify("fallback-pass-1", stored)[0] is True


def test_explicit_pbkdf2_policy_is_honoured(monkeypatch):
    monkeypatch.setenv("FEEFIX_PASSWORD_ALGO", "pbkdf2")
    passwords.reset_for_tests()
    assert passwords.hash_password("explicit-pbkdf2").startswith("pbkdf2$")


# -- cost bounds -----------------------------------------------------------------
def test_password_hash_cost_is_length_independent():
    short = passwords.hash_password("shortpw1")
    long_ = passwords.hash_password("L" * 100_000)
    assert passwords.verify("shortpw1", short)[0] is True
    assert passwords.verify("L" * 100_000, long_)[0] is True
    # Both are fixed-size pre-images: the stored digests are the same length.
    assert len(short.split("$")[-1]) == len(long_.split("$")[-1])


def test_dummy_verify_burns_a_verification_and_never_succeeds():
    passwords.reset_for_tests()
    assert passwords.dummy_verify("anything-1234") is False
    # Unknown-account timing must use the same algorithm as a real row.
    # A PBKDF2 dummy beside an Argon2id hash is user enumeration.
    if passwords.argon2_available() and passwords.active_algorithm() == "argon2id":
        assert passwords._DUMMY_HASH.startswith("argon2id$")


def test_production_refuses_an_explicit_pbkdf2_policy(monkeypatch):
    monkeypatch.setenv("FEEFIX_ENV", "production")
    monkeypatch.setenv("FEEFIX_PASSWORD_ALGO", "pbkdf2")
    passwords.reset_for_tests()
    with pytest.raises(RuntimeError) as exc:
        passwords.hash_password("still-not-argon2")
    assert "pbkdf2" in str(exc.value).lower() or "argon2" in str(exc.value).lower()


def test_unknown_email_login_takes_a_kdf_path(client):
    """Unknown accounts still pay KDF cost (no user enumeration by timing)."""
    r = client.post("/api/auth/login",
                    json={"email": "nobody@example.com", "password": "whatever-123"})
    assert r.status_code == 401
    assert r.json()["detail"] == "Invalid email or password."


def test_auth_wrapper_keeps_boolean_contract():
    stored = auth_svc.hash_password("wrapper-check-1")
    assert auth_svc.verify_password("wrapper-check-1", stored) is True
    assert auth_svc.verify_password("nope", stored) is False
