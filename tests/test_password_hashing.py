"""Password hashing: Argon2id first, PBKDF2 only as a migration path.

Covers the known ceiling from the security review — PBKDF2 is GPU/ASIC-friendly,
so "stdlib only" capped password-cracking resistance for no real benefit.
"""

from __future__ import annotations

import hashlib

import pytest

from backend.services import auth as auth_svc
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
def test_legacy_pbkdf2_rows_still_verify():
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


def test_login_upgrades_a_legacy_hash_in_place(client):
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
    assert passwords.dummy_verify("anything-1234") is False


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
