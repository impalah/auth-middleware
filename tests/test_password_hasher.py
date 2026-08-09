"""Tests for auth_middleware.password_hasher."""

import hashlib

from auth_middleware.password_hasher import hash_password, verify_password


class TestHashPassword:
    def test_returns_self_describing_format(self):
        hashed = hash_password("s3cret", iterations=1000)

        parts = hashed.split("$")
        assert len(parts) == 4
        assert parts[0] == "pbkdf2_sha256"
        assert parts[1] == "1000"

    def test_same_password_hashes_differently_each_time(self):
        # Random salt per call, even for the same password/iterations.
        a = hash_password("s3cret", iterations=1000)
        b = hash_password("s3cret", iterations=1000)

        assert a != b

    def test_uses_default_iterations_when_not_specified(self):
        from auth_middleware.password_hasher import DEFAULT_ITERATIONS

        hashed = hash_password("s3cret")
        assert hashed.split("$")[1] == str(DEFAULT_ITERATIONS)


class TestVerifyPassword:
    def test_verifies_correct_password(self):
        hashed = hash_password("s3cret", iterations=1000)
        assert verify_password("s3cret", hashed) is True

    def test_rejects_wrong_password(self):
        hashed = hash_password("s3cret", iterations=1000)
        assert verify_password("wrong-password", hashed) is False

    def test_rejects_empty_password_against_real_hash(self):
        hashed = hash_password("s3cret", iterations=1000)
        assert verify_password("", hashed) is False

    def test_verifies_with_stored_iteration_count_not_a_default(self):
        # The iteration count travels with the hash — verification must
        # use whatever count the hash itself specifies.
        hashed = hash_password("s3cret", iterations=333)
        assert verify_password("s3cret", hashed) is True

    def test_rejects_malformed_pbkdf2_hash(self):
        assert verify_password("s3cret", "pbkdf2_sha256$not-a-number$aa$bb") is False

    # --- Backward compatibility with the old unsalted SHA-256 format ---

    def test_accepts_legacy_unsalted_sha256_hash(self):
        legacy_hash = hashlib.sha256(b"s3cret").hexdigest()
        assert verify_password("s3cret", legacy_hash) is True

    def test_rejects_wrong_password_against_legacy_hash(self):
        legacy_hash = hashlib.sha256(b"s3cret").hexdigest()
        assert verify_password("wrong-password", legacy_hash) is False
