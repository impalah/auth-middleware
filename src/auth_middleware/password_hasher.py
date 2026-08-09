"""Password hashing for Basic Auth credential storage.

Uses PBKDF2-HMAC-SHA256 (stdlib, no extra dependency) with a random salt
and a configurable iteration count, in a self-describing storage format:
``pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>``.

Storing the iteration count alongside each hash means the work factor can
be raised over time (by changing ``DEFAULT_ITERATIONS``) without breaking
verification of hashes created with an older, lower count.
"""

import hashlib
import hmac
import secrets

_ALGORITHM = "pbkdf2_sha256"
_SALT_BYTES = 16

#: OWASP's 2023 minimum recommendation for PBKDF2-HMAC-SHA256.
DEFAULT_ITERATIONS = 600_000


def hash_password(password: str, *, iterations: int = DEFAULT_ITERATIONS) -> str:
    """Hash a password for storage as ``UserCredentials.hashed_password``.

    Args:
        password: The plaintext password to hash.
        iterations: PBKDF2 iteration count. Defaults to
            :data:`DEFAULT_ITERATIONS`.

    Returns:
        str: A self-describing hash string safe to store and later pass to
        :func:`verify_password`.
    """
    salt = secrets.token_bytes(_SALT_BYTES)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"{_ALGORITHM}${iterations}${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Verify a plaintext password against a stored hash.

    Supports hashes produced by :func:`hash_password`. For backward
    compatibility with credentials created before this module existed,
    also accepts a legacy raw SHA-256 hex digest (unsalted) — though any
    new credentials should always be created with :func:`hash_password`.

    Args:
        password: The plaintext password to check.
        stored: The stored hash, in either format.

    Returns:
        bool: True if the password matches, False otherwise.
    """
    parts = stored.split("$")
    if len(parts) == 4 and parts[0] == _ALGORITHM:
        _, iterations_str, salt_hex, hash_hex = parts
        try:
            iterations = int(iterations_str)
            salt = bytes.fromhex(salt_hex)
        except ValueError:
            return False
        derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
        return hmac.compare_digest(derived.hex(), hash_hex)

    # Legacy format: unsalted raw SHA-256 hex digest.
    legacy_hash = hashlib.sha256(password.encode()).hexdigest()
    return hmac.compare_digest(legacy_hash, stored)
