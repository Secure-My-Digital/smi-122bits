# $Intent: F4 remediation — per-user Argon2id salt + domain separation from HKDF. $
#
# Problem: one fixed public constant was used as BOTH the Argon2id salt and the
# HKDF salt, identical for every user. That enables cross-user precomputation
# against Argon2id and reuses a single value across two KDFs (no domain
# separation).
#
# Fix (vaultless-compatible, so it stays deterministic with NO stored salt):
#   * Argon2id salt is derived PER USER from a non-secret user identifier and a
#     fixed application root, under an "argon2id-salt" domain tag -> unique per
#     user, stable across runs, nothing to store.
#   * The HKDF salt is derived under a DIFFERENT domain tag, so the two KDFs
#     never share a salt value.
#
# The application root below is PUBLIC (a salt is not a secret); it only needs
# to be fixed and app-specific. Salts derived here are 16 bytes.

import hashlib
import hmac

# Public, fixed, app-specific root (not a secret). Keep stable across releases.
APP_SALT_ROOT = bytes.fromhex('d9266e3cce2546b6a11f7e7d1fe6ae23')

_ARGON_TAG = b'smi|argon2id-salt|v1|'
_HKDF_TAG = b'smi|hkdf-salt|v1'
SALT_LEN = 16


def _derive(tag: bytes, data: bytes = b'', n: int = SALT_LEN) -> bytes:
    return hmac.new(APP_SALT_ROOT, tag + data, hashlib.sha256).digest()[:n]


def argon2_salt(user_id: str) -> bytes:
    """Per-user Argon2id salt: unique per user, deterministic, unstored."""
    if not user_id:
        raise ValueError("user_id required for a per-user salt")
    return _derive(_ARGON_TAG, user_id.encode('utf-8'))


def hkdf_salt() -> bytes:
    """HKDF salt under a distinct domain (never equals an Argon2id salt)."""
    return _derive(_HKDF_TAG)
