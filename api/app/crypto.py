# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2024-2026 shdw <contact@resurgamus.com>
"""Settings encryption — Fernet (AES-128-CBC + HMAC-SHA256).

Encrypts sensitive values stored in alert_settings (tokens, passwords).
Key derived from TOKEN_HMAC_KEY via HKDF-SHA256.

Usage:
    from .crypto import encrypt_setting, decrypt_setting
    cipher = encrypt_setting("my-secret-token")
    plain  = decrypt_setting(cipher)
"""

import base64
import logging

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger(__name__)

_fernet: Fernet | None = None

# Prefix to distinguish encrypted values from plaintext (migration)
ENC_PREFIX = "enc:"


def _get_fernet() -> Fernet:
    """Lazy-init Fernet from TOKEN_HMAC_KEY."""
    global _fernet
    if _fernet is None:
        from .config import settings

        raw_key = settings.token_hmac_key.encode()
        # Derive a 32-byte key via HKDF (Fernet needs url-safe base64 of 32 bytes)
        derived = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=b"cmdb-settings-encryption",
            info=b"fernet-key",
        ).derive(raw_key)
        _fernet = Fernet(base64.urlsafe_b64encode(derived))
    return _fernet


def encrypt_setting(value: str) -> str:
    """Encrypt a setting value. Returns 'enc:<base64>' string."""
    if not value or value == "********":
        return ""
    token = _get_fernet().encrypt(value.encode())
    return ENC_PREFIX + token.decode()


def decrypt_setting(stored: str) -> str:
    """Decrypt a setting value. Handles both encrypted and legacy plaintext.

    - 'enc:...' → decrypt
    - plaintext  → return as-is (not yet migrated)
    """
    if not stored or not stored.startswith(ENC_PREFIX):
        return stored
    try:
        return _get_fernet().decrypt(stored[len(ENC_PREFIX) :].encode()).decode()
    except InvalidToken:
        logger.warning("Failed to decrypt setting — TOKEN_HMAC_KEY may have changed")
        return ""


def encrypt_auth_config(d: dict | None) -> dict:
    """Encrypt every string value of an auth-config dict (per-value enc:).

    Non-string values pass through untouched. Empty strings stay empty.
    Keeps the JSONB shape so the column type is unchanged.
    """
    if not d:
        return {}
    return {
        k: encrypt_setting(v) if isinstance(v, str) and v else v for k, v in d.items()
    }


def decrypt_auth_config(d: dict | None) -> dict:
    """Inverse of encrypt_auth_config. Legacy plaintext values pass through."""
    if not d:
        return {}
    return {k: decrypt_setting(v) if isinstance(v, str) else v for k, v in d.items()}
