"""Vault-env cryptographic primitives — matches the Node.js implementation exactly."""
from __future__ import annotations

import hashlib
import hmac
import os
import time
from base64 import b64decode, b64encode
from typing import Optional, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

SALT_ENCRYPT = b"vault-encrypt-v1"
SALT_AUTH = b"vault-auth-v1"
IV_LENGTH = 12
TAG_LENGTH = 16


def derive_key(vault_key: str, salt: str | bytes, device_secret: str | None = None) -> bytes:
    """Derive a 256-bit key using HKDF. Matches Node.js deriveKey() exactly."""
    if isinstance(salt, str):
        salt = salt.encode()

    if device_secret:
        ikm = hmac.new(vault_key.encode(), device_secret.encode(), hashlib.sha256).digest()
    else:
        ikm = vault_key.encode()

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"",
    ).derive(ikm)


def encrypt(plaintext: str, vault_key: str, device_secret: str | None = None) -> str:
    """AES-256-GCM encrypt. Returns base64(iv + tag + ciphertext)."""
    key = derive_key(vault_key, SALT_ENCRYPT, device_secret)
    iv = os.urandom(IV_LENGTH)
    aesgcm = AESGCM(key)
    # AESGCM.encrypt returns ciphertext + tag (tag is last 16 bytes)
    ct_with_tag = aesgcm.encrypt(iv, plaintext.encode(), None)
    # Split: ciphertext is everything except last 16 bytes, tag is last 16
    ciphertext = ct_with_tag[:-TAG_LENGTH]
    tag = ct_with_tag[-TAG_LENGTH:]
    # Pack as: iv + tag + ciphertext (matches Node.js format)
    packed = iv + tag + ciphertext
    return b64encode(packed).decode()


def decrypt(encrypted_b64: str, vault_key: str, device_secret: str | None = None) -> str:
    """AES-256-GCM decrypt from base64(iv + tag + ciphertext)."""
    key = derive_key(vault_key, SALT_ENCRYPT, device_secret)
    packed = b64decode(encrypted_b64)
    iv = packed[:IV_LENGTH]
    tag = packed[IV_LENGTH : IV_LENGTH + TAG_LENGTH]
    ciphertext = packed[IV_LENGTH + TAG_LENGTH :]
    aesgcm = AESGCM(key)
    # AESGCM.decrypt expects ciphertext + tag concatenated
    plaintext = aesgcm.decrypt(iv, ciphertext + tag, None)
    return plaintext.decode()


def sign(vault_key: str, body: str, device_secret: str | None = None) -> str:
    """HMAC-SHA256 signature for API auth. Returns 'v=<timestamp>,d=<hex digest>'."""
    auth_key = derive_key(vault_key, SALT_AUTH, device_secret)
    timestamp = str(int(time.time() * 1000))
    message = (body + timestamp).encode()
    digest = hmac.new(auth_key, message, hashlib.sha256).hexdigest()
    return f"v={timestamp},d={digest}"


def parse_vault_key(vault_key: str) -> dict | None:
    """Parse vk_<projectId>_<secret> into components."""
    if not vault_key or not vault_key.startswith("vk_"):
        return None
    parts = vault_key.split("_", 2)
    if len(parts) < 3:
        return None
    return {"project_id": parts[1], "secret": parts[2]}


def generate_device_secret() -> str:
    """Generate a random 32-byte hex device secret."""
    return os.urandom(32).hex()


def hash_device_secret(device_secret: str) -> str:
    """SHA-256 hash of device secret for server storage."""
    return hashlib.sha256(device_secret.encode()).hexdigest()
