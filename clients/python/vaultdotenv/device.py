"""Device secret management — read/write ~/.vault/<projectId>.key"""
from __future__ import annotations

import os
import platform
import stat
from pathlib import Path

import httpx

from vaultdotenv.crypto import (
    generate_device_secret,
    hash_device_secret,
    parse_vault_key,
    sign,
)

DEVICE_DIR = Path.home() / ".vault"


def get_device_key_path(project_id: str) -> Path:
    return DEVICE_DIR / f"{project_id}.key"


def load_device_secret(project_id: str) -> str | None:
    """Load device secret from env var or ~/.vault/<projectId>.key"""
    env_secret = os.environ.get("VAULT_DEVICE_SECRET")
    if env_secret:
        return env_secret

    key_path = get_device_key_path(project_id)
    if not key_path.exists():
        return None
    return key_path.read_text().strip()


def save_device_secret(project_id: str, device_secret: str) -> None:
    """Save device secret to ~/.vault/<projectId>.key with 0600 permissions."""
    DEVICE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    key_path = get_device_key_path(project_id)
    key_path.write_text(device_secret + "\n")
    key_path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def register_device(
    vault_key: str,
    vault_url: str = "https://api.vaultdotenv.io",
    device_name: str | None = None,
) -> dict:
    """Register this device with the vault server. Returns {device_id, device_secret, status}."""
    parsed = parse_vault_key(vault_key)
    if not parsed:
        raise ValueError("Invalid VAULT_KEY format")

    device_secret = generate_device_secret()
    device_hash = hash_device_secret(device_secret)

    import json
    body = json.dumps({
        "project_id": parsed["project_id"],
        "device_name": device_name or platform.node(),
        "device_hash": device_hash,
    })

    signature = sign(vault_key, body)

    resp = httpx.post(
        f"{vault_url}/api/v1/devices/register",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Vault-Signature": signature,
        },
    )

    if not resp.is_success:
        raise RuntimeError(f"Device registration failed ({resp.status_code}): {resp.text}")

    data = resp.json()
    save_device_secret(parsed["project_id"], device_secret)

    return {"device_id": data["device_id"], "device_secret": device_secret, "status": data["status"]}
