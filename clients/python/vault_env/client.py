"""Core vaultdotenv client — drop-in replacement for python-dotenv."""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import httpx

from vault_env.crypto import decrypt, encrypt, hash_device_secret, parse_vault_key, sign
from vault_env.device import load_device_secret

DEFAULT_VAULT_URL = "https://api.vaultdotenv.io"
CACHE_FILE = ".vault-cache"


def _parse_dotenv(content: str) -> dict[str, str]:
    """Parse a .env file into key-value pairs."""
    result = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip()
        if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
            val = val[1:-1]
        result[key] = val
    return result


def _load_cache(vault_key: str, cache_dir: Path, device_secret: str | None) -> dict | None:
    cache_path = cache_dir / CACHE_FILE
    if not cache_path.exists():
        return None
    try:
        encrypted = cache_path.read_text()
        decrypted = decrypt(encrypted, vault_key, device_secret)
        return json.loads(decrypted)
    except Exception:
        return None


def _save_cache(vault_key: str, secrets: dict, cache_dir: Path, device_secret: str | None) -> None:
    cache_path = cache_dir / CACHE_FILE
    encrypted = encrypt(json.dumps(secrets), vault_key, device_secret)
    cache_path.write_text(encrypted)


def pull_secrets(
    vault_key: str,
    environment: str = "development",
    vault_url: str = DEFAULT_VAULT_URL,
    device_secret: str | None = None,
) -> dict:
    """Pull secrets from the vault server. Returns {secrets: dict, version: int}."""
    parsed = parse_vault_key(vault_key)
    if not parsed:
        raise ValueError("Invalid VAULT_KEY format. Expected: vk_<projectId>_<secret>")

    if device_secret is None:
        device_secret = load_device_secret(parsed["project_id"])

    body_dict = {
        "project_id": parsed["project_id"],
        "environment": environment,
    }
    if device_secret:
        body_dict["device_hash"] = hash_device_secret(device_secret)

    body = json.dumps(body_dict)
    signature = sign(vault_key, body)

    resp = httpx.post(
        f"{vault_url}/api/v1/secrets/pull",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Vault-Signature": signature,
        },
    )

    if not resp.is_success:
        if resp.status_code == 403:
            text = resp.text
            if "pending" in text:
                raise RuntimeError("Device not yet approved. Ask the project owner to run: vaultdotenv approve-device")
            raise RuntimeError("Device not registered. Run: vaultdotenv register-device")
        raise RuntimeError(f"Vault pull failed ({resp.status_code}): {resp.text}")

    data = resp.json()
    decrypted = decrypt(data["secrets"], vault_key, device_secret)
    return {"secrets": json.loads(decrypted), "version": data["version"]}


def push_secrets(
    vault_key: str,
    secrets: dict,
    environment: str = "development",
    vault_url: str = DEFAULT_VAULT_URL,
    device_secret: str | None = None,
) -> dict:
    """Push secrets to the vault server. Returns {version: int}."""
    parsed = parse_vault_key(vault_key)
    if not parsed:
        raise ValueError("Invalid VAULT_KEY format. Expected: vk_<projectId>_<secret>")

    if device_secret is None:
        device_secret = load_device_secret(parsed["project_id"])

    encrypted_secrets = encrypt(json.dumps(secrets), vault_key, device_secret)

    body_dict = {
        "project_id": parsed["project_id"],
        "environment": environment,
        "secrets": encrypted_secrets,
        "key_names": list(secrets.keys()),
    }
    if device_secret:
        body_dict["device_hash"] = hash_device_secret(device_secret)

    body = json.dumps(body_dict)
    signature = sign(vault_key, body)

    resp = httpx.post(
        f"{vault_url}/api/v1/secrets/push",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Vault-Signature": signature,
        },
    )

    if not resp.is_success:
        raise RuntimeError(f"Vault push failed ({resp.status_code}): {resp.text}")

    return resp.json()


def _check_version(vault_key: str, environment: str, vault_url: str) -> dict:
    """Lightweight version check — no secrets transferred."""
    parsed = parse_vault_key(vault_key)
    body = json.dumps({"project_id": parsed["project_id"], "environment": environment})
    signature = sign(vault_key, body)

    resp = httpx.post(
        f"{vault_url}/api/v1/secrets/current-version",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Vault-Signature": signature,
        },
    )
    if not resp.is_success:
        raise RuntimeError(f"Version check failed ({resp.status_code})")
    return resp.json()


def load_vault(
    path: str | Path = ".env",
    environment: str | None = None,
    vault_url: str | None = None,
    override: bool = False,
    cache: bool = True,
) -> dict:
    """
    Drop-in replacement for dotenv.load_dotenv().

    Reads VAULT_KEY from .env, pulls secrets from vault server,
    injects into os.environ.
    """
    env_path = Path(path).resolve()
    environment = environment or os.environ.get("NODE_ENV") or os.environ.get("ENVIRONMENT") or "development"
    vault_url = vault_url or os.environ.get("VAULT_URL") or DEFAULT_VAULT_URL

    # Step 1: Read .env for VAULT_KEY
    vault_key = os.environ.get("VAULT_KEY")

    if not vault_key and env_path.exists():
        local_env = _parse_dotenv(env_path.read_text())
        vault_key = local_env.get("VAULT_KEY")

        for key, val in local_env.items():
            if key == "VAULT_KEY":
                continue
            if not override and key in os.environ:
                continue
            os.environ[key] = val

    # No VAULT_KEY — plain dotenv behavior
    if not vault_key:
        if env_path.exists():
            parsed = _parse_dotenv(env_path.read_text())
            for key, val in parsed.items():
                if not override and key in os.environ:
                    continue
                os.environ[key] = val
            return parsed
        return {}

    # Step 2: Load device secret
    parsed_key = parse_vault_key(vault_key)
    device_secret = load_device_secret(parsed_key["project_id"]) if parsed_key else None

    # Step 3: Pull from vault
    secrets = None
    version = None

    try:
        result = pull_secrets(vault_key, environment, vault_url)
        secrets = result["secrets"]
        version = result["version"]

        if cache:
            try:
                _save_cache(vault_key, secrets, env_path.parent, device_secret)
            except Exception:
                pass
    except Exception as err:
        if cache:
            secrets = _load_cache(vault_key, env_path.parent, device_secret)
            if secrets:
                import sys
                print("[vaultdotenv] Remote fetch failed, using cached secrets", file=sys.stderr)
            else:
                raise RuntimeError(f"[vaultdotenv] Failed to fetch secrets and no cache available: {err}") from err
        else:
            raise

    # Step 4: Inject into os.environ
    for key, val in secrets.items():
        if not override and key in os.environ:
            continue
        os.environ[key] = str(val)

    return secrets


def load_vault_sync(path: str | Path = ".env", override: bool = False) -> dict:
    """Synchronous config — reads from cache only (matches Node.js configSync)."""
    env_path = Path(path).resolve()

    if not env_path.exists():
        return {}

    local_env = _parse_dotenv(env_path.read_text())
    vault_key = local_env.get("VAULT_KEY")

    if not vault_key:
        for key, val in local_env.items():
            if not override and key in os.environ:
                continue
            os.environ[key] = val
        return local_env

    parsed_key = parse_vault_key(vault_key)
    device_secret = load_device_secret(parsed_key["project_id"]) if parsed_key else None

    cached = _load_cache(vault_key, env_path.parent, device_secret)
    if cached:
        for key, val in cached.items():
            if not override and key in os.environ:
                continue
            os.environ[key] = str(val)
        return cached

    import sys
    print("[vaultdotenv] No cache available, falling back to local .env", file=sys.stderr)
    for key, val in local_env.items():
        if not override and key in os.environ:
            continue
        os.environ[key] = val
    return local_env


# ── Watch / Hot Reload ────────────────────────────────────────────────────────

_watcher_stop = threading.Event()
_watcher_thread: threading.Thread | None = None


def watch(
    interval: float = 30.0,
    environment: str | None = None,
    vault_url: str | None = None,
    on_change: callable = None,
    on_error: callable = None,
):
    """
    Watch for secret changes and hot-reload into os.environ.

    Usage:
        vault_env.watch(
            interval=30,
            on_change=lambda changed, all_secrets: print("Updated:", changed.keys()),
        )
    """
    global _watcher_thread

    vault_key = os.environ.get("VAULT_KEY")
    if not vault_key:
        raise RuntimeError("[vaultdotenv] watch() requires VAULT_KEY — call load_vault() first")

    environment = environment or os.environ.get("NODE_ENV") or os.environ.get("ENVIRONMENT") or "development"
    vault_url = vault_url or os.environ.get("VAULT_URL") or DEFAULT_VAULT_URL

    parsed_key = parse_vault_key(vault_key)
    device_secret = load_device_secret(parsed_key["project_id"]) if parsed_key else None

    _watcher_stop.clear()
    current_version = None

    def _poll():
        nonlocal current_version

        while not _watcher_stop.is_set():
            try:
                data = _check_version(vault_key, environment, vault_url)
                version = data.get("version", 0)

                if current_version is None:
                    current_version = version
                elif version != current_version:
                    result = pull_secrets(vault_key, environment, vault_url)
                    current_version = result["version"]

                    changed = {}
                    for key, val in result["secrets"].items():
                        str_val = str(val)
                        if os.environ.get(key) != str_val:
                            changed[key] = str_val
                            os.environ[key] = str_val

                    if changed and on_change:
                        on_change(changed, result["secrets"])

            except Exception as err:
                if on_error:
                    on_error(err)
                else:
                    import sys
                    print(f"[vaultdotenv] Watch poll failed: {err}", file=sys.stderr)

            _watcher_stop.wait(interval)

    _watcher_thread = threading.Thread(target=_poll, daemon=True, name="vaultdotenv-watcher")
    _watcher_thread.start()


def unwatch():
    """Stop the active watcher."""
    global _watcher_thread
    _watcher_stop.set()
    if _watcher_thread:
        _watcher_thread.join(timeout=5)
        _watcher_thread = None
