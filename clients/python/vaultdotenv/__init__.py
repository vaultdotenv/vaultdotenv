"""vaultdotenv — Drop-in python-dotenv replacement with remote encrypted secrets."""

from vaultdotenv.client import load_vault, load_vault_sync, pull_secrets, push_secrets, watch, unwatch
from vaultdotenv.device import register_device, load_device_secret, save_device_secret

__all__ = [
    "load_vault",
    "load_vault_sync",
    "pull_secrets",
    "push_secrets",
    "watch",
    "unwatch",
    "register_device",
    "load_device_secret",
    "save_device_secret",
]
