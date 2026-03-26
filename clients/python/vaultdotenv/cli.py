#!/usr/bin/env python3
"""vaultdotenv CLI — remote secrets manager, drop-in dotenv replacement."""
from __future__ import annotations

import sys


def main():
    args = sys.argv[1:]
    command = args[0] if args else None

    if command == "login":
        from vaultdotenv.commands.auth import login
        login(args)
    elif command == "logout":
        from vaultdotenv.commands.auth import logout
        logout(args)
    elif command == "whoami":
        from vaultdotenv.commands.auth import whoami
        whoami(args)
    elif command == "init":
        from vaultdotenv.commands.init import init
        init(args)
    elif command == "projects":
        from vaultdotenv.commands.projects import list_projects
        list_projects(args)
    elif command == "push":
        from vaultdotenv.commands.secrets import push
        push(args)
    elif command == "pull":
        from vaultdotenv.commands.secrets import pull
        pull(args)
    elif command == "set":
        from vaultdotenv.commands.secrets import set_secret
        set_secret(args)
    elif command == "delete":
        from vaultdotenv.commands.secrets import delete
        delete(args)
    elif command == "get":
        from vaultdotenv.commands.secrets import get
        get(args)
    elif command == "versions":
        from vaultdotenv.commands.versions import versions
        versions(args)
    elif command == "rollback":
        from vaultdotenv.commands.versions import rollback
        rollback(args)
    elif command == "register-device":
        from vaultdotenv.commands.devices import register
        register(args)
    elif command == "approve-device":
        from vaultdotenv.commands.devices import approve
        approve(args)
    elif command == "list-devices":
        from vaultdotenv.commands.devices import list_devices
        list_devices(args)
    elif command == "revoke-device":
        from vaultdotenv.commands.devices import revoke
        revoke(args)
    elif command == "key":
        sub = args[1] if len(args) > 1 else None
        if sub == "save":
            from vaultdotenv.commands.keys import save
            save(args[1:])
        elif sub == "list":
            from vaultdotenv.commands.keys import list_keys
            list_keys(args[1:])
        elif sub == "remove":
            from vaultdotenv.commands.keys import remove
            remove(args[1:])
        else:
            print_key_help()
    else:
        print_help()


def print_help():
    print("""vaultdotenv — Remote secrets manager, drop-in dotenv replacement

Auth:
  vde login                            Log in via browser (links CLI to dashboard)
  vde logout                           Remove saved auth token
  vde whoami                           Show current logged-in user

Usage:
  vde projects                         List all your projects
  vde init [--name project]            Initialize a new vault project
  vde push [--env production]          Push .env secrets to vault
  vde pull [--env staging]             Pull secrets from vault
  vde set KEY "value" [--env prod]     Set a single secret
  vde delete KEY [--env prod]          Remove a secret (with confirmation)
  vde get KEY [--env prod]             Get a single secret (masked)
  vde get KEY --raw --token T          Reveal cleartext (requires token)
  vde versions [--env prod]            List secret versions
  vde rollback --version 5             Rollback to a specific version

Device management:
  vde register-device [--name X]       Register this machine with the vault
  vde approve-device --id X            Approve a pending device
  vde list-devices                     List all registered devices
  vde revoke-device --id X             Revoke a device's access

Key management:
  vde key save --project X --key vk_...  Save a vault key locally
  vde key list                           List saved project keys
  vde key remove --project X             Remove a saved key

Options:
  --project <name>  Use saved key for project (from key save)
  --env <name>      Environment (default: development)
  --url <url>       Vault server URL (default: api.vaultdotenv.io)
  --file <path>     Source .env file for push (default: .env)
  --output <path>   Output file for pull (default: stdout)
  --name <name>     Device or project name
  --id <id>         Device ID (for approve/revoke)
""")


def print_key_help():
    print("""Key management:
  vde key save --project X --key vk_...  Save a vault key locally
  vde key list                           List saved project keys
  vde key remove --project X             Remove a saved key
""")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
