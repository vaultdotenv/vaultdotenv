"""CLI projects command: list all projects."""
from __future__ import annotations

import sys

import httpx

from vaultdotenv.config import get_auth, get_vault_url


def list_projects(args: list[str]) -> None:
    """List all projects linked to your account."""
    auth = get_auth()
    if not auth or not auth.get("token"):
        print("Not logged in. Run: vde login")
        sys.exit(1)

    vault_url = get_vault_url(args)

    resp = httpx.get(
        f"{vault_url}/api/v1/dashboard/projects",
        headers={"Authorization": f"Bearer {auth['token']}"},
    )

    if resp.status_code == 401:
        print("Session expired. Run: vde login")
        sys.exit(1)

    if not resp.is_success:
        print(f"Error: {resp.text}")
        sys.exit(1)

    projects = resp.json().get("projects", [])

    if not projects:
        print("No projects found. Create one with: vde init")
        return

    print(f"\nProjects ({len(projects)}):\n")
    for p in projects:
        envs = ", ".join(e["name"] for e in p.get("environments", []))
        print(f"  {p['name']}")
        print(f"    ID: {p['id']}")
        if envs:
            print(f"    Environments: {envs}")
        print()
