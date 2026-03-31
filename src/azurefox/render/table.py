from __future__ import annotations

from io import StringIO

from rich.console import Console
from rich.table import Table


def render_table(command: str, payload: dict) -> str:
    table = Table(title=f"azurefox {command}")

    records = _records_for_command(command, payload)
    if not records:
        table.add_column("info")
        table.add_row("No records")
        return _render(table)

    keys = list(records[0].keys())
    for key in keys:
        table.add_column(key)

    for record in records:
        table.add_row(*[_value_to_string(record.get(key)) for key in keys])

    return _render(table)


def _records_for_command(command: str, payload: dict) -> list[dict]:
    if command == "whoami":
        principal = payload.get("principal") or {}
        sub = payload.get("subscription") or {}
        return [
            {
                "tenant_id": payload.get("tenant_id"),
                "subscription_id": sub.get("id"),
                "subscription_name": sub.get("display_name"),
                "principal_id": principal.get("id"),
                "principal_type": principal.get("principal_type"),
                "token_source": payload.get("metadata", {}).get("token_source"),
            }
        ]

    if command == "inventory":
        return [
            {
                "resource_groups": payload.get("resource_group_count", 0),
                "resources": payload.get("resource_count", 0),
                "top_types": len(payload.get("top_resource_types", {})),
                "issues": len(payload.get("issues", [])),
            }
        ]

    mapping = {
        "rbac": "role_assignments",
        "principals": "principals",
        "managed-identities": "identities",
        "storage": "storage_assets",
        "vms": "vm_assets",
    }
    key = mapping.get(command)
    if key:
        return payload.get(key, [])

    return []


def _value_to_string(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ",".join(str(v) for v in value)
    if isinstance(value, dict):
        return ",".join(f"{k}:{v}" for k, v in value.items())
    return str(value)


def _render(table: Table) -> str:
    sio = StringIO()
    console = Console(file=sio, force_terminal=False, color_system=None, width=160)
    console.print(table)
    return sio.getvalue()
