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

    if command == "permissions":
        return [
            {
                "principal": item.get("display_name") or item.get("principal_id"),
                "principal_type": item.get("principal_type"),
                "high_impact_roles": item.get("high_impact_roles", []),
                "assignment_count": item.get("role_assignment_count", 0),
                "privileged": str(bool(item.get("privileged", False))).lower(),
                "scope_count": item.get("scope_count", 0),
                "current_identity": str(bool(item.get("is_current_identity", False))).lower(),
            }
            for item in payload.get("permissions", [])
        ]

    if command == "privesc":
        return [
            {
                "principal": item.get("principal"),
                "path_type": item.get("path_type"),
                "asset": item.get("asset"),
                "impact_roles": item.get("impact_roles", []),
                "severity": item.get("severity"),
                "current_identity": str(bool(item.get("current_identity", False))).lower(),
            }
            for item in payload.get("paths", [])
        ]

    if command == "role-trusts":
        return [
            {
                "trust_type": item.get("trust_type"),
                "source": item.get("source_name") or item.get("source_object_id"),
                "source_type": item.get("source_type"),
                "target": item.get("target_name") or item.get("target_object_id"),
                "target_type": item.get("target_type"),
                "confidence": item.get("confidence"),
                "evidence_type": item.get("evidence_type"),
            }
            for item in payload.get("trusts", [])
        ]

    mapping = {
        "rbac": "role_assignments",
        "principals": "principals",
        "permissions": "permissions",
        "privesc": "paths",
        "role-trusts": "trusts",
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
