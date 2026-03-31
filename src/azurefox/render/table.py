from __future__ import annotations

from collections import Counter
from io import StringIO

from rich.console import Console
from rich.table import Table


def render_table(command: str, payload: dict) -> str:
    sio = StringIO()
    console = Console(file=sio, force_terminal=False, color_system=None, width=160)

    columns, records = _table_spec(command, payload)
    table = Table(title=f"azurefox {command}")

    if not records:
        table.add_column("info")
        table.add_row("No records")
    else:
        for _key, label in columns:
            table.add_column(label)
        for record in records:
            table.add_row(*[_value_to_string(record.get(key)) for key, _ in columns])

    console.print(table)

    findings = payload.get("findings", [])
    if findings:
        console.print("")
        console.print("Findings:")
        for finding in findings[:5]:
            severity = (finding.get("severity") or "unknown").upper()
            console.print(f"- {severity}: {finding.get('title')}")
            console.print(f"  {finding.get('description') or ''}")
        remaining = len(findings) - 5
        if remaining > 0:
            console.print(f"- ... plus {remaining} more findings in JSON artifacts.")

    issues = payload.get("issues", [])
    if issues:
        console.print("")
        console.print("Collection issues:")
        for issue in issues[:5]:
            kind = issue.get("kind") or "unknown"
            console.print(f"- {kind}: {issue.get('message')}")
        remaining = len(issues) - 5
        if remaining > 0:
            console.print(f"- ... plus {remaining} more collection issues in JSON artifacts.")

    takeaway = _takeaway_for_command(command, payload)
    if takeaway:
        console.print("")
        console.print(f"Takeaway: {takeaway}")

    return sio.getvalue()


def _table_spec(command: str, payload: dict) -> tuple[list[tuple[str, str]], list[dict]]:
    if command == "whoami":
        principal = payload.get("principal") or {}
        subscription = payload.get("subscription") or {}
        scopes = payload.get("effective_scopes") or []
        scope = scopes[0] if scopes else {}
        return (
            [
                ("subscription", "subscription"),
                ("principal", "principal"),
                ("type", "type"),
                ("token_source", "token"),
                ("scope", "scope"),
            ],
            [
                {
                    "subscription": subscription.get("display_name") or subscription.get("id"),
                    "principal": principal.get("display_name") or principal.get("id"),
                    "type": principal.get("principal_type"),
                    "token_source": payload.get("metadata", {}).get("token_source"),
                    "scope": scope.get("display_name") or scope.get("id"),
                }
            ],
        )

    if command == "inventory":
        top_types = payload.get("top_resource_types", {})
        return (
            [
                ("resource_groups", "resource groups"),
                ("resources", "resources"),
                ("top_type", "top type"),
                ("issues", "issues"),
            ],
            [
                {
                    "resource_groups": payload.get("resource_group_count", 0),
                    "resources": payload.get("resource_count", 0),
                    "top_type": next(iter(top_types.keys()), "none visible"),
                    "issues": len(payload.get("issues", [])),
                }
            ],
        )

    if command == "principals":
        return (
            [
                ("principal", "principal"),
                ("type", "type"),
                ("roles", "roles"),
                ("assignments", "assignments"),
                ("identity_context", "identity context"),
                ("sources", "sources"),
                ("current", "current"),
            ],
            [
                {
                    "principal": item.get("display_name") or item.get("id"),
                    "type": item.get("principal_type"),
                    "roles": item.get("role_names", []),
                    "assignments": item.get("role_assignment_count", 0),
                    "identity_context": _principal_identity_context(item),
                    "sources": item.get("sources", []),
                    "current": _bool_text(item.get("is_current_identity", False)),
                }
                for item in payload.get("principals", [])
            ],
        )

    if command == "permissions":
        return (
            [
                ("principal", "principal"),
                ("type", "type"),
                ("high_impact_roles", "high-impact roles"),
                ("assignments", "assignments"),
                ("scope_count", "scopes"),
                ("current", "current"),
            ],
            [
                {
                    "principal": item.get("display_name") or item.get("principal_id"),
                    "type": item.get("principal_type"),
                    "high_impact_roles": item.get("high_impact_roles", []),
                    "assignments": item.get("role_assignment_count", 0),
                    "scope_count": item.get("scope_count", 0),
                    "current": _bool_text(item.get("is_current_identity", False)),
                }
                for item in payload.get("permissions", [])
            ],
        )

    if command == "privesc":
        return (
            [
                ("severity", "severity"),
                ("principal", "principal"),
                ("path_type", "path"),
                ("asset", "asset"),
                ("why_it_matters", "why it matters"),
                ("current", "current"),
            ],
            [
                {
                    "severity": item.get("severity"),
                    "principal": item.get("principal"),
                    "path_type": item.get("path_type"),
                    "asset": item.get("asset") or "-",
                    "why_it_matters": item.get("summary"),
                    "current": _bool_text(item.get("current_identity", False)),
                }
                for item in payload.get("paths", [])
            ],
        )

    if command == "role-trusts":
        return (
            [
                ("trust_type", "trust"),
                ("source", "source"),
                ("target", "target"),
                ("confidence", "confidence"),
                ("why_it_matters", "why it matters"),
            ],
            [
                {
                    "trust_type": item.get("trust_type"),
                    "source": item.get("source_name") or item.get("source_object_id"),
                    "target": item.get("target_name") or item.get("target_object_id"),
                    "confidence": item.get("confidence"),
                    "why_it_matters": item.get("summary"),
                }
                for item in payload.get("trusts", [])
            ],
        )

    if command == "resource-trusts":
        return (
            [
                ("resource", "resource"),
                ("resource_type", "type"),
                ("trust_type", "trust"),
                ("target", "target"),
                ("exposure", "exposure"),
                ("why_it_matters", "why it matters"),
            ],
            [
                {
                    "resource": item.get("resource_name") or item.get("resource_id"),
                    "resource_type": item.get("resource_type"),
                    "trust_type": item.get("trust_type"),
                    "target": item.get("target"),
                    "exposure": item.get("exposure"),
                    "why_it_matters": item.get("summary"),
                }
                for item in payload.get("resource_trusts", [])
            ],
        )

    if command == "auth-policies":
        return (
            [
                ("policy", "policy"),
                ("state", "state"),
                ("scope", "scope"),
                ("operator_signal", "operator signal"),
            ],
            [
                {
                    "policy": item.get("name"),
                    "state": item.get("state"),
                    "scope": item.get("scope"),
                    "operator_signal": item.get("summary"),
                }
                for item in payload.get("auth_policies", [])
            ],
        )

    if command == "managed-identities":
        return (
            [
                ("name", "identity"),
                ("identity_type", "type"),
                ("attached_to", "attached to"),
                ("principal_id", "principal id"),
            ],
            payload.get("identities", []),
        )

    if command == "keyvault":
        return (
            [
                ("name", "vault"),
                ("resource_group", "resource group"),
                ("public_network_access", "public network"),
                ("network_default_action", "default action"),
                ("private_endpoint_enabled", "private endpoint"),
                ("purge_protection_enabled", "purge protection"),
                ("enable_rbac_authorization", "rbac mode"),
            ],
            [
                {
                    "name": item.get("name"),
                    "resource_group": item.get("resource_group"),
                    "public_network_access": item.get("public_network_access"),
                    "network_default_action": item.get("network_default_action"),
                    "private_endpoint_enabled": _bool_text(
                        item.get("private_endpoint_enabled", False)
                    ),
                    "purge_protection_enabled": _bool_text(
                        item.get("purge_protection_enabled", False)
                    ),
                    "enable_rbac_authorization": _bool_text(
                        item.get("enable_rbac_authorization", False)
                    ),
                }
                for item in payload.get("key_vaults", [])
            ],
        )

    if command == "storage":
        return (
            [
                ("name", "account"),
                ("resource_group", "resource group"),
                ("public_access", "public"),
                ("network_default_action", "default action"),
                ("private_endpoint_enabled", "private endpoint"),
                ("container_count", "containers"),
            ],
            [
                {
                    "name": item.get("name"),
                    "resource_group": item.get("resource_group"),
                    "public_access": _bool_text(item.get("public_access", False)),
                    "network_default_action": item.get("network_default_action"),
                    "private_endpoint_enabled": _bool_text(
                        item.get("private_endpoint_enabled", False)
                    ),
                    "container_count": item.get("container_count", 0),
                }
                for item in payload.get("storage_assets", [])
            ],
        )

    if command == "vms":
        return (
            [
                ("name", "asset"),
                ("vm_type", "type"),
                ("public_ips", "public ips"),
                ("private_ips", "private ips"),
                ("identity_ids", "identities"),
            ],
            payload.get("vm_assets", []),
        )

    mapping = {
        "rbac": "role_assignments",
    }
    key = mapping.get(command)
    if key:
        rows = payload.get(key, [])
        columns = [(item, item.replace("_", " ")) for item in rows[0].keys()] if rows else []
        return columns, rows

    return [], []


def _takeaway_for_command(command: str, payload: dict) -> str:
    if command == "whoami":
        principal = payload.get("principal") or {}
        subscription = payload.get("subscription") or {}
        return (
            f"Operating as {principal.get('display_name') or principal.get('id')} "
            f"({principal.get('principal_type')}) in "
            f"{subscription.get('display_name') or subscription.get('id')}."
        )

    if command == "principals":
        principals = payload.get("principals", [])
        current = sum(bool(item.get("is_current_identity")) for item in principals)
        privileged = sum(
            1
            for item in principals
            if any(role.lower() == "owner" for role in item.get("role_names", []))
        )
        return (
            f"{len(principals)} principals visible; {privileged} hold Owner and "
            f"{current} match the current identity."
        )

    if command == "privesc":
        paths = payload.get("paths", [])
        by_severity = Counter(item.get("severity") or "unknown" for item in paths)
        counts = ", ".join(f"{count} {severity}" for severity, count in sorted(by_severity.items()))
        if not counts:
            counts = "no meaningful paths"
        return f"{len(paths)} privilege-escalation paths surfaced; {counts}."

    if command == "role-trusts":
        trusts = payload.get("trusts", [])
        families = Counter(item.get("trust_type") or "unknown" for item in trusts)
        counts = ", ".join(f"{count} {name}" for name, count in sorted(families.items()))
        return f"{len(trusts)} trust edges surfaced; {counts or 'no trust edges visible'}."

    if command == "resource-trusts":
        resource_trusts = payload.get("resource_trusts", [])
        exposures = Counter(item.get("exposure") or "unknown" for item in resource_trusts)
        counts = ", ".join(f"{count} {name}" for name, count in sorted(exposures.items()))
        return (
            f"{len(resource_trusts)} resource trust surfaces visible; "
            f"{counts or 'no resource trust surfaces visible'}."
        )

    if command == "auth-policies":
        policies = payload.get("auth_policies", [])
        findings = payload.get("findings", [])
        issues = payload.get("issues", [])
        return (
            f"{len(policies)} policy rows, {len(findings)} findings, and "
            f"{len(issues)} collection issues visible from the current read path."
        )

    if command == "permissions":
        permissions = payload.get("permissions", [])
        privileged = sum(bool(item.get("privileged")) for item in permissions)
        return f"{privileged} of {len(permissions)} principals hold high-impact RBAC roles."

    if command == "managed-identities":
        identities = payload.get("identities", [])
        findings = payload.get("findings", [])
        return f"{len(identities)} managed identities visible; {len(findings)} elevated findings."

    if command == "storage":
        assets = payload.get("storage_assets", [])
        public_assets = sum(bool(item.get("public_access")) for item in assets)
        return (
            f"{len(assets)} storage accounts visible; "
            f"{public_assets} have public blob access enabled."
        )

    if command == "keyvault":
        key_vaults = payload.get("key_vaults", [])
        findings = payload.get("findings", [])
        return (
            f"{len(key_vaults)} Key Vault assets visible; "
            f"{len(findings)} exposure or recovery findings."
        )

    if command == "vms":
        vm_assets = payload.get("vm_assets", [])
        public_assets = sum(1 for item in vm_assets if item.get("public_ips"))
        return f"{len(vm_assets)} compute assets visible; {public_assets} have public IP exposure."

    if command == "inventory":
        return (
            f"{payload.get('resource_count', 0)} resources across "
            f"{payload.get('resource_group_count', 0)} resource groups."
        )

    if command == "rbac":
        assignments = payload.get("role_assignments", [])
        principals = payload.get("principals", [])
        return f"{len(assignments)} RBAC assignments across {len(principals)} principals."

    return ""


def _principal_identity_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("identity_names"):
        parts.append(f"identities={','.join(item.get('identity_names', []))}")
    if item.get("attached_to"):
        parts.append(f"attached={len(item.get('attached_to', []))}")
    if not parts:
        return "-"
    return "; ".join(parts)


def _bool_text(value: bool) -> str:
    return "yes" if value else "no"


def _value_to_string(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    if isinstance(value, dict):
        return ", ".join(f"{k}: {v}" for k, v in value.items())
    return str(value)
