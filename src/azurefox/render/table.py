from __future__ import annotations

from collections import Counter
from io import StringIO
from urllib.parse import urlparse

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

    if command == "arm-deployments":
        return (
            [
                ("name", "deployment"),
                ("scope", "scope"),
                ("provisioning_state", "state"),
                ("outputs_count", "outputs"),
                ("linked_refs", "linked refs"),
                ("why_it_matters", "why it matters"),
            ],
            [
                {
                    "name": item.get("name"),
                    "scope": _deployment_scope_label(item),
                    "provisioning_state": item.get("provisioning_state"),
                    "outputs_count": item.get("outputs_count", 0),
                    "linked_refs": _linked_reference_summary(item),
                    "why_it_matters": item.get("summary"),
                }
                for item in payload.get("deployments", [])
            ],
        )

    if command == "endpoints":
        return (
            [
                ("endpoint", "endpoint"),
                ("source_asset_name", "asset"),
                ("source_asset_kind", "kind"),
                ("exposure_family", "family"),
                ("ingress_path", "ingress"),
                ("why_it_matters", "why it matters"),
            ],
            [
                {
                    "endpoint": item.get("endpoint"),
                    "source_asset_name": item.get("source_asset_name"),
                    "source_asset_kind": item.get("source_asset_kind"),
                    "exposure_family": item.get("exposure_family"),
                    "ingress_path": item.get("ingress_path"),
                    "why_it_matters": item.get("summary"),
                }
                for item in payload.get("endpoints", [])
            ],
        )

    if command == "network-ports":
        return (
            [
                ("asset_name", "asset"),
                ("endpoint", "endpoint"),
                ("protocol", "protocol"),
                ("port", "port"),
                ("allow_source_summary", "allow source"),
                ("exposure_confidence", "confidence"),
                ("why_it_matters", "why it matters"),
            ],
            [
                {
                    "asset_name": item.get("asset_name"),
                    "endpoint": item.get("endpoint"),
                    "protocol": item.get("protocol"),
                    "port": item.get("port"),
                    "allow_source_summary": item.get("allow_source_summary"),
                    "exposure_confidence": item.get("exposure_confidence"),
                    "why_it_matters": item.get("summary"),
                }
                for item in payload.get("network_ports", [])
            ],
        )

    if command == "env-vars":
        return (
            [
                ("asset_name", "workload"),
                ("asset_kind", "kind"),
                ("identity", "identity"),
                ("setting_name", "setting"),
                ("value_type", "value type"),
                ("signal", "signal"),
                ("why_it_matters", "why it matters"),
            ],
            [
                {
                    "asset_name": item.get("asset_name"),
                    "asset_kind": item.get("asset_kind"),
                    "identity": _env_var_identity_context(item),
                    "setting_name": item.get("setting_name"),
                    "value_type": item.get("value_type"),
                    "signal": _env_var_signal(item),
                    "why_it_matters": item.get("summary"),
                }
                for item in payload.get("env_vars", [])
            ],
        )

    if command == "tokens-credentials":
        return (
            [
                ("asset_name", "asset"),
                ("asset_kind", "kind"),
                ("surface_type", "surface"),
                ("access_path", "access path"),
                ("priority", "priority"),
                ("operator_signal", "operator signal"),
                ("why_it_matters", "why it matters"),
            ],
            [
                {
                    "asset_name": item.get("asset_name"),
                    "asset_kind": item.get("asset_kind"),
                    "surface_type": item.get("surface_type"),
                    "access_path": item.get("access_path"),
                    "priority": item.get("priority"),
                    "operator_signal": item.get("operator_signal"),
                    "why_it_matters": item.get("summary"),
                }
                for item in payload.get("surfaces", [])
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
                    "network_default_action": _keyvault_default_action_text(item),
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

    if command == "nics":
        return (
            [
                ("name", "nic"),
                ("attached_asset", "attached asset"),
                ("private_ips", "private ips"),
                ("public_ip_refs", "public ip refs"),
                ("subnet_vnet", "subnet / vnet"),
                ("network_security_group", "nsg"),
            ],
            [
                {
                    "name": item.get("name"),
                    "attached_asset": _display_resource_name(item.get("attached_asset_id")),
                    "private_ips": item.get("private_ips"),
                    "public_ip_refs": _display_resource_refs(item.get("public_ip_ids")),
                    "subnet_vnet": _network_scope_summary(item),
                    "network_security_group": _display_resource_name(
                        item.get("network_security_group_id")
                    ),
                }
                for item in payload.get("nic_assets", [])
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
        return (
            f"{len(trusts)} trust edges surfaced; {counts or 'no trust edges visible'}. "
            "Delegated and admin consent grants are out of scope for this command."
        )

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

    if command == "nics":
        nic_assets = payload.get("nic_assets", [])
        attached = sum(bool(item.get("attached_asset_id")) for item in nic_assets)
        public_refs = sum(len(item.get("public_ip_ids", [])) for item in nic_assets)
        return (
            f"{len(nic_assets)} NICs visible; {attached} attached to visible assets and "
            f"{public_refs} reference public IP resources."
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

    if command == "arm-deployments":
        deployments = payload.get("deployments", [])
        findings = payload.get("findings", [])
        subscription_scope = sum(item.get("scope_type") == "subscription" for item in deployments)
        return (
            f"{len(deployments)} deployments visible; {subscription_scope} at subscription "
            f"scope and {len(findings)} findings."
        )

    if command == "endpoints":
        endpoints = payload.get("endpoints", [])
        families = Counter(item.get("exposure_family") or "unknown" for item in endpoints)
        family_order = {"public-ip": 0, "managed-web-hostname": 1}
        counts = ", ".join(
            f"{count} {name}"
            for name, count in sorted(
                families.items(),
                key=lambda item: (family_order.get(item[0], 9), item[0]),
            )
        )
        return (
            f"{len(endpoints)} reachable surfaces visible; "
            f"{counts or 'no reachable surfaces visible'}."
        )

    if command == "network-ports":
        network_ports = payload.get("network_ports", [])
        confidence = Counter(item.get("exposure_confidence") or "unknown" for item in network_ports)
        counts = ", ".join(f"{count} {name}" for name, count in sorted(confidence.items()))
        return (
            f"{len(network_ports)} port exposure rows visible; "
            f"{counts or 'no port exposure rows visible'}."
        )

    if command == "env-vars":
        env_vars = payload.get("env_vars", [])
        findings = payload.get("findings", [])
        workloads = {item.get("asset_id") for item in env_vars if item.get("asset_id")}
        plain_sensitive = sum(
            item.get("looks_sensitive") and item.get("value_type") == "plain-text"
            for item in env_vars
        )
        keyvault_refs = sum(item.get("value_type") == "keyvault-ref" for item in env_vars)
        return (
            f"{len(env_vars)} settings across {len(workloads)} workloads; "
            f"{plain_sensitive} plain-text sensitive settings, {keyvault_refs} Key Vault "
            f"references, and {len(findings)} findings."
        )

    if command == "tokens-credentials":
        surfaces = payload.get("surfaces", [])
        findings = payload.get("findings", [])
        assets = {item.get("asset_id") for item in surfaces if item.get("asset_id")}
        families = Counter(item.get("surface_type") or "unknown" for item in surfaces)
        counts = ", ".join(f"{count} {name}" for name, count in sorted(families.items()))
        return (
            f"{len(surfaces)} token or credential surfaces across {len(assets)} assets; "
            f"{counts or 'no surfaces visible'} and {len(findings)} findings."
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


def _deployment_scope_label(item: dict) -> str:
    if item.get("resource_group"):
        return f"rg:{item.get('resource_group')}"
    scope = str(item.get("scope") or "")
    if "/subscriptions/" in scope:
        subscription_id = scope.rstrip("/").split("/subscriptions/", 1)[-1].split("/", 1)[0]
        if subscription_id:
            return f"sub:{subscription_id}"
    return item.get("scope") or item.get("scope_type") or "-"


def _linked_reference_summary(item: dict) -> str:
    parts: list[str] = []
    if item.get("template_link"):
        parts.append(f"template={_display_link(item.get('template_link'))}")
    if item.get("parameters_link"):
        parts.append(f"parameters={_display_link(item.get('parameters_link'))}")
    if not parts:
        return "-"
    return ", ".join(parts)


def _display_link(value: object) -> str:
    if not value:
        return "-"

    parsed = urlparse(str(value))
    if parsed.netloc and parsed.path:
        return f"{parsed.netloc}{parsed.path}"
    return str(value)


def _env_var_signal(item: dict) -> str:
    parts: list[str] = []
    if item.get("looks_sensitive"):
        parts.append("sensitive-name")
    if item.get("value_type") == "keyvault-ref":
        parts.append("keyvault-ref")
    if item.get("reference_target"):
        parts.append(str(item.get("reference_target")))
    if not parts:
        return "-"
    return "; ".join(parts)


def _env_var_identity_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("workload_identity_type"):
        parts.append(str(item.get("workload_identity_type")))
    if item.get("workload_identity_ids"):
        parts.append(f"user-assigned={len(item.get('workload_identity_ids', []))}")
    if item.get("key_vault_reference_identity"):
        parts.append(_display_reference_identity(item.get("key_vault_reference_identity")))
    if not parts:
        return "-"
    return "; ".join(parts)


def _display_reference_identity(value: object) -> str:
    text = str(value or "")
    if not text:
        return "-"
    if text.lower() == "systemassigned":
        return "kv-ref=SystemAssigned"
    parts = [part for part in text.split("/") if part]
    if parts:
        return f"kv-ref={parts[-1]}"
    return f"kv-ref={text}"


def _display_resource_name(value: object) -> str:
    text = str(value or "")
    if not text:
        return "-"
    parts = [part for part in text.split("/") if part]
    return parts[-1] if parts else text


def _display_resource_refs(values: object) -> list[str]:
    if not isinstance(values, list):
        return []
    return [_display_resource_name(value) for value in values if value]


def _network_scope_summary(item: dict) -> str:
    subnet_names = _display_resource_refs(item.get("subnet_ids"))
    vnet_names = _display_resource_refs(item.get("vnet_ids"))

    parts: list[str] = []
    if subnet_names:
        parts.append(f"subnet={','.join(subnet_names)}")
    if vnet_names:
        parts.append(f"vnet={','.join(vnet_names)}")
    if not parts:
        return "-"
    return "; ".join(parts)


def _keyvault_default_action_text(item: dict) -> str | None:
    value = item.get("network_default_action")
    if value:
        return str(value)
    if str(item.get("public_network_access") or "").lower() == "enabled":
        return "implicit allow (ACL omitted)"
    return None


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
