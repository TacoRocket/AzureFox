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
            console.print(f"- {kind}: {issue.get('message')}", markup=False)
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

    if command == "app-services":
        return (
            [
                ("name", "app service"),
                ("default_hostname", "hostname"),
                ("runtime_stack", "runtime"),
                ("identity", "identity"),
                ("exposure", "exposure"),
                ("posture", "posture"),
                ("why_it_matters", "why it matters"),
            ],
            [
                {
                    "name": item.get("name"),
                    "default_hostname": item.get("default_hostname"),
                    "runtime_stack": item.get("runtime_stack") or "-",
                    "identity": _app_service_identity_context(item),
                    "exposure": _app_service_exposure_context(item),
                    "posture": _app_service_posture_context(item),
                    "why_it_matters": item.get("summary"),
                }
                for item in payload.get("app_services", [])
            ],
        )

    if command == "acr":
        return (
            [
                ("name", "registry"),
                ("login_server", "login server"),
                ("identity", "identity"),
                ("auth", "auth"),
                ("exposure", "exposure"),
                ("depth", "depth"),
                ("posture", "posture"),
                ("why_it_matters", "why it matters"),
            ],
            [
                {
                    "name": item.get("name"),
                    "login_server": item.get("login_server"),
                    "identity": _app_service_identity_context(item),
                    "auth": _acr_auth_context(item),
                    "exposure": _acr_exposure_context(item),
                    "depth": _acr_depth_context(item),
                    "posture": _acr_posture_context(item),
                    "why_it_matters": item.get("summary"),
                }
                for item in payload.get("registries", [])
            ],
        )

    if command == "databases":
        return (
            [
                ("name", "server"),
                ("engine", "engine"),
                ("endpoint", "endpoint"),
                ("identity", "identity"),
                ("inventory", "inventory"),
                ("exposure", "exposure"),
                ("posture", "posture"),
                ("why_it_matters", "why it matters"),
            ],
            [
                {
                    "name": item.get("name"),
                    "engine": item.get("engine"),
                    "endpoint": item.get("fully_qualified_domain_name"),
                    "identity": _app_service_identity_context(item),
                    "inventory": _database_inventory_context(item),
                    "exposure": _database_exposure_context(item),
                    "posture": _database_posture_context(item),
                    "why_it_matters": item.get("summary"),
                }
                for item in payload.get("database_servers", [])
            ],
        )

    if command == "dns":
        return (
            [
                ("name", "zone"),
                ("zone_kind", "kind"),
                ("inventory", "inventory"),
                ("namespace", "namespace"),
                ("why_it_matters", "why it matters"),
            ],
            [
                {
                    "name": item.get("name"),
                    "zone_kind": item.get("zone_kind"),
                    "inventory": _dns_inventory_context(item),
                    "namespace": _dns_namespace_context(item),
                    "why_it_matters": item.get("summary"),
                }
                for item in payload.get("dns_zones", [])
            ],
        )

    if command == "aks":
        return (
            [
                ("name", "cluster"),
                ("version", "version"),
                ("endpoint", "endpoint"),
                ("identity", "identity"),
                ("auth", "auth"),
                ("network", "network"),
                ("why_it_matters", "why it matters"),
            ],
            [
                {
                    "name": item.get("name"),
                    "version": _aks_version_context(item),
                    "endpoint": _aks_endpoint_context(item),
                    "identity": _aks_identity_context(item),
                    "auth": _aks_auth_context(item),
                    "network": _aks_network_context(item),
                    "why_it_matters": item.get("summary"),
                }
                for item in payload.get("aks_clusters", [])
            ],
        )

    if command == "api-mgmt":
        return (
            [
                ("name", "service"),
                ("gateway", "gateway"),
                ("identity", "identity"),
                ("inventory", "inventory"),
                ("exposure", "exposure"),
                ("posture", "posture"),
                ("why_it_matters", "why it matters"),
            ],
            [
                {
                    "name": item.get("name"),
                    "gateway": item.get("gateway_hostnames", []),
                    "identity": _app_service_identity_context(item),
                    "inventory": _api_mgmt_inventory_context(item),
                    "exposure": _api_mgmt_exposure_context(item),
                    "posture": _api_mgmt_posture_context(item),
                    "why_it_matters": item.get("summary"),
                }
                for item in payload.get("api_management_services", [])
            ],
        )

    if command == "functions":
        return (
            [
                ("name", "function app"),
                ("default_hostname", "hostname"),
                ("runtime", "runtime"),
                ("identity", "identity"),
                ("deployment", "deployment"),
                ("posture", "posture"),
                ("why_it_matters", "why it matters"),
            ],
            [
                {
                    "name": item.get("name"),
                    "default_hostname": item.get("default_hostname"),
                    "runtime": _function_runtime_context(item),
                    "identity": _app_service_identity_context(item),
                    "deployment": _function_deployment_context(item),
                    "posture": _function_posture_context(item),
                    "why_it_matters": item.get("summary"),
                }
                for item in payload.get("function_apps", [])
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
                ("exposure", "exposure"),
                ("auth", "auth / transport"),
                ("protocols", "protocols"),
                ("inventory", "inventory"),
            ],
            [
                {
                    "name": item.get("name"),
                    "resource_group": item.get("resource_group"),
                    "exposure": _storage_exposure_context(item),
                    "auth": _storage_auth_context(item),
                    "protocols": _storage_protocol_context(item),
                    "inventory": _storage_inventory_context(item),
                }
                for item in payload.get("storage_assets", [])
            ],
        )

    if command == "snapshots-disks":
        return (
            [
                ("name", "asset"),
                ("asset_kind", "kind"),
                ("priority", "priority"),
                ("attachment_source", "attachment / source"),
                ("sharing_export", "sharing / export"),
                ("encryption", "encryption"),
                ("why_it_matters", "why it matters"),
            ],
            [
                {
                    "name": item.get("name"),
                    "asset_kind": item.get("asset_kind"),
                    "priority": _snapshot_disk_priority_context(item),
                    "attachment_source": _snapshot_disk_attachment_context(item),
                    "sharing_export": _snapshot_disk_sharing_context(item),
                    "encryption": _snapshot_disk_encryption_context(item),
                    "why_it_matters": item.get("summary"),
                }
                for item in payload.get("snapshot_disk_assets", [])
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

    if command == "network-effective":
        return (
            [
                ("asset_name", "asset"),
                ("endpoint", "endpoint"),
                ("effective_exposure", "priority"),
                ("internet_exposed_ports", "internet ports"),
                ("constrained_ports", "narrower ports"),
                ("why_it_matters", "why it matters"),
            ],
            [
                {
                    "asset_name": item.get("asset_name"),
                    "endpoint": item.get("endpoint"),
                    "effective_exposure": item.get("effective_exposure"),
                    "internet_exposed_ports": item.get("internet_exposed_ports", []),
                    "constrained_ports": item.get("constrained_ports", []),
                    "why_it_matters": item.get("summary"),
                }
                for item in payload.get("effective_exposures", [])
            ],
        )

    if command == "workloads":
        return (
            [
                ("asset_name", "workload"),
                ("asset_kind", "kind"),
                ("identity", "identity"),
                ("endpoints", "endpoints"),
                ("ingress_paths", "ingress"),
                ("why_it_matters", "why it matters"),
            ],
            [
                {
                    "asset_name": item.get("asset_name"),
                    "asset_kind": item.get("asset_kind"),
                    "identity": _workload_identity_context(item),
                    "endpoints": item.get("endpoints", []),
                    "ingress_paths": item.get("ingress_paths", []),
                    "why_it_matters": item.get("summary"),
                }
                for item in payload.get("workloads", [])
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
        mode = payload.get("mode") or "fast"
        families = Counter(item.get("trust_type") or "unknown" for item in trusts)
        counts = ", ".join(f"{count} {name}" for name, count in sorted(families.items()))
        return (
            f"{len(trusts)} trust edges surfaced in {mode} mode; "
            f"{counts or 'no trust edges visible'}. "
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
        public_network_assets = sum(
            str(item.get("public_network_access") or "").lower() == "enabled"
            for item in assets
        )
        shared_key_assets = sum(item.get("allow_shared_key_access") is True for item in assets)
        return (
            f"{len(assets)} storage accounts visible; "
            f"{public_assets} allow public blob access, {public_network_assets} keep public "
            f"network access enabled, and {shared_key_assets} allow shared-key access."
        )

    if command == "snapshots-disks":
        assets = payload.get("snapshot_disk_assets", [])
        snapshots = sum(item.get("asset_kind") == "snapshot" for item in assets)
        detached = sum(item.get("attachment_state") == "detached" for item in assets)
        broad_access = sum(
            str(item.get("public_network_access") or "").lower() == "enabled"
            or str(item.get("network_access_policy") or "").lower() == "allowall"
            or item.get("max_shares") not in (None, 1)
            for item in assets
        )
        detached_label = "disk" if detached == 1 else "disks"
        return (
            f"{len(assets)} disk-backed assets visible; {snapshots} snapshots, {detached} "
            f"detached {detached_label}, and {broad_access} show broader sharing or export posture."
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

    if command == "workloads":
        workloads = payload.get("workloads", [])
        exposed = sum(bool(item.get("endpoints")) for item in workloads)
        identity_bearing = sum(bool(item.get("identity_type")) for item in workloads)
        compute_assets = sum(item.get("asset_kind") in {"VM", "VMSS"} for item in workloads)
        web_assets = len(workloads) - compute_assets
        return (
            f"{len(workloads)} workloads visible; {exposed} with visible endpoint paths, "
            f"{identity_bearing} with identity context, across {compute_assets} compute and "
            f"{web_assets} web assets."
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

    if command == "app-services":
        app_services = payload.get("app_services", [])
        https_only = sum(bool(item.get("https_only")) for item in app_services)
        public_network = sum(
            str(item.get("public_network_access") or "").lower() == "enabled"
            for item in app_services
        )
        identities = sum(bool(item.get("workload_identity_type")) for item in app_services)
        return (
            f"{len(app_services)} App Service apps visible; {public_network} keep public "
            f"network access enabled, {https_only} enforce HTTPS-only, and {identities} carry "
            "managed identity context."
        )

    if command == "acr":
        registries = payload.get("registries", [])
        public_network = sum(
            str(item.get("public_network_access") or "").lower() == "enabled"
            for item in registries
        )
        admin_auth = sum(item.get("admin_user_enabled") is True for item in registries)
        webhook_counts = [item.get("webhook_count") for item in registries]
        readable_webhooks = sum(count for count in webhook_counts if isinstance(count, int))
        if webhook_counts and any(count is None for count in webhook_counts):
            if readable_webhooks:
                webhook_phrase = (
                    f"at least {readable_webhooks} webhooks are visible, with some "
                    "registries unreadable"
                )
            else:
                webhook_phrase = (
                    "webhook visibility is unreadable from at least one visible registry"
                )
        else:
            webhook_phrase = f"{readable_webhooks} webhooks are visible"
        replication_counts = [item.get("replication_count") for item in registries]
        readable_replicated = sum(
            bool(item.get("replication_regions"))
            for item in registries
            if isinstance(item.get("replication_count"), int)
        )
        if replication_counts and any(count is None for count in replication_counts):
            if readable_replicated:
                replication_phrase = (
                    f"at least {readable_replicated} registries show replicated regions, "
                    "with some registries unreadable"
                )
            else:
                replication_phrase = (
                    "replication visibility is unreadable from at least one visible registry"
                )
        elif readable_replicated == 1:
            replication_phrase = "1 registry replicates content into additional regions"
        else:
            replication_phrase = (
                f"{readable_replicated} registries replicate content into additional regions"
            )
        return (
            f"{len(registries)} registries visible; {public_network} keep public network access "
            f"enabled, {admin_auth} allow admin-user auth, {webhook_phrase}, and "
            f"{replication_phrase}."
        )

    if command == "databases":
        database_servers = payload.get("database_servers", [])
        public_servers = sum(
            str(item.get("public_network_access") or "").lower() == "enabled"
            for item in database_servers
        )
        identities = sum(bool(item.get("workload_identity_type")) for item in database_servers)
        engines = {item.get("engine") for item in database_servers if item.get("engine")}
        database_counts = [item.get("database_count") for item in database_servers]
        readable_databases = sum(count for count in database_counts if isinstance(count, int))
        if database_counts and any(count is None for count in database_counts):
            if readable_databases:
                database_phrase = (
                    f"at least {readable_databases} user databases are visible, with some "
                    "servers unreadable"
                )
            else:
                database_phrase = (
                    "database visibility is unreadable from at least one visible server"
                )
        else:
            database_phrase = f"{readable_databases} user databases are visible"
        return (
            f"{len(database_servers)} relational database servers visible across "
            f"{len(engines)} engine families; {public_servers} keep public network access "
            f"enabled, {identities} carry managed identity context, and {database_phrase}."
        )

    if command == "dns":
        dns_zones = payload.get("dns_zones", [])
        public_zones = sum(item.get("zone_kind") == "public" for item in dns_zones)
        private_zones = sum(item.get("zone_kind") == "private" for item in dns_zones)
        private_endpoint_linked = sum(
            (item.get("private_endpoint_reference_count") or 0) > 0 for item in dns_zones
        )
        record_counts = [item.get("record_set_count") for item in dns_zones]
        readable_records = sum(count for count in record_counts if isinstance(count, int))
        if record_counts and any(count is None for count in record_counts):
            if readable_records:
                record_phrase = (
                    f"at least {readable_records} record sets are visible, with some zones "
                    "unreadable"
                )
            else:
                record_phrase = (
                    "record-set totals are unreadable from at least one visible zone"
                )
        else:
            record_phrase = f"{readable_records} record sets are visible"
        return (
            f"{len(dns_zones)} DNS zones visible; {public_zones} public, {private_zones} "
            f"private, {private_endpoint_linked} private zone(s) show visible private endpoint "
            f"references, and {record_phrase}."
        )

    if command == "network-effective":
        effective_exposures = payload.get("effective_exposures", [])
        by_confidence = Counter(
            str(item.get("effective_exposure") or "unknown").lower()
            for item in effective_exposures
        )
        internet_exposed = sum(
            1 for item in effective_exposures if item.get("internet_exposed_ports")
        )
        return (
            f"{len(effective_exposures)} public-IP exposure summaries visible; "
            f"{by_confidence.get('high', 0)} high, {by_confidence.get('medium', 0)} medium, "
            f"{by_confidence.get('low', 0)} low, and {internet_exposed} show broad "
            "internet-facing allow evidence."
        )

    if command == "aks":
        clusters = payload.get("aks_clusters", [])
        private_clusters = sum(item.get("private_cluster_enabled") is True for item in clusters)
        identities = sum(bool(item.get("cluster_identity_type")) for item in clusters)
        azure_rbac = sum(item.get("azure_rbac_enabled") is True for item in clusters)
        federation = sum(
            item.get("oidc_issuer_enabled") is True
            or item.get("workload_identity_enabled") is True
            for item in clusters
        )
        return (
            f"{len(clusters)} AKS clusters visible; {private_clusters} use private API "
            f"endpoints, {identities} expose cluster identity context, {azure_rbac} enable "
            f"Azure RBAC, and {federation} show Azure-side federation cues."
        )

    if command == "api-mgmt":
        services = payload.get("api_management_services", [])
        public_network = sum(
            str(item.get("public_network_access") or "").lower() == "enabled"
            for item in services
        )
        identities = sum(bool(item.get("workload_identity_type")) for item in services)
        named_value_counts = [item.get("named_value_count") for item in services]
        readable_named_values = sum(
            count for count in named_value_counts if isinstance(count, int)
        )
        if named_value_counts and any(count is None for count in named_value_counts):
            if readable_named_values:
                named_value_phrase = (
                    f"at least {readable_named_values} named values are visible, with some "
                    "services unreadable"
                )
            else:
                named_value_phrase = (
                    "named value visibility is unreadable from at least one visible service"
                )
        else:
            named_value_phrase = f"{readable_named_values} named values are visible"
        secret_named_value_counts = [
            item.get("named_value_secret_count") for item in services
        ]
        readable_secret_named_values = sum(
            count for count in secret_named_value_counts if isinstance(count, int)
        )
        secret_phrase = (
            f", including {readable_secret_named_values} marked secret"
            if secret_named_value_counts
            and all(isinstance(count, int) for count in secret_named_value_counts)
            else ""
        )
        return (
            f"{len(services)} API Management services visible; {public_network} keep public "
            f"network access enabled, {identities} carry managed identity context, and "
            f"{named_value_phrase}{secret_phrase}."
        )

    if command == "functions":
        function_apps = payload.get("function_apps", [])
        identities = sum(bool(item.get("workload_identity_type")) for item in function_apps)
        run_from_package = sum(bool(item.get("run_from_package")) for item in function_apps)
        keyvault_backed = sum(
            bool((item.get("key_vault_reference_count") or 0) > 0) for item in function_apps
        )
        return (
            f"{len(function_apps)} Function Apps visible; {identities} carry managed identity "
            f"context, {run_from_package} show run-from-package deployment, and "
            f"{keyvault_backed} include Key Vault-backed settings."
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


def _app_service_identity_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("workload_identity_type"):
        parts.append(str(item.get("workload_identity_type")))
    if item.get("workload_identity_ids"):
        parts.append(f"user-assigned={len(item.get('workload_identity_ids', []))}")
    if not parts:
        return "-"
    return "; ".join(parts)


def _app_service_exposure_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("default_hostname"):
        parts.append("hostname")
    if item.get("public_network_access"):
        parts.append(f"public={item.get('public_network_access')}")
    if not parts:
        return "-"
    return "; ".join(parts)


def _optional_count_text(value: object) -> str:
    if value is None:
        return "unknown"
    return str(value)


def _app_service_posture_context(item: dict) -> str:
    parts = [f"https={'yes' if item.get('https_only') else 'no'}"]
    if item.get("min_tls_version"):
        parts.append(f"tls={item.get('min_tls_version')}")
    if item.get("ftps_state"):
        parts.append(f"ftps={item.get('ftps_state')}")
    if item.get("client_cert_enabled"):
        parts.append("client-cert=yes")
    return "; ".join(parts)


def _acr_auth_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("admin_user_enabled") is True:
        parts.append("admin=yes")
    elif item.get("admin_user_enabled") is False:
        parts.append("admin=no")
    if item.get("anonymous_pull_enabled") is True:
        parts.append("anon-pull=yes")
    elif item.get("anonymous_pull_enabled") is False:
        parts.append("anon-pull=no")
    if not parts:
        return "-"
    return "; ".join(parts)


def _acr_exposure_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("public_network_access"):
        parts.append(f"public={item.get('public_network_access')}")
    if item.get("network_rule_default_action"):
        parts.append(f"default={item.get('network_rule_default_action')}")
    parts.append(f"pe={item.get('private_endpoint_connection_count', 0)}")
    return "; ".join(parts)


def _acr_posture_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("sku_name"):
        parts.append(str(item.get("sku_name")))
    if item.get("network_rule_bypass_options"):
        parts.append(f"bypass={item.get('network_rule_bypass_options')}")
    if item.get("data_endpoint_enabled") is True:
        parts.append("data-endpoint=yes")
    elif item.get("data_endpoint_enabled") is False:
        parts.append("data-endpoint=no")
    if item.get("quarantine_policy_status"):
        parts.append(f"quarantine={item.get('quarantine_policy_status')}")
    retention_status = item.get("retention_policy_status")
    if retention_status == "enabled" and item.get("retention_policy_days") is not None:
        parts.append(f"retention={item.get('retention_policy_days')}d")
    elif retention_status:
        parts.append(f"retention={retention_status}")
    trust_status = item.get("trust_policy_status")
    if trust_status == "enabled" and item.get("trust_policy_type"):
        parts.append(f"trust={item.get('trust_policy_type')}")
    elif trust_status:
        parts.append(f"trust={trust_status}")
    if not parts:
        return "-"
    return "; ".join(parts)


def _acr_depth_context(item: dict) -> str:
    parts: list[str] = []
    webhook_count = item.get("webhook_count")
    enabled_webhook_count = item.get("enabled_webhook_count")
    if webhook_count is not None:
        parts.append(f"webhooks={webhook_count}")
    if enabled_webhook_count is not None:
        parts.append(f"enabled={enabled_webhook_count}")
    if item.get("broad_webhook_scope_count"):
        parts.append(f"wide-scopes={item.get('broad_webhook_scope_count')}")
    if item.get("webhook_action_types"):
        parts.append(f"actions={','.join(item.get('webhook_action_types', []))}")
    replication_count = item.get("replication_count")
    if replication_count is not None:
        parts.append(f"replications={replication_count}")
    if item.get("replication_regions"):
        parts.append(f"regions={','.join(item.get('replication_regions', []))}")
    if not parts:
        return "-"
    return "; ".join(parts)


def _database_inventory_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("database_count") is not None:
        parts.append(f"dbs={item.get('database_count')}")
    if item.get("user_database_names"):
        parts.append(",".join(item.get("user_database_names", [])))
    if not parts:
        return "-"
    return "; ".join(parts)


def _database_exposure_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("fully_qualified_domain_name"):
        parts.append("fqdn")
    if item.get("public_network_access"):
        parts.append(f"public={item.get('public_network_access')}")
    if not parts:
        return "-"
    return "; ".join(parts)


def _database_posture_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("minimal_tls_version"):
        parts.append(f"tls={item.get('minimal_tls_version')}")
    if item.get("server_version"):
        parts.append(f"version={item.get('server_version')}")
    if item.get("high_availability_mode"):
        parts.append(f"ha={item.get('high_availability_mode')}")
    if item.get("delegated_subnet_resource_id"):
        parts.append("delegated-subnet=yes")
    if item.get("private_dns_zone_resource_id"):
        parts.append("private-dns=yes")
    if item.get("state"):
        parts.append(f"state={item.get('state')}")
    if not parts:
        return "-"
    return "; ".join(parts)


def _dns_inventory_context(item: dict) -> str:
    count = item.get("record_set_count")
    max_count = item.get("max_record_set_count")
    if count is None and max_count is None:
        return "-"
    if count is None:
        return f"records=?/{max_count}"
    if max_count is None:
        return f"records={count}"
    return f"records={count}/{max_count}"


def _dns_namespace_context(item: dict) -> str:
    if item.get("zone_kind") == "public":
        name_server_count = len(item.get("name_servers", []))
        return f"ns={name_server_count}" if name_server_count else "-"

    parts: list[str] = []
    if item.get("linked_virtual_network_count") is not None:
        parts.append(f"vnet-links={item.get('linked_virtual_network_count')}")
    if item.get("registration_virtual_network_count") is not None:
        parts.append(f"reg-links={item.get('registration_virtual_network_count')}")
    if item.get("private_endpoint_reference_count") is not None:
        parts.append(f"pe-refs={item.get('private_endpoint_reference_count')}")
    if not parts:
        return "-"
    return "; ".join(parts)


def _storage_exposure_context(item: dict) -> str:
    parts = [f"blob-public={'yes' if item.get('public_access') else 'no'}"]
    if item.get("public_network_access"):
        parts.append(f"public-net={str(item.get('public_network_access')).lower()}")
    if item.get("network_default_action"):
        parts.append(f"default={item.get('network_default_action')}")
    parts.append(f"private-endpoint={'yes' if item.get('private_endpoint_enabled') else 'no'}")
    return "; ".join(parts)


def _storage_auth_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("allow_shared_key_access") is True:
        parts.append("shared-key=yes")
    elif item.get("allow_shared_key_access") is False:
        parts.append("shared-key=no")
    if item.get("minimum_tls_version"):
        parts.append(f"tls={item.get('minimum_tls_version')}")
    if item.get("https_traffic_only_enabled") is True:
        parts.append("https-only=yes")
    elif item.get("https_traffic_only_enabled") is False:
        parts.append("https-only=no")
    if not parts:
        return "-"
    return "; ".join(parts)


def _storage_protocol_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("is_hns_enabled") is True:
        parts.append("hns=yes")
    elif item.get("is_hns_enabled") is False:
        parts.append("hns=no")
    if item.get("is_sftp_enabled") is True:
        parts.append("sftp=yes")
    elif item.get("is_sftp_enabled") is False:
        parts.append("sftp=no")
    if item.get("nfs_v3_enabled") is True:
        parts.append("nfs=yes")
    elif item.get("nfs_v3_enabled") is False:
        parts.append("nfs=no")
    if item.get("dns_endpoint_type"):
        parts.append(f"dns={str(item.get('dns_endpoint_type')).lower()}")
    if not parts:
        return "-"
    return "; ".join(parts)


def _storage_inventory_context(item: dict) -> str:
    parts: list[str] = []
    for key, label in (
        ("container_count", "blob"),
        ("file_share_count", "file"),
        ("queue_count", "queue"),
        ("table_count", "table"),
    ):
        value = item.get(key)
        if value is not None:
            parts.append(f"{label}={value}")
    if not parts:
        return "-"
    return "; ".join(parts)


def _snapshot_disk_priority_context(item: dict) -> str:
    reasons: list[str] = []
    if item.get("attachment_state") == "detached":
        reasons.append("detached")
    if item.get("asset_kind") == "snapshot":
        reasons.append("offline-copy")
    if str(item.get("public_network_access") or "").lower() == "enabled":
        reasons.append("public-net")
    if str(item.get("network_access_policy") or "").lower() == "allowall":
        reasons.append("allow-all")
    if item.get("max_shares") not in (None, 1):
        reasons.append(f"shared={item.get('max_shares')}")
    if item.get("disk_access_id"):
        reasons.append("disk-access")
    if not reasons:
        return "baseline"
    return ", ".join(reasons)


def _snapshot_disk_attachment_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("attachment_state") == "snapshot":
        parts.append(f"source={item.get('source_resource_name') or '-'}")
        if item.get("incremental") is True:
            parts.append("incremental=yes")
    elif item.get("attached_to_name"):
        parts.append(f"attached={item.get('attached_to_name')}")
        if item.get("disk_role"):
            parts.append(f"role={item.get('disk_role')}")
    else:
        parts.append("detached")
    return "; ".join(parts)


def _snapshot_disk_sharing_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("network_access_policy"):
        parts.append(f"policy={item.get('network_access_policy')}")
    if item.get("public_network_access"):
        parts.append(f"public={item.get('public_network_access')}")
    if item.get("max_shares") is not None:
        parts.append(f"max-shares={item.get('max_shares')}")
    if item.get("disk_access_id"):
        parts.append("disk-access=yes")
    if not parts:
        return "-"
    return "; ".join(parts)


def _snapshot_disk_encryption_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("encryption_type"):
        parts.append(f"type={item.get('encryption_type')}")
    if item.get("disk_encryption_set_id"):
        parts.append("des=yes")
    else:
        parts.append("des=no")
    if item.get("os_type"):
        parts.append(f"os={item.get('os_type')}")
    if item.get("size_gb") is not None:
        parts.append(f"size={item.get('size_gb')}g")
    return "; ".join(parts)


def _aks_version_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("kubernetes_version"):
        parts.append(f"k8s={item.get('kubernetes_version')}")
    if item.get("agent_pool_count") is not None:
        parts.append(f"pools={item.get('agent_pool_count')}")
    if item.get("sku_tier"):
        parts.append(f"tier={item.get('sku_tier')}")
    if not parts:
        return "-"
    return "; ".join(parts)


def _aks_identity_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("cluster_identity_type"):
        parts.append(str(item.get("cluster_identity_type")))
    if item.get("cluster_identity_ids"):
        parts.append(f"user-assigned={len(item.get('cluster_identity_ids', []))}")
    if item.get("cluster_identity_type") == "ServicePrincipal" and item.get("cluster_client_id"):
        parts.append("client-id=yes")
    if item.get("workload_identity_enabled") is True:
        parts.append("workload-id=yes")
    elif item.get("workload_identity_enabled") is False:
        parts.append("workload-id=no")
    if not parts:
        return "-"
    return "; ".join(parts)


def _aks_endpoint_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("private_cluster_enabled") is True:
        parts.append("private-api=yes")
    elif item.get("private_cluster_enabled") is False:
        parts.append("private-api=no")
    if item.get("fqdn"):
        parts.append("fqdn")
    if item.get("private_fqdn"):
        parts.append("private-fqdn")
    if item.get("public_fqdn_enabled") is True:
        parts.append("public-fqdn=yes")
    elif item.get("public_fqdn_enabled") is False and item.get("private_cluster_enabled") is True:
        parts.append("public-fqdn=no")
    if not parts:
        return "-"
    return "; ".join(parts)


def _aks_auth_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("aad_managed") is True:
        parts.append("aad=yes")
    elif item.get("aad_managed") is False:
        parts.append("aad=no")
    if item.get("azure_rbac_enabled") is True:
        parts.append("azure-rbac=yes")
    elif item.get("azure_rbac_enabled") is False:
        parts.append("azure-rbac=no")
    if item.get("local_accounts_disabled") is True:
        parts.append("local-accounts=disabled")
    elif item.get("local_accounts_disabled") is False:
        parts.append("local-accounts=enabled")
    if item.get("oidc_issuer_enabled") is True:
        parts.append("oidc=yes")
    elif item.get("oidc_issuer_enabled") is False:
        parts.append("oidc=no")
    if not parts:
        return "-"
    return "; ".join(parts)


def _aks_network_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("network_plugin"):
        parts.append(f"plugin={item.get('network_plugin')}")
    if item.get("network_policy"):
        parts.append(f"policy={item.get('network_policy')}")
    if item.get("outbound_type"):
        parts.append(f"outbound={item.get('outbound_type')}")
    if item.get("addon_names"):
        parts.append(f"addons={len(item.get('addon_names', []))}")
    if item.get("web_app_routing_enabled") is True:
        parts.append("webapp-routing=yes")
    elif item.get("web_app_routing_enabled") is False:
        parts.append("webapp-routing=no")
    if item.get("node_resource_group"):
        parts.append(f"node-rg={item.get('node_resource_group')}")
    if not parts:
        return "-"
    return "; ".join(parts)


def _function_runtime_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("runtime_stack"):
        parts.append(str(item.get("runtime_stack")))
    if item.get("functions_extension_version"):
        parts.append(f"functions={item.get('functions_extension_version')}")
    if not parts:
        return "-"
    return "; ".join(parts)


def _function_deployment_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("azure_webjobs_storage_value_type"):
        parts.append(f"storage={item.get('azure_webjobs_storage_value_type')}")
    if item.get("run_from_package") is True:
        parts.append("package=yes")
    elif item.get("run_from_package") is False:
        parts.append("package=disabled")
    if item.get("key_vault_reference_count") is not None:
        parts.append(f"kv-refs={item.get('key_vault_reference_count')}")
    if not parts:
        return "-"
    return "; ".join(parts)


def _function_posture_context(item: dict) -> str:
    parts = [f"https={'yes' if item.get('https_only') else 'no'}"]
    if item.get("min_tls_version"):
        parts.append(f"tls={item.get('min_tls_version')}")
    if item.get("ftps_state"):
        parts.append(f"ftps={item.get('ftps_state')}")
    if item.get("always_on") is True:
        parts.append("always-on=yes")
    elif item.get("always_on") is False:
        parts.append("always-on=no")
    return "; ".join(parts)


def _api_mgmt_inventory_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("api_count") is not None:
        parts.append(f"apis={item.get('api_count')}")
    if item.get("api_subscription_required_count") is not None:
        if item.get("api_count") is not None:
            parts.append(
                "sub-required="
                f"{item.get('api_subscription_required_count')}/{item.get('api_count')}"
            )
        else:
            parts.append(f"sub-required={item.get('api_subscription_required_count')}")
    if item.get("subscription_count") is not None:
        parts.append(f"subs={item.get('subscription_count')}")
    if item.get("active_subscription_count") is not None:
        parts.append(f"active-subs={item.get('active_subscription_count')}")
    if item.get("backend_count") is not None:
        parts.append(f"backends={item.get('backend_count')}")
    if item.get("backend_hostnames"):
        parts.append(f"backend-hosts={len(item.get('backend_hostnames', []))}")
    if item.get("named_value_count") is not None:
        parts.append(f"named-values={item.get('named_value_count')}")
    if not parts:
        return "-"
    return "; ".join(parts)


def _api_mgmt_exposure_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("gateway_hostnames"):
        parts.append(f"gateway={len(item.get('gateway_hostnames', []))}")
    if item.get("management_hostnames"):
        parts.append(f"management={len(item.get('management_hostnames', []))}")
    if item.get("portal_hostnames"):
        parts.append(f"portal={len(item.get('portal_hostnames', []))}")
    if item.get("public_network_access"):
        parts.append(f"public={item.get('public_network_access')}")
    if item.get("public_ip_addresses"):
        parts.append(f"public-ip={len(item.get('public_ip_addresses', []))}")
    if not parts:
        return "-"
    return "; ".join(parts)


def _api_mgmt_posture_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("sku_name"):
        parts.append(str(item.get("sku_name")))
    if item.get("virtual_network_type"):
        parts.append(f"vnet={item.get('virtual_network_type')}")
    if item.get("gateway_enabled") is True:
        parts.append("gateway=yes")
    elif item.get("gateway_enabled") is False:
        parts.append("gateway=no")
    if item.get("developer_portal_status"):
        parts.append(f"devportal={item.get('developer_portal_status')}")
    if item.get("named_value_secret_count") is not None:
        parts.append(f"named-secrets={item.get('named_value_secret_count')}")
    if item.get("named_value_key_vault_count") is not None:
        parts.append(f"kv-backed={item.get('named_value_key_vault_count')}")
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


def _workload_identity_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("identity_type"):
        parts.append(str(item.get("identity_type")))
    if item.get("identity_ids"):
        parts.append(f"ids={len(item.get('identity_ids', []))}")
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
