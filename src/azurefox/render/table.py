from __future__ import annotations

from collections import Counter
from io import StringIO
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table

from azurefox.devops_hints import describe_trusted_input, devops_next_review_hint
from azurefox.env_var_hints import env_var_next_review_hint
from azurefox.tokens_credential_hints import tokens_credential_next_review_hint


def render_table(command: str, payload: dict) -> str:
    sio = StringIO()
    console = Console(file=sio, force_terminal=False, color_system=None, width=160)

    if command == "devops":
        _render_devops_table(console, payload)
    elif command == "chains" and str(payload.get("family") or "") == "deployment-path":
        _render_deployment_path_table(console, payload)
    elif command == "chains" and str(payload.get("family") or "") == "escalation-path":
        _render_escalation_path_table(console, payload)
    else:
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
        console.print("Credential-scope issues:")
        for issue in issues[:5]:
            kind = issue.get("kind") or "unknown"
            console.print(f"- {kind}: {issue.get('message')}", markup=False)
        remaining = len(issues) - 5
        if remaining > 0:
            console.print(f"- ... plus {remaining} more credential-scope issues in JSON artifacts.")

    takeaway = _takeaway_for_command(command, payload)
    if takeaway:
        console.print("")
        console.print(f"Takeaway: {takeaway}")

    return sio.getvalue()


def _render_devops_table(console: Console, payload: dict) -> None:
    columns, records = _table_spec("devops", payload)
    display_columns = [item for item in columns if item[0] != "why_it_matters"]

    if not records:
        table = Table(title="azurefox devops")
        table.add_column("info")
        table.add_row("No records")
        console.print(table)
        return

    for index, record in enumerate(records):
        table = Table(title="azurefox devops" if index == 0 else None)
        for _key, label in display_columns:
            table.add_column(label)
        table.add_row(*[_value_to_string(record.get(key)) for key, _ in display_columns])
        console.print(table)
        if record.get("why_it_matters"):
            detail = Table(expand=True)
            detail.add_column("why it matters")
            detail.add_row(_value_to_string(record.get("why_it_matters")))
            console.print(detail)
        if index != len(records) - 1:
            console.print("")


def _render_deployment_path_table(console: Console, payload: dict) -> None:
    columns, records = _table_spec("chains", payload)
    display_columns = [item for item in columns if item[0] != "why_care"]

    if not records:
        table = Table(title="azurefox chains")
        table.add_column("info")
        table.add_row("No records")
        console.print(table)
        return

    for index, record in enumerate(records):
        table = Table(title="azurefox chains" if index == 0 else None)
        for _key, label in display_columns:
            table.add_column(label)
        table.add_row(*[_value_to_string(record.get(key)) for key, _ in display_columns])
        console.print(table)
        if record.get("why_care"):
            detail = Table(expand=True)
            detail.add_column("why care")
            detail.add_row(_value_to_string(record.get("why_care")))
            console.print(detail)
        if index != len(records) - 1:
            console.print("")


def _render_escalation_path_table(console: Console, payload: dict) -> None:
    columns, records = _table_spec("chains", payload)
    display_columns = [item for item in columns if item[0] != "why_care"]

    if not records:
        table = Table(title="azurefox chains")
        table.add_column("info")
        table.add_row("No records")
        console.print(table)
        return

    for index, record in enumerate(records):
        table = Table(title="azurefox chains" if index == 0 else None)
        for _key, label in display_columns:
            table.add_column(label)
        table.add_row(*[_value_to_string(record.get(key)) for key, _ in display_columns])
        console.print(table)
        if record.get("why_care"):
            detail = Table(expand=True)
            detail.add_column("why care")
            detail.add_row(_value_to_string(record.get("why_care")))
            console.print(detail)
        if index != len(records) - 1:
            console.print("")


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

    if command == "automation":
        return (
            [
                ("name", "automation account"),
                ("identity", "identity"),
                ("execution", "execution"),
                ("triggers", "triggers"),
                ("workers", "workers"),
                ("assets", "assets"),
                ("why_it_matters", "why it matters"),
            ],
            [
                {
                    "name": item.get("name"),
                    "identity": _automation_identity_context(item),
                    "execution": _automation_execution_context(item),
                    "triggers": _automation_trigger_context(item),
                    "workers": _automation_worker_context(item),
                    "assets": _automation_asset_context(item),
                    "why_it_matters": item.get("summary"),
                }
                for item in payload.get("automation_accounts", [])
            ],
        )

    if command == "devops":
        return (
            [
                ("project_name", "project"),
                ("name", "pipeline"),
                ("repository", "source"),
                ("triggers", "execution path"),
                ("injection", "injection"),
                ("azure_access", "control path"),
                ("secret_support", "secret support"),
                ("target_clues", "impact point"),
                ("next_review", "next review"),
                ("why_it_matters", "why it matters"),
            ],
            [
                {
                    "project_name": item.get("project_name"),
                    "name": item.get("name"),
                    "repository": _devops_repository_context(item),
                    "triggers": _devops_trigger_context(item),
                    "injection": _devops_injection_context(item),
                    "azure_access": _devops_access_context(item),
                    "secret_support": _devops_secret_context(item),
                    "target_clues": _devops_target_context(item),
                    "next_review": _devops_next_review(item),
                    "why_it_matters": item.get("summary"),
                }
                for item in payload.get("pipelines", [])
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

    if command == "application-gateway":
        return (
            [
                ("name", "gateway"),
                ("exposure", "exposure"),
                ("routing", "routing"),
                ("backends", "backends"),
                ("waf", "waf"),
                ("why_it_matters", "why it matters"),
            ],
            [
                {
                    "name": item.get("name"),
                    "exposure": _application_gateway_exposure_context(item),
                    "routing": _application_gateway_routing_context(item),
                    "backends": _application_gateway_backend_context(item),
                    "waf": _application_gateway_waf_context(item),
                    "why_it_matters": item.get("summary"),
                }
                for item in payload.get("application_gateways", [])
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
                ("next_review", "next review"),
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
                    "next_review": _env_var_next_review(item),
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
                ("next_review", "next review"),
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
                    "next_review": _tokens_credential_next_review(item),
                    "why_it_matters": item.get("summary"),
                }
                for item in payload.get("surfaces", [])
            ],
        )

    if command == "chains":
        family = str(payload.get("family") or "")
        if family == "deployment-path":
            return (
                [
                    ("priority", "priority"),
                    ("urgency", "urgency"),
                    ("asset_name", "source"),
                    ("path_concept", "path type"),
                    ("why_care", "why care"),
                    ("likely_impact", "likely azure impact"),
                    ("confidence_boundary", "confidence boundary"),
                    ("next_review", "next review"),
                ],
                [
                    {
                        "priority": item.get("priority"),
                        "urgency": item.get("urgency") or "-",
                        "asset_name": item.get("asset_name"),
                        "path_concept": _deployment_path_type(item),
                        "why_care": item.get("why_care") or item.get("asset_kind"),
                        "likely_impact": item.get("likely_impact") or _chains_target_context(item),
                        "confidence_boundary": item.get("confidence_boundary")
                        or _chains_note(item, family=family),
                        "next_review": item.get("next_review"),
                    }
                    for item in payload.get("paths", [])
                ],
            )
        if family == "escalation-path":
            return (
                [
                    ("priority", "priority"),
                    ("urgency", "urgency"),
                    ("asset_name", "starting foothold"),
                    ("path_concept", "path type"),
                    ("stronger_outcome", "stronger outcome"),
                    ("confidence_boundary", "confidence boundary"),
                    ("next_review", "next review"),
                    ("why_care", "why care"),
                ],
                [
                    {
                        "priority": item.get("priority"),
                        "urgency": item.get("urgency") or "-",
                        "asset_name": item.get("asset_name"),
                        "path_concept": _escalation_path_type(item),
                        "stronger_outcome": item.get("stronger_outcome") or item.get("likely_impact"),
                        "confidence_boundary": item.get("confidence_boundary")
                        or _chains_note(item, family=family),
                        "next_review": item.get("next_review"),
                        "why_care": item.get("why_care"),
                    }
                    for item in payload.get("paths", [])
                ],
            )
        return (
            [
                ("priority", "priority"),
                ("urgency", "urgency"),
                ("asset_name", "asset"),
                ("setting_name", "setting"),
                ("target_service", "target"),
                ("target_resolution", "target resolution"),
                ("target_names", "visible targets"),
                ("next_review", "next review"),
                ("note", "note"),
            ],
            [
                {
                    "priority": item.get("priority"),
                    "urgency": item.get("urgency") or "-",
                    "asset_name": item.get("asset_name"),
                    "setting_name": item.get("setting_name"),
                    "target_service": item.get("target_service"),
                    "target_resolution": item.get("target_resolution"),
                    "target_names": _chains_target_context(item),
                    "next_review": item.get("next_review"),
                    "note": _chains_note(item, family=family),
                }
                for item in payload.get("paths", [])
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
                ("scope_count", "scopes"),
                ("operator_signal", "operator signal"),
                ("next_review", "next review"),
            ],
            [
                {
                    "principal": item.get("display_name") or item.get("principal_id"),
                    "type": item.get("principal_type"),
                    "high_impact_roles": item.get("high_impact_roles", []),
                    "scope_count": item.get("scope_count", 0),
                    "operator_signal": item.get("operator_signal"),
                    "next_review": item.get("next_review"),
                }
                for item in payload.get("permissions", [])
            ],
        )

    if command == "privesc":
        return (
            [
                ("severity", "severity"),
                ("starting_foothold", "starting foothold"),
                ("path_type", "path"),
                ("target", "target"),
                ("operator_signal", "operator signal"),
                ("proof_boundary", "proof boundary"),
                ("next_review", "next review"),
            ],
            [
                {
                    "severity": item.get("severity"),
                    "starting_foothold": item.get("starting_foothold") or "unknown current foothold",
                    "path_type": item.get("path_type"),
                    "target": _privesc_target(item),
                    "operator_signal": item.get("operator_signal"),
                    "proof_boundary": _privesc_proof_boundary(item),
                    "next_review": item.get("next_review"),
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
                ("operator_signal", "operator signal"),
                ("next_review", "next review"),
            ],
            [
                {
                    "trust_type": item.get("trust_type"),
                    "source": item.get("source_name") or item.get("source_object_id"),
                    "target": item.get("target_name") or item.get("target_object_id"),
                    "confidence": item.get("confidence"),
                    "operator_signal": item.get("operator_signal"),
                    "next_review": item.get("next_review"),
                }
                for item in payload.get("trusts", [])
            ],
        )

    if command == "lighthouse":
        return (
            [
                ("scope", "scope"),
                ("managing_tenant", "managing tenant"),
                ("managed_tenant", "managed tenant"),
                ("access", "access"),
                ("state", "state"),
                ("why_it_matters", "why it matters"),
            ],
            [
                {
                    "scope": _lighthouse_scope_context(item),
                    "managing_tenant": (
                        item.get("managed_by_tenant_name")
                        or item.get("managed_by_tenant_id")
                        or "-"
                    ),
                    "managed_tenant": (
                        item.get("managee_tenant_name") or item.get("managee_tenant_id") or "-"
                    ),
                    "access": _lighthouse_access_context(item),
                    "state": _lighthouse_state_context(item),
                    "why_it_matters": item.get("summary"),
                }
                for item in payload.get("lighthouse_delegations", [])
            ],
        )

    if command == "cross-tenant":
        return (
            [
                ("name", "signal"),
                ("signal_type", "type"),
                ("tenant", "tenant"),
                ("scope", "scope"),
                ("posture", "posture"),
                ("attack_path", "attack path"),
                ("why_it_matters", "why it matters"),
            ],
            [
                {
                    "name": item.get("name"),
                    "signal_type": item.get("signal_type"),
                    "tenant": _cross_tenant_tenant_context(item),
                    "scope": item.get("scope"),
                    "posture": _cross_tenant_posture_context(item),
                    "attack_path": _cross_tenant_attack_path_context(item),
                    "why_it_matters": item.get("summary"),
                }
                for item in payload.get("cross_tenant_paths", [])
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
                ("operator_signal", "operator signal"),
                ("next_review", "next review"),
            ],
            [
                {
                    "name": item.get("name"),
                    "identity_type": item.get("identity_type"),
                    "attached_to": ", ".join(_display_resource_refs(item.get("attached_to"))),
                    "operator_signal": item.get("operator_signal"),
                    "next_review": item.get("next_review"),
                }
                for item in payload.get("identities", [])
            ],
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

    if command == "vmss":
        return (
            [
                ("name", "scale set"),
                ("location", "location"),
                ("sku_capacity", "sku / capacity"),
                ("orchestration", "orchestration"),
                ("identity", "identity"),
                ("frontend", "frontend"),
                ("network", "network"),
                ("why_it_matters", "why it matters"),
            ],
            [
                {
                    "name": item.get("name"),
                    "location": item.get("location"),
                    "sku_capacity": _vmss_capacity_context(item),
                    "orchestration": _vmss_rollout_context(item),
                    "identity": _vmss_identity_context(item),
                    "frontend": _vmss_frontend_context(item),
                    "network": _vmss_network_context(item),
                    "why_it_matters": item.get("summary"),
                }
                for item in payload.get("vmss_assets", [])
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
        rooted = sum(bool(item.get("current_identity")) for item in paths)
        visible_only = len(paths) - rooted
        if not counts:
            counts = "no meaningful paths"
        return (
            f"{len(paths)} privilege-escalation paths surfaced; {rooted} current-identity-rooted, "
            f"{visible_only} visible-only leads, {counts}."
        )

    if command == "role-trusts":
        trusts = payload.get("trusts", [])
        mode = payload.get("mode") or "fast"
        families = Counter(item.get("trust_type") or "unknown" for item in trusts)
        counts = ", ".join(f"{count} {name}" for name, count in sorted(families.items()))
        privilege_follow_ons = sum(
            "privilege confirmation next" in str(item.get("operator_signal") or "").lower()
            for item in trusts
        )
        ownership_follow_ons = sum(
            "ownership review next" in str(item.get("operator_signal") or "").lower()
            for item in trusts
        )
        outside_follow_ons = sum(
            "outside-tenant follow-on" in str(item.get("operator_signal") or "").lower()
            for item in trusts
        )
        return (
            f"{len(trusts)} trust edges surfaced in {mode} mode; "
            f"{counts or 'no trust edges visible'}. "
            f"{privilege_follow_ons} privilege-confirmation follow-ons, "
            f"{ownership_follow_ons} ownership-review follow-ons, and "
            f"{outside_follow_ons} outside-tenant follow-ons. "
            "Delegated and admin consent grants are out of scope for this command."
        )

    if command == "lighthouse":
        delegations = payload.get("lighthouse_delegations", [])
        subscription_scope = sum(item.get("scope_type") == "subscription" for item in delegations)
        eligible = sum((item.get("eligible_authorization_count") or 0) > 0 for item in delegations)
        broad_roles = sum(
            bool(item.get("has_owner_role")) or bool(item.get("has_user_access_administrator"))
            for item in delegations
        )
        return (
            f"{len(delegations)} Azure Lighthouse delegation(s) visible; "
            f"{subscription_scope} are subscription-scoped, {broad_roles} grant Owner or "
            f"User Access Administrator, and {eligible} include eligible access."
        )

    if command == "cross-tenant":
        paths = payload.get("cross_tenant_paths", [])
        high = sum(str(item.get("priority") or "").lower() == "high" for item in paths)
        lighthouse = sum(item.get("signal_type") == "lighthouse" for item in paths)
        external_sp = sum(item.get("signal_type") == "external-sp" for item in paths)
        policy = sum(item.get("signal_type") == "policy" for item in paths)
        return (
            f"{len(paths)} cross-tenant signal(s) visible; {high} high priority, "
            f"{lighthouse} delegated management, {external_sp} externally owned service "
            f"principal, and {policy} tenant policy cue."
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
            f"{len(issues)} credential-scope issues visible from current credentials."
        )

    if command == "permissions":
        permissions = payload.get("permissions", [])
        privileged = sum(bool(item.get("privileged")) for item in permissions)
        workload_pivots = sum(
            "workload pivot visible" in str(item.get("operator_signal") or "").lower()
            for item in permissions
        )
        trust_follow_ons = sum(
            "trust expansion follow-on" in str(item.get("operator_signal") or "").lower()
            for item in permissions
        )
        return (
            f"{privileged} of {len(permissions)} principals hold high-impact RBAC roles; "
            f"{workload_pivots} workload-pivot follow-ons and {trust_follow_ons} trust-expansion "
            "follow-ons."
        )

    if command == "managed-identities":
        identities = payload.get("identities", [])
        exposed = sum(
            "workload pivot" in str(item.get("operator_signal") or "").lower()
            and (
                str(item.get("operator_signal") or "").startswith("Public")
                or str(item.get("operator_signal") or "").startswith("Exposed")
            )
            for item in identities
        )
        direct_control = sum(
            "direct control visible" in str(item.get("operator_signal") or "").lower()
            for item in identities
        )
        return (
            f"{len(identities)} managed identities visible; {exposed} exposed workload pivots "
            f"and {direct_control} direct-control cues from current scope."
        )

    if command == "storage":
        assets = payload.get("storage_assets", [])
        public_assets = sum(bool(item.get("public_access")) for item in assets)
        public_network_assets = sum(
            str(item.get("public_network_access") or "").lower() == "enabled" for item in assets
        )
        shared_key_assets = sum(item.get("allow_shared_key_access") is True for item in assets)
        public_network_unreadable = sum(
            item.get("public_network_access") is None for item in assets
        )
        shared_key_unreadable = sum(item.get("allow_shared_key_access") is None for item in assets)
        posture_parts = [
            f"{public_assets} allow public blob access",
            f"{public_network_assets} keep public network access enabled",
        ]
        if public_network_unreadable:
            posture_parts.append(
                f"{public_network_unreadable} have unreadable public-network posture"
            )
        posture_parts.append(f"{shared_key_assets} allow shared-key access")
        if shared_key_unreadable:
            posture_parts.append(f"{shared_key_unreadable} have unreadable shared-key posture")
        return f"{len(assets)} storage accounts visible; {', '.join(posture_parts)}."

    if command == "snapshots-disks":
        assets = payload.get("snapshot_disk_assets", [])
        snapshots = sum(item.get("asset_kind") == "snapshot" for item in assets)
        detached = sum(item.get("attachment_state") == "detached" for item in assets)
        broad_access = sum(
            str(item.get("public_network_access") or "").lower() == "enabled"
            or str(item.get("network_access_policy") or "").lower() == "allowall"
            or item.get("max_shares") not in (None, 1)
            or bool(item.get("disk_access_id"))
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

    if command == "vmss":
        vmss_assets = payload.get("vmss_assets", [])
        identity_assets = sum(bool(item.get("identity_type")) for item in vmss_assets)
        public_frontend_assets = sum(
            (item.get("public_ip_configuration_count") or 0) > 0 for item in vmss_assets
        )
        configured_instances = sum(
            item.get("instance_count", 0)
            for item in vmss_assets
            if isinstance(item.get("instance_count"), int)
        )
        return (
            f"{len(vmss_assets)} VM scale sets visible; {public_frontend_assets} show public "
            f"frontend cues, {identity_assets} carry managed identity context, and "
            f"{configured_instances} configured instances are visible."
        )

    if command == "inventory":
        return (
            f"{payload.get('resource_count', 0)} resources across "
            f"{payload.get('resource_group_count', 0)} resource groups."
        )

    if command == "automation":
        automation_accounts = payload.get("automation_accounts", [])
        identity_accounts = sum(bool(item.get("identity_type")) for item in automation_accounts)
        webhook_accounts = sum(
            _value_gt_zero(item.get("webhook_count")) for item in automation_accounts
        )
        worker_accounts = sum(
            _value_gt_zero(item.get("hybrid_worker_group_count")) for item in automation_accounts
        )
        published_runbooks = sum(
            item.get("published_runbook_count", 0)
            for item in automation_accounts
            if isinstance(item.get("published_runbook_count"), int)
        )
        return (
            f"{len(automation_accounts)} Automation account(s) visible; {identity_accounts} carry "
            f"managed identity context, {webhook_accounts} expose webhook start paths, "
            f"{worker_accounts} show Hybrid Runbook Worker reach, and {published_runbooks} "
            "published runbooks are visible."
        )

    if command == "devops":
        pipelines = payload.get("pipelines", [])
        proven_injection = sum(
            bool(item.get("current_operator_injection_surface_types")) for item in pipelines
        )
        queue_only = sum(
            bool(item.get("current_operator_can_queue"))
            and not bool(item.get("current_operator_injection_surface_types"))
            for item in pipelines
        )
        non_repo_trust = sum(
            any(str(value) != "repository" for value in (item.get("trusted_input_types") or []))
            for item in pipelines
        )
        azure_paths = sum(bool(item.get("azure_service_connection_names")) for item in pipelines)
        visible_azure_repos = sum(
            item.get("repository_host_type") == "azure-repos"
            and item.get("source_visibility_state") == "visible"
            for item in pipelines
        )
        external_sources = sum(
            str(item.get("source_visibility_state") or "") == "external-reference"
            for item in pipelines
        )
        return (
            f"{len(pipelines)} Azure DevOps build definition(s) surfaced; "
            f"{proven_injection} expose a proven current-credential injection point, "
            f"{queue_only} add queue-only support without poisoning proof, "
            f"{visible_azure_repos} "
            f"point to visible Azure Repos sources, {external_sources} point to external "
            f"sources, {non_repo_trust} trust non-repo inputs, and {azure_paths} show "
            f"Azure-facing service connections."
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
            str(item.get("public_network_access") or "").lower() == "enabled" for item in registries
        )
        admin_auth = sum(item.get("admin_user_enabled") is True for item in registries)
        webhook_counts = [item.get("webhook_count") for item in registries]
        readable_webhooks = sum(count for count in webhook_counts if isinstance(count, int))
        if webhook_counts and any(count is None for count in webhook_counts):
            if readable_webhooks:
                webhook_phrase = (
                    f"at least {readable_webhooks} webhooks are visible, with some "
                    "registries outside current credential visibility"
                )
            else:
                webhook_phrase = (
                    "current credentials do not show webhook visibility on at least one "
                    "visible registry"
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
                    "with some registries outside current credential visibility"
                )
            else:
                replication_phrase = (
                    "current credentials do not show replication visibility on at least one "
                    "visible registry"
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
                    "servers outside current credential visibility"
                )
            else:
                database_phrase = (
                    "current credentials do not show database visibility on at least one "
                    "visible server"
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
                    "outside current credential visibility"
                )
            else:
                record_phrase = (
                    "current credentials do not show record-set totals on at least one visible zone"
                )
        else:
            record_phrase = f"{readable_records} record sets are visible"
        return (
            f"{len(dns_zones)} DNS zones visible; {public_zones} public, {private_zones} "
            f"private, {private_endpoint_linked} private zone(s) show visible private endpoint "
            f"references, and {record_phrase}."
        )

    if command == "application-gateway":
        application_gateways = payload.get("application_gateways", [])
        public_gateways = sum(
            (item.get("public_frontend_count") or 0) > 0 for item in application_gateways
        )
        shared_public_gateways = sum(
            (item.get("public_frontend_count") or 0) > 0
            and (
                (item.get("backend_pool_count") or 0) > 1
                or (item.get("backend_target_count") or 0) > 1
                or (item.get("listener_count") or 0) > 1
                or (item.get("request_routing_rule_count") or 0) > 1
            )
            for item in application_gateways
        )
        weak_public_gateways = sum(
            (item.get("public_frontend_count") or 0) > 0 and _application_gateway_waf_rank(item) < 3
            for item in application_gateways
        )
        return (
            f"{len(application_gateways)} Application Gateways visible; {public_gateways} "
            f"have public frontends, {shared_public_gateways} look like shared public front "
            f"doors, and {weak_public_gateways} public gateway(s) lack strong visible WAF "
            "coverage. Treat weak shared edge layers as clues that the apps behind them may "
            "deserve review next."
        )

    if command == "network-effective":
        effective_exposures = payload.get("effective_exposures", [])
        by_confidence = Counter(
            str(item.get("effective_exposure") or "unknown").lower() for item in effective_exposures
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
            item.get("oidc_issuer_enabled") is True or item.get("workload_identity_enabled") is True
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
            str(item.get("public_network_access") or "").lower() == "enabled" for item in services
        )
        identities = sum(bool(item.get("workload_identity_type")) for item in services)
        named_value_counts = [item.get("named_value_count") for item in services]
        readable_named_values = sum(count for count in named_value_counts if isinstance(count, int))
        if named_value_counts and any(count is None for count in named_value_counts):
            if readable_named_values:
                named_value_phrase = (
                    f"at least {readable_named_values} named values are visible, with some "
                    "services outside current credential visibility"
                )
            else:
                named_value_phrase = (
                    "current credentials do not show named values on at least one visible service"
                )
        else:
            named_value_phrase = f"{readable_named_values} named values are visible"
        secret_named_value_counts = [item.get("named_value_secret_count") for item in services]
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

    if command == "chains":
        paths = payload.get("paths", [])
        priorities = Counter(item.get("priority") or "unknown" for item in paths)
        urgencies = Counter(item.get("urgency") or "unknown" for item in paths)
        family = str(payload.get("family") or "chain")
        family_label = "credential paths"
        if family == "deployment-path":
            family_label = "deployment paths"
        elif family == "escalation-path":
            family_label = "escalation paths"
        elif family == "workload-identity-path":
            family_label = "workload-identity paths"
        priority_order = ("high", "medium", "low", "unknown")
        priority_counts = ", ".join(
            f"{priorities[name]} {name}" for name in priority_order if priorities.get(name)
        )
        urgency_order = ("pivot-now", "review-soon", "bookmark", "unknown")
        urgency_counts = ", ".join(
            f"{urgencies[name]} {name}" for name in urgency_order if urgencies.get(name)
        )
        if family == "deployment-path":
            concepts = Counter(item.get("path_concept") or "unknown" for item in paths)
            concept_counts = ", ".join(
                f"{count} {_deployment_path_type({'path_concept': name})}"
                for name, count in concepts.items()
                if name != "unknown"
            )
            return (
                f"{len(paths)} visible {family_label}; "
                f"{priority_counts or 'no ranked paths'}, "
                f"{urgency_counts or 'no urgency signals'}, "
                f"{concept_counts or 'no source-side actionability story'}."
            )
        if family == "escalation-path":
            concepts = Counter(item.get("path_concept") or "unknown" for item in paths)
            concept_counts = ", ".join(
                f"{count} {_escalation_path_type({'path_concept': name})}"
                for name, count in concepts.items()
                if name != "unknown"
            )
            return (
                f"{len(paths)} visible {family_label}; "
                f"{priority_counts or 'no ranked paths'}, "
                f"{urgency_counts or 'no urgency signals'}, "
                f"{concept_counts or 'no defended escalation stories'}."
            )
        services = Counter(item.get("target_service") or "unknown" for item in paths)
        counts = ", ".join(f"{count} {name}" for name, count in sorted(services.items()))
        return (
            f"{len(paths)} visible {family_label}; "
            f"{priority_counts or 'no ranked paths'}, "
            f"{urgency_counts or 'no urgency signals'}, "
            f"{counts or 'no joined downstream targets'}."
        )

    if command == "rbac":
        assignments = payload.get("role_assignments", [])
        principals = payload.get("principals", [])
        return f"{len(assignments)} RBAC assignments across {len(principals)} principals."

    return ""


def _automation_identity_context(item: dict) -> str:
    identity_type = item.get("identity_type")
    if not identity_type:
        return "none"
    return str(identity_type)


def _automation_execution_context(item: dict) -> str:
    runbooks = _value_or_unknown(item.get("runbook_count"))
    published = _value_or_unknown(item.get("published_runbook_count"))
    job_schedules = _value_or_unknown(item.get("job_schedule_count"))
    return f"published={published}/{runbooks}; job-schedules={job_schedules}"


def _automation_trigger_context(item: dict) -> str:
    schedules = _value_or_unknown(item.get("schedule_count"))
    webhooks = _value_or_unknown(item.get("webhook_count"))
    return f"schedules={schedules}; webhooks={webhooks}"


def _automation_worker_context(item: dict) -> str:
    groups = item.get("hybrid_worker_group_count")
    if groups is None:
        return "groups=?"
    return f"groups={groups}"


def _automation_asset_context(item: dict) -> str:
    credentials = _value_or_unknown(item.get("credential_count"))
    certificates = _value_or_unknown(item.get("certificate_count"))
    connections = _value_or_unknown(item.get("connection_count"))
    variables = _value_or_unknown(item.get("variable_count"))
    encrypted = _value_or_unknown(item.get("encrypted_variable_count"))
    return (
        f"cred={credentials}; cert={certificates}; conn={connections}; "
        f"vars={variables} ({encrypted} enc)"
    )


def _value_or_unknown(value: object) -> str:
    return str(value) if value is not None else "?"


def _value_gt_zero(value: object) -> bool:
    return isinstance(value, int) and value > 0


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


def _env_var_next_review(item: dict) -> str:
    return env_var_next_review_hint(
        setting_name=str(item.get("setting_name") or ""),
        value_type=str(item.get("value_type") or ""),
        looks_sensitive=bool(item.get("looks_sensitive")),
        reference_target=(
            str(item.get("reference_target")) if item.get("reference_target") else None
        ),
        workload_identity_type=(
            str(item.get("workload_identity_type")) if item.get("workload_identity_type") else None
        ),
    )


def _privesc_proof_boundary(item: dict) -> str:
    proven = str(item.get("proven_path") or "").strip()
    missing = str(item.get("missing_proof") or "").strip()
    if proven and missing:
        return f"{proven} {missing}"
    return proven or missing


def _privesc_target(item: dict) -> str:
    if item.get("current_identity"):
        return "current foothold"
    principal = str(item.get("principal") or "").strip()
    asset = str(item.get("asset") or "").strip()
    if principal and asset:
        return f"{principal} via {asset}"
    if principal:
        return principal
    if asset:
        return asset
    return "-"


def _tokens_credential_next_review(item: dict) -> str:
    return tokens_credential_next_review_hint(
        surface_type=str(item.get("surface_type") or ""),
        access_path=str(item.get("access_path") or ""),
        operator_signal=str(item.get("operator_signal") or ""),
    )


def _chains_target_context(item: dict) -> str:
    if item.get("target_visibility_issue"):
        return str(item.get("target_visibility_issue"))
    target_names = item.get("target_names") or []
    if target_names:
        return ",".join(str(value) for value in target_names[:3])
    target_count = item.get("target_count") or 0
    if target_count:
        return f"{target_count} visible target(s)"
    return "none joined"


def _deployment_path_type(item: dict) -> str:
    concept = str(item.get("path_concept") or "")
    labels = {
        "controllable-change-path": "controllable change path",
        "execution-hub": "execution hub",
        "secret-escalation-support": "secret-backed support",
    }
    return labels.get(concept, concept or "-")


def _escalation_path_type(item: dict) -> str:
    concept = str(item.get("path_concept") or "")
    labels = {
        "current-foothold-direct-control": "current foothold direct control",
        "trust-expansion": "trust expansion",
    }
    return labels.get(concept, concept or "-")


def _chains_note(item: dict, *, family: str = "") -> str:
    resolution = str(item.get("target_resolution") or "")
    target_service = str(item.get("target_service") or "target")

    if resolution == "named match":
        return "Named target matched visible inventory."
    if resolution == "visibility blocked":
        return f"{target_service} visibility is blocked; do not infer a target."
    if resolution == "narrowed candidates":
        if family == "deployment-path":
            return "Change-capable source narrows the next review set; exact target unconfirmed."
        return f"Secret-shaped clue suggests a {target_service} path; exact target unconfirmed."
    if resolution == "tenant-wide candidates":
        return f"{target_service} family is visible, but narrowing is still broad."
    if resolution == "service hint only":
        return f"{target_service} path is suggested, but no target inventory is visible."
    if resolution == "named target not visible":
        return "The named target is not visible in current inventory."
    return item.get("summary") or "-"


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


def _application_gateway_exposure_context(item: dict) -> str:
    parts: list[str] = []
    public_frontend_count = item.get("public_frontend_count") or 0
    private_frontend_count = item.get("private_frontend_count") or 0
    public_ip_addresses = item.get("public_ip_addresses", []) or []

    if public_frontend_count:
        public_phrase = f"public={public_frontend_count}"
        if public_ip_addresses:
            public_phrase += f" ({', '.join(public_ip_addresses)})"
        parts.append(public_phrase)
    if private_frontend_count:
        parts.append(f"private={private_frontend_count}")
    if item.get("subnet_ids"):
        parts.append(f"subnets={len(item.get('subnet_ids', []))}")

    if not parts:
        return "-"
    return "; ".join(parts)


def _application_gateway_routing_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("listener_count") is not None:
        parts.append(f"listeners={item.get('listener_count')}")
    if item.get("request_routing_rule_count") is not None:
        parts.append(f"rules={item.get('request_routing_rule_count')}")
    if item.get("url_path_map_count"):
        parts.append(f"path-maps={item.get('url_path_map_count')}")
    if item.get("redirect_configuration_count"):
        parts.append(f"redirects={item.get('redirect_configuration_count')}")
    if item.get("rewrite_rule_set_count"):
        parts.append(f"rewrites={item.get('rewrite_rule_set_count')}")
    if not parts:
        return "-"
    return "; ".join(parts)


def _application_gateway_backend_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("backend_pool_count") is not None:
        parts.append(f"pools={item.get('backend_pool_count')}")
    if item.get("backend_target_count") is not None:
        parts.append(f"targets={item.get('backend_target_count')}")
    if not parts:
        return "-"
    return "; ".join(parts)


def _application_gateway_waf_context(item: dict) -> str:
    if item.get("firewall_policy_id") and item.get("waf_mode"):
        return f"policy; {str(item.get('waf_mode')).lower()}"
    if item.get("firewall_policy_id"):
        return "policy attached"
    if item.get("waf_enabled") is True and item.get("waf_mode"):
        return f"enabled; {str(item.get('waf_mode')).lower()}"
    if item.get("waf_enabled") is True:
        return "enabled"
    if item.get("waf_enabled") is False:
        return "disabled"
    return "not visible"


def _application_gateway_waf_rank(item: dict) -> int:
    if item.get("firewall_policy_id"):
        mode = str(item.get("waf_mode") or "").strip().lower()
        if mode == "prevention":
            return 3
        if mode == "detection":
            return 1
        return 2

    if item.get("waf_enabled") is False:
        return 0

    mode = str(item.get("waf_mode") or "").strip().lower()
    if mode == "prevention":
        return 3
    if mode == "detection":
        return 1
    if item.get("waf_enabled") is True:
        return 2
    return 0


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


def _vmss_capacity_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("sku_name"):
        parts.append(str(item.get("sku_name")))
    if item.get("instance_count") is not None:
        parts.append(f"instances={item.get('instance_count')}")
    if item.get("zones"):
        parts.append(f"zones={len(item.get('zones', []))}")
    if not parts:
        return "-"
    return "; ".join(parts)


def _vmss_rollout_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("orchestration_mode"):
        parts.append(str(item.get("orchestration_mode")))
    if item.get("upgrade_mode"):
        parts.append(f"upgrade={item.get('upgrade_mode')}")
    if item.get("single_placement_group") is not None:
        parts.append("spg=yes" if item.get("single_placement_group") else "spg=no")
    if item.get("overprovision") is not None:
        parts.append("overprov=yes" if item.get("overprovision") else "overprov=no")
    if not parts:
        return "-"
    return "; ".join(parts)


def _vmss_identity_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("identity_type"):
        parts.append(str(item.get("identity_type")))
    if item.get("identity_ids"):
        parts.append(f"ids={len(item.get('identity_ids', []))}")
    if not parts:
        return "-"
    return "; ".join(parts)


def _vmss_frontend_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("public_ip_configuration_count"):
        parts.append(f"public-ip={item.get('public_ip_configuration_count')}")
    if item.get("inbound_nat_pool_count"):
        parts.append(f"nat-pools={item.get('inbound_nat_pool_count')}")
    if item.get("load_balancer_backend_pool_count"):
        parts.append(f"lb-backends={item.get('load_balancer_backend_pool_count')}")
    if item.get("application_gateway_backend_pool_count"):
        parts.append(f"appgw={item.get('application_gateway_backend_pool_count')}")
    if not parts:
        return "-"
    return "; ".join(parts)


def _vmss_network_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("nic_configuration_count"):
        parts.append(f"nic-configs={item.get('nic_configuration_count')}")
    subnet_names = _display_resource_refs(item.get("subnet_ids"))
    if subnet_names:
        parts.append(f"subnet={','.join(subnet_names)}")
    if item.get("zone_balance") is not None:
        parts.append("zone-balance=yes" if item.get("zone_balance") else "zone-balance=no")
    if not parts:
        return "-"
    return "; ".join(parts)


def _lighthouse_scope_context(item: dict) -> str:
    scope_label = item.get("scope_display_name") or _display_resource_name(item.get("scope_id"))
    scope_type = item.get("scope_type") or "scope"
    if scope_type == "resource_group":
        return f"resource-group::{scope_label}"
    return f"subscription::{scope_label}"


def _lighthouse_access_context(item: dict) -> str:
    parts: list[str] = []
    strongest_role = item.get("strongest_role_name")
    if strongest_role:
        parts.append(f"strongest={strongest_role}")
    parts.append(f"auth={item.get('authorization_count', 0)}")
    parts.append(f"eligible={item.get('eligible_authorization_count', 0)}")
    if item.get("has_delegated_role_assignments"):
        parts.append("delegated-role-assign=yes")
    plan_name = item.get("plan_name")
    if plan_name:
        parts.append(f"plan={plan_name}")
    return "; ".join(parts) if parts else "-"


def _lighthouse_state_context(item: dict) -> str:
    parts: list[str] = []
    assignment_state = item.get("provisioning_state")
    if assignment_state:
        parts.append(f"assignment={assignment_state}")
    definition_state = item.get("definition_provisioning_state")
    if definition_state and definition_state != assignment_state:
        parts.append(f"definition={definition_state}")
    return "; ".join(parts) if parts else "-"


def _cross_tenant_tenant_context(item: dict) -> str:
    tenant_name = item.get("tenant_name")
    tenant_id = item.get("tenant_id")
    if tenant_name and tenant_id:
        return f"{tenant_name} ({tenant_id})"
    if tenant_name:
        return str(tenant_name)
    if tenant_id:
        return str(tenant_id)
    return "-"


def _cross_tenant_posture_context(item: dict) -> str:
    parts: list[str] = []
    if item.get("priority"):
        parts.append(f"priority={item.get('priority')}")
    if item.get("posture"):
        parts.append(str(item.get("posture")))
    return "; ".join(parts) if parts else "-"


def _cross_tenant_attack_path_context(item: dict) -> str:
    attack_path = item.get("attack_path")
    signal_type = item.get("signal_type")
    if attack_path and signal_type:
        return f"{attack_path} via {signal_type}"
    if attack_path:
        return str(attack_path)
    return str(signal_type or "-")


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


def _devops_repository_context(item: dict) -> str:
    primary_input = _devops_primary_trusted_input(item)
    trusted_inputs = [
        value for value in item.get("trusted_inputs") or [] if isinstance(value, dict)
    ]
    if primary_input is not None:
        parts = [
            "primary="
            + describe_trusted_input(
                input_type=str(primary_input.get("input_type") or "") or None,
                ref=str(primary_input.get("ref") or "") or None,
            )
        ]
        if primary_input.get("visibility_state"):
            parts.append(f"state={primary_input.get('visibility_state')}")
        if primary_input.get("current_operator_access_state"):
            parts.append(f"current={primary_input.get('current_operator_access_state')}")
        if primary_input.get("trusted_input_permission_detail"):
            parts.append(f"proof={primary_input.get('trusted_input_permission_detail')}")
        elif primary_input.get("trusted_input_evidence_basis"):
            parts.append(f"proof={primary_input.get('trusted_input_evidence_basis')}")
        if len(trusted_inputs) > 1:
            parts.append(f"extra={len(trusted_inputs) - 1}")
        return "; ".join(parts)

    repo_host = item.get("repository_host_type")
    visibility = item.get("source_visibility_state")
    repo_name = item.get("repository_name")
    default_branch = item.get("default_branch")
    can_view = item.get("current_operator_can_view_source")
    can_contribute = item.get("current_operator_can_contribute_source")

    parts: list[str] = []
    if repo_host:
        parts.append(str(repo_host))
    if repo_name:
        repo_label = str(repo_name)
        if default_branch:
            repo_label = f"{repo_label}@{default_branch}"
        parts.append(repo_label)
    if visibility:
        parts.append(f"state={visibility}")
    if isinstance(can_view, bool) or isinstance(can_contribute, bool):
        parts.append(
            f"current=read={_tri_state_text(can_view)},write={_tri_state_text(can_contribute)}"
        )
    return "; ".join(parts) if parts else "-"


def _devops_trigger_context(item: dict) -> str:
    execution_modes = item.get("execution_modes") or []
    upstream_sources = item.get("upstream_sources") or []

    parts: list[str] = []
    if execution_modes:
        parts.append("modes=" + ",".join(str(value) for value in execution_modes))
    if upstream_sources:
        parts.append("from=" + ",".join(str(value) for value in upstream_sources))
    return "; ".join(parts) if parts else "manual-or-unreadable"


def _devops_injection_context(item: dict) -> str:
    visible = item.get("injection_surface_types") or []
    current = item.get("current_operator_injection_surface_types") or []
    parts: list[str] = []
    if item.get("primary_injection_surface"):
        parts.append("primary=" + str(item.get("primary_injection_surface")))
    if visible:
        parts.append("visible=" + ",".join(str(value) for value in visible))
    if current:
        parts.append("current=" + ",".join(str(value) for value in current))
    elif item.get("missing_injection_point"):
        parts.append("current=unproven")
    return "; ".join(parts) if parts else "-"


def _devops_access_context(item: dict) -> str:
    names = item.get("azure_service_connection_names") or []
    auth_schemes = item.get("azure_service_connection_auth_schemes") or []
    endpoint_types = item.get("azure_service_connection_types") or []
    can_queue = item.get("current_operator_can_queue")
    can_edit = item.get("current_operator_can_edit")

    parts: list[str] = []
    if isinstance(can_queue, bool) or isinstance(can_edit, bool):
        parts.append(f"current=queue={_tri_state_text(can_queue)},edit={_tri_state_text(can_edit)}")
    if names:
        parts.append("conn=" + ",".join(str(value) for value in names))
    if auth_schemes:
        parts.append("auth=" + ",".join(str(value) for value in auth_schemes))
    if endpoint_types:
        parts.append("type=" + ",".join(str(value) for value in endpoint_types))
    return "; ".join(parts) if parts else "-"


def _devops_secret_context(item: dict) -> str:
    parts: list[str] = []
    support_types = [
        str(value)
        for value in item.get("secret_support_types") or []
        if str(value) != "variable-groups"
    ]
    if support_types:
        parts.append("types=" + ",".join(support_types))
    if item.get("variable_group_names"):
        parts.append("groups=" + ",".join(str(value) for value in item["variable_group_names"]))
    if item.get("secret_variable_count"):
        parts.append(f"secrets={item.get('secret_variable_count')}")
    if item.get("key_vault_names"):
        parts.append("kv=" + ",".join(str(value) for value in item["key_vault_names"]))
    elif item.get("key_vault_group_names"):
        parts.append("kv-groups=" + ",".join(str(value) for value in item["key_vault_group_names"]))
    return "; ".join(parts) if parts else "-"


def _devops_target_context(item: dict) -> str:
    clues = item.get("target_clues") or []
    consequences = item.get("consequence_types") or []

    parts: list[str] = []
    if consequences:
        parts.append("consequence=" + ",".join(str(value) for value in consequences))
    if clues:
        parts.append("clue=" + ",".join(str(value) for value in clues))
    return "; ".join(parts) if parts else "-"


def _devops_next_review(item: dict) -> str:
    primary_input = _devops_primary_trusted_input(item)
    return devops_next_review_hint(
        target_clues=[str(value) for value in item.get("target_clues") or []],
        key_vault_names=[str(value) for value in item.get("key_vault_names") or []],
        key_vault_group_names=[str(value) for value in item.get("key_vault_group_names") or []],
        azure_service_connection_names=[
            str(value) for value in item.get("azure_service_connection_names") or []
        ],
        partial_read=bool(item.get("partial_read")),
        current_operator_can_queue=item.get("current_operator_can_queue"),
        current_operator_can_edit=item.get("current_operator_can_edit"),
        current_operator_can_contribute_source=item.get("current_operator_can_contribute_source"),
        current_operator_injection_surface_types=[
            str(value) for value in item.get("current_operator_injection_surface_types") or []
        ],
        primary_trusted_input_type=(
            str(primary_input.get("input_type")) if primary_input else None
        ),
        primary_trusted_input_ref=(str(primary_input.get("ref")) if primary_input else None),
        primary_injection_surface=str(item.get("primary_injection_surface") or "") or None,
        primary_trusted_input_access_state=(
            str(primary_input.get("current_operator_access_state"))
            if primary_input and primary_input.get("current_operator_access_state")
            else None
        ),
        repository_host_type=str(item.get("repository_host_type") or "") or None,
        source_visibility_state=str(item.get("source_visibility_state") or "") or None,
    )


def _devops_primary_trusted_input(item: dict) -> dict | None:
    trusted_inputs = [
        value for value in item.get("trusted_inputs") or [] if isinstance(value, dict)
    ]
    primary_ref = str(item.get("primary_trusted_input_ref") or "") or None
    if primary_ref:
        for trusted_input in trusted_inputs:
            if str(trusted_input.get("ref") or "") == primary_ref:
                return trusted_input
    return trusted_inputs[0] if trusted_inputs else None


def _bool_text(value: bool) -> str:
    return "yes" if value else "no"


def _tri_state_text(value: bool | None) -> str:
    if value is None:
        return "unknown"
    return _bool_text(value)


def _value_to_string(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    if isinstance(value, dict):
        return ", ".join(f"{k}: {v}" for k, v in value.items())
    return str(value)
