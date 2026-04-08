from __future__ import annotations

from azurefox.collectors.provider import BaseProvider
from azurefox.config import GlobalOptions
from azurefox.correlation.findings import (
    build_arm_deployment_findings,
    build_auth_policy_findings,
    build_env_var_findings,
    build_identity_findings,
    build_keyvault_findings,
    build_storage_findings,
    build_tokens_credentials_findings,
    build_vm_findings,
)
from azurefox.managed_identity_hints import (
    managed_identity_next_review_hint,
    managed_identity_operator_signal,
    managed_identity_summary,
)
from azurefox.models.commands import (
    AcrOutput,
    AksOutput,
    ApiMgmtOutput,
    ApplicationGatewayOutput,
    AppServicesOutput,
    ArmDeploymentsOutput,
    AuthPoliciesOutput,
    AutomationOutput,
    CrossTenantOutput,
    DatabasesOutput,
    DevopsOutput,
    DnsOutput,
    EndpointsOutput,
    EnvVarsOutput,
    FunctionsOutput,
    InventoryOutput,
    KeyVaultOutput,
    LighthouseOutput,
    ManagedIdentitiesOutput,
    NetworkEffectiveOutput,
    NetworkPortsOutput,
    NicsOutput,
    PermissionsOutput,
    PrincipalsOutput,
    PrivescOutput,
    RbacOutput,
    ResourceTrustsOutput,
    RoleTrustsOutput,
    SnapshotsDisksOutput,
    StorageOutput,
    TokensCredentialsOutput,
    VmsOutput,
    VmssOutput,
    WhoAmIOutput,
    WorkloadsOutput,
)
from azurefox.models.common import CommandMetadata
from azurefox.permissions_hints import (
    permissions_next_review_hint,
    permissions_operator_signal,
    permissions_summary,
)
from azurefox.role_trust_hints import (
    role_trust_control_primitive,
    role_trust_controlled_object,
    role_trust_defender_cut_point,
    role_trust_escalation_mechanism,
    role_trust_next_review_hint,
    role_trust_operator_signal,
    role_trust_summary,
    role_trust_usable_identity_result,
)


def collect_whoami(provider: BaseProvider, options: GlobalOptions) -> WhoAmIOutput:
    data = provider.whoami()
    output = WhoAmIOutput.model_validate(
        {
            "metadata": _metadata(
                provider,
                "whoami",
                options,
                data.get("token_source"),
                data.get("auth_mode"),
            ),
            **data,
        }
    )
    return output


def collect_inventory(provider: BaseProvider, options: GlobalOptions) -> InventoryOutput:
    data = provider.inventory()
    return InventoryOutput.model_validate(
        {"metadata": _metadata(provider, "inventory", options), **data}
    )


def collect_automation(provider: BaseProvider, options: GlobalOptions) -> AutomationOutput:
    data = provider.automation()
    automation_accounts = sorted(data.get("automation_accounts", []), key=_automation_sort_key)
    return AutomationOutput.model_validate(
        {
            "metadata": _metadata(provider, "automation", options),
            "findings": [],
            **data,
            "automation_accounts": automation_accounts,
        }
    )


def collect_devops(provider: BaseProvider, options: GlobalOptions) -> DevopsOutput:
    data = provider.devops()
    pipelines = sorted(data.get("pipelines", []), key=_devops_pipeline_sort_key)
    return DevopsOutput.model_validate(
        {
            "metadata": _metadata(provider, "devops", options),
            "findings": [],
            **data,
            "pipelines": pipelines,
        }
    )


def collect_app_services(provider: BaseProvider, options: GlobalOptions) -> AppServicesOutput:
    data = provider.app_services()
    app_services = sorted(data.get("app_services", []), key=_app_service_sort_key)
    return AppServicesOutput.model_validate(
        {
            "metadata": _metadata(provider, "app-services", options),
            "findings": [],
            **data,
            "app_services": app_services,
        }
    )


def collect_acr(provider: BaseProvider, options: GlobalOptions) -> AcrOutput:
    data = provider.acr()
    registries = sorted(data.get("registries", []), key=_acr_registry_sort_key)
    return AcrOutput.model_validate(
        {
            "metadata": _metadata(provider, "acr", options),
            "findings": [],
            **data,
            "registries": registries,
        }
    )


def collect_databases(provider: BaseProvider, options: GlobalOptions) -> DatabasesOutput:
    data = provider.databases()
    database_servers = sorted(data.get("database_servers", []), key=_database_server_sort_key)
    return DatabasesOutput.model_validate(
        {
            "metadata": _metadata(provider, "databases", options),
            "findings": [],
            **data,
            "database_servers": database_servers,
        }
    )


def collect_dns(provider: BaseProvider, options: GlobalOptions) -> DnsOutput:
    data = provider.dns()
    dns_zones = sorted(
        data.get("dns_zones", []),
        key=lambda item: (
            item.get("zone_kind") != "public",
            -_int_or_zero(len(item.get("name_servers", []) or [])),
            -_int_or_zero(item.get("private_endpoint_reference_count")),
            -_int_or_zero(item.get("linked_virtual_network_count")),
            -_int_or_zero(item.get("registration_virtual_network_count")),
            -_int_or_zero(item.get("record_set_count")),
            item.get("name") or "",
        ),
    )
    return DnsOutput.model_validate(
        {
            "metadata": _metadata(provider, "dns", options),
            "findings": [],
            **data,
            "dns_zones": dns_zones,
        }
    )


def collect_network_effective(
    provider: BaseProvider,
    options: GlobalOptions,
) -> NetworkEffectiveOutput:
    data = provider.network_effective()
    effective_exposures = sorted(
        data.get("effective_exposures", []),
        key=lambda item: (
            {"high": 0, "medium": 1, "low": 2}.get(str(item.get("effective_exposure")), 9),
            item.get("asset_name") or "",
            item.get("endpoint") or "",
        ),
    )
    return NetworkEffectiveOutput.model_validate(
        {
            "metadata": _metadata(provider, "network-effective", options),
            "findings": [],
            **data,
            "effective_exposures": effective_exposures,
        }
    )


def collect_aks(provider: BaseProvider, options: GlobalOptions) -> AksOutput:
    data = provider.aks()
    aks_clusters = sorted(data.get("aks_clusters", []), key=_aks_cluster_sort_key)
    return AksOutput.model_validate(
        {
            "metadata": _metadata(provider, "aks", options),
            "findings": [],
            **data,
            "aks_clusters": aks_clusters,
        }
    )


def collect_api_mgmt(provider: BaseProvider, options: GlobalOptions) -> ApiMgmtOutput:
    data = provider.api_mgmt()
    api_management_services = sorted(
        data.get("api_management_services", []),
        key=lambda item: (
            not _api_mgmt_priority(item),
            -_int_or_zero(item.get("named_value_secret_count")),
            -_int_or_zero(item.get("named_value_key_vault_count")),
            -_int_or_zero(item.get("subscription_count")),
            -len(item.get("backend_hostnames", []) or []),
            item.get("name") or "",
        ),
    )
    return ApiMgmtOutput.model_validate(
        {
            "metadata": _metadata(provider, "api-mgmt", options),
            "findings": [],
            **data,
            "api_management_services": api_management_services,
        }
    )


def collect_application_gateway(
    provider: BaseProvider,
    options: GlobalOptions,
) -> ApplicationGatewayOutput:
    data = provider.application_gateway()
    application_gateways = sorted(
        data.get("application_gateways", []),
        key=_application_gateway_sort_key,
    )
    return ApplicationGatewayOutput.model_validate(
        {
            "metadata": _metadata(provider, "application-gateway", options),
            "findings": [],
            **data,
            "application_gateways": application_gateways,
        }
    )


def collect_functions(provider: BaseProvider, options: GlobalOptions) -> FunctionsOutput:
    data = provider.functions()
    function_apps = sorted(data.get("function_apps", []), key=_function_app_sort_key)
    return FunctionsOutput.model_validate(
        {
            "metadata": _metadata(provider, "functions", options),
            "findings": [],
            **data,
            "function_apps": function_apps,
        }
    )


def collect_arm_deployments(provider: BaseProvider, options: GlobalOptions) -> ArmDeploymentsOutput:
    data = provider.arm_deployments()
    deployments = sorted(data.get("deployments", []), key=_arm_deployment_sort_key)
    findings = build_arm_deployment_findings(deployments)
    return ArmDeploymentsOutput.model_validate(
        {
            "metadata": _metadata(provider, "arm-deployments", options),
            **data,
            "deployments": deployments,
            "findings": findings,
        }
    )


def collect_env_vars(provider: BaseProvider, options: GlobalOptions) -> EnvVarsOutput:
    data = provider.env_vars()
    env_vars = sorted(
        data.get("env_vars", []),
        key=lambda item: (
            not (item.get("looks_sensitive") and item.get("value_type") == "plain-text"),
            item.get("value_type") != "keyvault-ref",
            item.get("asset_name") or "",
            item.get("setting_name") or "",
        ),
    )
    findings = build_env_var_findings(env_vars)
    return EnvVarsOutput.model_validate(
        {
            "metadata": _metadata(provider, "env-vars", options),
            **data,
            "env_vars": env_vars,
            "findings": findings,
        }
    )


def collect_endpoints(provider: BaseProvider, options: GlobalOptions) -> EndpointsOutput:
    data = provider.endpoints()
    return EndpointsOutput.model_validate(
        {
            "metadata": _metadata(provider, "endpoints", options),
            "findings": [],
            **data,
        }
    )


def collect_network_ports(provider: BaseProvider, options: GlobalOptions) -> NetworkPortsOutput:
    data = provider.network_ports()
    return NetworkPortsOutput.model_validate(
        {
            "metadata": _metadata(provider, "network-ports", options),
            "findings": [],
            **data,
        }
    )


def collect_tokens_credentials(
    provider: BaseProvider, options: GlobalOptions
) -> TokensCredentialsOutput:
    data = provider.tokens_credentials()
    surfaces = sorted(
        data.get("surfaces", []),
        key=lambda item: (
            {"high": 0, "medium": 1, "low": 2}.get(str(item.get("priority") or "").lower(), 9),
            item.get("asset_name") or "",
            item.get("surface_type") or "",
            item.get("operator_signal") or "",
        ),
    )
    findings = build_tokens_credentials_findings(surfaces)
    return TokensCredentialsOutput.model_validate(
        {
            "metadata": _metadata(provider, "tokens-credentials", options),
            **data,
            "surfaces": surfaces,
            "findings": findings,
        }
    )


def collect_rbac(provider: BaseProvider, options: GlobalOptions) -> RbacOutput:
    data = provider.rbac()
    return RbacOutput.model_validate({"metadata": _metadata(provider, "rbac", options), **data})


def collect_principals(provider: BaseProvider, options: GlobalOptions) -> PrincipalsOutput:
    data = provider.principals()
    return PrincipalsOutput.model_validate(
        {"metadata": _metadata(provider, "principals", options), **data}
    )


def collect_permissions(provider: BaseProvider, options: GlobalOptions) -> PermissionsOutput:
    data = provider.permissions()
    principals_data = provider.principals()
    permissions = _enrich_permission_rows(
        data.get("permissions", []),
        principals_data.get("principals", []),
    )
    return PermissionsOutput.model_validate(
        {
            "metadata": _metadata(provider, "permissions", options),
            **data,
            "permissions": permissions,
            "issues": [*data.get("issues", []), *principals_data.get("issues", [])],
        }
    )


def collect_privesc(provider: BaseProvider, options: GlobalOptions) -> PrivescOutput:
    data = provider.privesc()
    return PrivescOutput.model_validate(
        {"metadata": _metadata(provider, "privesc", options), **data}
    )


def collect_role_trusts(provider: BaseProvider, options: GlobalOptions) -> RoleTrustsOutput:
    data = provider.role_trusts(options.role_trusts_mode)
    trusts = _enrich_role_trust_rows(data.get("trusts", []))
    trusts = sorted(
        trusts,
        key=lambda item: (
            str(item.get("confidence") or "").lower() != "confirmed",
            _role_trust_priority(item),
            _role_trust_follow_on_rank(item.get("next_review")),
            item.get("source_name") or item.get("source_object_id") or "",
            item.get("target_name") or item.get("target_object_id") or "",
        ),
    )
    return RoleTrustsOutput.model_validate(
        {
            "metadata": _metadata(provider, "role-trusts", options),
            "mode": options.role_trusts_mode,
            **data,
            "trusts": trusts,
        }
    )


def collect_lighthouse(provider: BaseProvider, options: GlobalOptions) -> LighthouseOutput:
    data = provider.lighthouse()
    lighthouse_delegations = sorted(
        data.get("lighthouse_delegations", []),
        key=lambda item: (
            item.get("scope_type") != "subscription",
            _lighthouse_role_rank(item),
            item.get("authorization_count", 0) == 0,
            -_int_or_zero(item.get("authorization_count")),
            -_int_or_zero(item.get("eligible_authorization_count")),
            _lighthouse_state_rank(item),
            item.get("managed_by_tenant_name") or item.get("managed_by_tenant_id") or "",
            item.get("scope_display_name") or "",
            item.get("name") or "",
        ),
    )
    return LighthouseOutput.model_validate(
        {
            "metadata": _metadata(provider, "lighthouse", options),
            "findings": [],
            **data,
            "lighthouse_delegations": lighthouse_delegations,
        }
    )


def collect_cross_tenant(provider: BaseProvider, options: GlobalOptions) -> CrossTenantOutput:
    data = provider.cross_tenant()
    cross_tenant_paths = sorted(
        data.get("cross_tenant_paths", []),
        key=lambda item: (
            _priority_rank(item.get("priority")),
            _cross_tenant_signal_rank(item),
            _cross_tenant_scope_rank(item),
            item.get("tenant_name") or item.get("tenant_id") or "",
            item.get("name") or "",
        ),
    )
    return CrossTenantOutput.model_validate(
        {
            "metadata": _metadata(provider, "cross-tenant", options),
            "findings": [],
            **data,
            "cross_tenant_paths": cross_tenant_paths,
        }
    )


def collect_resource_trusts(provider: BaseProvider, options: GlobalOptions) -> ResourceTrustsOutput:
    data = provider.resource_trusts()
    return ResourceTrustsOutput.model_validate(
        {"metadata": _metadata(provider, "resource-trusts", options), **data}
    )


def collect_auth_policies(provider: BaseProvider, options: GlobalOptions) -> AuthPoliciesOutput:
    data = provider.auth_policies()
    findings = build_auth_policy_findings(
        data.get("auth_policies", []),
        data.get("issues", []),
    )
    auth_policies = sorted(
        data.get("auth_policies", []),
        key=lambda item: (
            not _auth_policy_has_findings(item, findings),
            not _auth_policy_has_issue(item, data.get("issues", [])),
            _auth_policy_state_rank(item),
            item.get("policy_type") != "security-defaults",
            item.get("policy_type") != "authorization-policy",
            item.get("name") or "",
        ),
    )
    return AuthPoliciesOutput.model_validate(
        {
            "metadata": _metadata(provider, "auth-policies", options),
            "findings": findings,
            **data,
            "auth_policies": auth_policies,
        }
    )


def collect_managed_identities(
    provider: BaseProvider, options: GlobalOptions
) -> ManagedIdentitiesOutput:
    data = provider.managed_identities()
    vms_data = provider.vms()
    vmss_data = provider.vmss()
    identities = _enrich_managed_identity_rows(
        data.get("identities", []),
        data.get("role_assignments", []),
        vms_data.get("vm_assets", []),
        vmss_data.get("vmss_assets", []),
    )
    findings = build_identity_findings(
        identities,
        data.get("role_assignments", []),
    )
    return ManagedIdentitiesOutput.model_validate(
        {
            "metadata": _metadata(provider, "managed-identities", options),
            "findings": findings,
            **data,
            "identities": identities,
            "issues": [
                *data.get("issues", []),
                *vms_data.get("issues", []),
                *vmss_data.get("issues", []),
            ],
        }
    )


def collect_keyvault(provider: BaseProvider, options: GlobalOptions) -> KeyVaultOutput:
    data = provider.keyvault()
    key_vaults = sorted(
        data.get("key_vaults", []),
        key=lambda item: (
            _keyvault_priority_rank(item),
            item.get("name") or "",
            item.get("id") or "",
        ),
    )
    data = {**data, "key_vaults": key_vaults}
    findings = build_keyvault_findings(data.get("key_vaults", []))
    return KeyVaultOutput.model_validate(
        {"metadata": _metadata(provider, "keyvault", options), "findings": findings, **data}
    )


def collect_storage(provider: BaseProvider, options: GlobalOptions) -> StorageOutput:
    data = provider.storage()
    storage_assets = sorted(
        data.get("storage_assets", []),
        key=lambda item: (
            _storage_priority_rank(item),
            item.get("name") or "",
            item.get("id") or "",
        ),
    )
    findings = build_storage_findings(storage_assets)
    return StorageOutput.model_validate(
        {
            "metadata": _metadata(provider, "storage", options),
            "findings": findings,
            **data,
            "storage_assets": storage_assets,
        }
    )


def collect_snapshots_disks(
    provider: BaseProvider,
    options: GlobalOptions,
) -> SnapshotsDisksOutput:
    data = provider.snapshots_disks()
    snapshot_disk_assets = sorted(
        data.get("snapshot_disk_assets", []),
        key=lambda item: (
            item.get("attachment_state") != "detached",
            item.get("asset_kind") != "snapshot",
            str(item.get("public_network_access") or "").lower() != "enabled",
            _priority_sort_value(item),
            item.get("attached_to_name") or "",
            item.get("source_resource_name") or "",
            item.get("name") or "",
        ),
    )
    return SnapshotsDisksOutput.model_validate(
        {
            "metadata": _metadata(provider, "snapshots-disks", options),
            "findings": [],
            **data,
            "snapshot_disk_assets": snapshot_disk_assets,
        }
    )


def collect_nics(provider: BaseProvider, options: GlobalOptions) -> NicsOutput:
    data = provider.nics()
    nic_assets = sorted(data.get("nic_assets", []), key=_nic_asset_sort_key)
    return NicsOutput.model_validate(
        {
            "metadata": _metadata(provider, "nics", options),
            "findings": [],
            **data,
            "nic_assets": nic_assets,
        }
    )


def collect_workloads(provider: BaseProvider, options: GlobalOptions) -> WorkloadsOutput:
    data = provider.workloads()
    return WorkloadsOutput.model_validate(
        {
            "metadata": _metadata(provider, "workloads", options),
            "findings": [],
            **data,
        }
    )


def collect_vms(provider: BaseProvider, options: GlobalOptions) -> VmsOutput:
    data = provider.vms()
    vm_assets = [
        item for item in data.get("vm_assets", []) if str(item.get("vm_type") or "vm") == "vm"
    ]
    vm_assets = sorted(vm_assets, key=_vm_asset_sort_key)
    findings = build_vm_findings(vm_assets)
    return VmsOutput.model_validate(
        {
            "metadata": _metadata(provider, "vms", options),
            "findings": findings,
            **data,
            "vm_assets": vm_assets,
        }
    )


def collect_vmss(provider: BaseProvider, options: GlobalOptions) -> VmssOutput:
    data = provider.vmss()
    vmss_assets = sorted(
        data.get("vmss_assets", []),
        key=lambda item: (
            not _vmss_has_frontend_priority(item),
            not bool(item.get("identity_type")),
            -_int_or_zero(item.get("public_ip_configuration_count")),
            -_int_or_zero(item.get("instance_count")),
            _vmss_orchestration_rank(item.get("orchestration_mode")),
            _vmss_upgrade_rank(item.get("upgrade_mode")),
            item.get("name") or "",
        ),
    )
    return VmssOutput.model_validate(
        {
            "metadata": _metadata(provider, "vmss", options),
            "findings": [],
            **data,
            "vmss_assets": vmss_assets,
        }
    )


def _metadata(
    provider: BaseProvider,
    command: str,
    options: GlobalOptions,
    token_source: str | None = None,
    auth_mode: str | None = None,
) -> CommandMetadata:
    context = provider.metadata_context()
    return CommandMetadata(
        command=command,
        tenant_id=options.tenant or context.get("tenant_id"),
        subscription_id=options.subscription or context.get("subscription_id"),
        devops_organization=options.devops_organization,
        token_source=token_source or context.get("token_source"),
        auth_mode=auth_mode or context.get("auth_mode"),
    )


def _priority_sort_value(item: dict) -> int:
    score = 0
    if item.get("disk_access_id"):
        score -= 2
    if item.get("max_shares") not in (None, 1):
        score -= 2
    if str(item.get("network_access_policy") or "").lower() == "allowall":
        score -= 2
    if str(item.get("public_network_access") or "").lower() == "enabled":
        score -= 1
    if item.get("disk_encryption_set_id") is None:
        score -= 1
    if item.get("attachment_state") == "detached":
        score -= 2
    if item.get("asset_kind") == "snapshot":
        score -= 1
    return score


def _vm_asset_sort_key(item: dict) -> tuple[bool, bool, int, int, str, str]:
    vm_type_rank = {"vm": 0, "vmss": 1}
    return (
        not bool(item.get("public_ips")),
        not bool(item.get("identity_ids")),
        vm_type_rank.get(str(item.get("vm_type") or "").lower(), 9),
        -_int_or_zero(len(item.get("public_ips", []) or [])),
        item.get("name") or "",
        item.get("id") or "",
    )


def _application_gateway_sort_key(item: dict) -> tuple[bool, int, int, int, int, int, int, str]:
    return (
        not bool(item.get("public_frontend_count")),
        -_int_or_zero(item.get("public_frontend_count")),
        -_application_gateway_shared_breadth(item),
        -_int_or_zero(item.get("listener_count")),
        -_int_or_zero(item.get("request_routing_rule_count")),
        -_int_or_zero(item.get("backend_target_count")),
        -_int_or_zero(item.get("backend_pool_count")),
        _application_gateway_waf_rank(item),
        item.get("name") or "",
    )


def _application_gateway_shared_breadth(item: dict) -> int:
    return sum(
        _int_or_zero(item.get(field_name))
        for field_name in (
            "listener_count",
            "request_routing_rule_count",
            "backend_target_count",
            "backend_pool_count",
        )
    )


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


def _lighthouse_role_rank(item: dict) -> tuple[int, int]:
    role_name = str(item.get("strongest_role_name") or "").strip().lower()
    if item.get("has_owner_role"):
        role_rank = 0
    elif item.get("has_user_access_administrator"):
        role_rank = 1
    elif role_name == "contributor":
        role_rank = 2
    elif role_name and role_name != "reader":
        role_rank = 3
    elif role_name == "reader":
        role_rank = 4
    else:
        role_rank = 5

    delegated_rank = 0 if item.get("has_delegated_role_assignments") else 1
    return role_rank, delegated_rank


def _lighthouse_state_rank(item: dict) -> tuple[int, int]:
    assignment_state = str(item.get("provisioning_state") or "").strip().lower()
    definition_state = str(item.get("definition_provisioning_state") or "").strip().lower()
    assignment_rank = 1 if assignment_state in {"", "succeeded"} else 0
    definition_rank = 1 if definition_state in {"", "succeeded"} else 0
    return assignment_rank, definition_rank


def _priority_rank(priority: object) -> int:
    return {"high": 0, "medium": 1, "low": 2}.get(str(priority or "").lower(), 9)


def _cross_tenant_signal_rank(item: dict) -> int:
    return {
        "lighthouse": 0,
        "external-sp": 1,
        "policy": 2,
    }.get(str(item.get("signal_type") or "").lower(), 9)


def _cross_tenant_scope_rank(item: dict) -> int:
    if str(item.get("signal_type") or "").lower() != "lighthouse":
        return 9

    scope = str(item.get("scope") or "").lower()
    if scope.startswith("subscription::"):
        return 0
    if scope.startswith("resource-group::"):
        return 1
    return 2


def _auth_policy_has_findings(item: dict, findings: list[dict]) -> bool:
    related_ids = {str(value) for value in item.get("related_ids", []) if value}
    if not related_ids:
        return False
    for finding in findings:
        finding_related_ids = {str(value) for value in finding.get("related_ids", []) if value}
        if related_ids & finding_related_ids:
            return True
    return False


def _auth_policy_has_issue(item: dict, issues: list[dict]) -> bool:
    collector_name = {
        "security-defaults": "auth_policies.security_defaults",
        "authorization-policy": "auth_policies.authorization_policy",
        "conditional-access": "auth_policies.conditional_access",
    }.get(item.get("policy_type"))
    if collector_name is None:
        return False
    return any(
        (issue.get("context") or {}).get("collector") == collector_name
        for issue in issues
        if isinstance(issue, dict)
    )


def _auth_policy_state_rank(item: dict) -> tuple[int, int]:
    policy_type = str(item.get("policy_type") or "")
    state = str(item.get("state") or "").lower()
    controls = {str(control).lower() for control in item.get("controls", [])}

    if policy_type == "security-defaults":
        return (0 if state == "disabled" else 2, 0)

    if policy_type == "authorization-policy":
        risky_controls = {
            "risky-app-consent:enabled",
            "guest-invites:everyone",
            "users-can-register-apps",
            "user-consent:self-service",
        }
        control_rank = 0 if controls & risky_controls else 1
        return (control_rank, 0)

    if policy_type == "conditional-access":
        if state == "disabled":
            return (0, 0)
        if state == "enabledforreportingbutnotenforced":
            return (1, 0)
        if state == "enabled":
            return (2, 0)
        return (3, 0)

    return (9, 0)


def _role_trust_priority(item: dict) -> tuple[int, int]:
    trust_type = str(item.get("trust_type") or "").strip().lower()
    evidence_type = str(item.get("evidence_type") or "").strip().lower()

    trust_rank = {
        "federated-credential": 0,
        "service-principal-owner": 1,
        "app-owner": 2,
        "app-to-service-principal": 3,
    }.get(trust_type, 9)

    evidence_rank = {
        "graph-federated-credential": 0,
        "graph-owner": 1,
        "graph-app-role-assignment": 2,
    }.get(evidence_type, 9)

    return trust_rank, evidence_rank


def _role_trust_follow_on_rank(next_review: object) -> int:
    text = str(next_review or "").lower()
    if "check permissions" in text:
        return 0
    if "review ownership" in text:
        return 1
    if "check cross-tenant" in text:
        return 2
    return 3


def _storage_priority_rank(item: dict) -> tuple[int, int, int, int, int, int]:
    public_access_rank = 0 if item.get("public_access") else 1

    public_network_enabled = str(item.get("public_network_access") or "").lower() == "enabled"
    network_default_action = str(item.get("network_default_action") or "").lower()
    if public_network_enabled and network_default_action == "allow":
        network_rank = 0
    elif public_network_enabled:
        network_rank = 1
    elif network_default_action == "allow":
        network_rank = 2
    else:
        network_rank = 3

    shared_key_rank = 0 if item.get("allow_shared_key_access") is True else 1
    tls_rank = {
        "tls1_0": 0,
        "tls1_1": 1,
        "tls1_2": 2,
        "tls1_3": 3,
    }.get(str(item.get("minimum_tls_version") or "").lower(), 1)
    https_rank = 0 if item.get("https_traffic_only_enabled") is False else 1
    private_endpoint_rank = 0 if not item.get("private_endpoint_enabled") else 1

    return (
        public_access_rank,
        network_rank,
        shared_key_rank,
        tls_rank,
        https_rank,
        private_endpoint_rank,
    )


def _keyvault_priority_rank(item: dict) -> tuple[int, int, int]:
    public_enabled = str(item.get("public_network_access") or "").lower() == "enabled"
    default_action = str(item.get("network_default_action") or "").lower()
    private_endpoint_enabled = bool(item.get("private_endpoint_enabled"))

    if public_enabled and not default_action and not private_endpoint_enabled:
        exposure_rank = 0
    elif public_enabled and default_action == "allow":
        exposure_rank = 1
    elif public_enabled and not private_endpoint_enabled:
        exposure_rank = 2
    elif public_enabled:
        exposure_rank = 3
    else:
        exposure_rank = 4

    purge_rank = 0 if item.get("purge_protection_enabled") is False else 1
    auth_rank = 0 if item.get("enable_rbac_authorization") is False else 1
    return exposure_rank, purge_rank, auth_rank


def _api_mgmt_priority(item: dict) -> bool:
    return bool(item.get("gateway_hostnames")) or (
        str(item.get("public_network_access") or "").lower() == "enabled"
    )


def _acr_registry_sort_key(item: dict) -> tuple[int, int, int, int, int, str]:
    return (
        _acr_registry_posture_rank(item),
        -_int_or_zero(item.get("enabled_webhook_count")),
        -_int_or_zero(item.get("replication_count")),
        -_acr_governance_weakness_score(item),
        -_int_or_zero(item.get("broad_webhook_scope_count")),
        item.get("name") or "",
    )


def _database_server_sort_key(item: dict) -> tuple[bool, int, int, bool, str, str]:
    return (
        not _database_server_exposure_priority(item),
        _database_tls_rank(item),
        -_int_or_zero(item.get("database_count")),
        not bool(item.get("workload_identity_type")),
        item.get("engine") or "",
        item.get("name") or "",
    )


def _aks_cluster_sort_key(item: dict) -> tuple[int, bool, int, int, tuple[int, int, int], str]:
    return (
        _aks_control_plane_rank(item),
        not bool(item.get("cluster_identity_type")),
        -_aks_federation_cue_count(item),
        -len(item.get("addon_names", []) or []),
        _aks_auth_cue_rank(item),
        item.get("name") or "",
    )


def _nic_asset_sort_key(item: dict) -> tuple[bool, bool, int, int, str, str]:
    boundary_signal_count = int(bool(item.get("network_security_group_id"))) + len(
        item.get("subnet_ids", []) or []
    ) + len(item.get("vnet_ids", []) or [])
    unusual_attachment = (
        item.get("attached_asset_id") is None or item.get("attached_asset_name") is None
    )
    return (
        not bool(item.get("public_ip_ids")),
        not unusual_attachment,
        -boundary_signal_count,
        -len(item.get("private_ips", []) or []),
        item.get("attached_asset_name") or "",
        item.get("name") or "",
    )


def _app_service_sort_key(item: dict) -> tuple[bool, bool, tuple[int, int, int, int], str]:
    return (
        not _web_workload_exposure_priority(item),
        not _has_workload_identity(item),
        _app_service_hardening_rank(item),
        item.get("name") or "",
    )


def _function_app_sort_key(item: dict) -> tuple[bool, bool, bool, tuple[int, int, int], str]:
    return (
        not _web_workload_exposure_priority(item),
        not _has_workload_identity(item),
        item.get("azure_webjobs_storage_value_type") != "plain-text",
        _function_deployment_signal_rank(item),
        item.get("name") or "",
    )


def _arm_deployment_sort_key(item: dict) -> tuple[int, int, int, int, bool, str, str]:
    link_count = int(bool(item.get("template_link"))) + int(bool(item.get("parameters_link")))
    provider_count = len(item.get("providers", []) or [])
    return (
        _arm_deployment_state_rank(item.get("provisioning_state")),
        -link_count,
        -_int_or_zero(item.get("outputs_count")),
        -max(_int_or_zero(item.get("output_resource_count")), provider_count),
        item.get("scope_type") == "subscription",
        item.get("resource_group") or "",
        item.get("name") or "",
    )


def _web_workload_exposure_priority(item: dict) -> bool:
    return bool(item.get("default_hostname")) or (
        str(item.get("public_network_access") or "").lower() == "enabled"
    )


def _has_workload_identity(item: dict) -> bool:
    return bool(item.get("workload_identity_type"))


def _app_service_hardening_rank(item: dict) -> tuple[int, int, int, int]:
    https_rank = 0 if item.get("https_only") is False else 1
    tls_rank = {
        "1.0": 0,
        "1.1": 1,
        "1.2": 2,
        "1.3": 3,
    }.get(str(item.get("min_tls_version") or ""), 4)
    ftps_rank = {
        "allallowed": 0,
        "ftpsonly": 1,
        "disabled": 2,
    }.get(str(item.get("ftps_state") or "").lower(), 3)
    client_cert_rank = 0 if item.get("client_cert_enabled") is False else 1
    return https_rank, tls_rank, ftps_rank, client_cert_rank


def _function_deployment_signal_rank(item: dict) -> tuple[int, int, int]:
    run_from_package_rank = 0 if item.get("run_from_package") is True else 1
    key_vault_rank = -_int_or_zero(item.get("key_vault_reference_count"))
    signal_count = int(item.get("run_from_package") is True) + int(
        _int_or_zero(item.get("key_vault_reference_count")) > 0
    )
    return -signal_count, run_from_package_rank, key_vault_rank


def _arm_deployment_state_rank(value: object) -> int:
    normalized = str(value or "").lower()
    if normalized == "failed":
        return 0
    if normalized and normalized != "succeeded":
        return 1
    return 2


def _vmss_has_frontend_priority(item: dict) -> bool:
    return any(
        _int_or_zero(item.get(key)) > 0
        for key in (
            "public_ip_configuration_count",
            "inbound_nat_pool_count",
            "load_balancer_backend_pool_count",
            "application_gateway_backend_pool_count",
        )
    )


def _vmss_orchestration_rank(value: object) -> int:
    return {"Flexible": 0, "Uniform": 1}.get(str(value or ""), 9)


def _vmss_upgrade_rank(value: object) -> int:
    return {"Manual": 0, "Rolling": 1, "Automatic": 2}.get(str(value or ""), 9)


def _acr_registry_posture_rank(item: dict) -> int:
    public_enabled = str(item.get("public_network_access") or "").lower() == "enabled"
    admin_enabled = item.get("admin_user_enabled") is True
    anonymous_pull_enabled = item.get("anonymous_pull_enabled") is True

    if public_enabled and (admin_enabled or anonymous_pull_enabled):
        return 0
    if public_enabled:
        return 1
    if admin_enabled or anonymous_pull_enabled:
        return 2
    return 3


def _acr_governance_weakness_score(item: dict) -> int:
    return sum(
        1
        for key, weak_values in (
            ("quarantine_policy_status", {"disabled"}),
            ("retention_policy_status", {"disabled"}),
            ("trust_policy_status", {"disabled"}),
        )
        if str(item.get(key) or "").lower() in weak_values
    )


def _database_server_exposure_priority(item: dict) -> bool:
    return str(item.get("public_network_access") or "").lower() == "enabled"


def _database_tls_rank(item: dict) -> int:
    return {
        "1.0": 0,
        "1.1": 1,
        "1.2": 2,
        "1.3": 3,
    }.get(str(item.get("minimal_tls_version") or ""), 4)


def _aks_control_plane_rank(item: dict) -> int:
    if bool(item.get("fqdn")) and item.get("private_cluster_enabled") is not True:
        return 0
    if item.get("public_fqdn_enabled") is True and bool(item.get("fqdn")):
        return 1
    return 2


def _aks_federation_cue_count(item: dict) -> int:
    return int(item.get("oidc_issuer_enabled") is True) + int(
        item.get("workload_identity_enabled") is True
    )


def _aks_auth_cue_rank(item: dict) -> tuple[int, int, int]:
    local_accounts_disabled = item.get("local_accounts_disabled")
    aad_managed = item.get("aad_managed")
    azure_rbac_enabled = item.get("azure_rbac_enabled")

    return (
        0 if local_accounts_disabled is False else 1 if local_accounts_disabled is True else 2,
        0 if aad_managed is False else 1 if aad_managed is True else 2,
        0 if azure_rbac_enabled is False else 1 if azure_rbac_enabled is True else 2,
    )


def _automation_sort_key(item: dict) -> tuple[bool, bool, bool, int, int, int, int, str]:
    secure_asset_total = sum(
        _int_or_zero(item.get(key))
        for key in (
            "credential_count",
            "certificate_count",
            "connection_count",
            "encrypted_variable_count",
        )
    )
    return (
        _int_or_zero(item.get("hybrid_worker_group_count")) == 0,
        not bool(item.get("identity_type")),
        _int_or_zero(item.get("webhook_count")) == 0,
        -_int_or_zero(item.get("published_runbook_count")),
        -_int_or_zero(item.get("job_schedule_count")),
        -secure_asset_total,
        -_int_or_zero(item.get("runbook_count")),
        item.get("name") or "",
    )


def _devops_pipeline_sort_key(item: dict) -> tuple[bool, bool, bool, bool, bool, str, str]:
    trigger_types = {str(value).lower() for value in item.get("trigger_types", [])}
    return (
        len(item.get("azure_service_connection_names", []) or []) == 0,
        _int_or_zero(item.get("secret_variable_count")) == 0,
        len(item.get("key_vault_group_names", []) or []) == 0,
        trigger_types.isdisjoint({"continuousintegration", "schedule"}),
        len(item.get("target_clues", []) or []) == 0,
        item.get("project_name") or "",
        item.get("name") or "",
    )


def _enrich_permission_rows(permissions: list[dict], principals: list[dict]) -> list[dict]:
    principals_by_id = {item.get("id"): item for item in principals if item.get("id")}
    enriched: list[dict] = []

    for permission in permissions:
        item = dict(permission)
        principal = principals_by_id.get(item.get("principal_id")) or {}
        identity_names = [str(value) for value in principal.get("identity_names") or [] if value]
        attached_to = [str(value) for value in principal.get("attached_to") or [] if value]
        sources = {str(value) for value in principal.get("sources") or [] if value}
        privileged = bool(item.get("privileged"))
        is_current_identity = bool(item.get("is_current_identity"))
        has_workload_pivot = bool(attached_to)
        workload_visibility_blocked = not has_workload_pivot and bool(
            identity_names or "managed-identities" in sources
        )
        workload_pivot_rank = 0 if identity_names and attached_to else 1 if attached_to else 9
        trust_expansion_follow_on = (
            privileged
            and not is_current_identity
            and not has_workload_pivot
            and not workload_visibility_blocked
            and (
                str(item.get("principal_type") or "").lower() == "serviceprincipal"
                or "managed-identities" in sources
            )
        )

        item["operator_signal"] = permissions_operator_signal(
            privileged=privileged,
            is_current_identity=is_current_identity,
            has_workload_pivot=has_workload_pivot,
            workload_visibility_blocked=workload_visibility_blocked,
            trust_expansion_follow_on=trust_expansion_follow_on,
        )
        item["next_review"] = permissions_next_review_hint(
            privileged=privileged,
            is_current_identity=is_current_identity,
            has_workload_pivot=has_workload_pivot,
            workload_visibility_blocked=workload_visibility_blocked,
            trust_expansion_follow_on=trust_expansion_follow_on,
        )
        item["summary"] = permissions_summary(
            principal_name=item.get("display_name") or item.get("principal_id") or "unknown",
            principal_type=item.get("principal_type", "unknown"),
            high_impact_roles=[str(value) for value in item.get("high_impact_roles") or []],
            scope_count=_int_or_zero(item.get("scope_count")) or len(item.get("scope_ids") or []),
            privileged=privileged,
            is_current_identity=is_current_identity,
            has_workload_pivot=has_workload_pivot,
            workload_visibility_blocked=workload_visibility_blocked,
            trust_expansion_follow_on=trust_expansion_follow_on,
            next_review=item["next_review"],
        )
        item["_workload_pivot_rank"] = workload_pivot_rank
        enriched.append(item)

    return sorted(enriched, key=_permission_row_sort_key)


def _enrich_role_trust_rows(trusts: list[dict]) -> list[dict]:
    enriched: list[dict] = []
    backing_service_principal_by_application_id: dict[str, str] = {}

    for trust in trusts:
        if (
            str(trust.get("trust_type") or "") == "federated-credential"
            and str(trust.get("source_type") or "") == "Application"
            and str(trust.get("target_type") or "") == "ServicePrincipal"
            and trust.get("source_object_id")
            and trust.get("target_name")
        ):
            backing_service_principal_by_application_id[str(trust["source_object_id"])] = str(
                trust["target_name"]
            )

    for trust in trusts:
        item = dict(trust)
        trust_type = str(item.get("trust_type") or "")
        source_name = item.get("source_name")
        target_name = item.get("target_name")
        summary = str(item.get("summary") or "")
        target_type = str(item.get("target_type") or "identity")
        source_type = str(item.get("source_type") or "identity")
        backing_service_principal_name = backing_service_principal_by_application_id.get(
            str(item.get("target_object_id") or "")
        )

        controlled_object_type, controlled_object_name = role_trust_controlled_object(
            trust_type=trust_type,
            source_name=source_name,
            source_type=source_type,
            target_name=target_name,
            target_type=target_type,
        )
        item["control_primitive"] = role_trust_control_primitive(
            trust_type=trust_type,
            target_type=target_type,
        )
        item["controlled_object_type"] = controlled_object_type
        item["controlled_object_name"] = controlled_object_name
        item["escalation_mechanism"] = role_trust_escalation_mechanism(
            trust_type=trust_type,
            source_name=source_name,
            target_name=target_name,
            target_type=target_type,
            backing_service_principal_name=backing_service_principal_name,
        )
        item["usable_identity_result"] = role_trust_usable_identity_result(
            trust_type=trust_type,
            source_name=source_name,
            target_name=target_name,
            target_type=target_type,
            backing_service_principal_name=backing_service_principal_name,
        )
        item["defender_cut_point"] = role_trust_defender_cut_point(
            trust_type=trust_type,
            source_name=source_name,
            target_name=target_name,
            target_type=target_type,
        )

        item["operator_signal"] = role_trust_operator_signal(
            trust_type=trust_type,
            source_name=source_name,
            target_name=target_name,
            summary=summary,
        )
        item["next_review"] = role_trust_next_review_hint(
            trust_type=trust_type,
            source_name=source_name,
            source_object_id=item.get("source_object_id") or "unknown",
            target_name=target_name,
            target_object_id=item.get("target_object_id") or "unknown",
            target_type=str(item.get("target_type") or "identity"),
            summary=summary,
        )
        item["summary"] = role_trust_summary(
            trust_type=trust_type,
            source_name=source_name,
            target_name=target_name,
            summary=summary,
            next_review=item["next_review"],
        )
        enriched.append(item)

    return enriched


def _permission_row_sort_key(item: dict) -> tuple[bool, int, int, int, int, str, str]:
    return (
        not bool(item.get("privileged")),
        _permission_follow_on_rank(item.get("next_review")),
        _int_or_zero(item.get("_workload_pivot_rank")),
        _permission_role_rank(item.get("high_impact_roles") or []),
        -_int_or_zero(item.get("scope_count")),
        -_int_or_zero(item.get("role_assignment_count")),
        item.get("display_name") or "",
        item.get("principal_id") or "",
    )


def _permission_follow_on_rank(next_review: object) -> int:
    text = str(next_review or "").lower()
    if "check privesc" in text:
        return 0
    if "check managed-identities" in text:
        return 1
    if "check role-trusts" in text:
        return 2
    return 3


def _permission_role_rank(high_impact_roles: object) -> int:
    roles = [str(value).lower() for value in high_impact_roles or []]
    if "owner" in roles:
        return 0
    if "user access administrator" in roles:
        return 1
    if "contributor" in roles:
        return 2
    return 9


_HIGH_IMPACT_ROLE_NAMES = {
    "owner",
    "contributor",
    "user access administrator",
}


def _enrich_managed_identity_rows(
    identities: list[dict],
    role_assignments: list[dict],
    vm_assets: list[dict],
    vmss_assets: list[dict],
) -> list[dict]:
    assignments_by_principal: dict[str, list[str]] = {}
    for assignment in role_assignments:
        principal_id = assignment.get("principal_id")
        role_name = assignment.get("role_name")
        if not principal_id or not role_name:
            continue
        assignments_by_principal.setdefault(principal_id, []).append(str(role_name))

    vm_by_id = {item.get("id"): item for item in vm_assets if item.get("id")}
    vmss_by_id = {item.get("id"): item for item in vmss_assets if item.get("id")}

    enriched: list[dict] = []
    for identity in identities:
        item = dict(identity)
        primary_attachment = _managed_identity_primary_attachment(
            item.get("attached_to", []),
            vm_by_id,
            vmss_by_id,
        )
        privileged_roles = sorted(
            {
                role_name
                for role_name in assignments_by_principal.get(item.get("principal_id") or "", [])
                if role_name.lower() in _HIGH_IMPACT_ROLE_NAMES
            }
        )
        attachment_count = len(item.get("attached_to", []) or [])
        visibility_blocked = not bool(item.get("principal_id"))
        attachment_kind = primary_attachment.get("kind")
        next_review = managed_identity_next_review_hint(
            attachment_kind=attachment_kind,
            privileged=bool(privileged_roles),
            visibility_blocked=visibility_blocked,
        )
        item["operator_signal"] = managed_identity_operator_signal(
            attachment_kind=attachment_kind,
            exposed=bool(primary_attachment.get("exposed")),
            privileged=bool(privileged_roles),
            visibility_blocked=visibility_blocked,
            attachment_count=attachment_count,
        )
        item["next_review"] = next_review
        item["summary"] = managed_identity_summary(
            identity_name=item.get("name") or item.get("id") or "unknown",
            attachment_name=primary_attachment.get("name"),
            attachment_kind=attachment_kind,
            exposed=bool(primary_attachment.get("exposed")),
            privileged_roles=privileged_roles,
            visibility_blocked=visibility_blocked,
            next_review=next_review,
            attachment_count=attachment_count,
        )
        enriched.append(item)

    return sorted(enriched, key=_managed_identity_sort_key)


def _managed_identity_primary_attachment(
    attached_to: object,
    vm_by_id: dict[str, dict],
    vmss_by_id: dict[str, dict],
) -> dict[str, object]:
    attachment_ids = [str(value) for value in attached_to or [] if value]
    candidates = [
        _managed_identity_attachment_context(value, vm_by_id, vmss_by_id)
        for value in attachment_ids
    ]
    candidates = [item for item in candidates if item]
    if not candidates:
        return {"kind": None, "name": None, "exposed": False}
    return min(candidates, key=_managed_identity_attachment_sort_key)


def _managed_identity_attachment_context(
    resource_id: str,
    vm_by_id: dict[str, dict],
    vmss_by_id: dict[str, dict],
) -> dict[str, object]:
    vm_asset = vm_by_id.get(resource_id)
    if vm_asset:
        return {
            "kind": "VM",
            "name": vm_asset.get("name") or _arm_name(resource_id),
            "exposed": bool(vm_asset.get("public_ips")),
        }

    vmss_asset = vmss_by_id.get(resource_id)
    if vmss_asset:
        return {
            "kind": "VMSS",
            "name": vmss_asset.get("name") or _arm_name(resource_id),
            "exposed": any(
                _int_or_zero(vmss_asset.get(key)) > 0
                for key in ("public_ip_configuration_count", "inbound_nat_pool_count")
            ),
        }

    lowered = resource_id.lower()
    if "/providers/microsoft.web/sites/" in lowered:
        return {
            "kind": "WebWorkload",
            "name": _arm_name(resource_id),
            "exposed": False,
        }
    if "/providers/microsoft.compute/virtualmachines/" in lowered:
        return {
            "kind": "VM",
            "name": _arm_name(resource_id),
            "exposed": False,
        }
    if "/providers/microsoft.compute/virtualmachinescalesets/" in lowered:
        return {
            "kind": "VMSS",
            "name": _arm_name(resource_id),
            "exposed": False,
        }
    return {
        "kind": None,
        "name": _arm_name(resource_id),
        "exposed": False,
    }


def _managed_identity_attachment_sort_key(item: dict[str, object]) -> tuple[bool, int, str]:
    kind_rank = {
        "VM": 0,
        "VMSS": 1,
        "FunctionApp": 2,
        "AppService": 3,
        "WebWorkload": 4,
        None: 9,
    }
    return (
        not bool(item.get("exposed")),
        kind_rank.get(item.get("kind"), 8),
        str(item.get("name") or ""),
    )


def _managed_identity_sort_key(item: dict) -> tuple[bool, bool, bool, int, str, str]:
    operator_signal = str(item.get("operator_signal") or "")
    exposed = "workload pivot" in operator_signal.lower() and (
        operator_signal.startswith("Public") or operator_signal.startswith("Exposed")
    )
    direct_control = "direct control visible" in operator_signal.lower()
    repeated = "reused across" in operator_signal.lower()
    kind_rank = {
        "VM": 0,
        "VMSS": 1,
        "FunctionApp": 2,
        "AppService": 3,
        "WebWorkload": 4,
        None: 9,
    }
    primary_kind = _managed_identity_attachment_context(
        str((item.get("attached_to") or [""])[0]),
        {},
        {},
    ).get("kind")
    return (
        not exposed,
        not direct_control,
        not repeated,
        kind_rank.get(primary_kind, 8),
        item.get("name") or "",
        item.get("id") or "",
    )


def _arm_name(resource_id: str) -> str:
    return resource_id.rstrip("/").split("/")[-1]


def _int_or_zero(value: object) -> int:
    return value if isinstance(value, int) else 0
