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
from azurefox.models.commands import (
    AcrOutput,
    AksOutput,
    ApiMgmtOutput,
    AppServicesOutput,
    ArmDeploymentsOutput,
    AuthPoliciesOutput,
    DatabasesOutput,
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


def collect_whoami(provider: BaseProvider, options: GlobalOptions) -> WhoAmIOutput:
    data = provider.whoami()
    output = WhoAmIOutput.model_validate(
        {
            "metadata": _metadata(provider, "whoami", options, data.get("token_source")),
            **data,
        }
    )
    return output


def collect_inventory(provider: BaseProvider, options: GlobalOptions) -> InventoryOutput:
    data = provider.inventory()
    return InventoryOutput.model_validate(
        {"metadata": _metadata(provider, "inventory", options), **data}
    )


def collect_app_services(provider: BaseProvider, options: GlobalOptions) -> AppServicesOutput:
    data = provider.app_services()
    return AppServicesOutput.model_validate(
        {
            "metadata": _metadata(provider, "app-services", options),
            "findings": [],
            **data,
        }
    )


def collect_acr(provider: BaseProvider, options: GlobalOptions) -> AcrOutput:
    data = provider.acr()
    return AcrOutput.model_validate(
        {
            "metadata": _metadata(provider, "acr", options),
            "findings": [],
            **data,
        }
    )


def collect_databases(provider: BaseProvider, options: GlobalOptions) -> DatabasesOutput:
    data = provider.databases()
    return DatabasesOutput.model_validate(
        {
            "metadata": _metadata(provider, "databases", options),
            "findings": [],
            **data,
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
    return AksOutput.model_validate(
        {
            "metadata": _metadata(provider, "aks", options),
            "findings": [],
            **data,
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


def collect_functions(provider: BaseProvider, options: GlobalOptions) -> FunctionsOutput:
    data = provider.functions()
    return FunctionsOutput.model_validate(
        {
            "metadata": _metadata(provider, "functions", options),
            "findings": [],
            **data,
        }
    )


def collect_arm_deployments(provider: BaseProvider, options: GlobalOptions) -> ArmDeploymentsOutput:
    data = provider.arm_deployments()
    deployments = sorted(
        data.get("deployments", []),
        key=lambda item: (
            item.get("scope_type") != "subscription",
            item.get("resource_group") or "",
            item.get("name") or "",
        ),
    )
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
    return PermissionsOutput.model_validate(
        {"metadata": _metadata(provider, "permissions", options), **data}
    )


def collect_privesc(provider: BaseProvider, options: GlobalOptions) -> PrivescOutput:
    data = provider.privesc()
    return PrivescOutput.model_validate(
        {"metadata": _metadata(provider, "privesc", options), **data}
    )


def collect_role_trusts(provider: BaseProvider, options: GlobalOptions) -> RoleTrustsOutput:
    data = provider.role_trusts(options.role_trusts_mode)
    trusts = sorted(
        data.get("trusts", []),
        key=lambda item: (
            str(item.get("confidence") or "").lower() != "confirmed",
            _role_trust_priority(item),
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
    findings = build_identity_findings(
        data.get("identities", []),
        data.get("role_assignments", []),
    )
    return ManagedIdentitiesOutput.model_validate(
        {
            "metadata": _metadata(provider, "managed-identities", options),
            "findings": findings,
            **data,
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
    nic_assets = sorted(
        data.get("nic_assets", []),
        key=lambda item: (
            item.get("attached_asset_name") is None,
            item.get("attached_asset_name") or "",
            item.get("name") or "",
        ),
    )
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
    findings = build_vm_findings(data.get("vm_assets", []))
    return VmsOutput.model_validate(
        {"metadata": _metadata(provider, "vms", options), "findings": findings, **data}
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
) -> CommandMetadata:
    context = provider.metadata_context()
    return CommandMetadata(
        command=command,
        tenant_id=options.tenant or context.get("tenant_id"),
        subscription_id=options.subscription or context.get("subscription_id"),
        token_source=token_source or context.get("token_source"),
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


def _int_or_zero(value: object) -> int:
    return value if isinstance(value, int) else 0
