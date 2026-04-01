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
    ArmDeploymentsOutput,
    AuthPoliciesOutput,
    EndpointsOutput,
    EnvVarsOutput,
    InventoryOutput,
    KeyVaultOutput,
    ManagedIdentitiesOutput,
    NetworkPortsOutput,
    NicsOutput,
    PermissionsOutput,
    PrincipalsOutput,
    PrivescOutput,
    RbacOutput,
    ResourceTrustsOutput,
    RoleTrustsOutput,
    StorageOutput,
    TokensCredentialsOutput,
    VmsOutput,
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
    data = provider.role_trusts()
    return RoleTrustsOutput.model_validate(
        {"metadata": _metadata(provider, "role-trusts", options), **data}
    )


def collect_resource_trusts(provider: BaseProvider, options: GlobalOptions) -> ResourceTrustsOutput:
    data = provider.resource_trusts()
    return ResourceTrustsOutput.model_validate(
        {"metadata": _metadata(provider, "resource-trusts", options), **data}
    )


def collect_auth_policies(provider: BaseProvider, options: GlobalOptions) -> AuthPoliciesOutput:
    data = provider.auth_policies()
    findings = build_auth_policy_findings(data.get("auth_policies", []))
    return AuthPoliciesOutput.model_validate(
        {
            "metadata": _metadata(provider, "auth-policies", options),
            "findings": findings,
            **data,
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
    findings = build_keyvault_findings(data.get("key_vaults", []))
    return KeyVaultOutput.model_validate(
        {"metadata": _metadata(provider, "keyvault", options), "findings": findings, **data}
    )


def collect_storage(provider: BaseProvider, options: GlobalOptions) -> StorageOutput:
    data = provider.storage()
    findings = build_storage_findings(data.get("storage_assets", []))
    return StorageOutput.model_validate(
        {"metadata": _metadata(provider, "storage", options), "findings": findings, **data}
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
