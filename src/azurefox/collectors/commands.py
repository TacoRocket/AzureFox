from __future__ import annotations

from azurefox.collectors.provider import BaseProvider
from azurefox.config import GlobalOptions
from azurefox.correlation.findings import (
    build_identity_findings,
    build_storage_findings,
    build_vm_findings,
)
from azurefox.models.commands import (
    InventoryOutput,
    ManagedIdentitiesOutput,
    PermissionsOutput,
    PrincipalsOutput,
    PrivescOutput,
    RbacOutput,
    StorageOutput,
    VmsOutput,
    WhoAmIOutput,
)
from azurefox.models.common import CommandMetadata


def collect_whoami(provider: BaseProvider, options: GlobalOptions) -> WhoAmIOutput:
    data = provider.whoami()
    output = WhoAmIOutput.model_validate(
        {
            "metadata": _metadata("whoami", options, data.get("token_source")),
            **data,
        }
    )
    return output


def collect_inventory(provider: BaseProvider, options: GlobalOptions) -> InventoryOutput:
    data = provider.inventory()
    return InventoryOutput.model_validate({"metadata": _metadata("inventory", options), **data})


def collect_rbac(provider: BaseProvider, options: GlobalOptions) -> RbacOutput:
    data = provider.rbac()
    return RbacOutput.model_validate({"metadata": _metadata("rbac", options), **data})


def collect_principals(provider: BaseProvider, options: GlobalOptions) -> PrincipalsOutput:
    data = provider.principals()
    return PrincipalsOutput.model_validate({"metadata": _metadata("principals", options), **data})


def collect_permissions(provider: BaseProvider, options: GlobalOptions) -> PermissionsOutput:
    data = provider.permissions()
    return PermissionsOutput.model_validate({"metadata": _metadata("permissions", options), **data})


def collect_privesc(provider: BaseProvider, options: GlobalOptions) -> PrivescOutput:
    data = provider.privesc()
    return PrivescOutput.model_validate({"metadata": _metadata("privesc", options), **data})


def collect_managed_identities(
    provider: BaseProvider, options: GlobalOptions
) -> ManagedIdentitiesOutput:
    data = provider.managed_identities()
    findings = build_identity_findings(
        data.get("identities", []),
        data.get("role_assignments", []),
    )
    return ManagedIdentitiesOutput.model_validate(
        {"metadata": _metadata("managed-identities", options), "findings": findings, **data}
    )


def collect_storage(provider: BaseProvider, options: GlobalOptions) -> StorageOutput:
    data = provider.storage()
    findings = build_storage_findings(data.get("storage_assets", []))
    return StorageOutput.model_validate(
        {"metadata": _metadata("storage", options), "findings": findings, **data}
    )


def collect_vms(provider: BaseProvider, options: GlobalOptions) -> VmsOutput:
    data = provider.vms()
    findings = build_vm_findings(data.get("vm_assets", []))
    return VmsOutput.model_validate(
        {"metadata": _metadata("vms", options), "findings": findings, **data}
    )


def _metadata(
    command: str, options: GlobalOptions, token_source: str | None = None
) -> CommandMetadata:
    return CommandMetadata(
        command=command,
        tenant_id=options.tenant,
        subscription_id=options.subscription,
        token_source=token_source,
    )
