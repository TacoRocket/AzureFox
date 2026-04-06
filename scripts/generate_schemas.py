from __future__ import annotations

import json
from pathlib import Path

from azurefox.models.commands import (
    AcrOutput,
    AksOutput,
    ApiMgmtOutput,
    ApplicationGatewayOutput,
    AppServicesOutput,
    ArmDeploymentsOutput,
    AuthPoliciesOutput,
    AutomationOutput,
    ChainsCommandOutput,
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

MODELS = {
    "whoami": WhoAmIOutput,
    "inventory": InventoryOutput,
    "automation": AutomationOutput,
    "chains": ChainsCommandOutput,
    "devops": DevopsOutput,
    "app-services": AppServicesOutput,
    "acr": AcrOutput,
    "databases": DatabasesOutput,
    "dns": DnsOutput,
    "application-gateway": ApplicationGatewayOutput,
    "network-effective": NetworkEffectiveOutput,
    "aks": AksOutput,
    "api-mgmt": ApiMgmtOutput,
    "functions": FunctionsOutput,
    "arm-deployments": ArmDeploymentsOutput,
    "auth-policies": AuthPoliciesOutput,
    "endpoints": EndpointsOutput,
    "env-vars": EnvVarsOutput,
    "network-ports": NetworkPortsOutput,
    "tokens-credentials": TokensCredentialsOutput,
    "rbac": RbacOutput,
    "principals": PrincipalsOutput,
    "permissions": PermissionsOutput,
    "privesc": PrivescOutput,
    "role-trusts": RoleTrustsOutput,
    "cross-tenant": CrossTenantOutput,
    "lighthouse": LighthouseOutput,
    "managed-identities": ManagedIdentitiesOutput,
    "keyvault": KeyVaultOutput,
    "resource-trusts": ResourceTrustsOutput,
    "storage": StorageOutput,
    "snapshots-disks": SnapshotsDisksOutput,
    "nics": NicsOutput,
    "workloads": WorkloadsOutput,
    "vms": VmsOutput,
    "vmss": VmssOutput,
}


def main() -> None:
    outdir = Path("schemas")
    outdir.mkdir(parents=True, exist_ok=True)

    for command, model in MODELS.items():
        payload = {
            "model": model.__name__,
            "top_level_fields": list(model.model_fields.keys()),
        }
        path = outdir / f"{command}.schema.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
