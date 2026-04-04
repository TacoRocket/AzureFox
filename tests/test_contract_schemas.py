from __future__ import annotations

import json
from pathlib import Path

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
    WhoAmIOutput,
    WorkloadsOutput,
)

MODEL_MAP = {
    "whoami": WhoAmIOutput,
    "inventory": InventoryOutput,
    "app-services": AppServicesOutput,
    "acr": AcrOutput,
    "databases": DatabasesOutput,
    "dns": DnsOutput,
    "network-effective": NetworkEffectiveOutput,
    "aks": AksOutput,
    "api-mgmt": ApiMgmtOutput,
    "functions": FunctionsOutput,
    "arm-deployments": ArmDeploymentsOutput,
    "endpoints": EndpointsOutput,
    "env-vars": EnvVarsOutput,
    "network-ports": NetworkPortsOutput,
    "tokens-credentials": TokensCredentialsOutput,
    "rbac": RbacOutput,
    "principals": PrincipalsOutput,
    "permissions": PermissionsOutput,
    "privesc": PrivescOutput,
    "role-trusts": RoleTrustsOutput,
    "resource-trusts": ResourceTrustsOutput,
    "auth-policies": AuthPoliciesOutput,
    "managed-identities": ManagedIdentitiesOutput,
    "keyvault": KeyVaultOutput,
    "storage": StorageOutput,
    "snapshots-disks": SnapshotsDisksOutput,
    "nics": NicsOutput,
    "workloads": WorkloadsOutput,
    "vms": VmsOutput,
}


def test_schema_contracts_match_top_level_fields() -> None:
    root = Path(__file__).resolve().parents[1]
    schema_dir = root / "schemas"

    for command, model in MODEL_MAP.items():
        payload = json.loads((schema_dir / f"{command}.schema.json").read_text(encoding="utf-8"))
        assert payload["model"] == model.__name__
        assert payload["top_level_fields"] == list(model.model_fields.keys())
