from __future__ import annotations

import json
from pathlib import Path

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
)

MODELS = {
    "whoami": WhoAmIOutput,
    "inventory": InventoryOutput,
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
    "managed-identities": ManagedIdentitiesOutput,
    "keyvault": KeyVaultOutput,
    "resource-trusts": ResourceTrustsOutput,
    "storage": StorageOutput,
    "nics": NicsOutput,
    "vms": VmsOutput,
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
