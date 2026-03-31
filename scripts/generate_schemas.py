from __future__ import annotations

import json
from pathlib import Path

from azurefox.models.commands import (
    InventoryOutput,
    KeyVaultOutput,
    ManagedIdentitiesOutput,
    RbacOutput,
    StorageOutput,
    VmsOutput,
    WhoAmIOutput,
)

MODELS = {
    "whoami": WhoAmIOutput,
    "inventory": InventoryOutput,
    "rbac": RbacOutput,
    "managed-identities": ManagedIdentitiesOutput,
    "keyvault": KeyVaultOutput,
    "storage": StorageOutput,
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
