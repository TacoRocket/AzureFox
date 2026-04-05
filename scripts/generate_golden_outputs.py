from __future__ import annotations

import json
from pathlib import Path

from azurefox.collectors.commands import (
    collect_arm_deployments,
    collect_cross_tenant,
    collect_env_vars,
    collect_inventory,
    collect_keyvault,
    collect_lighthouse,
    collect_managed_identities,
    collect_network_effective,
    collect_rbac,
    collect_resource_trusts,
    collect_storage,
    collect_vms,
    collect_vmss,
    collect_whoami,
    collect_workloads,
)
from azurefox.collectors.provider import FixtureProvider
from azurefox.config import GlobalOptions
from azurefox.models.common import OutputMode


def normalize(payload: dict) -> dict:
    payload = json.loads(json.dumps(payload))
    payload["metadata"]["generated_at"] = "<generated_at>"
    return payload


def main() -> None:
    fixture_provider = FixtureProvider(Path("tests/fixtures/lab_tenant"))
    options = GlobalOptions(
        tenant="11111111-1111-1111-1111-111111111111",
        subscription="22222222-2222-2222-2222-222222222222",
        output=OutputMode.JSON,
        outdir=Path("."),
        debug=False,
    )

    commands = {
        "whoami": collect_whoami,
        "inventory": collect_inventory,
        "arm-deployments": collect_arm_deployments,
        "env-vars": collect_env_vars,
        "network-effective": collect_network_effective,
        "rbac": collect_rbac,
        "cross-tenant": collect_cross_tenant,
        "lighthouse": collect_lighthouse,
        "managed-identities": collect_managed_identities,
        "keyvault": collect_keyvault,
        "resource-trusts": collect_resource_trusts,
        "storage": collect_storage,
        "vms": collect_vms,
        "vmss": collect_vmss,
        "workloads": collect_workloads,
    }

    outdir = Path("tests/golden")
    outdir.mkdir(parents=True, exist_ok=True)

    for command, collector in commands.items():
        model = collector(fixture_provider, options)
        payload = normalize(model.model_dump(mode="json"))
        path = outdir / f"{command}.json"
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
