from __future__ import annotations

import json
from pathlib import Path

from azurefox.collectors.commands import (
    collect_app_services,
    collect_arm_deployments,
    collect_auth_policies,
    collect_endpoints,
    collect_env_vars,
    collect_functions,
    collect_inventory,
    collect_keyvault,
    collect_managed_identities,
    collect_network_ports,
    collect_nics,
    collect_permissions,
    collect_principals,
    collect_privesc,
    collect_rbac,
    collect_resource_trusts,
    collect_role_trusts,
    collect_storage,
    collect_tokens_credentials,
    collect_vms,
    collect_whoami,
    collect_workloads,
)


def _normalize(payload: dict) -> dict:
    payload = json.loads(json.dumps(payload))
    payload["metadata"]["generated_at"] = "<generated_at>"
    return payload


def test_golden_outputs(fixture_provider, options) -> None:
    root = Path(__file__).resolve().parent
    golden_dir = root / "golden"

    collectors = {
        "whoami": collect_whoami,
        "inventory": collect_inventory,
        "app-services": collect_app_services,
        "functions": collect_functions,
        "arm-deployments": collect_arm_deployments,
        "endpoints": collect_endpoints,
        "env-vars": collect_env_vars,
        "network-ports": collect_network_ports,
        "tokens-credentials": collect_tokens_credentials,
        "rbac": collect_rbac,
        "principals": collect_principals,
        "permissions": collect_permissions,
        "privesc": collect_privesc,
        "role-trusts": collect_role_trusts,
        "resource-trusts": collect_resource_trusts,
        "auth-policies": collect_auth_policies,
        "managed-identities": collect_managed_identities,
        "keyvault": collect_keyvault,
        "storage": collect_storage,
        "nics": collect_nics,
        "workloads": collect_workloads,
        "vms": collect_vms,
    }

    for command, collector in collectors.items():
        model = collector(fixture_provider, options)
        expected = json.loads((golden_dir / f"{command}.json").read_text(encoding="utf-8"))
        assert _normalize(model.model_dump(mode="json")) == expected
