from __future__ import annotations

import json
from pathlib import Path

from azurefox.collectors.commands import (
    collect_acr,
    collect_aks,
    collect_api_mgmt,
    collect_application_gateway,
    collect_app_services,
    collect_arm_deployments,
    collect_auth_policies,
    collect_automation,
    collect_cross_tenant,
    collect_databases,
    collect_devops,
    collect_dns,
    collect_endpoints,
    collect_env_vars,
    collect_functions,
    collect_inventory,
    collect_keyvault,
    collect_lighthouse,
    collect_managed_identities,
    collect_network_effective,
    collect_network_ports,
    collect_nics,
    collect_permissions,
    collect_principals,
    collect_privesc,
    collect_rbac,
    collect_resource_trusts,
    collect_role_trusts,
    collect_snapshots_disks,
    collect_storage,
    collect_tokens_credentials,
    collect_vms,
    collect_vmss,
    collect_whoami,
    collect_workloads,
)


def _normalize(payload: dict) -> dict:
    payload = json.loads(json.dumps(payload))
    payload["metadata"]["generated_at"] = "<generated_at>"
    if payload["metadata"].get("devops_organization") is None:
        payload["metadata"].pop("devops_organization", None)
    return payload


def test_golden_outputs(fixture_provider, options) -> None:
    root = Path(__file__).resolve().parent
    golden_dir = root / "golden"

    collectors = {
        "whoami": collect_whoami,
        "inventory": collect_inventory,
        "automation": collect_automation,
        "devops": collect_devops,
        "app-services": collect_app_services,
        "acr": collect_acr,
        "databases": collect_databases,
        "dns": collect_dns,
        "application-gateway": collect_application_gateway,
        "network-effective": collect_network_effective,
        "aks": collect_aks,
        "api-mgmt": collect_api_mgmt,
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
        "cross-tenant": collect_cross_tenant,
        "lighthouse": collect_lighthouse,
        "resource-trusts": collect_resource_trusts,
        "auth-policies": collect_auth_policies,
        "managed-identities": collect_managed_identities,
        "keyvault": collect_keyvault,
        "storage": collect_storage,
        "snapshots-disks": collect_snapshots_disks,
        "nics": collect_nics,
        "workloads": collect_workloads,
        "vms": collect_vms,
        "vmss": collect_vmss,
    }

    for command, collector in collectors.items():
        model = collector(fixture_provider, options)
        expected = json.loads((golden_dir / f"{command}.json").read_text(encoding="utf-8"))
        assert _normalize(model.model_dump(mode="json")) == _normalize(expected)
