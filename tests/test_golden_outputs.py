from __future__ import annotations

import json
from pathlib import Path

from azurefox.collectors.commands import (
    collect_auth_policies,
    collect_inventory,
    collect_keyvault,
    collect_managed_identities,
    collect_permissions,
    collect_principals,
    collect_privesc,
    collect_rbac,
    collect_role_trusts,
    collect_storage,
    collect_vms,
    collect_whoami,
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
        "rbac": collect_rbac,
        "principals": collect_principals,
        "permissions": collect_permissions,
        "privesc": collect_privesc,
        "role-trusts": collect_role_trusts,
        "auth-policies": collect_auth_policies,
        "managed-identities": collect_managed_identities,
        "keyvault": collect_keyvault,
        "storage": collect_storage,
        "vms": collect_vms,
    }

    for command, collector in collectors.items():
        model = collector(fixture_provider, options)
        expected = json.loads((golden_dir / f"{command}.json").read_text(encoding="utf-8"))
        assert _normalize(model.model_dump(mode="json")) == expected
