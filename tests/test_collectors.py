from __future__ import annotations

from pathlib import Path

from azurefox.collectors.commands import (
    collect_inventory,
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
from azurefox.collectors.provider import FixtureProvider
from azurefox.config import GlobalOptions
from azurefox.models.common import OutputMode


class MetadataFixtureProvider(FixtureProvider):
    def metadata_context(self) -> dict[str, str | None]:
        return {
            "tenant_id": "tenant-from-provider",
            "subscription_id": "subscription-from-provider",
            "token_source": "azure_cli",
        }


def test_collect_whoami(fixture_provider, options) -> None:
    output = collect_whoami(fixture_provider, options)
    assert output.principal is not None
    assert output.principal.id == "33333333-3333-3333-3333-333333333333"


def test_collect_inventory(fixture_provider, options) -> None:
    output = collect_inventory(fixture_provider, options)
    assert output.resource_group_count == 4
    assert output.resource_count == 27


def test_collect_inventory_metadata_falls_back_to_provider_context(
    fixture_dir: Path, tmp_path: Path
) -> None:
    provider = MetadataFixtureProvider(fixture_dir)
    options = GlobalOptions(
        tenant=None,
        subscription=None,
        output=OutputMode.JSON,
        outdir=tmp_path,
        debug=False,
    )

    output = collect_inventory(provider, options)

    assert output.metadata.tenant_id == "tenant-from-provider"
    assert output.metadata.subscription_id == "subscription-from-provider"
    assert output.metadata.token_source == "azure_cli"


def test_collect_rbac(fixture_provider, options) -> None:
    output = collect_rbac(fixture_provider, options)
    assert len(output.role_assignments) == 2
    assert "Owner" in output.role_distribution()


def test_collect_principals(fixture_provider, options) -> None:
    output = collect_principals(fixture_provider, options)
    assert len(output.principals) == 2
    assert output.principals[0].is_current_identity is True
    assert "ua-app" in output.principals[0].identity_names


def test_collect_permissions(fixture_provider, options) -> None:
    output = collect_permissions(fixture_provider, options)
    assert len(output.permissions) == 2
    assert output.permissions[0].privileged is True
    assert output.permissions[0].high_impact_roles == ["Owner"]


def test_collect_privesc(fixture_provider, options) -> None:
    output = collect_privesc(fixture_provider, options)
    assert len(output.paths) == 2
    assert output.paths[0].path_type == "direct-role-abuse"
    assert output.paths[1].asset == "vm-web-01"


def test_collect_role_trusts(fixture_provider, options) -> None:
    output = collect_role_trusts(fixture_provider, options)
    assert len(output.trusts) == 6
    assert output.trusts[0].trust_type == "app-owner"
    assert output.trusts[2].evidence_type == "graph-federated-credential"


def test_collect_managed_identities(fixture_provider, options) -> None:
    output = collect_managed_identities(fixture_provider, options)
    assert len(output.identities) == 1
    assert len(output.findings) == 1


def test_collect_storage(fixture_provider, options) -> None:
    output = collect_storage(fixture_provider, options)
    assert len(output.storage_assets) == 2
    assert len(output.findings) == 2


def test_collect_vms(fixture_provider, options) -> None:
    output = collect_vms(fixture_provider, options)
    assert len(output.vm_assets) == 2
    assert len(output.findings) == 1
