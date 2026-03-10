from __future__ import annotations

from azurefox.models.common import SCHEMA_VERSION, ManagedIdentity, StorageAsset, VmAsset


def test_schema_version() -> None:
    assert SCHEMA_VERSION == "1.0.0"


def test_managed_identity_defaults() -> None:
    identity = ManagedIdentity(id="id-1", name="mi-1", identity_type="userAssigned")
    assert identity.attached_to == []
    assert identity.scope_ids == []


def test_storage_asset_defaults() -> None:
    asset = StorageAsset(id="s-1", name="st01")
    assert asset.public_access is False
    assert asset.private_endpoint_enabled is False


def test_vm_asset_defaults() -> None:
    vm = VmAsset(id="v-1", name="vm01")
    assert vm.private_ips == []
    assert vm.public_ips == []
