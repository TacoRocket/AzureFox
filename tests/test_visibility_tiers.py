from __future__ import annotations

import pytest

from azurefox.collectors.commands import collect_managed_identities, collect_permissions

VM_ID = (
    "/subscriptions/test/resourceGroups/rg-workload/providers/"
    "Microsoft.Compute/virtualMachines/vm-app-01"
)
IDENTITY_ID = (
    "/subscriptions/test/resourceGroups/rg-workload/providers/"
    "Microsoft.ManagedIdentity/userAssignedIdentities/ua-orders"
)
PRINCIPAL_ID = "33333333-3333-3333-3333-333333333333"


class _VisibilityTierProvider:
    def metadata_context(self) -> dict[str, str | None]:
        return {"tenant_id": None, "subscription_id": None, "token_source": None, "auth_mode": None}

    def vmss(self) -> dict:
        return {"vmss_assets": [], "issues": []}


def _permission_row(**overrides) -> dict:
    row = {
        "principal_id": PRINCIPAL_ID,
        "display_name": "ua-orders",
        "principal_type": "ServicePrincipal",
        "high_impact_roles": ["Contributor"],
        "all_role_names": ["Contributor"],
        "role_assignment_count": 1,
        "scope_count": 1,
        "scope_ids": ["/subscriptions/test"],
        "privileged": True,
        "is_current_identity": False,
    }
    row.update(overrides)
    return row


def _principal_row(**overrides) -> dict:
    row = {
        "id": PRINCIPAL_ID,
        "principal_type": "ServicePrincipal",
        "display_name": "ua-orders",
        "sources": ["rbac", "managed-identities"],
        "scope_ids": ["/subscriptions/test"],
        "role_names": ["Contributor"],
        "role_assignment_count": 1,
        "identity_names": ["ua-orders"],
        "identity_types": ["userAssigned"],
        "attached_to": [VM_ID],
        "is_current_identity": False,
    }
    row.update(overrides)
    return row


def _identity_row(**overrides) -> dict:
    row = {
        "id": IDENTITY_ID,
        "name": "ua-orders",
        "identity_type": "userAssigned",
        "principal_id": PRINCIPAL_ID,
        "client_id": "55555555-5555-5555-5555-555555555555",
        "attached_to": [VM_ID],
        "scope_ids": ["/subscriptions/test"],
    }
    row.update(overrides)
    return row


def _role_assignment_row(**overrides) -> dict:
    row = {
        "id": "ra-owner",
        "scope_id": "/subscriptions/test",
        "principal_id": PRINCIPAL_ID,
        "principal_type": "ServicePrincipal",
        "role_definition_id": "rd-owner",
        "role_name": "Owner",
    }
    row.update(overrides)
    return row


def _vm_asset(**overrides) -> dict:
    row = {
        "id": VM_ID,
        "name": "vm-app-01",
        "public_ips": ["52.160.10.20"],
    }
    row.update(overrides)
    return row


class HighVisibilityProvider(_VisibilityTierProvider):
    def permissions(self) -> dict:
        return {"permissions": [_permission_row()], "issues": []}

    def principals(self) -> dict:
        return {"principals": [_principal_row()], "issues": []}

    def managed_identities(self) -> dict:
        return {
            "identities": [_identity_row()],
            "role_assignments": [_role_assignment_row()],
            "issues": [],
        }

    def vms(self) -> dict:
        return {"vm_assets": [_vm_asset()], "issues": []}


class MediumVisibilityProvider(HighVisibilityProvider):
    def principals(self) -> dict:
        return {"principals": [_principal_row(attached_to=[])], "issues": []}

    def managed_identities(self) -> dict:
        return {
            "identities": [_identity_row(principal_id=None)],
            "role_assignments": [],
            "issues": [],
        }


class LowVisibilityProvider(MediumVisibilityProvider):
    def permissions(self) -> dict:
        return {
            "permissions": [
                _permission_row(
                    high_impact_roles=[],
                    all_role_names=["Reader"],
                    privileged=False,
                )
            ],
            "issues": [],
        }

    def vms(self) -> dict:
        return {
            "vm_assets": [],
            "issues": [
                {
                    "kind": "permission_denied",
                    "message": "vms[rg-workload/vm-app-01]: 403 Forbidden",
                    "context": {"collector": "vms[rg-workload/vm-app-01]"},
                }
            ],
        }


@pytest.mark.parametrize(
    ("provider_cls", "expected_signal", "summary_fragment", "expected_next_review"),
    [
        (
            HighVisibilityProvider,
            "Direct control visible; workload pivot visible.",
            "already has direct control visible",
            "Check managed-identities for the workload pivot behind this direct control row.",
        ),
        (
            MediumVisibilityProvider,
            "Direct control visible; visibility blocked.",
            "backing workload pivot stays visibility blocked",
            "Check managed-identities; current scope does not yet show the workload pivot behind "
            "this direct-control row.",
        ),
        (
            LowVisibilityProvider,
            "Direct control not confirmed.",
            "does not yet show direct control from visible RBAC",
            "Check rbac for the exact assignment evidence behind this lower-signal row.",
        ),
    ],
)
def test_permissions_visibility_tiers_degrade_honestly(
    options,
    provider_cls,
    expected_signal: str,
    summary_fragment: str,
    expected_next_review: str,
) -> None:
    output = collect_permissions(provider_cls(), options)
    row = output.permissions[0]

    assert row.display_name == "ua-orders"
    assert row.operator_signal == expected_signal
    assert summary_fragment in (row.summary or "")
    assert row.next_review == expected_next_review


@pytest.mark.parametrize(
    ("provider_cls", "expected_signal", "summary_fragment", "expected_next_review", "issue_kind"),
    [
        (
            HighVisibilityProvider,
            "Public VM workload pivot; direct control visible.",
            "direct control through high-impact roles",
            "Check permissions for direct control on this identity, then vms for the host context "
            "behind the workload pivot.",
            None,
        ),
        (
            MediumVisibilityProvider,
            "Public VM workload pivot; visibility blocked.",
            "current scope does not show the backing principal cleanly",
            "Check vms for the host context behind this workload pivot; current scope does not yet "
            "show direct control on this identity.",
            None,
        ),
        (
            LowVisibilityProvider,
            "VM workload pivot; visibility blocked.",
            "current scope does not show the backing principal cleanly",
            "Check vms for the host context behind this workload pivot; current scope does not yet "
            "show direct control on this identity.",
            "permission_denied",
        ),
    ],
)
def test_managed_identities_visibility_tiers_degrade_honestly(
    options,
    provider_cls,
    expected_signal: str,
    summary_fragment: str,
    expected_next_review: str,
    issue_kind: str | None,
) -> None:
    output = collect_managed_identities(provider_cls(), options)
    row = output.identities[0]

    assert row.name == "ua-orders"
    assert row.operator_signal == expected_signal
    assert summary_fragment in (row.summary or "")
    assert row.next_review == expected_next_review

    if issue_kind is None:
        assert output.issues == []
    else:
        assert output.issues[0].kind == issue_kind
