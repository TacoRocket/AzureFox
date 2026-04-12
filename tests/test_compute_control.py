from __future__ import annotations

from azurefox.chains.compute_control import collect_compute_control_records
from azurefox.models.commands import (
    ManagedIdentitiesOutput,
    PermissionsOutput,
    TokensCredentialsOutput,
    WorkloadsOutput,
)
from azurefox.models.common import (
    CommandMetadata,
    ManagedIdentity,
    PermissionSummary,
    RoleAssignment,
    TokenCredentialSurfaceSummary,
    WorkloadSummary,
)


def _metadata(command: str) -> CommandMetadata:
    return CommandMetadata(command=command)


def test_compute_control_admits_system_assigned_workload_via_workload_principal() -> None:
    loaded = {
        "tokens-credentials": TokensCredentialsOutput(
            metadata=_metadata("tokens-credentials"),
            surfaces=[
                TokenCredentialSurfaceSummary(
                    asset_id="/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-public-api",
                    asset_name="app-public-api",
                    asset_kind="AppService",
                    resource_group="rg-apps",
                    location="eastus",
                    surface_type="managed-identity-token",
                    access_path="workload-identity",
                    priority="medium",
                    operator_signal="SystemAssigned",
                    summary="App Service can request tokens through its attached identity.",
                    related_ids=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-public-api",
                        "aaaa1111-1111-1111-1111-111111111111",
                    ],
                )
            ],
        ),
        "workloads": WorkloadsOutput(
            metadata=_metadata("workloads"),
            workloads=[
                WorkloadSummary(
                    asset_id="/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-public-api",
                    asset_name="app-public-api",
                    asset_kind="AppService",
                    resource_group="rg-apps",
                    location="eastus",
                    identity_type="SystemAssigned",
                    identity_principal_id="aaaa1111-1111-1111-1111-111111111111",
                    endpoints=["app-public-api.azurewebsites.net"],
                    ingress_paths=["azurewebsites-default-hostname"],
                    exposure_families=["managed-web-hostname"],
                    summary=(
                        "App Service exposes a reachable hostname and carries a system identity."
                    ),
                    related_ids=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-public-api",
                        "aaaa1111-1111-1111-1111-111111111111",
                    ],
                )
            ],
        ),
        "managed-identities": ManagedIdentitiesOutput(
            metadata=_metadata("managed-identities"),
            identities=[],
            role_assignments=[],
        ),
        "permissions": PermissionsOutput(
            metadata=_metadata("permissions"),
            permissions=[
                PermissionSummary(
                    principal_id="aaaa1111-1111-1111-1111-111111111111",
                    display_name="app-public-api-system",
                    principal_type="ServicePrincipal",
                    high_impact_roles=["Contributor"],
                    all_role_names=["Contributor"],
                    role_assignment_count=1,
                    scope_count=1,
                    scope_ids=["/subscriptions/sub/resourceGroups/rg-apps"],
                    privileged=True,
                )
            ],
        ),
    }

    paths, issues = collect_compute_control_records("compute-control", loaded)

    assert not issues
    assert len(paths) == 1
    row = paths[0]
    assert row.asset_name == "app-public-api"
    assert row.insertion_point == "reachable service token request path"
    assert row.target_names == ["app-public-api system identity"]
    assert row.evidence_commands == ["tokens-credentials", "workloads", "permissions"]
    assert row.joined_surface_types == [
        "managed-identity-token",
        "workload",
        "workload-principal",
        "permissions",
    ]
    assert "inferred from workload metadata" in (row.confidence_boundary or "")


def test_compute_control_prefers_explicit_system_identity_anchor_when_present() -> None:
    loaded = {
        "tokens-credentials": TokensCredentialsOutput(
            metadata=_metadata("tokens-credentials"),
            surfaces=[
                TokenCredentialSurfaceSummary(
                    asset_id="/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-public-api",
                    asset_name="app-public-api",
                    asset_kind="AppService",
                    resource_group="rg-apps",
                    location="eastus",
                    surface_type="managed-identity-token",
                    access_path="workload-identity",
                    priority="medium",
                    operator_signal="SystemAssigned",
                    summary="App Service can request tokens through its attached identity.",
                    related_ids=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-public-api",
                        "aaaa1111-1111-1111-1111-111111111111",
                    ],
                )
            ],
        ),
        "workloads": WorkloadsOutput(
            metadata=_metadata("workloads"),
            workloads=[
                WorkloadSummary(
                    asset_id="/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-public-api",
                    asset_name="app-public-api",
                    asset_kind="AppService",
                    resource_group="rg-apps",
                    location="eastus",
                    identity_type="SystemAssigned",
                    identity_principal_id="aaaa1111-1111-1111-1111-111111111111",
                    endpoints=["app-public-api.azurewebsites.net"],
                    ingress_paths=["azurewebsites-default-hostname"],
                    exposure_families=["managed-web-hostname"],
                    summary=(
                        "App Service exposes a reachable hostname and carries a system identity."
                    ),
                    related_ids=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-public-api",
                        "aaaa1111-1111-1111-1111-111111111111",
                    ],
                )
            ],
        ),
        "managed-identities": ManagedIdentitiesOutput(
            metadata=_metadata("managed-identities"),
            identities=[
                ManagedIdentity(
                    id="/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-public-api/identities/system",
                    name="app-public-api-system",
                    identity_type="systemAssigned",
                    principal_id="aaaa1111-1111-1111-1111-111111111111",
                    attached_to=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-public-api"
                    ],
                )
            ],
            role_assignments=[],
        ),
        "permissions": PermissionsOutput(
            metadata=_metadata("permissions"),
            permissions=[
                PermissionSummary(
                    principal_id="aaaa1111-1111-1111-1111-111111111111",
                    display_name="app-public-api-system",
                    principal_type="ServicePrincipal",
                    high_impact_roles=["Contributor"],
                    all_role_names=["Contributor"],
                    role_assignment_count=1,
                    scope_count=1,
                    scope_ids=["/subscriptions/sub/resourceGroups/rg-apps"],
                    privileged=True,
                )
            ],
        ),
    }

    paths, issues = collect_compute_control_records("compute-control", loaded)

    assert not issues
    assert len(paths) == 1
    row = paths[0]
    assert row.target_ids == [
        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-public-api/identities/system"
    ]
    assert row.target_names == ["app-public-api-system"]
    assert row.evidence_commands == [
        "tokens-credentials",
        "workloads",
        "managed-identities",
        "permissions",
    ]
    assert row.joined_surface_types == [
        "managed-identity-token",
        "workload",
        "identity-anchor",
        "permissions",
    ]
    assert "the attached identity" in (row.confidence_boundary or "")


def test_compute_control_excludes_mixed_identity_workloads_until_actor_is_explicit() -> None:
    loaded = {
        "tokens-credentials": TokensCredentialsOutput(
            metadata=_metadata("tokens-credentials"),
            surfaces=[
                TokenCredentialSurfaceSummary(
                    asset_id="/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders",
                    asset_name="func-orders",
                    asset_kind="FunctionApp",
                    resource_group="rg-apps",
                    location="eastus",
                    surface_type="managed-identity-token",
                    access_path="workload-identity",
                    priority="medium",
                    operator_signal="SystemAssigned, UserAssigned; user-assigned=1",
                    summary="Function App can request tokens through multiple attached identities.",
                    related_ids=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders",
                        "cccc2222-2222-2222-2222-222222222222",
                        "/subscriptions/sub/resourceGroups/rg-identities/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-orders",
                    ],
                )
            ],
        ),
        "workloads": WorkloadsOutput(
            metadata=_metadata("workloads"),
            workloads=[
                WorkloadSummary(
                    asset_id="/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders",
                    asset_name="func-orders",
                    asset_kind="FunctionApp",
                    resource_group="rg-apps",
                    location="eastus",
                    identity_type="SystemAssigned, UserAssigned",
                    identity_principal_id="cccc2222-2222-2222-2222-222222222222",
                    identity_ids=[
                        "/subscriptions/sub/resourceGroups/rg-identities/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-orders"
                    ],
                    endpoints=["func-orders.azurewebsites.net"],
                    ingress_paths=["azure-functions-default-hostname"],
                    exposure_families=["managed-web-hostname"],
                    summary="Function App exposes a hostname and carries mixed identities.",
                    related_ids=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders",
                        "cccc2222-2222-2222-2222-222222222222",
                        "/subscriptions/sub/resourceGroups/rg-identities/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-orders",
                    ],
                )
            ],
        ),
        "managed-identities": ManagedIdentitiesOutput(
            metadata=_metadata("managed-identities"),
            identities=[
                ManagedIdentity(
                    id="/subscriptions/sub/resourceGroups/rg-identities/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-orders",
                    name="ua-orders",
                    identity_type="userAssigned",
                    principal_id="dddd3333-3333-3333-3333-333333333333",
                    attached_to=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders"
                    ],
                )
            ],
            role_assignments=[
                RoleAssignment(
                    id="ra-orders",
                    scope_id="/subscriptions/sub",
                    principal_id="dddd3333-3333-3333-3333-333333333333",
                    principal_type="ServicePrincipal",
                    role_name="Owner",
                )
            ],
        ),
        "permissions": PermissionsOutput(
            metadata=_metadata("permissions"),
            permissions=[
                PermissionSummary(
                    principal_id="dddd3333-3333-3333-3333-333333333333",
                    display_name="ua-orders",
                    principal_type="ServicePrincipal",
                    high_impact_roles=["Owner"],
                    all_role_names=["Owner"],
                    role_assignment_count=1,
                    scope_count=1,
                    scope_ids=["/subscriptions/sub"],
                    privileged=True,
                )
            ],
        ),
    }

    paths, issues = collect_compute_control_records("compute-control", loaded)

    assert not issues
    assert paths == []
