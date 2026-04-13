from __future__ import annotations

from azurefox.chains.compute_control import collect_compute_control_records
from azurefox.models.commands import (
    EnvVarsOutput,
    ManagedIdentitiesOutput,
    PermissionsOutput,
    TokensCredentialsOutput,
    WorkloadsOutput,
)
from azurefox.models.common import (
    CollectionIssue,
    CommandMetadata,
    EnvVarSummary,
    ManagedIdentity,
    PermissionSummary,
    RoleAssignment,
    TokenCredentialSurfaceSummary,
    WorkloadSummary,
)
from tests.truthfulness import (
    assert_issue_collectors_include,
    assert_rows_exclude,
    assert_rows_include,
    row_by_field,
)


def _metadata(command: str) -> CommandMetadata:
    return CommandMetadata(command=command)


def _base_loaded_workload(
    *,
    asset_name: str,
    asset_kind: str,
    asset_id: str,
    principal_id: str,
    token_summary: str,
    workload_summary: str,
    endpoints: list[str],
    ingress_paths: list[str],
    exposure_families: list[str],
    permission: PermissionSummary | None,
    identities: list[ManagedIdentity] | None = None,
    managed_identity_issues: list[CollectionIssue] | None = None,
) -> dict[str, object]:
    return {
        "tokens-credentials": TokensCredentialsOutput(
            metadata=_metadata("tokens-credentials"),
            surfaces=[
                TokenCredentialSurfaceSummary(
                    asset_id=asset_id,
                    asset_name=asset_name,
                    asset_kind=asset_kind,
                    resource_group="rg-apps",
                    location="eastus",
                    surface_type="managed-identity-token",
                    access_path="workload-identity",
                    priority="medium",
                    operator_signal="SystemAssigned",
                    summary=token_summary,
                    related_ids=[asset_id, principal_id],
                )
            ],
            issues=[],
        ),
        "workloads": WorkloadsOutput(
            metadata=_metadata("workloads"),
            workloads=[
                WorkloadSummary(
                    asset_id=asset_id,
                    asset_name=asset_name,
                    asset_kind=asset_kind,
                    resource_group="rg-apps",
                    location="eastus",
                    identity_type="SystemAssigned",
                    identity_principal_id=principal_id,
                    endpoints=endpoints,
                    ingress_paths=ingress_paths,
                    exposure_families=exposure_families,
                    summary=workload_summary,
                    related_ids=[asset_id, principal_id],
                )
            ],
            issues=[],
        ),
        "managed-identities": ManagedIdentitiesOutput(
            metadata=_metadata("managed-identities"),
            identities=identities or [],
            role_assignments=[],
            issues=managed_identity_issues or [],
        ),
        "env-vars": EnvVarsOutput(
            metadata=_metadata("env-vars"),
            env_vars=[],
            issues=[],
        ),
        "permissions": PermissionsOutput(
            metadata=_metadata("permissions"),
            permissions=[permission] if permission is not None else [],
            issues=[],
        ),
    }


def _base_loaded_app_service(
    *,
    asset_name: str,
    principal_id: str,
    permission: PermissionSummary | None,
    identities: list[ManagedIdentity] | None = None,
    managed_identity_issues: list[CollectionIssue] | None = None,
) -> dict[str, object]:
    asset_id = (
        "/subscriptions/sub/resourceGroups/rg-apps/providers/"
        f"Microsoft.Web/sites/{asset_name}"
    )
    return _base_loaded_workload(
        asset_name=asset_name,
        asset_kind="AppService",
        asset_id=asset_id,
        principal_id=principal_id,
        token_summary="App Service can request tokens through its attached identity.",
        workload_summary="App Service exposes a reachable hostname and carries a system identity.",
        endpoints=[f"{asset_name}.azurewebsites.net"],
        ingress_paths=["azurewebsites-default-hostname"],
        exposure_families=["managed-web-hostname"],
        permission=permission,
        identities=identities,
        managed_identity_issues=managed_identity_issues,
    )


def _base_loaded_container_app(
    *,
    asset_name: str,
    principal_id: str,
    permission: PermissionSummary | None,
    external: bool,
    identities: list[ManagedIdentity] | None = None,
    managed_identity_issues: list[CollectionIssue] | None = None,
) -> dict[str, object]:
    asset_id = (
        "/subscriptions/sub/resourceGroups/rg-apps/providers/"
        f"Microsoft.App/containerApps/{asset_name}"
    )
    hostname = f"{asset_name}.eastus.azurecontainerapps.io"
    return _base_loaded_workload(
        asset_name=asset_name,
        asset_kind="ContainerApp",
        asset_id=asset_id,
        principal_id=principal_id,
        token_summary="Container App can request tokens through its attached identity.",
        workload_summary=(
            "Container App exposes ingress and carries a system identity."
            if external
            else "Container App is internal-only and carries a system identity."
        ),
        endpoints=[hostname] if external else [],
        ingress_paths=["azure-container-apps-default-hostname"] if external else [],
        exposure_families=["managed-web-hostname"] if external else [],
        permission=permission,
        identities=identities,
        managed_identity_issues=managed_identity_issues,
    )


def _base_loaded_container_instance(
    *,
    asset_name: str,
    principal_id: str,
    permission: PermissionSummary | None,
    public: bool,
    identities: list[ManagedIdentity] | None = None,
    managed_identity_issues: list[CollectionIssue] | None = None,
) -> dict[str, object]:
    asset_id = (
        "/subscriptions/sub/resourceGroups/rg-apps/providers/"
        f"Microsoft.ContainerInstance/containerGroups/{asset_name}"
    )
    endpoints = []
    exposure_families = []
    ingress_paths = []
    if public:
        endpoints = [f"{asset_name}.eastus.azurecontainer.io", "52.160.10.30"]
        exposure_families = ["managed-container-fqdn", "public-ip"]
        ingress_paths = [
            "azure-container-instances-fqdn",
            "azure-container-instances-public-ip",
        ]
    return _base_loaded_workload(
        asset_name=asset_name,
        asset_kind="ContainerInstance",
        asset_id=asset_id,
        principal_id=principal_id,
        token_summary="Container group can request tokens through its attached identity.",
        workload_summary=(
            "Container group exposes a public endpoint and carries a system identity."
            if public
            else "Container group is internal-only and carries a system identity."
        ),
        endpoints=endpoints,
        ingress_paths=ingress_paths,
        exposure_families=exposure_families,
        permission=permission,
        identities=identities,
        managed_identity_issues=managed_identity_issues,
    )


def test_compute_control_admits_system_assigned_workload_via_workload_principal() -> None:
    loaded = _base_loaded_app_service(
        asset_name="app-public-api",
        principal_id="aaaa1111-1111-1111-1111-111111111111",
        permission=PermissionSummary(
            principal_id="aaaa1111-1111-1111-1111-111111111111",
            display_name="app-public-api-system",
            principal_type="ServicePrincipal",
            priority="high",
            high_impact_roles=["Contributor"],
            all_role_names=["Contributor"],
            role_assignment_count=1,
            scope_count=1,
            scope_ids=["/subscriptions/sub/resourceGroups/rg-apps"],
            privileged=True,
        ),
    )

    paths, issues = collect_compute_control_records("compute-control", loaded)

    assert not issues
    assert_rows_include(paths, field="asset_name", expected=["app-public-api"])
    row = row_by_field(paths, field="asset_name", expected="app-public-api")
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


def test_compute_control_admits_container_app_via_workload_principal() -> None:
    loaded = _base_loaded_container_app(
        asset_name="aca-orders",
        principal_id="abab1111-1111-1111-1111-111111111111",
        permission=PermissionSummary(
            principal_id="abab1111-1111-1111-1111-111111111111",
            display_name="aca-orders-system",
            principal_type="ServicePrincipal",
            priority="high",
            high_impact_roles=["Contributor"],
            all_role_names=["Contributor"],
            role_assignment_count=1,
            scope_count=1,
            scope_ids=["/subscriptions/sub/resourceGroups/rg-apps"],
            privileged=True,
        ),
        external=True,
    )

    paths, issues = collect_compute_control_records("compute-control", loaded)

    assert not issues
    assert_rows_include(paths, field="asset_name", expected=["aca-orders"])
    row = row_by_field(paths, field="asset_name", expected="aca-orders")
    assert row.asset_kind == "ContainerApp"
    assert row.insertion_point == "reachable service token request path"
    assert row.priority == "high"
    assert row.urgency == "pivot-now"
    assert row.target_names == ["aca-orders system identity"]
    assert row.evidence_commands == ["tokens-credentials", "workloads", "permissions"]
    assert row.joined_surface_types == [
        "managed-identity-token",
        "workload",
        "workload-principal",
        "permissions",
    ]
    assert (
        "a way to make this public-facing service ask Azure for its own token"
        in (row.why_care or "")
    )
    assert "public reachability alone does not prove that path" in (row.why_care or "")


def test_compute_control_admits_container_instance_via_workload_principal() -> None:
    loaded = _base_loaded_container_instance(
        asset_name="aci-public-api",
        principal_id="acac1111-1111-1111-1111-111111111111",
        permission=PermissionSummary(
            principal_id="acac1111-1111-1111-1111-111111111111",
            display_name="aci-public-api-system",
            principal_type="ServicePrincipal",
            priority="high",
            high_impact_roles=["Contributor"],
            all_role_names=["Contributor"],
            role_assignment_count=1,
            scope_count=1,
            scope_ids=["/subscriptions/sub/resourceGroups/rg-apps"],
            privileged=True,
        ),
        public=True,
    )

    paths, issues = collect_compute_control_records("compute-control", loaded)

    assert not issues
    assert_rows_include(paths, field="asset_name", expected=["aci-public-api"])
    row = row_by_field(paths, field="asset_name", expected="aci-public-api")
    assert row.asset_kind == "ContainerInstance"
    assert row.insertion_point == "reachable service token request path"
    assert row.priority == "high"
    assert row.urgency == "pivot-now"
    assert row.target_names == ["aci-public-api system identity"]
    assert row.evidence_commands == ["tokens-credentials", "workloads", "permissions"]
    assert row.joined_surface_types == [
        "managed-identity-token",
        "workload",
        "workload-principal",
        "permissions",
    ]
    assert (
        "a way to make this public-facing container group ask Azure for its own token"
        in (row.why_care or "")
    )
    assert "public reachability alone does not prove that path" in (row.why_care or "")


def test_compute_control_prefers_explicit_system_identity_anchor_when_present() -> None:
    loaded = _base_loaded_app_service(
        asset_name="app-public-api",
        principal_id="aaaa1111-1111-1111-1111-111111111111",
        permission=PermissionSummary(
            principal_id="aaaa1111-1111-1111-1111-111111111111",
            display_name="app-public-api-system",
            principal_type="ServicePrincipal",
            priority="high",
            high_impact_roles=["Contributor"],
            all_role_names=["Contributor"],
            role_assignment_count=1,
            scope_count=1,
            scope_ids=["/subscriptions/sub/resourceGroups/rg-apps"],
            privileged=True,
        ),
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
    )

    paths, issues = collect_compute_control_records("compute-control", loaded)

    assert not issues
    assert_rows_include(paths, field="asset_name", expected=["app-public-api"])
    row = row_by_field(paths, field="asset_name", expected="app-public-api")
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


def test_compute_control_emits_bounded_mixed_identity_candidates_when_actor_is_not_explicit() -> (
    None
):
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
                    id="/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders/identities/system",
                    name="func-orders-system",
                    identity_type="systemAssigned",
                    principal_id="cccc2222-2222-2222-2222-222222222222",
                    attached_to=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders"
                    ],
                ),
                ManagedIdentity(
                    id="/subscriptions/sub/resourceGroups/rg-identities/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-orders",
                    name="ua-orders",
                    identity_type="userAssigned",
                    principal_id="dddd3333-3333-3333-3333-333333333333",
                    attached_to=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders"
                    ],
                ),
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
                    priority="high",
                    high_impact_roles=["Owner"],
                    all_role_names=["Owner"],
                    role_assignment_count=1,
                    scope_count=1,
                    scope_ids=["/subscriptions/sub"],
                    privileged=True,
                )
            ],
        ),
        "env-vars": EnvVarsOutput(
            metadata=_metadata("env-vars"),
            env_vars=[],
            issues=[],
        ),
    }

    paths, issues = collect_compute_control_records("compute-control", loaded)

    assert not issues
    assert_rows_include(paths, field="asset_name", expected=["func-orders"])
    row = row_by_field(paths, field="asset_name", expected="func-orders")
    assert row.target_names == ["func-orders-system", "ua-orders"]
    assert row.target_resolution == "narrowed candidates"
    assert row.confirmation_basis == "mixed-identity-attached-candidates"
    assert row.target_count == 2
    assert "cannot directly verify" in (row.confidence_boundary or "")
    assert "attached identities currently in play" in (row.confidence_boundary or "")
    assert "func-orders-system" in (row.target_names or [])
    assert "ua-orders=Owner across subscription-wide scope" in (row.stronger_outcome or "")
    assert "does not directly verify" in (row.missing_confirmation or "")


def test_compute_control_admits_mixed_identity_workload_when_env_vars_corroborate_choice() -> None:
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
            issues=[],
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
            issues=[],
        ),
        "managed-identities": ManagedIdentitiesOutput(
            metadata=_metadata("managed-identities"),
            identities=[
                ManagedIdentity(
                    id="/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders/identities/system",
                    name="func-orders-system",
                    identity_type="systemAssigned",
                    principal_id="cccc2222-2222-2222-2222-222222222222",
                    attached_to=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders"
                    ],
                ),
                ManagedIdentity(
                    id="/subscriptions/sub/resourceGroups/rg-identities/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-orders",
                    name="ua-orders",
                    identity_type="userAssigned",
                    principal_id="dddd3333-3333-3333-3333-333333333333",
                    attached_to=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders"
                    ],
                ),
            ],
            role_assignments=[],
            issues=[],
        ),
        "env-vars": EnvVarsOutput(
            metadata=_metadata("env-vars"),
            env_vars=[
                EnvVarSummary(
                    asset_id="/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders",
                    asset_name="func-orders",
                    asset_kind="FunctionApp",
                    resource_group="rg-apps",
                    location="eastus",
                    workload_identity_type="SystemAssigned, UserAssigned",
                    workload_principal_id="cccc2222-2222-2222-2222-222222222222",
                    workload_client_id="dddd2222-2222-2222-2222-222222222222",
                    workload_identity_ids=[
                        "/subscriptions/sub/resourceGroups/rg-identities/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-orders"
                    ],
                    key_vault_reference_identity="SystemAssigned",
                    setting_name="PAYMENT_API_KEY",
                    value_type="keyvault-ref",
                    looks_sensitive=True,
                    reference_target="kvlabopen01.vault.azure.net/secrets/payment-api-key",
                    summary=(
                        "Function App uses a Key Vault-backed setting via SystemAssigned identity."
                    ),
                )
            ],
            issues=[],
        ),
        "permissions": PermissionsOutput(
            metadata=_metadata("permissions"),
            permissions=[
                PermissionSummary(
                    principal_id="cccc2222-2222-2222-2222-222222222222",
                    display_name="func-orders-system",
                    principal_type="ServicePrincipal",
                    priority="high",
                    high_impact_roles=["Contributor"],
                    all_role_names=["Contributor"],
                    role_assignment_count=1,
                    scope_count=1,
                    scope_ids=["/subscriptions/sub/resourceGroups/rg-apps"],
                    privileged=True,
                )
            ],
            issues=[],
        ),
    }

    paths, issues = collect_compute_control_records("compute-control", loaded)

    assert not issues
    assert_rows_include(paths, field="asset_name", expected=["func-orders"])
    row = row_by_field(paths, field="asset_name", expected="func-orders")
    assert row.target_names == ["func-orders-system"]
    assert row.evidence_commands == [
        "tokens-credentials",
        "workloads",
        "env-vars",
        "managed-identities",
        "permissions",
    ]
    assert row.joined_surface_types == [
        "managed-identity-token",
        "workload",
        "identity-choice-corroboration",
        "identity-anchor",
        "permissions",
    ]
    assert row.target_resolution == "identity-choice-corroborated"
    assert row.confirmation_basis == "mixed-identity-corroborated-permission-join"
    assert "mixed identities" in (row.confidence_boundary or "")
    assert "cannot directly verify" in (row.confidence_boundary or "")
    assert "SystemAssigned" in (row.confidence_boundary or "")
    assert "does not directly verify" in (row.missing_confirmation or "")


def test_compute_control_admits_user_assigned_choice_when_env_vars_names_resource_id() -> None:
    user_assigned_id = (
        "/subscriptions/sub/resourceGroups/rg-identities/providers/"
        "Microsoft.ManagedIdentity/userAssignedIdentities/ua-orders"
    )
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
                        user_assigned_id,
                    ],
                )
            ],
            issues=[],
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
                    identity_ids=[user_assigned_id],
                    endpoints=["func-orders.azurewebsites.net"],
                    ingress_paths=["azure-functions-default-hostname"],
                    exposure_families=["managed-web-hostname"],
                    summary="Function App exposes a hostname and carries mixed identities.",
                    related_ids=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders",
                        "cccc2222-2222-2222-2222-222222222222",
                        user_assigned_id,
                    ],
                )
            ],
            issues=[],
        ),
        "managed-identities": ManagedIdentitiesOutput(
            metadata=_metadata("managed-identities"),
            identities=[
                ManagedIdentity(
                    id="/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders/identities/system",
                    name="func-orders-system",
                    identity_type="systemAssigned",
                    principal_id="cccc2222-2222-2222-2222-222222222222",
                    attached_to=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders"
                    ],
                ),
                ManagedIdentity(
                    id=user_assigned_id,
                    name="ua-orders",
                    identity_type="userAssigned",
                    principal_id="dddd3333-3333-3333-3333-333333333333",
                    attached_to=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders"
                    ],
                ),
            ],
            role_assignments=[],
            issues=[],
        ),
        "env-vars": EnvVarsOutput(
            metadata=_metadata("env-vars"),
            env_vars=[
                EnvVarSummary(
                    asset_id="/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders",
                    asset_name="func-orders",
                    asset_kind="FunctionApp",
                    resource_group="rg-apps",
                    location="eastus",
                    workload_identity_type="SystemAssigned, UserAssigned",
                    workload_principal_id="cccc2222-2222-2222-2222-222222222222",
                    workload_client_id="dddd2222-2222-2222-2222-222222222222",
                    workload_identity_ids=[user_assigned_id],
                    key_vault_reference_identity=user_assigned_id,
                    setting_name="PAYMENT_API_KEY",
                    value_type="keyvault-ref",
                    looks_sensitive=True,
                    reference_target="kvlabopen01.vault.azure.net/secrets/payment-api-key",
                    summary=(
                        "Function App uses a Key Vault-backed setting via a user-assigned identity."
                    ),
                )
            ],
            issues=[],
        ),
        "permissions": PermissionsOutput(
            metadata=_metadata("permissions"),
            permissions=[
                PermissionSummary(
                    principal_id="dddd3333-3333-3333-3333-333333333333",
                    display_name="ua-orders",
                    principal_type="ServicePrincipal",
                    priority="high",
                    high_impact_roles=["Owner"],
                    all_role_names=["Owner"],
                    role_assignment_count=1,
                    scope_count=1,
                    scope_ids=["/subscriptions/sub"],
                    privileged=True,
                )
            ],
            issues=[],
        ),
    }

    paths, issues = collect_compute_control_records("compute-control", loaded)

    assert not issues
    assert_rows_include(paths, field="asset_name", expected=["func-orders"])
    row = row_by_field(paths, field="asset_name", expected="func-orders")
    assert row.target_names == ["ua-orders"]
    assert row.target_resolution == "identity-choice-corroborated"
    assert row.confirmation_basis == "mixed-identity-corroborated-permission-join"
    assert "ua-orders" in (row.confidence_boundary or "")


def test_compute_control_falls_back_when_corroborated_identity_lacks_control() -> None:
    user_assigned_id = (
        "/subscriptions/sub/resourceGroups/rg-identities/providers/"
        "Microsoft.ManagedIdentity/userAssignedIdentities/ua-orders"
    )
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
                        user_assigned_id,
                    ],
                )
            ],
            issues=[],
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
                    identity_ids=[user_assigned_id],
                    endpoints=["func-orders.azurewebsites.net"],
                    ingress_paths=["azure-functions-default-hostname"],
                    exposure_families=["managed-web-hostname"],
                    summary="Function App exposes a hostname and carries mixed identities.",
                    related_ids=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders",
                        "cccc2222-2222-2222-2222-222222222222",
                        user_assigned_id,
                    ],
                )
            ],
            issues=[],
        ),
        "managed-identities": ManagedIdentitiesOutput(
            metadata=_metadata("managed-identities"),
            identities=[
                ManagedIdentity(
                    id="/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders/identities/system",
                    name="func-orders-system",
                    identity_type="systemAssigned",
                    principal_id="cccc2222-2222-2222-2222-222222222222",
                    attached_to=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders"
                    ],
                ),
                ManagedIdentity(
                    id=user_assigned_id,
                    name="ua-orders",
                    identity_type="userAssigned",
                    principal_id="dddd3333-3333-3333-3333-333333333333",
                    attached_to=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders"
                    ],
                ),
            ],
            role_assignments=[],
            issues=[],
        ),
        "env-vars": EnvVarsOutput(
            metadata=_metadata("env-vars"),
            env_vars=[
                EnvVarSummary(
                    asset_id="/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders",
                    asset_name="func-orders",
                    asset_kind="FunctionApp",
                    resource_group="rg-apps",
                    location="eastus",
                    workload_identity_type="SystemAssigned, UserAssigned",
                    workload_principal_id="cccc2222-2222-2222-2222-222222222222",
                    workload_client_id="dddd2222-2222-2222-2222-222222222222",
                    workload_identity_ids=[user_assigned_id],
                    key_vault_reference_identity="SystemAssigned",
                    setting_name="PAYMENT_API_KEY",
                    value_type="keyvault-ref",
                    looks_sensitive=True,
                    reference_target="kvlabopen01.vault.azure.net/secrets/payment-api-key",
                    summary=(
                        "Function App uses a Key Vault-backed setting via SystemAssigned identity."
                    ),
                )
            ],
            issues=[],
        ),
        "permissions": PermissionsOutput(
            metadata=_metadata("permissions"),
            permissions=[
                PermissionSummary(
                    principal_id="dddd3333-3333-3333-3333-333333333333",
                    display_name="ua-orders",
                    principal_type="ServicePrincipal",
                    priority="high",
                    high_impact_roles=["Owner"],
                    all_role_names=["Owner"],
                    role_assignment_count=1,
                    scope_count=1,
                    scope_ids=["/subscriptions/sub"],
                    privileged=True,
                )
            ],
            issues=[],
        ),
    }

    paths, issues = collect_compute_control_records("compute-control", loaded)

    assert not issues
    assert_rows_include(paths, field="asset_name", expected=["func-orders"])
    row = row_by_field(paths, field="asset_name", expected="func-orders")
    assert row.target_resolution == "narrowed candidates"
    assert row.confirmation_basis == "mixed-identity-attached-candidates"
    assert row.target_names == ["func-orders-system", "ua-orders"]
    assert "ua-orders=Owner across subscription-wide scope" in (row.stronger_outcome or "")


def test_compute_control_rejects_conflicting_env_var_identity_hints() -> None:
    user_assigned_id = (
        "/subscriptions/sub/resourceGroups/rg-identities/providers/"
        "Microsoft.ManagedIdentity/userAssignedIdentities/ua-orders"
    )
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
                        user_assigned_id,
                    ],
                )
            ],
            issues=[],
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
                    identity_ids=[user_assigned_id],
                    endpoints=["func-orders.azurewebsites.net"],
                    ingress_paths=["azure-functions-default-hostname"],
                    exposure_families=["managed-web-hostname"],
                    summary="Function App exposes a hostname and carries mixed identities.",
                    related_ids=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders",
                        "cccc2222-2222-2222-2222-222222222222",
                        user_assigned_id,
                    ],
                )
            ],
            issues=[],
        ),
        "managed-identities": ManagedIdentitiesOutput(
            metadata=_metadata("managed-identities"),
            identities=[
                ManagedIdentity(
                    id="/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders/identities/system",
                    name="func-orders-system",
                    identity_type="systemAssigned",
                    principal_id="cccc2222-2222-2222-2222-222222222222",
                    attached_to=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders"
                    ],
                ),
                ManagedIdentity(
                    id=user_assigned_id,
                    name="ua-orders",
                    identity_type="userAssigned",
                    principal_id="dddd3333-3333-3333-3333-333333333333",
                    attached_to=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders"
                    ],
                ),
            ],
            role_assignments=[],
            issues=[],
        ),
        "env-vars": EnvVarsOutput(
            metadata=_metadata("env-vars"),
            env_vars=[
                EnvVarSummary(
                    asset_id="/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders",
                    asset_name="func-orders",
                    asset_kind="FunctionApp",
                    resource_group="rg-apps",
                    location="eastus",
                    workload_identity_type="SystemAssigned, UserAssigned",
                    workload_principal_id="cccc2222-2222-2222-2222-222222222222",
                    workload_client_id="dddd2222-2222-2222-2222-222222222222",
                    workload_identity_ids=[user_assigned_id],
                    key_vault_reference_identity="SystemAssigned",
                    setting_name="PAYMENT_API_KEY",
                    value_type="keyvault-ref",
                    looks_sensitive=True,
                    reference_target="kvlabopen01.vault.azure.net/secrets/payment-api-key",
                    summary=(
                        "Function App uses a Key Vault-backed setting via SystemAssigned identity."
                    ),
                ),
                EnvVarSummary(
                    asset_id="/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders",
                    asset_name="func-orders",
                    asset_kind="FunctionApp",
                    resource_group="rg-apps",
                    location="eastus",
                    workload_identity_type="SystemAssigned, UserAssigned",
                    workload_principal_id="cccc2222-2222-2222-2222-222222222222",
                    workload_client_id="dddd2222-2222-2222-2222-222222222222",
                    workload_identity_ids=[user_assigned_id],
                    key_vault_reference_identity=user_assigned_id,
                    setting_name="PAYMENT_API_KEY_ALT",
                    value_type="keyvault-ref",
                    looks_sensitive=True,
                    reference_target="kvlabopen01.vault.azure.net/secrets/payment-api-key-alt",
                    summary=(
                        "Function App uses a Key Vault-backed setting via a user-assigned identity."
                    ),
                ),
            ],
            issues=[],
        ),
        "permissions": PermissionsOutput(
            metadata=_metadata("permissions"),
            permissions=[
                PermissionSummary(
                    principal_id="cccc2222-2222-2222-2222-222222222222",
                    display_name="func-orders-system",
                    principal_type="ServicePrincipal",
                    priority="high",
                    high_impact_roles=["Contributor"],
                    all_role_names=["Contributor"],
                    role_assignment_count=1,
                    scope_count=1,
                    scope_ids=["/subscriptions/sub/resourceGroups/rg-apps"],
                    privileged=True,
                ),
                PermissionSummary(
                    principal_id="dddd3333-3333-3333-3333-333333333333",
                    display_name="ua-orders",
                    principal_type="ServicePrincipal",
                    priority="high",
                    high_impact_roles=["Owner"],
                    all_role_names=["Owner"],
                    role_assignment_count=1,
                    scope_count=1,
                    scope_ids=["/subscriptions/sub"],
                    privileged=True,
                ),
            ],
            issues=[],
        ),
    }

    paths, issues = collect_compute_control_records("compute-control", loaded)

    assert not issues
    assert_rows_include(paths, field="asset_name", expected=["func-orders"])
    row = row_by_field(paths, field="asset_name", expected="func-orders")
    assert row.target_resolution == "narrowed candidates"
    assert row.confirmation_basis == "mixed-identity-attached-candidates"
    assert row.target_names == ["func-orders-system", "ua-orders"]


def test_compute_control_rejects_duplicate_user_assigned_suffix_match() -> None:
    user_assigned_id_a = (
        "/subscriptions/sub/resourceGroups/rg-identities-a/providers/"
        "Microsoft.ManagedIdentity/userAssignedIdentities/ua-shared"
    )
    user_assigned_id_b = (
        "/subscriptions/sub/resourceGroups/rg-identities-b/providers/"
        "Microsoft.ManagedIdentity/userAssignedIdentities/ua-shared"
    )
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
                    operator_signal="SystemAssigned, UserAssigned; user-assigned=2",
                    summary="Function App can request tokens through multiple attached identities.",
                    related_ids=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders",
                        "cccc2222-2222-2222-2222-222222222222",
                        user_assigned_id_a,
                        user_assigned_id_b,
                    ],
                )
            ],
            issues=[],
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
                    identity_ids=[user_assigned_id_a, user_assigned_id_b],
                    endpoints=["func-orders.azurewebsites.net"],
                    ingress_paths=["azure-functions-default-hostname"],
                    exposure_families=["managed-web-hostname"],
                    summary="Function App exposes a hostname and carries mixed identities.",
                    related_ids=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders",
                        "cccc2222-2222-2222-2222-222222222222",
                        user_assigned_id_a,
                        user_assigned_id_b,
                    ],
                )
            ],
            issues=[],
        ),
        "managed-identities": ManagedIdentitiesOutput(
            metadata=_metadata("managed-identities"),
            identities=[
                ManagedIdentity(
                    id=user_assigned_id_a,
                    name="ua-shared-a",
                    identity_type="userAssigned",
                    principal_id="dddd3333-3333-3333-3333-333333333333",
                    attached_to=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders"
                    ],
                ),
                ManagedIdentity(
                    id=user_assigned_id_b,
                    name="ua-shared-b",
                    identity_type="userAssigned",
                    principal_id="eeee4444-4444-4444-4444-444444444444",
                    attached_to=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders"
                    ],
                ),
            ],
            role_assignments=[],
            issues=[],
        ),
        "env-vars": EnvVarsOutput(
            metadata=_metadata("env-vars"),
            env_vars=[
                EnvVarSummary(
                    asset_id="/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders",
                    asset_name="func-orders",
                    asset_kind="FunctionApp",
                    resource_group="rg-apps",
                    location="eastus",
                    workload_identity_type="SystemAssigned, UserAssigned",
                    workload_principal_id="cccc2222-2222-2222-2222-222222222222",
                    workload_client_id="dddd2222-2222-2222-2222-222222222222",
                    workload_identity_ids=[user_assigned_id_a, user_assigned_id_b],
                    key_vault_reference_identity="ua-shared",
                    setting_name="PAYMENT_API_KEY",
                    value_type="keyvault-ref",
                    looks_sensitive=True,
                    reference_target="kvlabopen01.vault.azure.net/secrets/payment-api-key",
                    summary=(
                        "Function App uses a Key Vault-backed setting via a user-assigned identity."
                    ),
                )
            ],
            issues=[],
        ),
        "permissions": PermissionsOutput(
            metadata=_metadata("permissions"),
            permissions=[
                PermissionSummary(
                    principal_id="dddd3333-3333-3333-3333-333333333333",
                    display_name="ua-shared-a",
                    principal_type="ServicePrincipal",
                    priority="high",
                    high_impact_roles=["Owner"],
                    all_role_names=["Owner"],
                    role_assignment_count=1,
                    scope_count=1,
                    scope_ids=["/subscriptions/sub"],
                    privileged=True,
                )
            ],
            issues=[],
        ),
    }

    paths, issues = collect_compute_control_records("compute-control", loaded)

    assert not issues
    assert_rows_include(paths, field="asset_name", expected=["func-orders"])
    row = row_by_field(paths, field="asset_name", expected="func-orders")
    assert row.target_resolution == "narrowed candidates"
    assert row.confirmation_basis == "mixed-identity-attached-candidates"
    assert row.target_names == ["func-orders system identity", "ua-shared-a", "ua-shared-b"]


def test_compute_control_bounded_candidates_do_not_claim_anchor_without_identity_rows() -> None:
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
            issues=[],
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
            issues=[],
        ),
        "managed-identities": ManagedIdentitiesOutput(
            metadata=_metadata("managed-identities"),
            identities=[],
            role_assignments=[],
            issues=[],
        ),
        "env-vars": EnvVarsOutput(
            metadata=_metadata("env-vars"),
            env_vars=[],
            issues=[],
        ),
        "permissions": PermissionsOutput(
            metadata=_metadata("permissions"),
            permissions=[
                PermissionSummary(
                    principal_id="cccc2222-2222-2222-2222-222222222222",
                    display_name="func-orders-system",
                    principal_type="ServicePrincipal",
                    priority="high",
                    high_impact_roles=["Contributor"],
                    all_role_names=["Contributor"],
                    role_assignment_count=1,
                    scope_count=1,
                    scope_ids=["/subscriptions/sub/resourceGroups/rg-apps"],
                    privileged=True,
                )
            ],
            issues=[],
        ),
    }

    paths, issues = collect_compute_control_records("compute-control", loaded)

    assert not issues
    assert_rows_include(paths, field="asset_name", expected=["func-orders"])
    row = row_by_field(paths, field="asset_name", expected="func-orders")
    assert row.target_resolution == "narrowed candidates"
    assert row.evidence_commands == ["tokens-credentials", "workloads", "permissions"]
    assert row.joined_surface_types == [
        "managed-identity-token",
        "workload",
        "workload-principal",
        "permissions",
    ]


def test_compute_control_suppresses_mixed_identity_workload_without_visible_control() -> None:
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
            issues=[],
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
            issues=[],
        ),
        "managed-identities": ManagedIdentitiesOutput(
            metadata=_metadata("managed-identities"),
            identities=[
                ManagedIdentity(
                    id="/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders/identities/system",
                    name="func-orders-system",
                    identity_type="systemAssigned",
                    principal_id="cccc2222-2222-2222-2222-222222222222",
                    attached_to=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders"
                    ],
                ),
                ManagedIdentity(
                    id="/subscriptions/sub/resourceGroups/rg-identities/providers/Microsoft.ManagedIdentity/userAssignedIdentities/ua-orders",
                    name="ua-orders",
                    identity_type="userAssigned",
                    principal_id="dddd3333-3333-3333-3333-333333333333",
                    attached_to=[
                        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders"
                    ],
                ),
            ],
            role_assignments=[],
            issues=[],
        ),
        "permissions": PermissionsOutput(
            metadata=_metadata("permissions"),
            permissions=[],
            issues=[],
        ),
        "env-vars": EnvVarsOutput(
            metadata=_metadata("env-vars"),
            env_vars=[],
            issues=[],
        ),
    }

    paths, issues = collect_compute_control_records("compute-control", loaded)

    assert not issues
    assert_rows_exclude(paths, field="asset_name", expected=["func-orders"])


def test_compute_control_suppresses_system_assigned_workload_without_stronger_control() -> None:
    loaded = _base_loaded_app_service(
        asset_name="app-empty-mi",
        principal_id="eeee3333-3333-3333-3333-333333333333",
        permission=None,
        identities=[
            ManagedIdentity(
                id="/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-empty-mi/identities/system",
                name="app-empty-mi-system",
                identity_type="systemAssigned",
                principal_id="eeee3333-3333-3333-3333-333333333333",
                attached_to=[
                    "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-empty-mi"
                ],
            )
        ],
    )

    paths, issues = collect_compute_control_records("compute-control", loaded)

    assert not issues
    assert_rows_exclude(paths, field="asset_name", expected=["app-empty-mi"])


def test_compute_control_suppresses_container_app_without_stronger_control() -> None:
    loaded = _base_loaded_container_app(
        asset_name="aca-internal-jobs",
        principal_id="abab2222-2222-2222-2222-222222222222",
        permission=None,
        external=False,
    )

    paths, issues = collect_compute_control_records("compute-control", loaded)

    assert not issues
    assert_rows_exclude(paths, field="asset_name", expected=["aca-internal-jobs"])


def test_compute_control_suppresses_container_instance_without_stronger_control() -> None:
    loaded = _base_loaded_container_instance(
        asset_name="aci-internal-worker",
        principal_id="acac2222-2222-2222-2222-222222222222",
        permission=None,
        public=False,
    )

    paths, issues = collect_compute_control_records("compute-control", loaded)

    assert not issues
    assert_rows_exclude(paths, field="asset_name", expected=["aci-internal-worker"])


def test_compute_control_preserves_partial_visibility_issues_when_row_still_admits() -> None:
    loaded = _base_loaded_app_service(
        asset_name="app-empty-mi",
        principal_id="eeee3333-3333-3333-3333-333333333333",
        permission=PermissionSummary(
            principal_id="eeee3333-3333-3333-3333-333333333333",
            display_name="app-empty-mi-system",
            principal_type="ServicePrincipal",
            priority="high",
            high_impact_roles=["Contributor"],
            all_role_names=["Contributor"],
            role_assignment_count=1,
            scope_count=1,
            scope_ids=["/subscriptions/sub/resourceGroups/rg-apps"],
            privileged=True,
        ),
        managed_identity_issues=[
            CollectionIssue(
                kind="permission_denied",
                message="managed-identities[app-empty-mi]: nested configuration read blocked",
                context={"collector": "managed-identities[app-empty-mi]"},
            )
        ],
    )

    paths, issues = collect_compute_control_records("compute-control", loaded)

    assert_rows_include(paths, field="asset_name", expected=["app-empty-mi"])
    assert_issue_collectors_include(
        issues,
        expected_collectors=["managed-identities[app-empty-mi]"],
    )
