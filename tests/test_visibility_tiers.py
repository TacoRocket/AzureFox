"""Visibility-tier tests.

Internal shorthand:
- high: admin-like visibility
- medium: operator/dev-like visibility
- low: user-like visibility
"""

from __future__ import annotations

import pytest

from azurefox.collectors.commands import (
    collect_devops,
    collect_env_vars,
    collect_functions,
    collect_managed_identities,
    collect_permissions,
)
from azurefox.render.table import render_table

VM_ID = (
    "/subscriptions/test/resourceGroups/rg-workload/providers/"
    "Microsoft.Compute/virtualMachines/vm-app-01"
)
IDENTITY_ID = (
    "/subscriptions/test/resourceGroups/rg-workload/providers/"
    "Microsoft.ManagedIdentity/userAssignedIdentities/ua-orders"
)
FUNCTION_APP_ID = (
    "/subscriptions/test/resourceGroups/rg-apps/providers/Microsoft.Web/sites/func-orders"
)
PRINCIPAL_ID = "33333333-3333-3333-3333-333333333333"
PIPELINE_ID = "https://dev.azure.com/contoso/app-platform/_build?definitionId=27"
KEY_VAULT_TARGET = "kv-orders.vault.azure.net/secrets/payment-api-key"

TIER_ALIASES = {
    "high": "admin-like visibility",
    "medium": "operator/dev-like visibility",
    "low": "user-like visibility",
}


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


def _trusted_input(**overrides) -> dict:
    row = {
        "input_type": "repository",
        "ref": "repository:azure-repos:func-orders@refs/heads/main",
        "visibility_state": "visible",
        "current_operator_access_state": "read",
        "current_operator_can_poison": False,
        "surface_types": ["repo-content"],
        "join_ids": [],
    }
    row.update(overrides)
    return row


def _devops_pipeline(**overrides) -> dict:
    row = {
        "id": PIPELINE_ID,
        "definition_id": "27",
        "name": "deploy-func-orders",
        "project_id": "proj-app-platform",
        "project_name": "app-platform",
        "path": "\\Production",
        "repository_id": "repo-func-orders",
        "repository_name": "func-orders",
        "repository_type": "TfsGit",
        "repository_url": "https://dev.azure.com/contoso/app-platform/_git/func-orders",
        "repository_host_type": "azure-repos",
        "source_visibility_state": "visible",
        "default_branch": "refs/heads/main",
        "trigger_types": ["continuousIntegration"],
        "variable_group_names": ["func-orders-release"],
        "secret_variable_count": 2,
        "secret_variable_names": ["FUNCTIONS_API_KEY", "STORAGE_CONN"],
        "key_vault_group_names": ["func-orders-kv"],
        "key_vault_names": ["kv-orders"],
        "azure_service_connection_names": ["prod-subscription"],
        "azure_service_connection_types": ["azurerm"],
        "azure_service_connection_auth_schemes": ["ServicePrincipal"],
        "azure_service_connection_ids": ["service-conn-1"],
        "azure_service_connection_principal_ids": [PRINCIPAL_ID],
        "azure_service_connection_client_ids": ["sp-client-id"],
        "azure_service_connection_tenant_ids": ["tenant-test"],
        "azure_service_connection_subscription_ids": ["subscription-test"],
        "target_clues": ["Functions"],
        "risk_cues": [
            "auto-triggered",
            "azure deployment connection",
            "key vault-backed variables",
        ],
        "execution_modes": ["auto-trigger"],
        "upstream_sources": ["repo:azure-repos:func-orders@refs/heads/main"],
        "trusted_inputs": [_trusted_input()],
        "trusted_input_types": ["repository"],
        "trusted_input_refs": ["repository:azure-repos:func-orders@refs/heads/main"],
        "trusted_input_join_ids": [],
        "primary_injection_surface": "repo-content",
        "primary_trusted_input_ref": "repository:azure-repos:func-orders@refs/heads/main",
        "source_join_ids": [],
        "trigger_join_ids": [],
        "identity_join_ids": [],
        "secret_support_types": ["variable-groups", "keyvault-backed-inputs"],
        "secret_dependency_ids": ["func-orders-release", "keyvault:kv-orders"],
        "injection_surface_types": ["repo-content"],
        "current_operator_injection_surface_types": [],
        "edit_path_state": "repo-backed",
        "queue_path_state": "visible",
        "rerun_path_state": "visible",
        "approval_path_state": "unknown",
        "current_operator_can_view_definition": True,
        "current_operator_can_queue": True,
        "current_operator_can_edit": False,
        "current_operator_can_view_source": True,
        "current_operator_can_contribute_source": False,
        "consequence_types": ["redeploy-workload"],
        "missing_execution_path": False,
        "missing_injection_point": False,
        "missing_target_mapping": False,
        "partial_read": False,
        "summary": (
            "Pipeline 'deploy-func-orders' points at a named Function App deployment path with "
            "Azure control and vault-backed support."
        ),
        "related_ids": [PIPELINE_ID, FUNCTION_APP_ID],
    }
    row.update(overrides)
    return row


def _function_app(**overrides) -> dict:
    row = {
        "id": FUNCTION_APP_ID,
        "name": "func-orders",
        "resource_group": "rg-apps",
        "location": "eastus",
        "state": "Running",
        "default_hostname": "func-orders.azurewebsites.net",
        "app_service_plan_id": (
            "/subscriptions/test/resourceGroups/rg-apps/providers/"
            "Microsoft.Web/serverfarms/asp-functions"
        ),
        "public_network_access": "Enabled",
        "https_only": True,
        "client_cert_enabled": False,
        "min_tls_version": "1.2",
        "ftps_state": "Disabled",
        "runtime_stack": "PYTHON|3.11",
        "functions_extension_version": "~4",
        "always_on": True,
        "workload_identity_type": "SystemAssigned, UserAssigned",
        "workload_principal_id": PRINCIPAL_ID,
        "workload_client_id": "dddd2222-2222-2222-2222-222222222222",
        "workload_identity_ids": [IDENTITY_ID],
        "azure_webjobs_storage_value_type": "plain-text",
        "azure_webjobs_storage_reference_target": None,
        "run_from_package": True,
        "key_vault_reference_count": 1,
        "summary": (
            "Function App 'func-orders' exposes a public hostname, uses managed identity, and "
            "shows deployment-setting clues worth follow-up."
        ),
        "related_ids": [FUNCTION_APP_ID, IDENTITY_ID],
    }
    row.update(overrides)
    return row


def _env_var_row(**overrides) -> dict:
    row = {
        "asset_id": FUNCTION_APP_ID,
        "asset_name": "func-orders",
        "asset_kind": "FunctionApp",
        "resource_group": "rg-apps",
        "location": "eastus",
        "workload_identity_type": "SystemAssigned, UserAssigned",
        "workload_principal_id": PRINCIPAL_ID,
        "workload_client_id": "dddd2222-2222-2222-2222-222222222222",
        "workload_identity_ids": [IDENTITY_ID],
        "key_vault_reference_identity": "SystemAssigned",
        "setting_name": "PAYMENT_API_KEY",
        "value_type": "keyvault-ref",
        "looks_sensitive": True,
        "reference_target": KEY_VAULT_TARGET,
        "summary": (
            "FunctionApp 'func-orders' maps setting 'PAYMENT_API_KEY' to Key Vault-backed "
            "configuration via SystemAssigned identity."
        ),
        "related_ids": [FUNCTION_APP_ID, IDENTITY_ID],
    }
    row.update(overrides)
    return row


def _chain_path_row(**overrides) -> dict:
    row = {
        "chain_id": "credential-path-func-orders-payment-api-key",
        "asset_id": FUNCTION_APP_ID,
        "asset_name": "func-orders",
        "asset_kind": "FunctionApp",
        "location": "eastus",
        "source_command": "env-vars",
        "source_context": "Function App app settings",
        "setting_name": "PAYMENT_API_KEY",
        "clue_type": "keyvault-ref",
        "confirmation_basis": "setting reference",
        "priority": "high",
        "urgency": "review-soon",
        "visible_path": "Key Vault-backed setting -> secret path",
        "target_service": "keyvault",
        "target_resolution": "named match",
        "evidence_commands": ["env-vars", "keyvault"],
        "joined_surface_types": ["app-settings", "vault-reference"],
        "target_count": 1,
        "target_ids": [
            "/subscriptions/test/resourceGroups/rg-secrets/providers/Microsoft.KeyVault/vaults/kv-orders"
        ],
        "target_names": ["kv-orders"],
        "target_visibility_issue": None,
        "next_review": "Check vault access path and referenced secret use.",
        "summary": (
            "FunctionApp 'func-orders' exposes a Key Vault-backed setting and the visible naming "
            "matches a vault already visible in inventory."
        ),
        "missing_confirmation": "",
        "related_ids": [FUNCTION_APP_ID],
    }
    row.update(overrides)
    return row


def _chains_payload(*, path: dict, issues: list[dict] | None = None) -> dict:
    return {
        "metadata": {"command": "chains"},
        "grouped_command_name": "chains",
        "family": "credential-path",
        "input_mode": "live",
        "command_state": "extraction-only",
        "summary": "Visibility-tier test payload.",
        "claim_boundary": "Only visible edges are shown.",
        "current_gap": "Deeper confirmation still depends on the backing command visibility.",
        "artifact_preference_order": [],
        "backing_commands": ["env-vars", "keyvault"],
        "source_artifacts": [],
        "paths": [path],
        "issues": issues or [],
    }


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

    def devops(self) -> dict:
        return {"pipelines": [_devops_pipeline()], "issues": []}

    def functions(self) -> dict:
        return {"function_apps": [_function_app()], "issues": []}

    def env_vars(self) -> dict:
        return {"env_vars": [_env_var_row()], "issues": []}


class MediumVisibilityProvider(HighVisibilityProvider):
    def principals(self) -> dict:
        return {"principals": [_principal_row(attached_to=[])], "issues": []}

    def managed_identities(self) -> dict:
        return {
            "identities": [_identity_row(principal_id=None)],
            "role_assignments": [],
            "issues": [],
        }

    def devops(self) -> dict:
        return {
            "pipelines": [
                _devops_pipeline(
                    source_visibility_state="inferred-only",
                    trusted_inputs=[
                        _trusted_input(
                            visibility_state="exists-only",
                            current_operator_access_state="exists-only",
                        )
                    ],
                    current_operator_can_view_source=False,
                    summary=(
                        "Pipeline 'deploy-func-orders' still points at a Function App deployment "
                        "path, but current source-side proof is weaker."
                    ),
                )
            ],
            "issues": [],
        }

    def functions(self) -> dict:
        return {
            "function_apps": [
                _function_app(
                    azure_webjobs_storage_value_type=None,
                    azure_webjobs_storage_reference_target=None,
                    run_from_package=None,
                    key_vault_reference_count=None,
                )
            ],
            "issues": [
                {
                    "kind": "permission_denied",
                    "message": "functions[rg-apps/func-orders].app_settings: 403 Forbidden",
                    "context": {"collector": "functions[rg-apps/func-orders].app_settings"},
                }
            ],
        }

    def env_vars(self) -> dict:
        return {
            "env_vars": [
                _env_var_row(
                    reference_target=None,
                    key_vault_reference_identity=None,
                    summary=(
                        "FunctionApp 'func-orders' still shows a Key Vault-backed setting path, "
                        "but current credentials do not show the exact referenced secret."
                    ),
                )
            ],
            "issues": [
                {
                    "kind": "permission_denied",
                    "message": "env_vars[rg-apps/func-orders].key_vault_reference: 403 Forbidden",
                    "context": {"collector": "env_vars[rg-apps/func-orders].key_vault_reference"},
                }
            ],
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

    def devops(self) -> dict:
        return {
            "pipelines": [
                _devops_pipeline(
                    source_visibility_state="inferred-only",
                    target_clues=[],
                    key_vault_group_names=[],
                    key_vault_names=[],
                    azure_service_connection_names=[],
                    azure_service_connection_types=[],
                    azure_service_connection_auth_schemes=[],
                    azure_service_connection_ids=[],
                    azure_service_connection_principal_ids=[],
                    azure_service_connection_client_ids=[],
                    azure_service_connection_tenant_ids=[],
                    azure_service_connection_subscription_ids=[],
                    trusted_inputs=[
                        _trusted_input(
                            visibility_state="exists-only",
                            current_operator_access_state="exists-only",
                        )
                    ],
                    partial_read=True,
                    summary=(
                        "Pipeline 'deploy-func-orders' is visible, but current credentials do not "
                        "show enough Azure DevOps backing detail to pick the next Azure target "
                        "confidently."
                    ),
                )
            ],
            "issues": [
                {
                    "kind": "partial_collection",
                    "message": (
                        "devops[app-platform/deploy-func-orders]: unresolved variable group refs"
                    ),
                    "context": {"collector": "devops[app-platform/deploy-func-orders]"},
                }
            ],
        }

    def functions(self) -> dict:
        return {
            "function_apps": [
                _function_app(
                    workload_identity_type=None,
                    workload_principal_id=None,
                    workload_client_id=None,
                    workload_identity_ids=[],
                    azure_webjobs_storage_value_type=None,
                    azure_webjobs_storage_reference_target=None,
                    run_from_package=None,
                    key_vault_reference_count=None,
                    summary=(
                        "Function App 'func-orders' is still visible at the service shell level, "
                        "but current credentials do not show identity or deployment-setting detail "
                        "cleanly."
                    ),
                )
            ],
            "issues": [
                {
                    "kind": "permission_denied",
                    "message": "functions[rg-apps/func-orders].configuration: 403 Forbidden",
                    "context": {"collector": "functions[rg-apps/func-orders].configuration"},
                },
                {
                    "kind": "permission_denied",
                    "message": "functions[rg-apps/func-orders].app_settings: 403 Forbidden",
                    "context": {"collector": "functions[rg-apps/func-orders].app_settings"},
                },
            ],
        }

    def env_vars(self) -> dict:
        return {
            "env_vars": [
                _env_var_row(
                    workload_identity_type=None,
                    workload_principal_id=None,
                    workload_client_id=None,
                    workload_identity_ids=[],
                    key_vault_reference_identity=None,
                    value_type="unknown",
                    reference_target=None,
                    summary=(
                        "FunctionApp 'func-orders' still exposes a sensitive setting name, but "
                        "current credentials do not show whether the backing value is plain-text "
                        "or Key Vault-backed."
                    ),
                )
            ],
            "issues": [
                {
                    "kind": "permission_denied",
                    "message": "env_vars[rg-apps/func-orders].app_settings: 403 Forbidden",
                    "context": {"collector": "env_vars[rg-apps/func-orders].app_settings"},
                }
            ],
        }


@pytest.mark.parametrize(
    ("provider_cls", "expected_signal", "summary_fragment", "expected_next_review"),
    [
        pytest.param(
            HighVisibilityProvider,
            "Direct control visible; workload pivot visible.",
            "already has direct control visible",
            "Check managed-identities for the workload pivot behind this direct control row.",
            id=f"high-{TIER_ALIASES['high']}",
        ),
        pytest.param(
            MediumVisibilityProvider,
            "Direct control visible; visibility blocked.",
            "backing workload pivot stays visibility blocked",
            "Check managed-identities; current scope does not yet show the workload pivot behind "
            "this direct-control row.",
            id=f"medium-{TIER_ALIASES['medium']}",
        ),
        pytest.param(
            LowVisibilityProvider,
            "Direct control not confirmed.",
            "does not yet show direct control from visible RBAC",
            "Check rbac for the exact assignment evidence behind this lower-signal row.",
            id=f"low-{TIER_ALIASES['low']}",
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
        pytest.param(
            HighVisibilityProvider,
            "Public VM workload pivot; direct control visible.",
            "direct control through high-impact roles",
            "Check permissions for direct control on this identity, then vms for the host context "
            "behind the workload pivot.",
            None,
            id=f"high-{TIER_ALIASES['high']}",
        ),
        pytest.param(
            MediumVisibilityProvider,
            "Public VM workload pivot; visibility blocked.",
            "current scope does not show the backing principal cleanly",
            "Check vms for the host context behind this workload pivot; current scope does not yet "
            "show direct control on this identity.",
            None,
            id=f"medium-{TIER_ALIASES['medium']}",
        ),
        pytest.param(
            LowVisibilityProvider,
            "VM workload pivot; visibility blocked.",
            "current scope does not show the backing principal cleanly",
            "Check vms for the host context behind this workload pivot; current scope does not yet "
            "show direct control on this identity.",
            "permission_denied",
            id=f"low-{TIER_ALIASES['low']}",
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


def test_devops_visibility_tiers_keep_routing_honest(options) -> None:
    high = collect_devops(HighVisibilityProvider(), options)
    medium = collect_devops(MediumVisibilityProvider(), options)
    low = collect_devops(LowVisibilityProvider(), options)

    assert high.pipelines[0].name == medium.pipelines[0].name == low.pipelines[0].name == (
        "deploy-func-orders"
    )

    high_rendered = " ".join(render_table("devops", high.model_dump(mode="json")).split())
    medium_rendered = " ".join(render_table("devops", medium.model_dump(mode="json")).split())
    low_rendered = " ".join(render_table("devops", low.model_dump(mode="json")).split())

    assert "Check functions" in high_rendered
    assert "deployment" in high_rendered
    assert "target;" in high_rendered
    assert "role-trusts" in high_rendered
    assert "Azure control;" in high_rendered
    assert "review keyvault" in high_rendered
    assert "vault-backed" in high_rendered

    assert "shows that it" in medium_rendered
    assert "exists;" in medium_rendered
    assert "Azure Repos" in medium_rendered
    assert "only inferred" in medium_rendered
    assert "Check functions" in medium_rendered
    assert "deployment" in medium_rendered
    assert "target;" in medium_rendered
    assert "role-trusts" in medium_rendered

    assert "Restore" in low_rendered
    assert "variable-group" in low_rendered
    assert "visibility" in low_rendered
    assert "next Azure" in low_rendered
    assert "follow-up." in low_rendered
    assert "Current-scope issues:" in low_rendered
    assert "partial_collection" in low_rendered
    assert low.issues[0].kind == "partial_collection"


def test_functions_visibility_tiers_keep_service_shell_visible(options) -> None:
    high = collect_functions(HighVisibilityProvider(), options)
    medium = collect_functions(MediumVisibilityProvider(), options)
    low = collect_functions(LowVisibilityProvider(), options)

    high_row = high.function_apps[0]
    medium_row = medium.function_apps[0]
    low_row = low.function_apps[0]

    assert high_row.name == medium_row.name == low_row.name == "func-orders"
    assert high_row.azure_webjobs_storage_value_type == "plain-text"
    assert medium_row.azure_webjobs_storage_value_type is None
    assert low_row.azure_webjobs_storage_value_type is None
    assert high_row.key_vault_reference_count == 1
    assert medium_row.key_vault_reference_count is None
    assert low_row.key_vault_reference_count is None
    assert high_row.workload_identity_type == "SystemAssigned, UserAssigned"
    assert medium_row.workload_identity_type == "SystemAssigned, UserAssigned"
    assert low_row.workload_identity_type is None

    assert high.issues == []
    assert medium.issues[0].kind == "permission_denied"
    assert low.issues[0].kind == "permission_denied"

    medium_rendered = render_table("functions", medium.model_dump(mode="json"))
    low_rendered = render_table("functions", low.model_dump(mode="json"))

    assert "func-orders" in medium_rendered
    assert "Current-scope issues:" in medium_rendered
    assert "functions[rg-apps/func-orders].app_settings" in medium_rendered

    assert "func-orders" in low_rendered
    assert "Current-scope issues:" in low_rendered
    assert "functions[rg-apps/func-orders].configuration" in low_rendered


def test_env_vars_visibility_tiers_keep_next_review_honest(options) -> None:
    high = collect_env_vars(HighVisibilityProvider(), options)
    medium = collect_env_vars(MediumVisibilityProvider(), options)
    low = collect_env_vars(LowVisibilityProvider(), options)

    high_row = high.env_vars[0]
    medium_row = medium.env_vars[0]
    low_row = low.env_vars[0]

    assert high_row.setting_name == medium_row.setting_name == low_row.setting_name == (
        "PAYMENT_API_KEY"
    )
    assert high_row.asset_name == medium_row.asset_name == low_row.asset_name == "func-orders"
    assert high_row.reference_target == KEY_VAULT_TARGET
    assert medium_row.reference_target is None
    assert low_row.reference_target is None
    assert high_row.value_type == "keyvault-ref"
    assert medium_row.value_type == "keyvault-ref"
    assert low_row.value_type == "unknown"
    assert high.issues == []
    assert medium.issues[0].kind == "permission_denied"
    assert low.issues[0].kind == "permission_denied"

    high_rendered = " ".join(render_table("env-vars", high.model_dump(mode="json")).split())
    medium_rendered = " ".join(render_table("env-vars", medium.model_dump(mode="json")).split())
    low_rendered = " ".join(render_table("env-vars", low.model_dump(mode="json")).split())

    assert KEY_VAULT_TARGET in high_rendered
    assert "Check keyvault for the" in high_rendered
    assert "referenced secret" in high_rendered
    assert "managed-identities" in high_rendered

    assert KEY_VAULT_TARGET not in medium_rendered
    assert "keyvault-ref" in medium_rendered
    assert "Check keyvault for the" in medium_rendered
    assert "referenced secret" in medium_rendered
    assert "managed-identities" in medium_rendered
    assert "Current-scope issues:" in medium_rendered
    assert "env_vars[rg-apps/func-orders].key_vault_reference" in medium_rendered

    assert "unknown" in low_rendered
    assert "Review the workload config" in low_rendered
    assert "deeper follow-up." in low_rendered
    assert "Current-scope issues:" in low_rendered
    assert "env_vars[rg-apps/func-orders].app_settings" in low_rendered
    assert "keyvault-ref" not in low_rendered


def test_chains_visibility_tiers_avoid_fake_target_certainty() -> None:
    high_rendered = " ".join(
        render_table(
            "chains",
            _chains_payload(
                path=_chain_path_row(),
            ),
        ).split()
    )
    medium_rendered = " ".join(
        render_table(
            "chains",
            _chains_payload(
                path=_chain_path_row(
                    target_resolution="narrowed candidates",
                    target_count=2,
                    target_names=["kv-orders", "kv-shared"],
                    next_review="Confirm the exact target before deeper follow-up.",
                    summary=(
                        "FunctionApp 'func-orders' still exposes a vault-backed setting, but the "
                        "current view only narrows the likely vault set."
                    ),
                ),
            ),
        ).split()
    )
    low_rendered = " ".join(
        render_table(
            "chains",
            _chains_payload(
                path=_chain_path_row(
                    target_resolution="visibility blocked",
                    target_count=0,
                    target_names=[],
                    target_visibility_issue=(
                        "permission_denied: keyvault.vaults: current credentials do not show "
                        "enough vault visibility to choose a target"
                    ),
                    next_review="Restore keyvault visibility before choosing a target.",
                    summary=(
                        "FunctionApp 'func-orders' still exposes a vault-backed setting, but "
                        "current credentials do not show enough target-side visibility to name "
                        "the vault confidently."
                    ),
                ),
                issues=[
                    {
                        "kind": "permission_denied",
                        "message": (
                            "keyvault.vaults: current credentials do not show enough vault "
                            "visibility to choose a target"
                        ),
                        "context": {"collector": "keyvault.vaults"},
                    }
                ],
            ),
        ).split()
    )

    assert "func-orders" in high_rendered
    assert "PAYMENT_API_KEY" in high_rendered
    assert "named match" in high_rendered
    assert "kv-orders" in high_rendered
    assert "Named target matched" in high_rendered
    assert "visible inventory." in high_rendered
    assert "Check vault access path" in high_rendered
    assert "referenced secret" in high_rendered
    assert "use." in high_rendered

    assert "func-orders" in medium_rendered
    assert "PAYMENT_API_KEY" in medium_rendered
    assert "narrowed candidates" in medium_rendered
    assert "kv-orders" in medium_rendered
    assert "kv-shared" in medium_rendered
    assert "This app exposes a" in medium_rendered
    assert "secret-shaped" in medium_rendered
    assert "exact target" in medium_rendered
    assert "unconfirmed." in medium_rendered
    assert "Confirm the exact" in medium_rendered
    assert "deeper" in medium_rendered
    assert "follow-up." in medium_rendered

    assert "func-orders" in low_rendered
    assert "PAYMENT_API_KEY" in low_rendered
    assert "visibility blocked" in low_rendered
    assert "permission_denied: keyvault.vaults" in low_rendered
    assert "blocked;" in low_rendered
    assert "infer" in low_rendered
    assert "target." in low_rendered
    assert "Restore keyvault" in low_rendered
    assert "choosing a target." in low_rendered
    assert "Current-scope issues:" in low_rendered
    assert "Claim boundary:" not in low_rendered
    assert "Current gap:" not in low_rendered
    assert "kv-orders,kv-shared" not in low_rendered
