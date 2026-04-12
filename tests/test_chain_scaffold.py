from __future__ import annotations

from azurefox.chains.registry import (
    GROUPED_COMMAND_INPUT_MODES,
    GROUPED_COMMAND_NAME,
    PREFERRED_ARTIFACT_ORDER,
    chain_family_names,
    get_chain_family_spec,
    implemented_chain_family_names,
    is_implemented_chain_family,
)
from azurefox.chains.scaffold import build_chains_scaffold_output
from azurefox.models.common import (
    AksClusterAsset,
    AppServiceAsset,
    ArmDeploymentSummary,
    AutomationAccountAsset,
    DatabaseServerAsset,
    DevopsPipelineAsset,
    EnvVarSummary,
    FunctionAppAsset,
    KeyVaultAsset,
    ManagedIdentity,
    PermissionSummary,
    PrivescPathSummary,
    RoleAssignment,
    RoleTrustSummary,
    StorageAsset,
    TokenCredentialSurfaceSummary,
    WorkloadSummary,
)

COMMAND_MODEL_FIELDS = {
    "aks": set(AksClusterAsset.model_fields),
    "app-services": set(AppServiceAsset.model_fields),
    "arm-deployments": set(ArmDeploymentSummary.model_fields),
    "automation": set(AutomationAccountAsset.model_fields),
    "databases": set(DatabaseServerAsset.model_fields),
    "devops": set(DevopsPipelineAsset.model_fields),
    "env-vars": set(EnvVarSummary.model_fields),
    "functions": set(FunctionAppAsset.model_fields),
    "keyvault": set(KeyVaultAsset.model_fields),
    "managed-identities": set(ManagedIdentity.model_fields),
    "permissions": set(PermissionSummary.model_fields),
    "privesc": set(PrivescPathSummary.model_fields),
    "rbac": set(RoleAssignment.model_fields),
    "role-trusts": set(RoleTrustSummary.model_fields),
    "storage": set(StorageAsset.model_fields),
    "tokens-credentials": set(TokenCredentialSurfaceSummary.model_fields),
    "workloads": set(WorkloadSummary.model_fields),
}


def test_chain_registry_uses_expected_grouped_command_shape() -> None:
    assert GROUPED_COMMAND_NAME == "chains"
    assert GROUPED_COMMAND_INPUT_MODES == ("live", "artifacts")
    assert PREFERRED_ARTIFACT_ORDER == ("loot", "json")


def test_chain_registry_keeps_first_family_order() -> None:
    assert chain_family_names() == (
        "credential-path",
        "deployment-path",
        "escalation-path",
        "compute-control",
    )


def test_chain_registry_implemented_state_drives_runnable_families() -> None:
    assert implemented_chain_family_names() == (
        "credential-path",
        "deployment-path",
        "escalation-path",
        "compute-control",
    )
    assert is_implemented_chain_family("credential-path") is True
    assert is_implemented_chain_family("compute-control") is True


def test_chain_registry_scaffold_fields_exist_on_backing_models() -> None:
    for family_name in chain_family_names():
        family = get_chain_family_spec(family_name)
        assert family is not None
        for source in family.source_commands:
            model_fields = COMMAND_MODEL_FIELDS[source.command]
            for field_name in source.minimum_fields:
                assert field_name in model_fields


def test_build_chains_scaffold_output_returns_selected_family_only() -> None:
    output = build_chains_scaffold_output("credential-path")

    assert output.metadata.command == "chains"
    assert output.grouped_command_name == "chains"
    assert output.command_state == "scaffold"
    assert output.selected_family == "credential-path"
    assert len(output.families) == 1
    assert output.families[0].family == "credential-path"
    assert output.families[0].state == "implemented"
    assert output.families[0].best_current_examples == [
        "env-vars -> tokens-credentials -> databases",
        "env-vars -> tokens-credentials -> storage",
    ]


def test_build_chains_scaffold_output_marks_planned_family_state() -> None:
    output = build_chains_scaffold_output("compute-control")

    assert len(output.families) == 1
    assert output.families[0].family == "compute-control"
    assert output.families[0].state == "implemented"
    assert "intentionally narrow in v1" in output.families[0].current_gap


def test_build_chains_scaffold_output_raises_for_unknown_family() -> None:
    try:
        build_chains_scaffold_output("banana-path")
    except ValueError as exc:
        assert "Unknown chain family" in str(exc)
    else:  # pragma: no cover - safety rail
        raise AssertionError("expected ValueError for unknown chain family")
