from __future__ import annotations

import json
from pathlib import Path

from azurefox.chains.deployment_path import (
    admit_deployment_path_row,
    assess_deployment_source,
    target_family_hints_from_arm_deployment,
)
from azurefox.chains.runner import _structured_deployment_target_matches
from azurefox.chains.runner import (
    _automation_current_operator_access,
    _automation_scope_label,
)
from azurefox.models.common import (
    ArmDeploymentSummary,
    AutomationAccountAsset,
    DevopsPipelineAsset,
)


def test_devops_pipeline_with_service_connection_is_change_capable() -> None:
    pipeline = _load_devops_pipeline("deploy-aks-prod")

    assessment = assess_deployment_source(pipeline)

    assert assessment.posture == "can already change Azure here"
    assert assessment.path_concept == "controllable-change-path"
    assert "azure-service-connection" in assessment.change_signals
    assert "redeploy-workload" in assessment.consequence_types
    assert assessment.target_family_hints == ("aks",)


def test_devops_pipeline_with_only_secret_support_is_not_change_capable() -> None:
    pipeline = DevopsPipelineAsset(
        id="devops/pipeline/release-secrets-only",
        definition_id="77",
        name="release-secrets-only",
        project_name="prod-platform",
        secret_variable_count=3,
        secret_variable_names=["ARM_CLIENT_SECRET"],
        key_vault_names=["kv-prod-shared"],
        variable_group_names=["prod-release-secrets"],
        summary="Secret support without a visible Azure change path.",
    )

    assessment = assess_deployment_source(pipeline)

    assert assessment.posture == "stores secrets here"
    assert assessment.path_concept == "secret-escalation-support"
    assert "secret-variables" in assessment.secret_support_signals
    assert "keyvault-backed-support" in assessment.secret_support_signals


def test_automation_account_with_identity_and_execution_surface_is_change_capable() -> None:
    account = _load_automation_account("aa-hybrid-prod")

    assessment = assess_deployment_source(account)

    assert assessment.posture == "can already change Azure here"
    assert assessment.path_concept == "execution-hub"
    assert "managed-identity" in assessment.change_signals
    assert "published-runbooks" in assessment.change_signals
    assert "webhook-start" in assessment.change_signals
    assert "run-recurring-execution" in assessment.consequence_types


def test_automation_account_without_identity_stays_secret_support_only() -> None:
    account = _load_automation_account("aa-lab-quiet")

    assessment = assess_deployment_source(account)

    assert assessment.posture == "stores secrets here"
    assert "connections" in assessment.secret_support_signals


def test_name_only_inference_caps_deployment_row_at_narrowed_candidates() -> None:
    source = assess_deployment_source(_load_devops_pipeline("deploy-appservice-prod"))

    admission = admit_deployment_path_row(
        source,
        exact_target_count=1,
        confirmation_basis="name-only-inference",
    )

    assert admission.admitted is True
    assert admission.state == "narrowed candidates"


def test_visibility_issue_keeps_change_capable_source_visible_as_blocked() -> None:
    source = assess_deployment_source(_load_devops_pipeline("deploy-appservice-prod"))

    admission = admit_deployment_path_row(
        source,
        visibility_issue="partial_collection: app-services: current scope cannot read web apps",
    )

    assert admission.admitted is True
    assert admission.state == "visibility blocked"
    assert "does not confirm" in admission.reason


def test_exact_named_match_survives_visibility_issue() -> None:
    source = assess_deployment_source(_load_devops_pipeline("deploy-appservice-prod"))

    admission = admit_deployment_path_row(
        source,
        exact_target_count=1,
        confirmation_basis="parsed-config-target",
        visibility_issue="partial_collection: app-services: current scope cannot read all apps",
    )

    assert admission.admitted is True
    assert admission.state == "named match"


def test_secret_support_source_without_consequence_grounding_stays_blocked() -> None:
    source = assess_deployment_source(
        DevopsPipelineAsset(
            id="devops/pipeline/release-secrets-only",
            definition_id="77",
            name="release-secrets-only",
            project_name="prod-platform",
            secret_variable_count=3,
            secret_variable_names=["ARM_CLIENT_SECRET"],
            key_vault_names=["kv-prod-shared"],
            variable_group_names=["prod-release-secrets"],
            summary="Secret support without a visible Azure change path.",
        )
    )

    admission = admit_deployment_path_row(
        source,
        exact_target_count=1,
        confirmation_basis="resource-id-match",
    )

    assert admission.admitted is False
    assert admission.state == "blocked"
    assert "defended Azure impact point" in admission.reason


def test_secret_support_source_admits_visibility_blocked_rows_when_mapping_is_missing() -> None:
    source = assess_deployment_source(
        AutomationAccountAsset(
            id="automation/account/quiet-secret-support",
            name="quiet-secret-support",
            encrypted_variable_count=1,
            connection_count=1,
            consequence_types=["consume-secret-backed-deployment-material"],
            missing_execution_path=False,
            missing_target_mapping=True,
            summary="Secret-backed support exists but target mapping is missing.",
        )
    )

    admission = admit_deployment_path_row(source)

    assert admission.admitted is True
    assert admission.state == "visibility blocked"
    assert "stronger target mapping" in admission.reason


def test_missing_execution_path_blocks_deployment_row_even_with_target_hints() -> None:
    source = assess_deployment_source(
        DevopsPipelineAsset(
            id="devops/pipeline/missing-foothold",
            definition_id="109",
            name="missing-foothold",
            project_name="prod-platform",
            azure_service_connection_names=["prod-subscription"],
            target_clues=["App Service"],
            consequence_types=["redeploy-workload"],
            missing_execution_path=True,
            summary="Target hints exist, but no visible execution foothold is exposed.",
        )
    )

    admission = admit_deployment_path_row(
        source,
        narrowed_candidate_count=2,
        confirmation_basis="name-only-inference",
    )

    assert admission.admitted is False
    assert admission.state == "blocked"
    assert "execution foothold" in admission.reason


def test_visible_edit_or_queue_foothold_can_keep_deployment_row_admissible() -> None:
    source = assess_deployment_source(
        DevopsPipelineAsset(
            id="devops/pipeline/manual-but-actionable",
            definition_id="110",
            name="manual-but-actionable",
            project_name="prod-platform",
            azure_service_connection_names=["prod-subscription"],
            target_clues=["App Service"],
            consequence_types=["redeploy-workload"],
            missing_execution_path=False,
            summary="Current credentials can still queue or edit this manual definition.",
        )
    )

    admission = admit_deployment_path_row(
        source,
        narrowed_candidate_count=1,
        confirmation_basis="name-only-inference",
    )

    assert admission.admitted is True
    assert admission.state == "narrowed candidates"


def test_arm_deployment_provider_hints_narrow_to_supported_workload_families() -> None:
    deployment = _load_arm_deployment("app-failed")

    assert target_family_hints_from_arm_deployment(deployment) == ("app-services", "functions")


def test_structured_target_clue_can_reach_exact_named_match_input() -> None:
    pipeline = DevopsPipelineAsset(
        id="devops/pipeline/release-appservice-prod",
        definition_id="88",
        name="release-appservice-prod",
        project_name="prod-platform",
        azure_service_connection_names=["prod-appsvc-wif"],
        target_clues=["App Service: app-public-api"],
        summary="Structured target clue test.",
    )

    matches, confirmation_basis = _structured_deployment_target_matches(
        pipeline.model_dump(mode="json"),
        "app-services",
        [
            {
                "id": (
                    "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/"
                    "app-public-api"
                ),
                "name": "app-public-api",
            }
        ],
    )

    assert confirmation_basis == "parsed-config-target"
    assert [item["name"] for item in matches] == ["app-public-api"]


def test_automation_current_operator_access_uses_role_definition_id_and_best_scope_match() -> None:
    access = _automation_current_operator_access(
        {
            "id": (
                "/subscriptions/test-sub/resourceGroups/rg-ops/providers/Microsoft.Automation/"
                "automationAccounts/aa-prod"
            )
        },
        [
            {
                "scope_id": "/subscriptions/test-sub",
                "role_definition_id": (
                    "/subscriptions/test-sub/providers/Microsoft.Authorization/"
                    "roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
                ),
                "role_name": "Owner (renamed locally)",
            },
            {
                "scope_id": (
                    "/subscriptions/test-sub/resourceGroups/rg-ops/providers/Microsoft.Automation/"
                    "automationAccounts/aa-prod"
                ),
                "role_definition_id": None,
                "role_name": " automation  operator ",
            },
        ],
    )

    assert access == {
        "capability": "edit",
        "role_name": "Owner (renamed locally)",
        "scope_id": "/subscriptions/test-sub",
    }


def test_automation_scope_label_keeps_child_resource_scope_distinct_from_resource_group() -> None:
    scope_id = (
        "/subscriptions/test-sub/resourceGroups/rg-ops/providers/Microsoft.Automation/"
        "automationAccounts/aa-prod/runbooks/Redeploy-App"
    )
    resource_id = (
        "/subscriptions/test-sub/resourceGroups/rg-ops/providers/Microsoft.Automation/"
        "automationAccounts/aa-prod"
    )

    assert _automation_scope_label(scope_id, resource_id=resource_id) == "resource scope Redeploy-App"


def _load_devops_pipeline(name: str) -> DevopsPipelineAsset:
    payload = json.loads(
        (Path(__file__).resolve().parent / "fixtures" / "lab_tenant" / "devops.json").read_text(
            encoding="utf-8"
        )
    )
    for item in payload["pipelines"]:
        if item["name"] == name:
            return DevopsPipelineAsset.model_validate(item)
    raise AssertionError(f"missing devops fixture pipeline {name}")


def _load_automation_account(name: str) -> AutomationAccountAsset:
    payload = json.loads(
        (Path(__file__).resolve().parent / "fixtures" / "lab_tenant" / "automation.json").read_text(
            encoding="utf-8"
        )
    )
    for item in payload["automation_accounts"]:
        if item["name"] == name:
            return AutomationAccountAsset.model_validate(item)
    raise AssertionError(f"missing automation fixture account {name}")


def _load_arm_deployment(name: str) -> ArmDeploymentSummary:
    payload = json.loads(
        (
            Path(__file__).resolve().parent / "fixtures" / "lab_tenant" / "arm_deployments.json"
        ).read_text(encoding="utf-8")
    )
    for item in payload["deployments"]:
        if item["name"] == name:
            return ArmDeploymentSummary.model_validate(item)
    raise AssertionError(f"missing ARM deployment fixture {name}")
