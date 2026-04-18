from __future__ import annotations

import json
from pathlib import Path

from azurefox.chains.deployment_path import (
    admit_deployment_path_row,
    assess_deployment_source,
    target_family_hints_from_arm_deployment,
)
from azurefox.chains.runner import (
    _automation_current_operator_access,
    _automation_scope_label,
    _best_automation_target_mapping,
    _deployment_joined_key_vaults,
    _structured_deployment_target_matches,
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


def test_devops_pipeline_with_structured_target_clue_keeps_family_hint() -> None:
    pipeline = DevopsPipelineAsset(
        id="devops/pipeline/release-appservice-prod",
        definition_id="88",
        name="release-appservice-prod",
        project_name="prod-platform",
        azure_service_connection_names=["prod-appsvc-wif"],
        target_clues=["App Service: app-public-api"],
        consequence_types=["redeploy-workload"],
        summary="Structured target clue should still drive family hints.",
    )

    assessment = assess_deployment_source(pipeline)

    assert assessment.target_family_hints == ("app-services",)


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


def test_structured_target_clue_can_match_exact_resource_id() -> None:
    pipeline = DevopsPipelineAsset(
        id="devops/pipeline/release-appservice-prod",
        definition_id="88",
        name="release-appservice-prod",
        project_name="prod-platform",
        azure_service_connection_names=["prod-appsvc-wif"],
        target_clues=[
            "App Service: "
            "/subscriptions/sub/resourceGroups/rg-apps/providers/"
            "Microsoft.Web/sites/app-public-api"
        ],
        summary="Structured target resource id test.",
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
                "name": "not-the-join-key",
            }
        ],
    )

    assert confirmation_basis == "resource-id-match"
    assert [item["id"] for item in matches] == [
        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/app-public-api"
    ]


def test_structured_target_clue_can_match_exact_hostname() -> None:
    pipeline = DevopsPipelineAsset(
        id="devops/pipeline/release-appservice-prod",
        definition_id="88",
        name="release-appservice-prod",
        project_name="prod-platform",
        azure_service_connection_names=["prod-appsvc-wif"],
        target_clues=["App Service: https://app-public-api.azurewebsites.net"],
        summary="Structured target hostname test.",
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
                "default_hostname": "app-public-api.azurewebsites.net",
            }
        ],
    )

    assert confirmation_basis == "normalized-uri-match"
    assert [item["name"] for item in matches] == ["app-public-api"]


def test_structured_target_clue_can_match_exact_aks_private_fqdn() -> None:
    pipeline = DevopsPipelineAsset(
        id="devops/pipeline/deploy-aks-prod",
        definition_id="17",
        name="deploy-aks-prod",
        project_name="prod-platform",
        azure_service_connection_names=["prod-subscription"],
        target_clues=["AKS/Kubernetes: https://aks-ops-01-abcd1234.privatelink.eastus.azmk8s.io"],
        summary="Structured target AKS hostname test.",
    )

    matches, confirmation_basis = _structured_deployment_target_matches(
        pipeline.model_dump(mode="json"),
        "aks",
        [
            {
                "id": (
                    "/subscriptions/sub/resourceGroups/rg-workload/providers/"
                    "Microsoft.ContainerService/managedClusters/aks-ops-01"
                ),
                "name": "aks-ops-01",
                "private_fqdn": "aks-ops-01-abcd1234.privatelink.eastus.azmk8s.io",
            }
        ],
    )

    assert confirmation_basis == "normalized-uri-match"
    assert [item["name"] for item in matches] == ["aks-ops-01"]


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
    assert (
        _automation_scope_label(scope_id, resource_id=resource_id)
        == "resource scope Redeploy-App"
    )


def test_best_automation_target_mapping_uses_runbook_names_to_narrow_visible_targets() -> None:
    account = _load_automation_account("aa-hybrid-prod").model_dump(mode="json")
    app_services = json.loads(
        (
            Path(__file__).resolve().parent / "fixtures" / "lab_tenant" / "app_services.json"
        ).read_text(encoding="utf-8")
    )
    functions = json.loads(
        (Path(__file__).resolve().parent / "fixtures" / "lab_tenant" / "functions.json").read_text(
            encoding="utf-8"
        )
    )
    aks = json.loads(
        (Path(__file__).resolve().parent / "fixtures" / "lab_tenant" / "aks.json").read_text(
            encoding="utf-8"
        )
    )
    arm = json.loads(
        (
            Path(__file__).resolve().parent / "fixtures" / "lab_tenant" / "arm_deployments.json"
        ).read_text(encoding="utf-8")
    )

    mapping = _best_automation_target_mapping(
        account,
        target_candidates={
            "app-services": app_services["app_services"],
            "functions": functions["function_apps"],
            "aks": aks["aks_clusters"],
            "arm-deployments": arm["deployments"],
        },
        target_visibility_notes={
            "app-services": None,
            "functions": None,
            "aks": None,
            "arm-deployments": None,
        },
        target_visibility_issues={
            "app-services": None,
            "functions": None,
            "aks": None,
            "arm-deployments": None,
        },
        arm_correlations={
            "app-services": [arm["deployments"][2]],
            "functions": [arm["deployments"][2]],
            "aks": [],
            "arm-deployments": arm["deployments"],
        },
    )

    assert mapping is not None
    assert mapping["target_family"] == "app-services"
    assert mapping["exact_targets"] == []
    assert [item["name"] for item in mapping["target_candidates"]] == ["app-public-api"]
    assert mapping["confirmation_basis"] == "same-workload-corroborated"


def test_best_automation_target_mapping_does_not_remap_from_name_overlap_alone() -> None:
    account = _load_automation_account("aa-hybrid-prod").model_dump(mode="json")
    target_inputs = _load_automation_target_inputs()

    mapping = _best_automation_mapping(
        account,
        target_inputs=target_inputs,
        arm_correlations={
            "app-services": [],
            "functions": [],
            "aks": [],
            "arm-deployments": target_inputs["arm-deployments"],
        },
    )

    assert mapping is None


def test_best_automation_target_mapping_uses_primary_runbook_path_for_exact_match() -> None:
    account = _load_automation_account("aa-hybrid-prod").model_dump(mode="json")
    account["primary_runbook_name"] = "app-public-api"
    account["webhook_runbook_names"] = ["app-public-api", "app-empty-mi"]
    account["published_runbook_names"] = ["app-public-api", "app-empty-mi", "func-orders"]
    target_inputs = _load_automation_target_inputs()

    mapping = _best_automation_mapping(
        account,
        target_inputs=target_inputs,
        arm_correlations={
            "app-services": [],
            "functions": [],
            "aks": [],
            "arm-deployments": target_inputs["arm-deployments"],
        },
    )

    assert mapping is not None
    assert mapping["target_family"] == "app-services"
    assert mapping["exact_targets"] == []
    assert [item["name"] for item in mapping["target_candidates"]] == ["app-public-api"]
    assert mapping["confirmation_basis"] == "name-only-inference"


def test_best_automation_target_mapping_does_not_widen_from_non_active_published_runbooks() -> None:
    account = _load_automation_account("aa-hybrid-prod").model_dump(mode="json")
    account["primary_runbook_name"] = "func-orders"
    account["primary_start_mode"] = "webhook"
    account["webhook_runbook_names"] = ["func-orders"]
    account["published_runbook_names"] = ["func-orders", "app-empty-mi", "app-public-api"]
    target_inputs = _load_automation_target_inputs()

    mapping = _best_automation_mapping(
        account,
        target_inputs=target_inputs,
        arm_correlations={
            "app-services": [target_inputs["arm-deployments"][2]],
            "functions": [target_inputs["arm-deployments"][2]],
            "aks": [],
            "arm-deployments": target_inputs["arm-deployments"],
        },
    )

    assert mapping is not None
    assert mapping["target_family"] == "functions"
    assert [item["name"] for item in mapping["exact_targets"]] == ["func-orders"]
    assert mapping["confirmation_basis"] == "same-workload-corroborated"


def test_best_automation_target_mapping_falls_back_to_published_name_only_inference() -> None:
    account = _load_automation_account("aa-hybrid-prod").model_dump(mode="json")
    account["primary_runbook_name"] = "Nightly-Reconcile"
    account["primary_start_mode"] = "webhook"
    account["webhook_runbook_names"] = ["Nightly-Reconcile"]
    account["published_runbook_names"] = ["Nightly-Reconcile", "app-public-api"]
    account["trigger_join_ids"] = ["automation-webhook:nightly-reconcile"]
    target_inputs = _load_automation_target_inputs()

    mapping = _best_automation_mapping(
        account,
        target_inputs=target_inputs,
        arm_correlations={
            "app-services": [target_inputs["arm-deployments"][2]],
            "functions": [],
            "aks": [],
            "arm-deployments": target_inputs["arm-deployments"],
        },
    )

    assert mapping is not None
    assert mapping["exact_targets"] == []
    assert [item["name"] for item in mapping["target_candidates"]] == ["app-public-api"]
    assert mapping["confirmation_basis"] == "name-only-inference"


def test_best_automation_target_mapping_supports_raw_trigger_join_ids() -> None:
    account = _load_automation_account("aa-hybrid-prod").model_dump(mode="json")
    account["trigger_join_ids"] = [
        "/subscriptions/sub/resourceGroups/rg-ops/providers/Microsoft.Automation/"
        "automationAccounts/aa-hybrid-prod/webhooks/app-public-api"
    ]
    target_inputs = _load_automation_target_inputs()

    mapping = _best_automation_mapping(
        account,
        target_inputs=target_inputs,
        arm_correlations={
            "app-services": [target_inputs["arm-deployments"][2]],
            "functions": [],
            "aks": [],
            "arm-deployments": target_inputs["arm-deployments"],
        },
    )

    assert mapping is not None
    assert mapping["target_family"] == "app-services"
    assert [item["name"] for item in mapping["exact_targets"]] == ["app-public-api"]
    assert mapping["confirmation_basis"] == "same-workload-corroborated"


def test_best_automation_target_mapping_does_not_promote_duplicate_name_collisions() -> None:
    account = _load_automation_account("aa-hybrid-prod").model_dump(mode="json")
    account["primary_runbook_name"] = "shared-api"
    account["webhook_runbook_names"] = ["shared-api"]
    target_inputs = _load_automation_target_inputs()
    target_inputs["app-services"] = [
        {
            "id": (
                "/subscriptions/sub/resourceGroups/rg-apps/providers/"
                "Microsoft.Web/sites/shared-a"
            ),
            "name": "shared-api",
        },
        {
            "id": (
                "/subscriptions/sub/resourceGroups/rg-apps/providers/"
                "Microsoft.Web/sites/shared-b"
            ),
            "name": "shared-api",
        },
    ]

    mapping = _best_automation_mapping(
        account,
        target_inputs=target_inputs,
        arm_correlations={
            "app-services": [target_inputs["arm-deployments"][2]],
            "functions": [],
            "aks": [],
            "arm-deployments": target_inputs["arm-deployments"],
        },
    )

    assert mapping is not None
    assert mapping["target_family"] == "app-services"
    assert mapping["exact_targets"] == []
    assert [item["id"] for item in mapping["target_candidates"]] == [
        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/shared-a",
        "/subscriptions/sub/resourceGroups/rg-apps/providers/Microsoft.Web/sites/shared-b",
    ]
    assert mapping["confirmation_basis"] == "name-only-inference"


def test_structured_target_clue_ignores_non_azure_dotted_host_values() -> None:
    pipeline = DevopsPipelineAsset(
        id="devops/pipeline/release-appservice-prod",
        definition_id="88",
        name="release-appservice-prod",
        project_name="prod-platform",
        azure_service_connection_names=["prod-appsvc-wif"],
        target_clues=["App Service: release-1.2.3"],
        summary="Structured target dotted host guard.",
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
                "default_hostname": "app-public-api.azurewebsites.net",
            }
        ],
    )

    assert matches == []
    assert confirmation_basis is None


def test_structured_target_clue_ignores_appservice_scm_hosts() -> None:
    pipeline = DevopsPipelineAsset(
        id="devops/pipeline/release-appservice-prod",
        definition_id="88",
        name="release-appservice-prod",
        project_name="prod-platform",
        azure_service_connection_names=["prod-appsvc-wif"],
        target_clues=["App Service: https://app-public-api.scm.azurewebsites.net"],
        summary="Structured target scm host guard.",
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
                "default_hostname": "app-public-api.azurewebsites.net",
            }
        ],
    )

    assert matches == []
    assert confirmation_basis is None


def test_structured_target_clue_ignores_unstructured_prefixed_payloads() -> None:
    pipeline = DevopsPipelineAsset(
        id="devops/pipeline/release-appservice-prod",
        definition_id="88",
        name="release-appservice-prod",
        project_name="prod-platform",
        azure_service_connection_names=["prod-appsvc-wif"],
        target_clues=["App Service: release notes for blue deployment"],
        summary="Structured target prefixed payload guard.",
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
                "default_hostname": "app-public-api.azurewebsites.net",
            }
        ],
    )

    assert matches == []
    assert confirmation_basis is None


def test_structured_target_clue_ignores_wrong_family_resource_ids() -> None:
    pipeline = DevopsPipelineAsset(
        id="devops/pipeline/release-appservice-prod",
        definition_id="88",
        name="release-appservice-prod",
        project_name="prod-platform",
        azure_service_connection_names=["prod-appsvc-wif"],
        target_clues=[
            "App Service: "
            "/subscriptions/sub/resourceGroups/rg-workload/providers/"
            "Microsoft.ContainerService/managedClusters/aks-ops-01"
        ],
        summary="Structured target wrong-family resource id guard.",
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

    assert matches == []
    assert confirmation_basis is None


def test_deployment_joined_key_vaults_keeps_duplicate_named_vault_records() -> None:
    joined = _deployment_joined_key_vaults(
        {
            "key_vault_names": ["kv-prod-shared"],
        },
        {
            "kv-prod-shared": [
                {
                    "id": (
                        "/subscriptions/sub-a/resourceGroups/rg-a/providers/"
                        "Microsoft.KeyVault/vaults/kv-prod-shared"
                    ),
                    "name": "kv-prod-shared",
                },
                {
                    "id": (
                        "/subscriptions/sub-b/resourceGroups/rg-b/providers/"
                        "Microsoft.KeyVault/vaults/kv-prod-shared"
                    ),
                    "name": "kv-prod-shared",
                },
            ]
        },
    )

    assert [item["id"] for item in joined] == [
        "/subscriptions/sub-a/resourceGroups/rg-a/providers/Microsoft.KeyVault/vaults/kv-prod-shared",
        "/subscriptions/sub-b/resourceGroups/rg-b/providers/Microsoft.KeyVault/vaults/kv-prod-shared",
    ]


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


def _best_automation_mapping(
    account: dict,
    *,
    target_inputs: dict[str, list[dict]],
    arm_correlations: dict[str, list[dict]],
) -> dict[str, object] | None:
    return _best_automation_target_mapping(
        account,
        target_candidates=target_inputs,
        target_visibility_notes={
            "app-services": None,
            "functions": None,
            "aks": None,
            "arm-deployments": None,
        },
        target_visibility_issues={
            "app-services": None,
            "functions": None,
            "aks": None,
            "arm-deployments": None,
        },
        arm_correlations=arm_correlations,
    )


def _load_automation_target_inputs() -> dict[str, list[dict]]:
    fixtures_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"
    app_services = json.loads((fixtures_dir / "app_services.json").read_text(encoding="utf-8"))
    functions = json.loads((fixtures_dir / "functions.json").read_text(encoding="utf-8"))
    aks = json.loads((fixtures_dir / "aks.json").read_text(encoding="utf-8"))
    arm = json.loads((fixtures_dir / "arm_deployments.json").read_text(encoding="utf-8"))
    return {
        "app-services": app_services["app_services"],
        "functions": functions["function_apps"],
        "aks": aks["aks_clusters"],
        "arm-deployments": arm["deployments"],
    }


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
