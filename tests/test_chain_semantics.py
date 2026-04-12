from __future__ import annotations

from azurefox.chains.credential_path import _build_candidate_record
from azurefox.chains.deployment_path import DeploymentSourceAssessment
from azurefox.chains.runner import (
    _build_escalation_trust_record,
    _deployment_confidence_boundary,
    _deployment_current_operator_suffix,
    _deployment_devops_insertion_point,
    _deployment_next_review,
    _deployment_why_care,
    _devops_execution_identity_name,
    _devops_joined_permission,
    _devops_joined_role_trusts,
    _source_current_operator_can_inject,
)
from azurefox.chains.semantics import (
    ChainSemanticContext,
    evaluate_chain_semantics,
    semantic_priority_sort_value,
    semantic_urgency_sort_value,
)
from azurefox.models.common import RoleTrustSummary


def test_credential_path_semantics_promote_named_match() -> None:
    decision = evaluate_chain_semantics(
        ChainSemanticContext(
            family="credential-path",
            clue_type="keyvault-reference",
            target_service="keyvault",
            target_resolution="named match",
            target_count=1,
        )
    )

    assert decision.priority == "high"
    assert decision.urgency == "review-soon"
    assert "Check vault access path" in decision.next_review


def test_credential_path_semantics_distinguish_single_vs_broad_candidates() -> None:
    medium = evaluate_chain_semantics(
        ChainSemanticContext(
            family="credential-path",
            clue_type="plain-text-secret",
            target_service="database",
            target_resolution="narrowed candidates",
            target_count=1,
        )
    )
    low = evaluate_chain_semantics(
        ChainSemanticContext(
            family="credential-path",
            clue_type="plain-text-secret",
            target_service="storage",
            target_resolution="narrowed candidates",
            target_count=2,
        )
    )

    assert medium.priority == "medium"
    assert medium.urgency == "review-soon"
    assert low.priority == "low"
    assert low.urgency == "bookmark"


def test_chain_semantics_have_default_path_for_other_families() -> None:
    decision = evaluate_chain_semantics(
        ChainSemanticContext(
            family="deployment-path",
            clue_type="deployment-link",
            target_service="aks",
            target_resolution="named match",
            target_count=1,
        )
    )

    assert decision.priority == "high"
    assert decision.urgency == "review-soon"
    assert "deployment evidence" in decision.next_review


def test_compute_control_semantics_promote_direct_token_opportunity() -> None:
    decision = evaluate_chain_semantics(
        ChainSemanticContext(
            family="compute-control",
            clue_type="managed-identity-token",
            target_service="azure-control",
            target_resolution="path-confirmed",
            target_count=1,
            path_concept="direct-token-opportunity",
        )
    )

    assert decision.priority == "high"
    assert decision.urgency == "pivot-now"
    assert "compute foothold" in decision.next_review


def test_deployment_path_semantics_promote_narrowed_devops_targets() -> None:
    decision = evaluate_chain_semantics(
        ChainSemanticContext(
            family="deployment-path",
            clue_type="azure-service-connection",
            target_service="aks",
            target_resolution="narrowed candidates",
            target_count=2,
            path_concept="controllable-change-path",
        )
    )

    assert decision.priority == "medium"
    assert decision.urgency == "review-soon"
    assert "permissions or role-trusts" in decision.next_review


def test_deployment_path_named_devops_target_stays_below_high_without_poison_proof() -> None:
    decision = evaluate_chain_semantics(
        ChainSemanticContext(
            family="deployment-path",
            clue_type="controllable-change-path",
            target_service="app-service",
            target_resolution="named match",
            target_count=1,
            source_command="devops",
            path_concept="controllable-change-path",
            current_operator_can_drive=True,
            current_operator_can_inject=False,
        )
    )

    assert decision.priority == "medium"
    assert decision.urgency == "review-soon"
    assert "trusted input is writable" in decision.next_review


def test_deployment_path_artifact_visibility_stays_below_high_without_producer_control() -> None:
    decision = evaluate_chain_semantics(
        ChainSemanticContext(
            family="deployment-path",
            clue_type="controllable-change-path",
            target_service="app-service",
            target_resolution="named match",
            target_count=1,
            source_command="devops",
            path_concept="controllable-change-path",
            current_operator_can_drive=True,
            current_operator_can_inject=False,
        )
    )

    assert decision.priority == "medium"
    assert decision.urgency == "review-soon"
    assert "trusted input is writable" in decision.next_review


def test_deployment_path_artifact_producer_control_can_raise_devops_row() -> None:
    decision = evaluate_chain_semantics(
        ChainSemanticContext(
            family="deployment-path",
            clue_type="controllable-change-path",
            target_service="app-service",
            target_resolution="named match",
            target_count=1,
            source_command="devops",
            path_concept="controllable-change-path",
            current_operator_can_drive=True,
            current_operator_can_inject=True,
        )
    )

    assert decision.priority == "high"
    assert decision.urgency == "pivot-now"
    assert "poison a trusted input" in decision.next_review


def test_devops_edit_rights_count_as_definition_edit_injection() -> None:
    assert (
        _source_current_operator_can_inject(
            "devops",
            {
                "current_operator_can_queue": True,
                "current_operator_can_edit": True,
                "current_operator_can_contribute_source": False,
                "current_operator_injection_surface_types": ["definition-edit"],
            },
        )
        is True
    )


def test_deployment_path_secure_file_use_suffix_stays_use_scoped() -> None:
    assert (
        _deployment_current_operator_suffix(
            "devops",
            {
                "trusted_inputs": [
                    {
                        "input_type": "secure-file",
                        "ref": "secure-file:codesign-cert.pfx",
                        "current_operator_access_state": "use",
                    }
                ],
                "primary_trusted_input_ref": "secure-file:codesign-cert.pfx",
                "current_operator_injection_surface_types": [],
                "current_operator_can_queue": False,
                "current_operator_can_edit": False,
            },
        )
        == (
            "Current credentials can use that secure file in pipeline context, but "
            "Azure DevOps evidence here does not prove secure-file administration."
        )
    )


def test_deployment_path_secure_file_use_insertion_point_stays_use_scoped() -> None:
    assert (
        _deployment_devops_insertion_point(
            {
                "trusted_inputs": [
                    {
                        "input_type": "secure-file",
                        "ref": "secure-file:codesign-cert.pfx",
                        "current_operator_access_state": "use",
                    }
                ],
                "primary_trusted_input_ref": "secure-file:codesign-cert.pfx",
                "current_operator_injection_surface_types": [],
                "current_operator_can_queue": False,
                "current_operator_can_edit": False,
            }
        )
        == (
            "Current scope shows secure file codesign-cert.pfx as usable in pipeline context, "
            "but not administrable."
        )
    )


def test_deployment_path_artifact_read_insertion_point_stays_producer_scoped() -> None:
    assert (
        _deployment_devops_insertion_point(
            {
                "trusted_inputs": [
                    {
                        "input_type": "pipeline-artifact",
                        "ref": "pipeline-artifact:prod-platform/shared-build#signed-drop",
                        "current_operator_access_state": "read",
                    }
                ],
                "primary_trusted_input_ref": (
                    "pipeline-artifact:prod-platform/shared-build#signed-drop"
                ),
                "current_operator_injection_surface_types": [],
                "current_operator_can_queue": False,
                "current_operator_can_edit": False,
            }
        )
        == (
            "Current scope shows the upstream producer behind pipeline artifact "
            "prod-platform/shared-build#signed-drop as readable, not writable."
        )
    )


def test_deployment_path_definition_edit_boundary_stays_definition_scoped() -> None:
    source = {
        "current_operator_can_edit": True,
        "current_operator_injection_surface_types": ["definition-edit"],
        "joined_permission": {"display_name": "build-sp"},
    }

    assert (
        _deployment_confidence_boundary(
            source_command="devops",
            source=source,
            target_label="App Service",
            target_resolution="named match",
            confirmation_basis="parsed-config-target",
            current_operator_can_drive=True,
            current_operator_can_inject=True,
            missing_target_mapping=False,
        )
        == (
            "Current evidence shows you can edit this pipeline definition so it runs as Azure "
            "identity 'build-sp' against the exact App Service target, but not a separate "
            "direct sign-in as Azure identity 'build-sp'."
        )
    )


def test_deployment_path_definition_edit_next_review_stays_definition_scoped() -> None:
    assert (
        _deployment_next_review(
            source_command="devops",
            source={
                "current_operator_can_edit": True,
                "current_operator_injection_surface_types": ["definition-edit"],
            },
            path_concept="controllable-change-path",
            target_family="app-services",
            target_resolution="named match",
            target_names=["app-public-api"],
            target_label="App Service",
            supporting_deployments=[],
        )
        == (
            "Current credentials can already edit this pipeline definition directly; AzureFox "
            "already named the exact App Service target app-public-api."
        )
    )


def test_secret_support_rows_stay_lower_priority() -> None:
    decision = evaluate_chain_semantics(
        ChainSemanticContext(
            family="deployment-path",
            clue_type="secret-escalation-support",
            target_service="arm-deployment",
            target_resolution="visibility blocked",
            target_count=0,
            path_concept="secret-escalation-support",
        )
    )

    assert decision.priority == "low"
    assert decision.urgency == "bookmark"
    assert "secret-backed support boundary" in decision.next_review


def test_escalation_path_semantics_promote_current_foothold_direct_control() -> None:
    decision = evaluate_chain_semantics(
        ChainSemanticContext(
            family="escalation-path",
            clue_type="direct-role-abuse",
            target_service="azure-control",
            target_resolution="path-confirmed",
            target_count=1,
            source_command="privesc",
            path_concept="current-foothold-direct-control",
        )
    )

    assert decision.priority == "high"
    assert decision.urgency == "pivot-now"
    assert "current foothold" in decision.next_review


def test_escalation_path_semantics_keep_trust_expansion_below_direct_control() -> None:
    confirmed = evaluate_chain_semantics(
        ChainSemanticContext(
            family="escalation-path",
            clue_type="service-principal-owner",
            target_service="identity-trust",
            target_resolution="path-confirmed",
            target_count=1,
            source_command="role-trusts",
            path_concept="trust-expansion",
        )
    )
    visible_only = evaluate_chain_semantics(
        ChainSemanticContext(
            family="escalation-path",
            clue_type="service-principal-owner",
            target_service="identity-trust",
            target_resolution="target-confirmed",
            target_count=1,
            source_command="role-trusts",
            path_concept="trust-expansion",
        )
    )

    assert confirmed.priority == "medium"
    assert confirmed.urgency == "review-soon"
    assert "stronger target" in confirmed.next_review
    assert visible_only.priority == "low"
    assert visible_only.urgency == "bookmark"
    assert "meaningful Azure control" in visible_only.next_review


def test_escalation_path_trust_rows_require_explicit_transform_and_target_control() -> None:
    privesc_row = {
        "starting_foothold": "automation-runner (current foothold)",
        "principal": "automation-runner",
        "principal_type": "ServicePrincipal",
    }
    relationship_only = RoleTrustSummary(
        trust_type="service-principal-owner",
        source_object_id="sp-1",
        source_name="automation-runner",
        source_type="ServicePrincipal",
        target_object_id="sp-2",
        target_name="build-sp",
        target_type="ServicePrincipal",
        evidence_type="graph-owner",
        confidence="confirmed",
        control_primitive="owner-control",
        controlled_object_type="ServicePrincipal",
        controlled_object_name="build-sp",
        escalation_mechanism=(
            "Owner-level control over service principal 'build-sp' is visible, but the exact "
            "authentication-control transform is not yet explicit."
        ),
        usable_identity_result=None,
        defender_cut_point="Remove the owner-level control path over service principal 'build-sp'.",
        summary="test",
    )

    record = _build_escalation_trust_record(
        "escalation-path",
        privesc_row,
        [relationship_only],
        {
            "sp-2": {
                "principal_id": "sp-2",
                "high_impact_roles": ["Owner"],
                "scope_ids": ["/subscriptions/sub"],
                "scope_count": 1,
            }
        },
        current_foothold_id="sp-1",
    )

    assert record is None


def test_escalation_path_trust_rows_use_hidden_role_trust_transform_fields() -> None:
    privesc_row = {
        "starting_foothold": "ci-admin@lab.local (current foothold)",
        "principal": "ci-admin@lab.local",
        "principal_type": "User",
    }
    transform_ready = RoleTrustSummary(
        trust_type="app-owner",
        source_object_id="user-1",
        source_name="ci-admin@lab.local",
        source_type="User",
        target_object_id="app-1",
        target_name="build-app",
        target_type="Application",
        evidence_type="graph-owner",
        confidence="confirmed",
        control_primitive="change-auth-material",
        controlled_object_type="Application",
        controlled_object_name="build-app",
        escalation_mechanism=(
            "Control of application 'build-app' could change authentication material that makes "
            "service principal 'build-sp' usable."
        ),
        usable_identity_result=(
            "Control of application 'build-app' could make service principal 'build-sp' usable."
        ),
        defender_cut_point=(
            "Remove the ownership path that lets the source control application 'build-app'."
        ),
        next_review=(
            "Check role-trusts for the ownership path and backing application object, then "
            "confirm build-sp in permissions."
        ),
        summary="test",
    )

    record = _build_escalation_trust_record(
        "escalation-path",
        privesc_row,
        [transform_ready],
        {
            "app-1": {
                "principal_id": "app-1",
                "high_impact_roles": ["Owner"],
                "scope_ids": ["/subscriptions/sub"],
                "scope_count": 1,
            }
        },
        current_foothold_id="user-1",
    )

    assert record is not None
    assert record.insertion_point == transform_ready.escalation_mechanism
    assert "could make service principal 'build-sp' usable" in record.confidence_boundary
    assert "Remove the ownership path" in (record.why_care or "")
    assert record.target_resolution == "path-confirmed"


def test_devops_joined_permission_ignores_service_connection_id_matches() -> None:
    joined = _devops_joined_permission(
        {
            "azure_service_connection_ids": ["endpoint-1"],
            "azure_service_connection_principal_ids": ["sp-1"],
            "azure_service_connection_client_ids": ["app-1"],
            "identity_join_ids": ["endpoint-1", "sp-1", "app-1"],
        },
        {
            "endpoint-1": {"display_name": "wrong-endpoint"},
            "sp-1": {"display_name": "build-sp"},
        },
    )

    assert joined == {"display_name": "build-sp"}


def test_devops_joined_role_trusts_prefers_internal_app_to_sp_link_first() -> None:
    trusts = _devops_joined_role_trusts(
        {
            "azure_service_connection_principal_ids": ["sp-1"],
            "azure_service_connection_client_ids": ["app-1"],
        },
        {
            "sp-1": [
                {
                    "trust_type": "service-principal-owner",
                    "source_object_id": "runner-sp",
                    "source_name": "automation-runner",
                    "target_object_id": "sp-1",
                    "target_name": "build-sp",
                },
                {
                    "trust_type": "federated-credential",
                    "source_object_id": "app-1",
                    "source_name": "build-app",
                    "target_object_id": "sp-1",
                    "target_name": "build-sp",
                },
            ],
            "app-1": [
                {
                    "trust_type": "app-owner",
                    "source_object_id": "user-1",
                    "source_name": "ci-admin@lab.local",
                    "target_object_id": "app-1",
                    "target_name": "build-app",
                },
                {
                    "trust_type": "federated-credential",
                    "source_object_id": "app-1",
                    "source_name": "build-app",
                    "target_object_id": "sp-1",
                    "target_name": "build-sp",
                },
            ],
        },
    )

    assert trusts[0]["trust_type"] == "federated-credential"
    assert _devops_execution_identity_name(
        {
            "azure_service_connection_principal_ids": ["sp-1"],
            "azure_service_connection_client_ids": ["app-1"],
            "joined_role_trusts": trusts,
        }
    ) == "build-sp"


def test_deployment_why_care_definition_edit_does_not_claim_trusted_input_poisoning() -> None:
    text = _deployment_why_care(
        "devops",
        {
            "trusted_inputs": [
                {
                    "input_type": "repository",
                    "ref": "repository:azure-repos:customer-portal@refs/heads/main",
                }
            ],
            "primary_trusted_input_ref": "repository:azure-repos:customer-portal@refs/heads/main",
            "current_operator_can_edit": True,
            "current_operator_injection_surface_types": ["definition-edit"],
            "joined_permission": {"display_name": "build-sp", "privileged": False},
        },
        assessment=DeploymentSourceAssessment(
            source_command="devops",
            source_name="deploy-appservice-prod",
            posture="can already change Azure here",
            path_concept="controllable-change-path",
        ),
    )

    assert "edit this pipeline definition directly" in text
    assert "poison that source" not in text


def test_semantic_priority_sort_value_orders_highest_first() -> None:
    assert semantic_priority_sort_value("high") < semantic_priority_sort_value("medium")
    assert semantic_priority_sort_value("medium") < semantic_priority_sort_value("low")


def test_semantic_urgency_sort_value_orders_fastest_follow_up_first() -> None:
    assert semantic_urgency_sort_value("pivot-now") < semantic_urgency_sort_value("review-soon")
    assert semantic_urgency_sort_value("review-soon") < semantic_urgency_sort_value("bookmark")


def test_blocked_candidate_record_does_not_leak_candidate_names_into_summary() -> None:
    record = _build_candidate_record(
        "credential-path",
        {
            "asset_id": (
                "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Web/sites/app-public-api"
            ),
            "asset_name": "app-public-api",
            "asset_kind": "AppService",
            "location": "eastus",
            "setting_name": "DB_PASSWORD",
            "related_ids": [],
        },
        [],
        "database",
        [
            {
                "id": (
                    "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Sql/servers/"
                    "sql-public-legacy"
                ),
                "name": "sql-public-legacy",
                "location": "eastus",
            }
        ],
        visibility_note=(
            "Current credentials may not show full database visibility, so this target picture "
            "may be incomplete."
        ),
        visibility_issue=(
            "permission_denied: databases.servers: current credentials do not show database "
            "visibility for at least one visible server"
        ),
    )

    assert record.target_resolution == "visibility blocked"
    assert record.target_names == []
    assert record.target_ids == []
    assert "sql-public-legacy" not in record.summary
    assert "cannot tell which database it reaches" in record.summary
