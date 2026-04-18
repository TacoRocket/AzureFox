from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from azurefox.chains.credential_path import _build_candidate_record
from azurefox.chains.deployment_path import DeploymentSourceAssessment
from azurefox.chains.runner import (
    _build_escalation_path_output,
    _deployment_confidence_boundary,
    _deployment_current_operator_suffix,
    _deployment_devops_insertion_point,
    _deployment_next_review,
    _deployment_why_care,
    _devops_execution_identity_name,
    _devops_joined_permission,
    _devops_joined_role_trusts,
    _select_escalation_trust_record,
    _source_current_operator_can_inject,
)
from azurefox.chains.semantics import (
    ChainSemanticContext,
    evaluate_chain_semantics,
    semantic_priority_sort_value,
    semantic_urgency_sort_value,
)
from azurefox.config import GlobalOptions
from azurefox.models.commands import PermissionsOutput, RoleTrustsOutput
from azurefox.models.common import CommandMetadata, OutputMode, PermissionSummary, RoleTrustSummary


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


def test_credential_path_semantics_handle_secret_clue_without_service_bucket() -> None:
    decision = evaluate_chain_semantics(
        ChainSemanticContext(
            family="credential-path",
            clue_type="plain-text-secret",
            target_service="downstream service",
            target_resolution="service hint only",
            target_count=0,
        )
    )

    assert decision.priority == "low"
    assert decision.urgency == "bookmark"
    assert "does not identify the downstream service" in decision.next_review


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


def test_escalation_direct_control_uses_single_rg_scope_text() -> None:
    options = GlobalOptions(
        tenant=None,
        subscription="sub-test",
        output=OutputMode.JSON,
        outdir=Path("/tmp/azurefox-escalation-scope-text"),
        debug=False,
    )
    output = _build_escalation_path_output(
        options,
        "escalation-path",
        {
            "permissions": PermissionsOutput(
                metadata=CommandMetadata(command="permissions", subscription_id="sub-test"),
                permissions=[
                    PermissionSummary(
                        principal_id="current-sp",
                        display_name="current-sp",
                        principal_type="ServicePrincipal",
                        priority="high",
                        high_impact_roles=["Contributor"],
                        all_role_names=["Contributor"],
                        role_assignment_count=1,
                        scope_count=1,
                        scope_ids=["/subscriptions/sub-test/resourceGroups/rg-workload"],
                        privileged=True,
                        is_current_identity=True,
                    )
                ],
            ),
            "role-trusts": RoleTrustsOutput(
                metadata=CommandMetadata(command="role-trusts", subscription_id="sub-test"),
                trusts=[],
                issues=[],
            ),
        },
    )

    direct_row = next(
        row for row in output.paths if row.path_concept == "current-foothold-direct-control"
    )

    assert direct_row.stronger_outcome == "Contributor on resource group 'rg-workload'"
    assert "Contributor on resource group 'rg-workload'" in (direct_row.why_care or "")


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
            source_command="permissions",
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


def test_escalation_path_semantics_rank_app_permission_reach_as_follow_on() -> None:
    confirmed = evaluate_chain_semantics(
        ChainSemanticContext(
            family="escalation-path",
            clue_type="app-to-service-principal",
            target_service="identity-trust",
            target_resolution="path-confirmed",
            target_count=1,
            source_command="role-trusts",
            path_concept="app-permission-reach",
        )
    )
    visible_only = evaluate_chain_semantics(
        ChainSemanticContext(
            family="escalation-path",
            clue_type="app-to-service-principal",
            target_service="identity-trust",
            target_resolution="target-confirmed",
            target_count=1,
            source_command="role-trusts",
            path_concept="app-permission-reach",
        )
    )

    assert confirmed.priority == "medium"
    assert confirmed.urgency == "review-soon"
    assert "application-permission grant" in confirmed.next_review
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
            "Owner-level control over service principal 'build-sp' could add or replace "
            "authentication material Azure accepts for service principal 'build-sp'."
        ),
        usable_identity_result=None,
        defender_cut_point="Remove the owner-level control path over service principal 'build-sp'.",
        summary="test",
    )

    record = _select_escalation_trust_record(
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
        current_foothold_permission=None,
    )

    assert record is None


def test_escalation_path_ignores_visible_privileged_principal_that_is_not_current() -> None:
    options = GlobalOptions(
        tenant="tenant-id",
        subscription="sub-id",
        output=OutputMode.TABLE,
        outdir=Path("/tmp/azurefox-escalation-path-negative"),
        debug=False,
    )

    loaded = {
        "permissions": SimpleNamespace(
            permissions=[
                PermissionSummary(
                    principal_id="user-1",
                    display_name="operator@lab.local",
                    principal_type="User",
                    priority="low",
                    high_impact_roles=[],
                    all_role_names=["Reader"],
                    scope_count=1,
                    scope_ids=["/subscriptions/sub-id"],
                    privileged=False,
                    is_current_identity=True,
                ),
                PermissionSummary(
                    principal_id="sp-1",
                    display_name="nearby-owner-sp",
                    principal_type="ServicePrincipal",
                    priority="medium",
                    high_impact_roles=["Owner"],
                    all_role_names=["Owner"],
                    scope_count=1,
                    scope_ids=["/subscriptions/other-sub"],
                    privileged=True,
                    is_current_identity=False,
                ),
            ],
            issues=[],
        ),
        "role-trusts": SimpleNamespace(trusts=[], issues=[]),
    }

    output = _build_escalation_path_output(options, "escalation-path", loaded)

    assert output.backing_commands == ["permissions", "role-trusts"]
    assert output.paths == []


def test_escalation_path_keeps_multiple_current_footholds_instead_of_picking_one() -> None:
    options = GlobalOptions(
        tenant="tenant-id",
        subscription="sub-id",
        output=OutputMode.TABLE,
        outdir=Path("/tmp/azurefox-escalation-path-multi-current"),
        debug=False,
    )

    loaded = {
        "permissions": SimpleNamespace(
            permissions=[
                PermissionSummary(
                    principal_id="sp-1",
                    display_name="current-owner-a",
                    principal_type="ServicePrincipal",
                    priority="high",
                    high_impact_roles=["Owner"],
                    all_role_names=["Owner"],
                    scope_count=1,
                    scope_ids=["/subscriptions/sub-a"],
                    privileged=True,
                    is_current_identity=True,
                ),
                PermissionSummary(
                    principal_id="sp-2",
                    display_name="current-owner-b",
                    principal_type="ServicePrincipal",
                    priority="high",
                    high_impact_roles=["Contributor"],
                    all_role_names=["Contributor"],
                    scope_count=1,
                    scope_ids=["/subscriptions/sub-b/resourceGroups/rg-apps"],
                    privileged=True,
                    is_current_identity=True,
                ),
            ],
            issues=[],
        ),
        "role-trusts": SimpleNamespace(trusts=[], issues=[]),
    }

    output = _build_escalation_path_output(options, "escalation-path", loaded)

    direct_rows = [
        row for row in output.paths if row.path_concept == "current-foothold-direct-control"
    ]
    assert [row.asset_name for row in direct_rows] == [
        "current-owner-a (current foothold)",
        "current-owner-b (current foothold)",
    ]
def test_escalation_path_service_principal_takeover_rows_use_explicit_transform_fields() -> None:
    privesc_row = {
        "starting_foothold": "azurefox-lab-sp (current foothold)",
        "principal": "azurefox-lab-sp",
        "principal_type": "ServicePrincipal",
    }
    transform_ready = RoleTrustSummary(
        trust_type="service-principal-owner",
        source_object_id="sp-current",
        source_name="azurefox-lab-sp",
        source_type="ServicePrincipal",
        target_object_id="sp-1",
        target_name="build-sp",
        target_type="ServicePrincipal",
        evidence_type="graph-owner",
        confidence="confirmed",
        control_primitive="owner-control",
        controlled_object_type="ServicePrincipal",
        controlled_object_name="build-sp",
        escalation_mechanism=(
            "Owner-level control over service principal 'build-sp' could add or replace "
            "authentication material Azure accepts for service principal 'build-sp'."
        ),
        usable_identity_result="That could make service principal 'build-sp' usable.",
        defender_cut_point="Remove the owner-level control path over service principal 'build-sp'.",
        next_review="Check permissions for Azure control on service principal 'build-sp'.",
        summary="test",
    )

    record = _select_escalation_trust_record(
        "escalation-path",
        privesc_row,
        [transform_ready],
        {
            "sp-1": {
                "principal_id": "sp-1",
                "high_impact_roles": ["Owner"],
                "scope_ids": [
                    "/subscriptions/other/resourceGroups/rg-build",
                    "/subscriptions/other/resourceGroups/rg-shared",
                ],
                "scope_count": 2,
            }
        },
        current_foothold_id="sp-current",
        current_foothold_permission={
            "principal_id": "sp-current",
            "high_impact_roles": ["Owner"],
            "scope_ids": ["/subscriptions/sub/resourceGroups/rg-apps"],
            "scope_count": 1,
        },
    )

    assert record is not None
    assert record.clue_type == "service-principal-owner"
    assert record.visible_path == (
        "Current foothold -> service principal takeover -> higher-value identity"
    )
    assert "could make service principal 'build-sp' usable" in record.confidence_boundary
    assert "can take over service principal 'build-sp'" in (record.why_care or "")
    assert "Owner-level Azure control, including role assignment" in (record.why_care or "")
    assert "resource groups 'rg-build' and 'rg-shared'" in (record.why_care or "")
    assert "Remove the owner-level control path" in (record.why_care or "")


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
        backing_service_principal_id="sp-1",
        backing_service_principal_name="build-sp",
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

    record = _select_escalation_trust_record(
        "escalation-path",
        privesc_row,
        [transform_ready],
        {
            "sp-1": {
                "principal_id": "sp-1",
                "high_impact_roles": ["Owner"],
                "scope_ids": [
                    "/subscriptions/sub/resourceGroups/rg-build",
                    "/subscriptions/sub/resourceGroups/rg-shared",
                ],
                "scope_count": 2,
            }
        },
        current_foothold_id="user-1",
        current_foothold_permission={
            "principal_id": "user-1",
            "high_impact_roles": ["Contributor"],
            "scope_ids": ["/subscriptions/sub/resourceGroups/rg-apps"],
            "scope_count": 1,
        },
    )

    assert record is not None
    assert record.insertion_point == transform_ready.escalation_mechanism
    assert record.target_ids == ["sp-1"]
    assert record.target_names == ["build-sp"]
    assert "could make service principal 'build-sp' usable" in record.confidence_boundary
    assert "backs service principal 'build-sp'" in (record.why_care or "")
    assert "Owner-level Azure control, including role assignment" in (record.why_care or "")
    assert "resource groups 'rg-build' and 'rg-shared'" in (record.why_care or "")
    assert "Remove the ownership path" in (record.why_care or "")
    assert record.target_resolution == "path-confirmed"


def test_escalation_path_prefers_visible_federated_takeover_when_app_control_exists() -> None:
    privesc_row = {
        "starting_foothold": "ci-admin@lab.local (current foothold)",
        "principal": "ci-admin@lab.local",
        "principal_type": "User",
    }
    app_owner = RoleTrustSummary(
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
        backing_service_principal_id="sp-1",
        backing_service_principal_name="build-sp",
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
        next_review="app-owner review",
        summary="test",
    )
    federated = RoleTrustSummary(
        trust_type="federated-credential",
        source_object_id="app-1",
        source_name="build-app",
        source_type="Application",
        target_object_id="sp-1",
        target_name="build-sp",
        target_type="ServicePrincipal",
        evidence_type="graph-federated-credential",
        confidence="confirmed",
        control_primitive="existing-federated-credential",
        controlled_object_type="Application",
        controlled_object_name="build-app",
        escalation_mechanism=(
            "Application 'build-app' already has federated trust that can yield service principal "
            "'build-sp' access."
        ),
        usable_identity_result="Federated sign-in can yield service principal 'build-sp' access.",
        next_review="Check permissions for Azure control on service principal 'build-sp'.",
        summary="test",
        related_ids=["app-1", "fic-1", "sp-1"],
    )

    record = _select_escalation_trust_record(
        "escalation-path",
        privesc_row,
        [app_owner, federated],
        {
            "sp-1": {
                "principal_id": "sp-1",
                "high_impact_roles": ["Owner"],
                "scope_ids": [
                    "/subscriptions/sub/resourceGroups/rg-build",
                    "/subscriptions/sub/resourceGroups/rg-shared",
                ],
                "scope_count": 2,
            }
        },
        current_foothold_id="user-1",
        current_foothold_permission={
            "principal_id": "user-1",
            "high_impact_roles": ["Contributor"],
            "scope_ids": ["/subscriptions/sub/resourceGroups/rg-apps"],
            "scope_count": 1,
        },
    )

    assert record is not None
    assert record.clue_type == "federated-credential"
    assert record.insertion_point == (
        "Application 'build-app' already has federated trust that can yield service principal "
        "'build-sp' access."
    )
    assert (
        "already has federated trust into service principal 'build-sp'"
        in (record.why_care or "")
    )
    assert "Owner-level Azure control, including role assignment" in (record.why_care or "")
    assert "visible federated subject" in (record.why_care or "")
    assert (
        record.next_review
        == "Check permissions for Azure control on service principal 'build-sp'."
    )


def test_escalation_path_prefers_easier_federated_path_when_control_gain_matches() -> None:
    privesc_row = {
        "starting_foothold": "azurefox-lab-sp (current foothold)",
        "principal": "azurefox-lab-sp",
        "principal_type": "ServicePrincipal",
    }
    app_owner = RoleTrustSummary(
        trust_type="app-owner",
        source_object_id="sp-current",
        source_name="azurefox-lab-sp",
        source_type="ServicePrincipal",
        target_object_id="app-1",
        target_name="build-app",
        target_type="Application",
        evidence_type="graph-owner",
        confidence="confirmed",
        control_primitive="change-auth-material",
        controlled_object_type="Application",
        controlled_object_name="build-app",
        backing_service_principal_id="sp-1",
        backing_service_principal_name="build-sp",
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
        next_review="app-owner review",
        summary="test",
    )
    direct_service_owner = RoleTrustSummary(
        trust_type="service-principal-owner",
        source_object_id="sp-current",
        source_name="azurefox-lab-sp",
        source_type="ServicePrincipal",
        target_object_id="sp-1",
        target_name="build-sp",
        target_type="ServicePrincipal",
        evidence_type="graph-owner",
        confidence="confirmed",
        control_primitive="owner-control",
        controlled_object_type="ServicePrincipal",
        controlled_object_name="build-sp",
        escalation_mechanism=(
            "Owner-level control over service principal 'build-sp' could add or replace "
            "authentication material Azure accepts for service principal 'build-sp'."
        ),
        usable_identity_result="That could make service principal 'build-sp' usable.",
        next_review="Check permissions for Azure control on service principal 'build-sp'.",
        summary="test",
        related_ids=["sp-current", "sp-1"],
    )
    federated = RoleTrustSummary(
        trust_type="federated-credential",
        source_object_id="app-1",
        source_name="build-app",
        source_type="Application",
        target_object_id="sp-1",
        target_name="build-sp",
        target_type="ServicePrincipal",
        evidence_type="graph-federated-credential",
        confidence="confirmed",
        control_primitive="existing-federated-credential",
        controlled_object_type="Application",
        controlled_object_name="build-app",
        escalation_mechanism=(
            "Application 'build-app' already has federated trust that can yield service principal "
            "'build-sp' access."
        ),
        usable_identity_result="Federated sign-in can yield service principal 'build-sp' access.",
        next_review="Check permissions for Azure control on service principal 'build-sp'.",
        summary="test",
        related_ids=["app-1", "fic-1", "sp-1"],
    )

    record = _select_escalation_trust_record(
        "escalation-path",
        privesc_row,
        [app_owner, direct_service_owner, federated],
        {
            "sp-1": {
                "principal_id": "sp-1",
                "high_impact_roles": ["Owner"],
                "scope_ids": [
                    "/subscriptions/other/resourceGroups/rg-build",
                    "/subscriptions/other/resourceGroups/rg-shared",
                ],
                "scope_count": 2,
            }
        },
        current_foothold_id="sp-current",
        current_foothold_permission={
            "principal_id": "sp-current",
            "high_impact_roles": ["Owner"],
            "scope_ids": ["/subscriptions/sub/resourceGroups/rg-apps"],
            "scope_count": 1,
        },
    )

    assert record is not None
    assert record.clue_type == "federated-credential"
    assert "already has federated trust into service principal 'build-sp'" in (
        record.why_care or ""
    )
    assert "visible federated subject" in (record.why_care or "")


def test_escalation_path_prefers_higher_value_federated_path_over_lower_value_direct_takeover(
) -> None:
    privesc_row = {
        "starting_foothold": "azurefox-lab-sp (current foothold)",
        "principal": "azurefox-lab-sp",
        "principal_type": "ServicePrincipal",
    }
    app_owner = RoleTrustSummary(
        trust_type="app-owner",
        source_object_id="sp-current",
        source_name="azurefox-lab-sp",
        source_type="ServicePrincipal",
        target_object_id="app-1",
        target_name="build-app",
        target_type="Application",
        evidence_type="graph-owner",
        confidence="confirmed",
        control_primitive="change-auth-material",
        controlled_object_type="Application",
        controlled_object_name="build-app",
        backing_service_principal_id="sp-owner",
        backing_service_principal_name="owner-sp",
        escalation_mechanism=(
            "Control of application 'build-app' could change authentication material that makes "
            "service principal 'owner-sp' usable."
        ),
        usable_identity_result=(
            "Control of application 'build-app' could make service principal 'owner-sp' usable."
        ),
        next_review="Check permissions for Azure control on service principal 'owner-sp'.",
        summary="test",
    )
    federated = RoleTrustSummary(
        trust_type="federated-credential",
        source_object_id="app-1",
        source_name="build-app",
        source_type="Application",
        target_object_id="sp-owner",
        target_name="owner-sp",
        target_type="ServicePrincipal",
        evidence_type="graph-federated-credential",
        confidence="confirmed",
        control_primitive="existing-federated-credential",
        controlled_object_type="Application",
        controlled_object_name="build-app",
        escalation_mechanism=(
            "Application 'build-app' already has federated trust that can yield service principal "
            "'owner-sp' access."
        ),
        usable_identity_result="Federated sign-in can yield service principal 'owner-sp' access.",
        next_review="Check permissions for Azure control on service principal 'owner-sp'.",
        summary="test",
    )
    lower_value_service_owner = RoleTrustSummary(
        trust_type="service-principal-owner",
        source_object_id="sp-current",
        source_name="azurefox-lab-sp",
        source_type="ServicePrincipal",
        target_object_id="sp-low",
        target_name="low-sp",
        target_type="ServicePrincipal",
        evidence_type="graph-owner",
        confidence="confirmed",
        control_primitive="owner-control",
        controlled_object_type="ServicePrincipal",
        controlled_object_name="low-sp",
        escalation_mechanism=(
            "Owner-level control over service principal 'low-sp' could add or replace "
            "authentication material Azure accepts for service principal 'low-sp'."
        ),
        usable_identity_result="That could make service principal 'low-sp' usable.",
        next_review="Check permissions for Azure control on service principal 'low-sp'.",
        summary="test",
    )

    record = _select_escalation_trust_record(
        "escalation-path",
        privesc_row,
        [app_owner, federated, lower_value_service_owner],
        {
            "sp-owner": {
                "principal_id": "sp-owner",
                "high_impact_roles": ["Owner"],
                "scope_ids": [
                    "/subscriptions/other/resourceGroups/rg-owner-a",
                    "/subscriptions/other/resourceGroups/rg-owner-b",
                ],
                "scope_count": 2,
            },
            "sp-low": {
                "principal_id": "sp-low",
                "high_impact_roles": ["Contributor"],
                "scope_ids": ["/subscriptions/other/resourceGroups/rg-low"],
                "scope_count": 1,
            },
        },
        current_foothold_id="sp-current",
        current_foothold_permission={
            "principal_id": "sp-current",
            "high_impact_roles": ["Contributor"],
            "scope_ids": ["/subscriptions/sub/resourceGroups/rg-apps"],
            "scope_count": 1,
        },
    )

    assert record is not None
    assert record.clue_type == "federated-credential"
    assert record.target_names == ["owner-sp"]


def test_escalation_path_trust_row_suppresses_when_no_net_gain() -> None:
    privesc_row = {
        "starting_foothold": "azurefox-lab-sp (current foothold)",
        "principal": "azurefox-lab-sp",
        "principal_type": "ServicePrincipal",
    }
    transform_ready = RoleTrustSummary(
        trust_type="app-owner",
        source_object_id="sp-current",
        source_name="azurefox-lab-sp",
        source_type="ServicePrincipal",
        target_object_id="app-1",
        target_name="build-app",
        target_type="Application",
        evidence_type="graph-owner",
        confidence="confirmed",
        control_primitive="change-auth-material",
        controlled_object_type="Application",
        controlled_object_name="build-app",
        backing_service_principal_id="sp-1",
        backing_service_principal_name="build-sp",
        escalation_mechanism=(
            "Control of application 'build-app' could change authentication material that makes "
            "service principal 'build-sp' usable."
        ),
        usable_identity_result=(
            "Control of application 'build-app' could make service principal 'build-sp' usable."
        ),
        summary="test",
    )

    record = _select_escalation_trust_record(
        "escalation-path",
        privesc_row,
        [transform_ready],
        {
            "sp-1": {
                "principal_id": "sp-1",
                "high_impact_roles": ["Owner"],
                "scope_ids": [
                    "/subscriptions/sub/resourceGroups/rg-build",
                    "/subscriptions/sub/resourceGroups/rg-shared",
                ],
                "scope_count": 2,
            }
        },
        current_foothold_id="sp-current",
        current_foothold_permission={
            "principal_id": "sp-current",
            "high_impact_roles": ["Owner"],
            "scope_ids": ["/subscriptions/sub"],
            "scope_count": 1,
        },
    )

    assert record is None


def test_escalation_path_output_keeps_app_permission_reach_beside_best_trust_expansion() -> None:
    options = GlobalOptions(
        tenant=None,
        subscription=None,
        output=OutputMode.JSON,
        outdir=Path("/tmp/azurefox-escalation-app-permission"),
        debug=False,
    )

    loaded = {
        "permissions": SimpleNamespace(
            permissions=[
                PermissionSummary(
                    principal_id="sp-current",
                    display_name="azurefox-lab-sp",
                    principal_type="ServicePrincipal",
                    priority="medium",
                    high_impact_roles=["Contributor"],
                    all_role_names=["Contributor"],
                    role_assignment_count=1,
                    scope_count=1,
                    scope_ids=["/subscriptions/sub"],
                    privileged=True,
                    is_current_identity=True,
                ),
                PermissionSummary(
                    principal_id="sp-build",
                    display_name="build-sp",
                    principal_type="ServicePrincipal",
                    priority="high",
                    high_impact_roles=["Owner"],
                    all_role_names=["Owner"],
                    role_assignment_count=2,
                    scope_count=2,
                    scope_ids=[
                        "/subscriptions/other/resourceGroups/rg-build",
                        "/subscriptions/other/resourceGroups/rg-shared",
                    ],
                    privileged=True,
                    is_current_identity=False,
                ),
            ],
            issues=[],
        ),
        "role-trusts": SimpleNamespace(
            trusts=[
                RoleTrustSummary(
                    trust_type="service-principal-owner",
                    source_object_id="sp-current",
                    source_name="azurefox-lab-sp",
                    source_type="ServicePrincipal",
                    target_object_id="sp-build",
                    target_name="build-sp",
                    target_type="ServicePrincipal",
                    evidence_type="graph-owner",
                    confidence="confirmed",
                    control_primitive="owner-control",
                    controlled_object_type="ServicePrincipal",
                    controlled_object_name="build-sp",
                    escalation_mechanism=(
                        "Owner-level control over service principal 'build-sp' could add or "
                        "replace authentication material Azure accepts for service principal "
                        "'build-sp'."
                    ),
                    usable_identity_result=(
                        "That could make service principal 'build-sp' usable."
                    ),
                    next_review=(
                        "Check permissions for Azure control on service principal 'build-sp'."
                    ),
                    summary="test",
                    related_ids=["sp-current", "sp-build"],
                ),
                RoleTrustSummary(
                    trust_type="app-to-service-principal",
                    source_object_id="sp-current",
                    source_name="azurefox-lab-sp",
                    source_type="ServicePrincipal",
                    target_object_id="sp-build",
                    target_name="build-sp",
                    target_type="ServicePrincipal",
                    evidence_type="graph-app-role-assignment",
                    confidence="confirmed",
                    control_primitive="existing-app-role-assignment",
                    controlled_object_type="ServicePrincipal",
                    controlled_object_name="build-sp",
                    escalation_mechanism=(
                        "Service principal 'azurefox-lab-sp' already holds an application-"
                        "permission path into service principal 'build-sp'."
                    ),
                    usable_identity_result=(
                        "Service principal 'azurefox-lab-sp' already has application-permission "
                        "reach to 'build-sp'."
                    ),
                    next_review=(
                        "Review the exact application-permission grant and the stronger target "
                        "behind this path."
                    ),
                    summary="test",
                    related_ids=["sp-current", "app-role-build-1", "sp-build"],
                ),
            ],
            issues=[],
        ),
    }

    output = _build_escalation_path_output(options, "escalation-path", loaded)

    assert [row.path_concept for row in output.paths] == [
        "current-foothold-direct-control",
        "app-permission-reach",
        "trust-expansion",
    ]
    app_permission_row = next(
        row for row in output.paths if row.path_concept == "app-permission-reach"
    )
    trust_row = next(row for row in output.paths if row.path_concept == "trust-expansion")
    assert app_permission_row.clue_type == "app-to-service-principal"
    assert app_permission_row.visible_path == (
        "Current foothold -> app permission -> higher-value identity"
    )
    assert "application-permission reach into service principal 'build-sp'" in (
        app_permission_row.why_care or ""
    )
    assert trust_row.clue_type == "service-principal-owner"


def test_escalation_path_prefers_bigger_control_upgrade_before_easier_path() -> None:
    options = GlobalOptions(
        tenant=None,
        subscription=None,
        output=OutputMode.JSON,
        outdir=Path("/tmp/azurefox-escalation-upgrade-order"),
        debug=False,
    )

    loaded = {
        "permissions": SimpleNamespace(
            permissions=[
                PermissionSummary(
                    principal_id="sp-current",
                    display_name="azurefox-lab-sp",
                    principal_type="ServicePrincipal",
                    priority="medium",
                    high_impact_roles=["Contributor"],
                    all_role_names=["Contributor"],
                    role_assignment_count=1,
                    scope_count=1,
                    scope_ids=["/subscriptions/sub"],
                    privileged=True,
                    is_current_identity=True,
                ),
                PermissionSummary(
                    principal_id="sp-owner",
                    display_name="owner-sp",
                    principal_type="ServicePrincipal",
                    priority="high",
                    high_impact_roles=["Owner"],
                    all_role_names=["Owner"],
                    role_assignment_count=1,
                    scope_count=1,
                    scope_ids=["/subscriptions/other/resourceGroups/rg-owner"],
                    privileged=True,
                    is_current_identity=False,
                ),
                PermissionSummary(
                    principal_id="sp-contrib",
                    display_name="contrib-sp",
                    principal_type="ServicePrincipal",
                    priority="medium",
                    high_impact_roles=["Contributor"],
                    all_role_names=["Contributor"],
                    role_assignment_count=1,
                    scope_count=1,
                    scope_ids=["/subscriptions/other/resourceGroups/rg-contrib"],
                    privileged=True,
                    is_current_identity=False,
                ),
            ],
            issues=[],
        ),
        "role-trusts": SimpleNamespace(
            trusts=[
                RoleTrustSummary(
                    trust_type="service-principal-owner",
                    source_object_id="sp-current",
                    source_name="azurefox-lab-sp",
                    source_type="ServicePrincipal",
                    target_object_id="sp-owner",
                    target_name="owner-sp",
                    target_type="ServicePrincipal",
                    evidence_type="graph-owner",
                    confidence="confirmed",
                    control_primitive="owner-control",
                    controlled_object_type="ServicePrincipal",
                    controlled_object_name="owner-sp",
                    escalation_mechanism=(
                        "Owner-level control over service principal 'owner-sp' could add or "
                        "replace authentication material Azure accepts for service principal "
                        "'owner-sp'."
                    ),
                    usable_identity_result=(
                        "That could make service principal 'owner-sp' usable."
                    ),
                    next_review=(
                        "Check permissions for Azure control on service principal 'owner-sp'."
                    ),
                    summary="test",
                    related_ids=["sp-current", "sp-owner"],
                ),
                RoleTrustSummary(
                    trust_type="app-to-service-principal",
                    source_object_id="sp-current",
                    source_name="azurefox-lab-sp",
                    source_type="ServicePrincipal",
                    target_object_id="sp-contrib",
                    target_name="contrib-sp",
                    target_type="ServicePrincipal",
                    evidence_type="graph-app-role-assignment",
                    confidence="confirmed",
                    control_primitive="existing-app-role-assignment",
                    controlled_object_type="ServicePrincipal",
                    controlled_object_name="contrib-sp",
                    escalation_mechanism=(
                        "Service principal 'azurefox-lab-sp' already holds an application-"
                        "permission path into service principal 'contrib-sp'."
                    ),
                    usable_identity_result=(
                        "Service principal 'azurefox-lab-sp' already has application-permission "
                        "reach to 'contrib-sp'."
                    ),
                    next_review=(
                        "Review the exact application-permission grant and the stronger target "
                        "behind this path."
                    ),
                    summary="test",
                    related_ids=["sp-current", "app-role-contrib-1", "sp-contrib"],
                ),
            ],
            issues=[],
        ),
    }

    output = _build_escalation_path_output(options, "escalation-path", loaded)

    assert [row.path_concept for row in output.paths] == [
        "current-foothold-direct-control",
        "trust-expansion",
        "app-permission-reach",
    ]
    assert output.paths[1].clue_type == "service-principal-owner"
    assert output.paths[2].clue_type == "app-to-service-principal"


def test_escalation_path_keeps_distinct_app_permission_targets() -> None:
    options = GlobalOptions(
        tenant=None,
        subscription=None,
        output=OutputMode.JSON,
        outdir=Path("/tmp/azurefox-escalation-multi-app-permission"),
        debug=False,
    )

    loaded = {
        "permissions": SimpleNamespace(
            permissions=[
                PermissionSummary(
                    principal_id="sp-current",
                    display_name="azurefox-lab-sp",
                    principal_type="ServicePrincipal",
                    priority="medium",
                    high_impact_roles=["Contributor"],
                    all_role_names=["Contributor"],
                    role_assignment_count=1,
                    scope_count=1,
                    scope_ids=["/subscriptions/sub"],
                    privileged=True,
                    is_current_identity=True,
                ),
                PermissionSummary(
                    principal_id="sp-build",
                    display_name="build-sp",
                    principal_type="ServicePrincipal",
                    priority="high",
                    high_impact_roles=["Owner"],
                    all_role_names=["Owner"],
                    role_assignment_count=1,
                    scope_count=1,
                    scope_ids=["/subscriptions/other/resourceGroups/rg-build"],
                    privileged=True,
                    is_current_identity=False,
                ),
                PermissionSummary(
                    principal_id="sp-ops",
                    display_name="ops-sp",
                    principal_type="ServicePrincipal",
                    priority="medium",
                    high_impact_roles=["Contributor"],
                    all_role_names=["Contributor"],
                    role_assignment_count=1,
                    scope_count=1,
                    scope_ids=["/subscriptions/other/resourceGroups/rg-ops"],
                    privileged=True,
                    is_current_identity=False,
                ),
            ],
            issues=[],
        ),
        "role-trusts": SimpleNamespace(
            trusts=[
                RoleTrustSummary(
                    trust_type="app-to-service-principal",
                    source_object_id="sp-current",
                    source_name="azurefox-lab-sp",
                    source_type="ServicePrincipal",
                    target_object_id="sp-build",
                    target_name="build-sp",
                    target_type="ServicePrincipal",
                    evidence_type="graph-app-role-assignment",
                    confidence="confirmed",
                    control_primitive="existing-app-role-assignment",
                    controlled_object_type="ServicePrincipal",
                    controlled_object_name="build-sp",
                    escalation_mechanism=(
                        "Service principal 'azurefox-lab-sp' already holds an application-"
                        "permission path into service principal 'build-sp'."
                    ),
                    usable_identity_result=(
                        "Service principal 'azurefox-lab-sp' already has application-permission "
                        "reach to 'build-sp'."
                    ),
                    next_review=(
                        "Review the exact application-permission grant and the stronger target "
                        "behind this path."
                    ),
                    summary="test",
                    related_ids=["sp-current", "app-role-build-1", "sp-build"],
                ),
                RoleTrustSummary(
                    trust_type="app-to-service-principal",
                    source_object_id="sp-current",
                    source_name="azurefox-lab-sp",
                    source_type="ServicePrincipal",
                    target_object_id="sp-ops",
                    target_name="ops-sp",
                    target_type="ServicePrincipal",
                    evidence_type="graph-app-role-assignment",
                    confidence="confirmed",
                    control_primitive="existing-app-role-assignment",
                    controlled_object_type="ServicePrincipal",
                    controlled_object_name="ops-sp",
                    escalation_mechanism=(
                        "Service principal 'azurefox-lab-sp' already holds an application-"
                        "permission path into service principal 'ops-sp'."
                    ),
                    usable_identity_result=(
                        "Service principal 'azurefox-lab-sp' already has application-permission "
                        "reach to 'ops-sp'."
                    ),
                    next_review=(
                        "Review the exact application-permission grant and the stronger target "
                        "behind this path."
                    ),
                    summary="test",
                    related_ids=["sp-current", "app-role-ops-1", "sp-ops"],
                ),
            ],
            issues=[],
        ),
    }

    output = _build_escalation_path_output(options, "escalation-path", loaded)

    app_permission_rows = [
        row for row in output.paths if row.path_concept == "app-permission-reach"
    ]

    assert len(app_permission_rows) == 2
    assert {row.target_names[0] for row in app_permission_rows} == {"build-sp", "ops-sp"}


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
