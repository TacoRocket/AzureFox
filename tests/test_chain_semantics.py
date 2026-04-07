from __future__ import annotations

from azurefox.chains.runner import _build_candidate_record
from azurefox.chains.semantics import (
    ChainSemanticContext,
    evaluate_chain_semantics,
    semantic_priority_sort_value,
)


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
    assert low.priority == "low"


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
    assert "deployment evidence" in decision.next_review


def test_deployment_path_semantics_promote_narrowed_devops_targets() -> None:
    decision = evaluate_chain_semantics(
        ChainSemanticContext(
            family="deployment-path",
            clue_type="azure-service-connection",
            target_service="aks",
            target_resolution="narrowed candidates",
            target_count=2,
        )
    )

    assert decision.priority == "medium"
    assert "narrowed deployment targets" in decision.next_review


def test_semantic_priority_sort_value_orders_highest_first() -> None:
    assert semantic_priority_sort_value("high") < semantic_priority_sort_value("medium")
    assert semantic_priority_sort_value("medium") < semantic_priority_sort_value("low")


def test_blocked_candidate_record_does_not_leak_candidate_names_into_summary() -> None:
    record = _build_candidate_record(
        "credential-path",
        {
            "asset_id": (
                "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Web/sites/"
                "app-public-api"
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
    assert "cannot name candidate database targets" in record.summary
