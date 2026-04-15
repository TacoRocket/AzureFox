from __future__ import annotations

import json
from pathlib import Path

from azurefox.chains.presentation import normalize_chain_path_row
from azurefox.config import GlobalOptions
from azurefox.models.common import SCHEMA_VERSION, OutputMode
from azurefox.output.writer import write_artifacts


def _options(tmp_path: Path) -> GlobalOptions:
    return GlobalOptions(
        tenant=None,
        subscription=None,
        output=OutputMode.JSON,
        outdir=tmp_path,
        debug=False,
    )


def test_write_artifacts_loot_uses_semantic_high_band_for_tokens_credentials(
    tmp_path: Path,
) -> None:
    surfaces = [
        {
            "asset_name": f"target-{index:02d}",
            "priority": "high" if index < 3 else "medium",
            "summary": f"ranked target {index:02d}",
        }
        for index in range(12)
    ]
    payload = {
        "metadata": {
            "schema_version": SCHEMA_VERSION,
            "command": "tokens-credentials",
            "generated_at": "2026-04-06T12:00:00Z",
            "tenant_id": "tenant-1",
            "subscription_id": "sub-1",
        },
        "surfaces": surfaces,
        "findings": [],
        "issues": [],
    }

    artifact_paths = write_artifacts("tokens-credentials", payload, _options(tmp_path))
    loot_payload = json.loads(artifact_paths["loot"].read_text(encoding="utf-8"))
    json_payload = json.loads(artifact_paths["json"].read_text(encoding="utf-8"))

    assert loot_payload["metadata"] == {
        "schema_version": SCHEMA_VERSION,
        "command": "tokens-credentials",
    }
    assert "generated_at" in json_payload["metadata"]
    assert "tenant_id" not in loot_payload["metadata"]
    assert "findings" not in loot_payload
    assert "issues" not in loot_payload
    assert loot_payload["surfaces"] == json_payload["surfaces"][:3]
    assert {row["priority"] for row in loot_payload["surfaces"]} == {"high"}
    assert loot_payload["loot_scope"] == {
        "selection": "semantic-high-priority",
        "priority_band": "high",
        "source_count": 12,
        "returned_count": 3,
    }


def test_write_artifacts_loot_falls_back_to_ranked_cutoff_without_high_band(tmp_path: Path) -> None:
    surfaces = [
        {
            "asset_name": f"target-{index:02d}",
            "priority": "medium" if index < 11 else "low",
            "summary": f"ranked target {index:02d}",
        }
        for index in range(12)
    ]
    payload = {
        "metadata": {
            "schema_version": SCHEMA_VERSION,
            "command": "tokens-credentials",
            "generated_at": "2026-04-06T12:00:00Z",
        },
        "surfaces": surfaces,
        "findings": [],
        "issues": [],
    }

    artifact_paths = write_artifacts("tokens-credentials", payload, _options(tmp_path))
    loot_payload = json.loads(artifact_paths["loot"].read_text(encoding="utf-8"))

    assert loot_payload["surfaces"] == surfaces[:10]
    assert loot_payload["loot_scope"] == {
        "selection": "top-ranked-targets",
        "source_count": 12,
        "returned_count": 10,
        "limit": 10,
    }


def test_write_artifacts_loot_uses_semantic_high_band_for_cross_tenant(tmp_path: Path) -> None:
    paths = [
        {
            "name": "contoso-owner",
            "priority": "high",
            "summary": "outside tenant has owner access",
        },
        {
            "name": "external-sp",
            "priority": "high",
            "summary": "outside tenant app has high-impact role",
        },
        {
            "name": "fabrikam-rg",
            "priority": "low",
            "summary": "resource group support path",
        },
    ]
    payload = {
        "metadata": {
            "schema_version": SCHEMA_VERSION,
            "command": "cross-tenant",
            "generated_at": "2026-04-06T12:00:00Z",
        },
        "cross_tenant_paths": paths,
        "findings": [],
        "issues": [],
    }

    artifact_paths = write_artifacts("cross-tenant", payload, _options(tmp_path))
    loot_payload = json.loads(artifact_paths["loot"].read_text(encoding="utf-8"))

    assert loot_payload["cross_tenant_paths"] == paths[:2]
    assert {row["priority"] for row in loot_payload["cross_tenant_paths"]} == {"high"}
    assert loot_payload["loot_scope"] == {
        "selection": "semantic-high-priority",
        "priority_band": "high",
        "source_count": 3,
        "returned_count": 2,
    }


def test_write_artifacts_loot_uses_semantic_high_band_for_permissions(tmp_path: Path) -> None:
    permissions = [
        {
            "display_name": "current-sp",
            "priority": "high",
            "summary": "current foothold direct control",
        },
        {
            "display_name": "workload-sp",
            "priority": "high",
            "summary": "workload-linked privileged identity",
        },
        {
            "display_name": "trust-sp",
            "priority": "medium",
            "summary": "trust expansion follow-on",
        },
    ]
    payload = {
        "metadata": {
            "schema_version": SCHEMA_VERSION,
            "command": "permissions",
            "generated_at": "2026-04-06T12:00:00Z",
        },
        "permissions": permissions,
        "issues": [],
    }

    artifact_paths = write_artifacts("permissions", payload, _options(tmp_path))
    loot_payload = json.loads(artifact_paths["loot"].read_text(encoding="utf-8"))

    assert loot_payload["permissions"] == permissions[:2]
    assert {row["priority"] for row in loot_payload["permissions"]} == {"high"}
    assert loot_payload["loot_scope"] == {
        "selection": "semantic-high-priority",
        "priority_band": "high",
        "source_count": 3,
        "returned_count": 2,
    }


def test_write_artifacts_loot_uses_semantic_high_band_for_privesc(tmp_path: Path) -> None:
    paths = [
        {
            "principal": "current-sp",
            "priority": "high",
            "summary": "direct role abuse",
        },
        {
            "principal": "vm-pivot",
            "priority": "medium",
            "summary": "public identity pivot",
        },
    ]
    payload = {
        "metadata": {
            "schema_version": SCHEMA_VERSION,
            "command": "privesc",
            "generated_at": "2026-04-06T12:00:00Z",
        },
        "paths": paths,
        "issues": [],
    }

    artifact_paths = write_artifacts("privesc", payload, _options(tmp_path))
    loot_payload = json.loads(artifact_paths["loot"].read_text(encoding="utf-8"))

    assert loot_payload["paths"] == paths[:1]
    assert {row["priority"] for row in loot_payload["paths"]} == {"high"}
    assert loot_payload["loot_scope"] == {
        "selection": "semantic-high-priority",
        "priority_band": "high",
        "source_count": 2,
        "returned_count": 1,
    }


def test_write_artifacts_loot_caps_semantic_high_band_at_limit(tmp_path: Path) -> None:
    surfaces = [
        {
            "asset_name": f"target-{index:02d}",
            "priority": "high",
            "summary": f"ranked target {index:02d}",
        }
        for index in range(12)
    ]
    payload = {
        "metadata": {
            "schema_version": SCHEMA_VERSION,
            "command": "tokens-credentials",
            "generated_at": "2026-04-06T12:00:00Z",
        },
        "surfaces": surfaces,
        "findings": [],
        "issues": [],
    }

    artifact_paths = write_artifacts("tokens-credentials", payload, _options(tmp_path))
    loot_payload = json.loads(artifact_paths["loot"].read_text(encoding="utf-8"))

    assert loot_payload["surfaces"] == surfaces[:10]
    assert loot_payload["loot_scope"] == {
        "selection": "semantic-high-priority",
        "priority_band": "high",
        "source_count": 12,
        "returned_count": 10,
        "limit": 10,
    }


def test_write_artifacts_loot_uses_semantic_high_band_for_chains_family(tmp_path: Path) -> None:
    paths = [
        {
            "asset_name": "deploy-aks-prod",
            "priority": "high",
            "summary": "current credentials can already modify the trusted input",
        },
        {
            "asset_name": "plan-infra-prod",
            "priority": "medium",
            "summary": "insertion point is less directly actionable",
        },
        {
            "asset_name": "aa-lab-quiet",
            "priority": "low",
            "summary": "support-only automation concentration path",
        },
    ]
    payload = {
        "metadata": {
            "schema_version": SCHEMA_VERSION,
            "command": "chains",
            "generated_at": "2026-04-06T12:00:00Z",
        },
        "grouped_command_name": "chains",
        "family": "deployment-path",
        "input_mode": "live",
        "command_state": "extraction-only",
        "summary": "test summary",
        "claim_boundary": "test claim boundary",
        "current_gap": "test current gap",
        "artifact_preference_order": [],
        "backing_commands": ["devops", "automation"],
        "source_artifacts": [],
        "paths": paths,
        "issues": [],
    }

    artifact_paths = write_artifacts("chains", payload, _options(tmp_path))
    loot_payload = json.loads(artifact_paths["loot"].read_text(encoding="utf-8"))

    assert len(loot_payload["paths"]) == 1
    assert loot_payload["paths"][0]["asset_name"] == "deploy-aks-prod"
    assert loot_payload["paths"][0]["priority"] == "high"
    assert "source" in loot_payload["paths"][0]
    assert {row["priority"] for row in loot_payload["paths"]} == {"high"}
    assert loot_payload["loot_scope"] == {
        "selection": "semantic-high-priority",
        "priority_band": "high",
        "source_count": 3,
        "returned_count": 1,
    }


def test_write_artifacts_chains_overview_loot_stays_on_ranked_cutoff(tmp_path: Path) -> None:
    families = [
        {
            "family": f"family-{index:02d}",
            "state": "implemented",
            "summary": f"summary {index:02d}",
        }
        for index in range(12)
    ]
    payload = {
        "metadata": {
            "schema_version": SCHEMA_VERSION,
            "command": "chains",
            "generated_at": "2026-04-06T12:00:00Z",
        },
        "grouped_command_name": "chains",
        "command_state": "extraction-only",
        "current_behavior": "overview",
        "planned_input_modes": [],
        "preferred_artifact_order": [],
        "families": families,
        "issues": [],
    }

    artifact_paths = write_artifacts("chains", payload, _options(tmp_path))
    loot_payload = json.loads(artifact_paths["loot"].read_text(encoding="utf-8"))

    assert loot_payload["families"] == families[:10]
    assert loot_payload["loot_scope"] == {
        "selection": "top-ranked-targets",
        "source_count": 12,
        "returned_count": 10,
        "limit": 10,
    }


def test_write_artifacts_loot_uses_semantic_high_band_for_all_supported_chains_families(
    tmp_path: Path,
) -> None:
    family_payloads = {
        "credential-path": [
            {
                "asset_name": "func-orders",
                "priority": "high",
                "target_service": "keyvault",
                "target_names": ["kvlabopen01"],
                "target_resolution": "named match",
                "summary": "FunctionApp pulls secret from visible Key Vault.",
            },
            {
                "asset_name": "web-legacy",
                "priority": "medium",
                "target_service": "storage",
                "target_resolution": "service hint only",
                "summary": "Legacy path still needs target confirmation.",
            },
        ],
        "deployment-path": [
            {
                "asset_name": "deploy-aks-prod",
                "priority": "high",
                "actionability_state": "currently actionable",
                "target_service": "aks",
                "target_names": ["aks-prod-01"],
                "target_resolution": "named match",
                "summary": "Current credentials can already modify that trusted input.",
            },
            {
                "asset_name": "plan-infra-prod",
                "priority": "low",
                "actionability_state": "support-only",
                "target_service": "arm-deployments",
                "target_resolution": "service hint only",
                "summary": "Support-only deployment signal.",
            },
        ],
        "compute-control": [
            {
                "asset_name": "app-empty-mi",
                "priority": "high",
                "urgency": "pivot-now",
                "insertion_point": "reachable service token request path",
                "target_resolution": "path-confirmed",
                "target_names": ["app-empty-mi-system"],
                "stronger_outcome": "Contributor across subscription-wide scope",
                "summary": "Managed identity token path already visible from this workload.",
            },
            {
                "asset_name": "internal-vm",
                "priority": "medium",
                "urgency": "review-soon",
                "insertion_point": "IMDS token path",
                "target_resolution": "path-confirmed",
                "target_names": ["vm-mi"],
                "stronger_outcome": "Reader on one resource group",
                "summary": "Internal-only compute token path.",
            },
        ],
        "escalation-path": [
            {
                "asset_name": "azurefox-lab-sp (current foothold)",
                "path_concept": "current-foothold-direct-control",
                "priority": "high",
                "summary": "Current foothold already carries Azure control.",
            },
            {
                "asset_name": "automation-mi",
                "path_concept": "trust-expansion",
                "priority": "medium",
                "summary": "Trust expansion follow-on.",
            },
        ],
    }

    for family, paths in family_payloads.items():
        payload = {
            "metadata": {
                "schema_version": SCHEMA_VERSION,
                "command": "chains",
                "generated_at": "2026-04-06T12:00:00Z",
            },
            "grouped_command_name": "chains",
            "family": family,
            "input_mode": "live",
            "command_state": "extraction-only",
            "summary": "test summary",
            "claim_boundary": "test claim boundary",
            "current_gap": "test current gap",
            "artifact_preference_order": [],
            "backing_commands": [],
            "source_artifacts": [],
            "paths": paths,
            "issues": [],
        }

        artifact_paths = write_artifacts("chains", payload, _options(tmp_path / family))
        loot_payload = json.loads(artifact_paths["loot"].read_text(encoding="utf-8"))

        assert loot_payload["family"] == family
        assert len(loot_payload["paths"]) == 1
        assert loot_payload["paths"][0]["asset_name"] == paths[0]["asset_name"]
        assert loot_payload["paths"][0]["priority"] == "high"
        assert loot_payload["loot_scope"] == {
            "selection": "semantic-high-priority",
            "priority_band": "high",
            "source_count": len(paths),
            "returned_count": 1,
        }


def test_write_artifacts_enriches_compute_control_json_contract(tmp_path: Path) -> None:
    payload = {
        "metadata": {
            "schema_version": SCHEMA_VERSION,
            "command": "chains",
            "generated_at": "2026-04-06T12:00:00Z",
        },
        "grouped_command_name": "chains",
        "family": "compute-control",
        "input_mode": "live",
        "command_state": "extraction-only",
        "summary": "test summary",
        "claim_boundary": "test claim boundary",
        "current_gap": "test current gap",
        "artifact_preference_order": [],
        "backing_commands": ["tokens-credentials", "permissions"],
        "source_artifacts": [],
        "paths": [
            {
                "asset_name": "app-empty-mi",
                "priority": "high",
                "urgency": "pivot-now",
                "insertion_point": "reachable service token request path",
                "target_names": ["app-empty-mi-system"],
                "target_resolution": "path-confirmed",
                "stronger_outcome": "Contributor across subscription-wide scope",
                "why_care": "AppService note",
                "next_review": "Check app-services.",
            }
        ],
        "issues": [],
    }

    artifact_paths = write_artifacts("chains", payload, _options(tmp_path))
    json_payload = json.loads(artifact_paths["json"].read_text(encoding="utf-8"))
    row = json_payload["paths"][0]

    assert row["when"] == "act now"
    assert row["reach_from_here"] == "public exposure visible; exploitation not proved"
    assert row["compute_foothold"] == "app-empty-mi"
    assert row["token_path"] == "service token request"
    assert row["identity"] == "app-empty-mi-system"
    assert row["azure_access"] == "Contributor across subscription-wide scope"
    assert row["proof_status"] == "confirmed"
    assert row["note"] == "AppService note"


def test_write_artifacts_enriches_escalation_path_json_contract(tmp_path: Path) -> None:
    payload = {
        "metadata": {
            "schema_version": SCHEMA_VERSION,
            "command": "chains",
            "generated_at": "2026-04-06T12:00:00Z",
        },
        "grouped_command_name": "chains",
        "family": "escalation-path",
        "input_mode": "live",
        "command_state": "extraction-only",
        "summary": "test summary",
        "claim_boundary": "test claim boundary",
        "current_gap": "test current gap",
        "artifact_preference_order": [],
        "backing_commands": ["permissions", "role-trusts"],
        "source_artifacts": [],
        "paths": [
            {
                "asset_name": "azurefox-lab-sp (current foothold)",
                "path_concept": "current-foothold-direct-control",
                "priority": "high",
                "urgency": "pivot-now",
                "stronger_outcome": "Owner across subscription-wide scope",
                "confidence_boundary": "bounded current-foothold proof",
                "why_care": "Current foothold already carries Azure control.",
                "next_review": "Check rbac for exact assignment evidence.",
            }
        ],
        "issues": [],
    }

    artifact_paths = write_artifacts("chains", payload, _options(tmp_path))
    json_payload = json.loads(artifact_paths["json"].read_text(encoding="utf-8"))
    row = json_payload["paths"][0]

    assert row["starting_foothold"] == "azurefox-lab-sp (current foothold)"
    assert row["path_type"] == "current foothold direct control"
    assert row["note"] == "Current foothold already carries Azure control."


def test_write_artifacts_enriches_credential_path_json_contract(tmp_path: Path) -> None:
    payload = {
        "metadata": {
            "schema_version": SCHEMA_VERSION,
            "command": "chains",
            "generated_at": "2026-04-06T12:00:00Z",
        },
        "grouped_command_name": "chains",
        "family": "credential-path",
        "input_mode": "live",
        "command_state": "extraction-only",
        "summary": "test summary",
        "claim_boundary": "test claim boundary",
        "current_gap": "test current gap",
        "artifact_preference_order": [],
        "backing_commands": ["env-vars", "tokens-credentials", "databases", "storage", "keyvault"],
        "source_artifacts": [],
        "paths": [
            {
                "asset_name": "func-orders",
                "setting_name": "PAYMENT_API_KEY",
                "target_service": "keyvault",
                "target_resolution": "named match",
                "target_names": ["kvlabopen01"],
                "priority": "high",
                "urgency": "review-soon",
                "next_review": "Check vault access path and referenced secret use.",
                "summary": "FunctionApp pulls secret from visible Key Vault.",
            }
        ],
        "issues": [],
    }

    artifact_paths = write_artifacts("chains", payload, _options(tmp_path))
    json_payload = json.loads(artifact_paths["json"].read_text(encoding="utf-8"))
    row = json_payload["paths"][0]

    assert row["asset"] == "func-orders"
    assert row["setting"] == "PAYMENT_API_KEY"
    assert row["target"] == "keyvault"
    assert row["visible_targets"] == "kvlabopen01"
    assert row["confidence_boundary"] == "Named target matched visible inventory."


def test_credential_path_named_target_not_visible_uses_target_service_name() -> None:
    row = normalize_chain_path_row(
        "credential-path",
        {
            "asset_name": "app-orders",
            "setting_name": "DB_PASSWORD",
            "target_service": "database",
            "target_resolution": "named target not visible",
            "summary": "summary fallback should not win",
        },
    )

    assert row["confidence_boundary"] == (
        "This app names a database target AzureFox cannot see in current inventory."
    )


def test_write_artifacts_enriches_deployment_path_json_contract(tmp_path: Path) -> None:
    payload = {
        "metadata": {
            "schema_version": SCHEMA_VERSION,
            "command": "chains",
            "generated_at": "2026-04-06T12:00:00Z",
        },
        "grouped_command_name": "chains",
        "family": "deployment-path",
        "input_mode": "live",
        "command_state": "extraction-only",
        "summary": "test summary",
        "claim_boundary": "test claim boundary",
        "current_gap": "test current gap",
        "artifact_preference_order": [],
        "backing_commands": ["devops", "automation", "permissions", "rbac"],
        "source_artifacts": [],
        "paths": [
            {
                "asset_name": "deploy-aks-prod",
                "priority": "high",
                "urgency": "pivot-now",
                "actionability_state": "consequence-grounded but insertion point unproven",
                "insertion_point": "pipeline artifact through trusted release path",
                "target_service": "aks",
                "target_resolution": "narrowed candidates",
                "target_names": ["aks-prod-01"],
                "why_care": "Current credentials can already modify that trusted input.",
                "next_review": "Review the exact artifact handoff into AKS.",
            }
        ],
        "issues": [],
    }

    artifact_paths = write_artifacts("chains", payload, _options(tmp_path))
    json_payload = json.loads(artifact_paths["json"].read_text(encoding="utf-8"))
    row = json_payload["paths"][0]

    assert row["source"] == "deploy-aks-prod"
    assert row["actionability"] == "grounded, insertion unproven"
    assert row["insertion_point_display"] == "pipeline artifact\nthrough trusted release path"
    assert row["likely_azure_impact"] == "aks-prod-01"
    assert row["confidence_boundary"] == (
        "Change-capable source narrows the next review set; exact target unconfirmed."
    )
    assert row["whats_missing"] == row["confidence_boundary"]
    assert row["note"] == "Current credentials can already modify that trusted input."


def test_deployment_path_insertion_point_display_preserves_structured_strings() -> None:
    row = normalize_chain_path_row(
        "deployment-path",
        {
            "asset_name": "deploy-api-prod",
            "insertion_point": (
                "artifact fetch at https://example.com/@refs/heads/main#deploy "
                "through /subscriptions/123/resourceGroups/rg-app"
            ),
            "target_service": "app-services",
            "target_resolution": "service hint only",
        },
    )

    assert row["insertion_point_display"] == (
        "artifact fetch\nat https://example.com/@refs/heads/main#deploy\nthrough "
        "/subscriptions/123/resourceGroups/rg-app"
    )


def test_write_artifacts_loot_keeps_nonempty_findings_and_issues(tmp_path: Path) -> None:
    payload = {
        "metadata": {
            "schema_version": SCHEMA_VERSION,
            "command": "storage",
            "generated_at": "2026-04-06T12:00:00Z",
        },
        "storage_assets": [],
        "findings": [
            {
                "kind": "public_access",
                "summary": "Storage account allows public access.",
                "related_ids": ["storage-1"],
            }
        ],
        "issues": [
            {
                "kind": "permission_denied",
                "message": "storage.accounts: 403 Forbidden",
                "context": {"collector": "storage.accounts"},
            }
        ],
    }

    artifact_paths = write_artifacts("storage", payload, _options(tmp_path))
    loot_payload = json.loads(artifact_paths["loot"].read_text(encoding="utf-8"))

    assert loot_payload["metadata"] == {
        "schema_version": SCHEMA_VERSION,
        "command": "storage",
    }
    assert loot_payload["findings"] == payload["findings"]
    assert loot_payload["issues"] == payload["issues"]


def test_write_artifacts_network_effective_uses_row_mapped_loot_and_csv(tmp_path: Path) -> None:
    exposures = [
        {
            "asset_name": f"vm-web-{index:02d}",
            "effective_exposure": "high" if index < 3 else "medium",
            "endpoint": f"52.160.10.{index}",
        }
        for index in range(12)
    ]
    payload = {
        "metadata": {
            "schema_version": SCHEMA_VERSION,
            "command": "network-effective",
            "generated_at": "2026-04-06T12:00:00Z",
        },
        "effective_exposures": exposures,
        "findings": [],
        "issues": [],
    }

    artifact_paths = write_artifacts("network-effective", payload, _options(tmp_path))
    loot_payload = json.loads(artifact_paths["loot"].read_text(encoding="utf-8"))
    csv_lines = artifact_paths["csv"].read_text(encoding="utf-8").splitlines()

    assert loot_payload["effective_exposures"] == exposures[:10]
    assert loot_payload["loot_scope"] == {
        "selection": "top-ranked-targets",
        "source_count": 12,
        "returned_count": 10,
        "limit": 10,
    }
    assert csv_lines[0].startswith("asset_name,")
    assert len(csv_lines) == 13


def test_write_artifacts_snapshot_disks_stays_on_ranked_cutoff_despite_table_priority_context(
    tmp_path: Path,
) -> None:
    snapshot_disk_assets = [
        {
            "name": f"snapshot-{index:02d}",
            "asset_kind": "snapshot",
            "attachment_state": "detached",
            "public_network_access": "Enabled",
            "network_access_policy": "AllowAll",
            "summary": f"snapshot summary {index:02d}",
        }
        for index in range(12)
    ]
    payload = {
        "metadata": {
            "schema_version": SCHEMA_VERSION,
            "command": "snapshots-disks",
            "generated_at": "2026-04-06T12:00:00Z",
        },
        "snapshot_disk_assets": snapshot_disk_assets,
        "findings": [],
        "issues": [],
    }

    artifact_paths = write_artifacts("snapshots-disks", payload, _options(tmp_path))
    loot_payload = json.loads(artifact_paths["loot"].read_text(encoding="utf-8"))

    assert loot_payload["snapshot_disk_assets"] == snapshot_disk_assets[:10]
    assert loot_payload["loot_scope"] == {
        "selection": "top-ranked-targets",
        "source_count": 12,
        "returned_count": 10,
        "limit": 10,
    }
