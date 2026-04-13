from __future__ import annotations

import csv
import json
import shutil
from pathlib import Path

from typer.testing import CliRunner

from azurefox.cli import app

runner = CliRunner()


def _strip_artifact_lines(output: str) -> str:
    return "\n".join(
        line for line in output.splitlines() if not line.startswith("[chains] ")
    ).strip()


def _read_fixture_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_fixture_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _contributor_app_permission_trust() -> dict:
    return {
        "trust_type": "app-to-service-principal",
        "source_object_id": "33333333-3333-3333-3333-333333333333",
        "source_name": "azurefox-lab-sp",
        "source_type": "ServicePrincipal",
        "target_object_id": "66666666-6666-6666-6666-666666666666",
        "target_name": "build-sp",
        "target_type": "ServicePrincipal",
        "evidence_type": "graph-app-role-assignment",
        "confidence": "confirmed",
        "control_primitive": "existing-app-role-assignment",
        "controlled_object_type": "ServicePrincipal",
        "controlled_object_name": "build-sp",
        "backing_service_principal_id": None,
        "backing_service_principal_name": None,
        "escalation_mechanism": (
            "Service principal 'azurefox-lab-sp' already holds an application-permission "
            "path into service principal 'build-sp'."
        ),
        "usable_identity_result": (
            "Service principal 'azurefox-lab-sp' already has application-permission reach "
            "to 'build-sp'."
        ),
        "defender_cut_point": (
            "Remove the app-role assignment path from service principal "
            "'azurefox-lab-sp' to 'build-sp'."
        ),
        "operator_signal": "Trust expansion visible; privilege confirmation next.",
        "next_review": (
            "Review the exact application-permission grant and the stronger target behind "
            "this path."
        ),
        "summary": (
            "Service principal 'azurefox-lab-sp' holds an application permission or app-role "
            "assignment to 'build-sp'. This row is a trust-edge and application-permission cue; "
            "confirm whether the same identity also holds Azure control. Review the exact "
            "application-permission grant and the stronger target behind this path."
        ),
        "related_ids": [
            "33333333-3333-3333-3333-333333333333",
            "app-role-build-1",
            "66666666-6666-6666-6666-666666666666",
        ],
    }


def _contributor_view_fixture_dir(tmp_path: Path) -> Path:
    source_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"
    fixture_dir = tmp_path / "contributor-view-fixture"
    shutil.copytree(source_dir, fixture_dir)

    permissions_path = fixture_dir / "permissions.json"
    permissions_payload = _read_fixture_json(permissions_path)
    current_permission = permissions_payload["permissions"][0]
    current_permission["high_impact_roles"] = ["Contributor"]
    current_permission["all_role_names"] = ["Contributor"]
    current_permission["role_assignment_count"] = 1
    _write_fixture_json(permissions_path, permissions_payload)

    rbac_path = fixture_dir / "rbac.json"
    rbac_payload = _read_fixture_json(rbac_path)
    rbac_payload["role_assignments"] = [
        {
            "id": "ra-contrib-1",
            "scope_id": "/subscriptions/22222222-2222-2222-2222-222222222222",
            "principal_id": "33333333-3333-3333-3333-333333333333",
            "principal_type": "ServicePrincipal",
            "role_definition_id": "rd-contributor",
            "role_name": "Contributor",
        },
        {
            "id": "ra-2",
            "scope_id": "/subscriptions/22222222-2222-2222-2222-222222222222",
            "principal_id": "44444444-4444-4444-4444-444444444444",
            "principal_type": "User",
            "role_definition_id": "rd-reader",
            "role_name": "Reader",
        },
    ]
    _write_fixture_json(rbac_path, rbac_payload)

    role_trusts_path = fixture_dir / "role_trusts.json"
    role_trusts_payload = _read_fixture_json(role_trusts_path)
    role_trusts_payload["trusts"].append(_contributor_app_permission_trust())
    _write_fixture_json(role_trusts_path, role_trusts_payload)

    return fixture_dir


def test_cli_smoke_all_commands(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    commands = [
        "whoami",
        "inventory",
        "chains",
        "automation",
        "devops",
        "app-services",
        "acr",
        "databases",
        "dns",
        "application-gateway",
        "aks",
        "api-mgmt",
        "functions",
        "container-apps",
        "container-instances",
        "arm-deployments",
        "endpoints",
        "network-effective",
        "env-vars",
        "network-ports",
        "tokens-credentials",
        "rbac",
        "principals",
        "permissions",
        "privesc",
        "role-trusts",
        "cross-tenant",
        "lighthouse",
        "resource-trusts",
        "auth-policies",
        "managed-identities",
        "keyvault",
        "storage",
        "snapshots-disks",
        "nics",
        "workloads",
        "vms",
        "vmss",
    ]

    for command in commands:
        argv = ["--outdir", str(tmp_path), "--output", "json", command]
        if command == "chains":
            argv.append("credential-path")
        result = runner.invoke(
            app,
            argv,
            env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
        )
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["metadata"]["command"] == command
        if command == "role-trusts":
            assert payload["mode"] == "fast"
        assert (tmp_path / "loot" / f"{command}.json").exists()


def test_cli_smoke_chains_credential_path_json(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "--output", "json", "chains", "credential-path"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["metadata"]["command"] == "chains"
    assert payload["family"] == "credential-path"
    assert payload["command_state"] == "extraction-only"
    assert payload["claim_boundary"].startswith("Can claim that the visible evidence suggests")
    assert payload["current_gap"].startswith("The live family now joins backing evidence")
    assert payload["artifact_preference_order"] == []
    assert payload["source_artifacts"] == []
    assert payload["backing_commands"] == [
        "env-vars",
        "tokens-credentials",
        "databases",
        "storage",
        "keyvault",
    ]
    assert len(payload["paths"]) == 3
    assert payload["paths"][0]["target_service"] == "keyvault"
    assert payload["paths"][0]["target_resolution"] == "named match"
    assert payload["paths"][0]["priority"] == "high"
    assert payload["paths"][0]["target_names"] == ["kvlabopen01"]
    assert "Check vault access path" in payload["paths"][0]["next_review"]
    assert (
        payload["paths"][0]["confidence_boundary"]
        == "Your current identity can read this secret."
    )
    assert "Your current identity can read that secret." in payload["paths"][0]["summary"]
    assert payload["paths"][0]["missing_confirmation"] == ""
    assert payload["paths"][1]["target_service"] == "database"
    assert payload["paths"][1]["priority"] == "medium"
    assert payload["paths"][2]["target_service"] == "storage"
    assert payload["paths"][2]["priority"] == "low"
    assert {item["setting_name"] for item in payload["paths"]} == {
        "DB_PASSWORD",
        "AzureWebJobsStorage",
        "PAYMENT_API_KEY",
    }
    assert {
        item["target_resolution"]
        for item in payload["paths"]
        if item["target_service"] in {"database", "storage"}
    } == {"narrowed candidates"}


def test_cli_smoke_chains_credential_path_table_output(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "chains", "credential-path"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )
    normalized_output = " ".join(result.stdout.split()).lower()

    assert result.exit_code == 0
    assert "azurefox chains" in result.stdout
    assert (
        "Follow credential clues from surfaced secret-bearing or token-bearing evidence toward "
        "the likely downstream service."
        in result.stdout
    )
    assert "kvlabopen01" in result.stdout
    assert "priority" in result.stdout
    assert "target resolution" in result.stdout
    assert "next review" in result.stdout
    assert "confidence boundary" in result.stdout
    assert "high" in result.stdout
    assert "medium" in result.stdout
    assert "low" in result.stdout
    assert "narrowed" in normalized_output
    assert "candidates" in normalized_output
    assert "token surfaces do not" in normalized_output
    assert "database target." in normalized_output
    assert "stlabpub01" in result.stdout
    assert "stlabpriv01" in result.stdout
    assert "exact storage" in normalized_output
    assert "target." in normalized_output
    assert "loaded evidence does" in normalized_output
    assert "setting is not" in normalized_output
    assert "confirmed to reach it." in normalized_output
    assert "Claim boundary:" not in result.stdout
    assert "Current gap:" not in result.stdout
    assert "Takeaway:" not in result.stdout


def test_cli_smoke_chains_deployment_path_table_output(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "chains", "deployment-path"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    assert "azurefox chains" in result.stdout
    assert "note" in result.stdout
    assert "actionability" in result.stdout
    assert "insertion point" in result.stdout
    assert "likely azure impact" in result.stdout
    assert "what's missing" in result.stdout
    assert "deploy-aks-prod" in result.stdout
    assert "plan-infra-prod" in result.stdout
    assert "aa-hybrid-prod" in result.stdout
    assert "repo-content" in result.stdout
    assert "currently actionable" in result.stdout
    assert "conditionally" in result.stdout
    assert "support-only" in result.stdout
    assert "Redeploy-App" in result.stdout
    assert "Lab-Maintenance" in result.stdout
    assert "Takeaway:" not in result.stdout


def test_cli_smoke_chains_deployment_path_json(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "--output", "json", "chains", "deployment-path"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["metadata"]["command"] == "chains"
    assert payload["family"] == "deployment-path"
    assert payload["command_state"] == "extraction-only"
    assert payload["artifact_preference_order"] == []
    assert payload["source_artifacts"] == []
    assert payload["backing_commands"] == [
        "devops",
        "automation",
        "permissions",
        "rbac",
        "role-trusts",
        "keyvault",
        "arm-deployments",
        "aks",
        "functions",
        "app-services",
    ]
    assert len(payload["paths"]) == 6
    assert {item["asset_name"] for item in payload["paths"]} == {
        "deploy-aks-prod",
        "deploy-appservice-prod",
        "deploy-artifact-app-prod",
        "plan-infra-prod",
        "aa-hybrid-prod",
        "aa-lab-quiet",
    }
    assert {item["target_service"] for item in payload["paths"]} == {
        "aks",
        "app-service",
        "arm-deployment",
    }
    assert {item["target_resolution"] for item in payload["paths"]} == {
        "named match",
        "narrowed candidates",
        "visibility blocked",
    }
    assert {item["priority"] for item in payload["paths"]} == {"high", "low", "medium"}
    assert {item["path_concept"] for item in payload["paths"]} == {
        "controllable-change-path",
        "execution-hub",
        "secret-escalation-support",
    }
    assert {item["actionability_state"] for item in payload["paths"]} == {
        "currently actionable",
        "conditionally actionable",
        "consequence-grounded but insertion point unproven",
        "support-only",
    }
    support_row = next(item for item in payload["paths"] if item["asset_name"] == "aa-lab-quiet")
    assert support_row["priority"] == "low"
    assert support_row["actionability_state"] == "support-only"
    assert "Lab-Maintenance" in support_row["insertion_point"]
    assert (
        "concentrates connections and encrypted variables around reusable automation"
        in support_row["why_care"]
    )
    assert "does not yet map what runbook Lab-Maintenance changes" in support_row["next_review"]
    automation_row = next(
        item for item in payload["paths"] if item["asset_name"] == "aa-hybrid-prod"
    )
    assert automation_row["target_resolution"] == "narrowed candidates"
    assert automation_row["target_service"] == "app-service"
    assert automation_row["actionability_state"] == "currently actionable"
    assert automation_row["priority"] == "high"
    assert "webhook path can start runbook Redeploy-App" in automation_row["insertion_point"]
    assert (
        "current role assignment Owner at subscription scope"
        in automation_row["insertion_point"]
    )
    assert "role-trusts" in automation_row["evidence_commands"]
    assert "rbac" in automation_row["evidence_commands"]
    assert "not the exact App Service target" in automation_row["confidence_boundary"]
    assert automation_row["confirmation_basis"] == "same-workload-corroborated"
    assert "ops-deploy-sp" in automation_row["why_care"]
    assert automation_row["target_names"] == ["app-public-api"]
    assert automation_row["likely_impact"] == "1 visible app service candidate(s): app-public-api"
    assert "narrowed the visible App Service candidates to app-public-api" in automation_row[
        "next_review"
    ]
    assert "editable trigger or definition path" not in automation_row["next_review"]
    assert "trigger webhook runbook Redeploy-App" not in automation_row["next_review"]
    assert "confirm which runbook and trigger path performs the Azure change" not in (
        automation_row["next_review"]
    )
    assert "app-failed" in automation_row["next_review"]
    assert "recurring Azure execution" in automation_row["why_care"]
    assert "Visible App Service evidence keeps 1 candidate(s) in play" in automation_row["why_care"]
    aks_row = next(item for item in payload["paths"] if item["asset_name"] == "deploy-aks-prod")
    assert aks_row["actionability_state"] == "conditionally actionable"
    assert "Queue this pipeline now" in aks_row["insertion_point"]
    assert "permission-summary" in aks_row["joined_surface_types"]
    assert "permissions" in aks_row["evidence_commands"]
    assert "keyvault" in aks_row["evidence_commands"]
    assert "kv-prod-shared" in aks_row["why_care"]
    assert "Key Vault support" in aks_row["why_care"]
    assert "current-credential run-path control" in aks_row["confidence_boundary"]
    assert "not a writable source" in aks_row["confidence_boundary"]
    assert "exact AKS cluster target" in aks_row["confidence_boundary"]
    assert "candidate(s) in play" in aks_row["why_care"]
    assert "AzureFox already narrowed the visible AKS cluster candidates" in aks_row["next_review"]
    appsvc_row = next(
        item for item in payload["paths"] if item["asset_name"] == "deploy-appservice-prod"
    )
    assert appsvc_row["target_resolution"] == "named match"
    assert appsvc_row["confirmation_basis"] == "parsed-config-target"
    assert appsvc_row["actionability_state"] == "currently actionable"
    assert "Poison repository" in appsvc_row["insertion_point"]
    assert appsvc_row["target_names"] == ["app-public-api"]
    assert appsvc_row["likely_impact"] == "exact app service: app-public-api"
    assert "trust-edge" in appsvc_row["joined_surface_types"]
    assert "Azure identity 'build-sp'" in appsvc_row["confidence_boundary"]
    assert "App Service target" in appsvc_row["confidence_boundary"]
    assert "target-side record" in appsvc_row["why_care"]
    assert "app-public-api.azurewebsites.net" in appsvc_row["why_care"]
    assert (
        "separate direct sign-in as Azure identity 'build-sp'"
        in appsvc_row["confidence_boundary"]
    )
    assert (
        "AzureFox already named the exact App Service target app-public-api"
        in appsvc_row["next_review"]
    )
    plan_row = next(item for item in payload["paths"] if item["asset_name"] == "plan-infra-prod")
    assert "kv-platform-shared" in plan_row["why_care"]
    assert "Key Vault support" in plan_row["why_care"]


def test_cli_smoke_chains_compute_control_json(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "--output", "json", "chains", "compute-control"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["metadata"]["command"] == "chains"
    assert payload["family"] == "compute-control"
    assert payload["command_state"] == "extraction-only"
    assert payload["artifact_preference_order"] == []
    assert payload["source_artifacts"] == []
    assert payload["backing_commands"] == [
        "tokens-credentials",
        "env-vars",
        "workloads",
        "managed-identities",
        "permissions",
    ]
    assert len(payload["paths"]) == 6
    names = [item["asset_name"] for item in payload["paths"]]
    assert names == [
        "aca-orders",
        "aci-public-api",
        "app-empty-mi",
        "func-orders",
        "vm-web-01",
        "vmss-edge-01",
    ]
    assert {item["target_resolution"] for item in payload["paths"]} == {
        "path-confirmed",
        "identity-choice-corroborated",
    }

    aca_row = next(item for item in payload["paths"] if item["asset_name"] == "aca-orders")
    assert aca_row["asset_kind"] == "ContainerApp"
    assert aca_row["path_concept"] == "direct-token-opportunity"
    assert aca_row["priority"] == "high"
    assert aca_row["urgency"] == "pivot-now"
    assert aca_row["when"] == "act now"
    assert aca_row["reach_from_here"] == "public exposure visible; exploitation not proved"
    assert aca_row["compute_foothold"] == "aca-orders"
    assert aca_row["token_path"] == "service token request"
    assert aca_row["identity"] == "aca-orders system identity"
    assert aca_row["azure_access"] == "Contributor across subscription-wide scope"
    assert aca_row["proof_status"] == "confirmed"
    assert aca_row["stronger_outcome"] == "Contributor across subscription-wide scope"
    assert "ContainerApp 'aca-orders' can request tokens as aca-orders system identity" in aca_row[
        "note"
    ]
    assert "public-facing service" in aca_row["note"]
    assert "Check workloads for the compute foothold" in aca_row["next_review"]

    aci_row = next(item for item in payload["paths"] if item["asset_name"] == "aci-public-api")
    assert aci_row["asset_kind"] == "ContainerInstance"
    assert aci_row["path_concept"] == "direct-token-opportunity"
    assert aci_row["priority"] == "high"
    assert aci_row["urgency"] == "pivot-now"
    assert aci_row["when"] == "act now"
    assert aci_row["reach_from_here"] == "public exposure visible; exploitation not proved"
    assert aci_row["compute_foothold"] == "aci-public-api"
    assert aci_row["token_path"] == "service token request"
    assert aci_row["identity"] == "aci-public-api system identity"
    assert aci_row["azure_access"] == "Contributor across subscription-wide scope"
    assert aci_row["proof_status"] == "confirmed"
    assert aci_row["stronger_outcome"] == "Contributor across subscription-wide scope"
    assert (
        "ContainerInstance 'aci-public-api' can request tokens as aci-public-api system identity"
        in aci_row["note"]
    )
    assert "public-facing container group" in aci_row["note"]
    assert "Check workloads for the compute foothold" in aci_row["next_review"]

    app_row = next(item for item in payload["paths"] if item["asset_name"] == "app-empty-mi")
    assert app_row["asset_kind"] == "AppService"
    assert app_row["path_concept"] == "direct-token-opportunity"
    assert app_row["priority"] == "high"
    assert app_row["urgency"] == "pivot-now"
    assert app_row["when"] == "act now"
    assert app_row["reach_from_here"] == "public exposure visible; exploitation not proved"
    assert app_row["compute_foothold"] == "app-empty-mi"
    assert app_row["token_path"] == "service token request"
    assert app_row["identity"] == "app-empty-mi-system"
    assert app_row["azure_access"] == "Contributor across subscription-wide scope"
    assert app_row["proof_status"] == "confirmed"
    assert app_row["stronger_outcome"] == "Contributor across subscription-wide scope"
    assert "can request tokens as app-empty-mi-system" in app_row["note"]
    assert "Check app-services for the running service foothold" in app_row["next_review"]

    func_row = next(item for item in payload["paths"] if item["asset_name"] == "func-orders")
    assert func_row["asset_kind"] == "FunctionApp"
    assert func_row["path_concept"] == "direct-token-opportunity"
    assert func_row["priority"] == "high"
    assert func_row["urgency"] == "pivot-now"
    assert func_row["when"] == "act now"
    assert func_row["reach_from_here"] == "public exposure visible; exploitation not proved"
    assert func_row["compute_foothold"] == "func-orders"
    assert func_row["token_path"] == "service token request"
    assert func_row["identity"] == "func-orders-system"
    assert func_row["azure_access"] == "Contributor across subscription-wide scope"
    assert func_row["proof_status"] == "best current match"
    assert func_row["target_names"] == ["func-orders-system"]
    assert func_row["target_resolution"] == "identity-choice-corroborated"
    assert func_row["confirmation_basis"] == "mixed-identity-corroborated-permission-join"
    assert "cannot directly verify" in func_row["confidence_boundary"]
    assert "SystemAssigned" in func_row["confidence_boundary"]
    assert "does not directly verify" in func_row["missing_confirmation"]
    assert "best current lead" in func_row["note"]
    assert "already narrows this path to the identity shown here" in func_row["next_review"]

    vm_row = next(item for item in payload["paths"] if item["asset_name"] == "vm-web-01")
    assert vm_row["asset_kind"] == "VM"
    assert vm_row["path_concept"] == "direct-token-opportunity"
    assert vm_row["insertion_point"] == "public IMDS token path"
    assert vm_row["when"] == "act now"
    assert vm_row["reach_from_here"] == "public exposure visible; exploitation not proved"
    assert vm_row["compute_foothold"] == "vm-web-01"
    assert vm_row["token_path"] == "public VM metadata token"
    assert vm_row["identity"] == "ua-app"
    assert vm_row["azure_access"] == "Owner across subscription-wide scope"
    assert vm_row["proof_status"] == "confirmed"
    assert vm_row["stronger_outcome"] == "Owner across subscription-wide scope"
    assert vm_row["priority"] == "high"
    assert vm_row["urgency"] == "pivot-now"
    assert vm_row["target_service"] == "azure-control"
    assert "token-capable compute foothold" in vm_row["confidence_boundary"]
    assert "Check vms for the host foothold" in vm_row["next_review"]
    assert "can request tokens as ua-app" in vm_row["why_care"]
    assert "can request tokens as ua-app" in vm_row["note"]

    vmss_row = next(item for item in payload["paths"] if item["asset_name"] == "vmss-edge-01")
    assert vmss_row["asset_kind"] == "VMSS"
    assert vmss_row["path_concept"] == "direct-token-opportunity"
    assert vmss_row["priority"] == "medium"
    assert vmss_row["urgency"] == "review-soon"
    assert vmss_row["when"] == "review soon"
    assert vmss_row["reach_from_here"] == "current access does not show the start"
    assert vmss_row["compute_foothold"] == "vmss-edge-01"
    assert vmss_row["token_path"] == "VM metadata token"
    assert vmss_row["identity"] == "vmss-edge-01-system"
    assert vmss_row["azure_access"] == "Contributor across subscription-wide scope"
    assert vmss_row["proof_status"] == "confirmed"
    assert vmss_row["stronger_outcome"] == "Contributor across subscription-wide scope"
    assert "host-level execution or admin access" in vmss_row["note"]
    assert "Check vmss for the fleet foothold" in vmss_row["next_review"]


def test_cli_smoke_chains_escalation_path_json(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "--output", "json", "chains", "escalation-path"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["metadata"]["command"] == "chains"
    assert payload["family"] == "escalation-path"
    assert payload["command_state"] == "extraction-only"
    assert payload["artifact_preference_order"] == []
    assert payload["source_artifacts"] == []
    assert payload["backing_commands"] == [
        "permissions",
        "role-trusts",
    ]
    assert len(payload["paths"]) == 2

    direct_row = next(
        item
        for item in payload["paths"]
        if item["path_concept"] == "current-foothold-direct-control"
    )
    trust_row = next(
        item for item in payload["paths"] if item["path_concept"] == "trust-expansion"
    )

    assert direct_row["asset_name"] == "azurefox-lab-sp (current foothold)"
    assert direct_row["starting_foothold"] == "azurefox-lab-sp (current foothold)"
    assert direct_row["path_type"] == "current foothold direct control"
    assert direct_row["priority"] == "high"
    assert direct_row["urgency"] == "pivot-now"
    assert direct_row["stronger_outcome"] == "Owner across subscription-wide scope"
    assert direct_row["target_resolution"] == "path-confirmed"
    assert direct_row["evidence_commands"] == ["permissions"]
    assert "direct Azure control" in direct_row["why_care"]
    assert direct_row["note"] == direct_row["why_care"]
    assert "already holds high-impact RBAC" in direct_row["confidence_boundary"]

    assert trust_row["asset_name"] == "azurefox-lab-sp (current foothold)"
    assert trust_row["starting_foothold"] == "azurefox-lab-sp (current foothold)"
    assert trust_row["path_type"] == "trust expansion"
    assert trust_row["clue_type"] == "federated-credential"
    assert trust_row["stronger_outcome"] == "Owner across 2 visible scopes"
    assert trust_row["target_resolution"] == "path-confirmed"
    assert trust_row["evidence_commands"] == ["role-trusts", "permissions"]
    assert trust_row["target_names"] == ["build-sp"]
    assert "build-sp" in trust_row["note"]
    assert "already has federated trust into service principal 'build-sp'" in trust_row["note"]
    assert "Owner-level Azure control, including role assignment" in trust_row["note"]
    assert "resource groups 'rg-build-dr' and 'rg-identity'" in trust_row["note"]
    assert "visible federated subject" in trust_row["note"]
    assert (
        "already has federated trust that can yield service principal 'build-sp' access"
        in trust_row["confidence_boundary"]
    )


def test_cli_smoke_chains_escalation_path_table_output(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "chains", "escalation-path"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    normalized_output = " ".join(result.stdout.split())
    assert "azurefox chains" in result.stdout
    assert "starting foothold" in result.stdout
    assert "path type" in result.stdout
    assert "stronger outcome" in result.stdout
    assert "note" in result.stdout
    assert "confidence boundary" not in result.stdout
    assert "next review" not in result.stdout
    assert "direct Azure control" in result.stdout
    assert "AzureFox is not" in result.stdout
    assert "narrowing one exact downstream action" in result.stdout
    assert "trust expansion" in result.stdout
    assert "build-sp" in result.stdout
    assert "federated trust" in result.stdout
    assert "resource groups" in normalized_output
    assert "'rg-build-dr' and 'rg-identity'" in normalized_output


def test_cli_smoke_rbac_contributor_view_json(tmp_path: Path) -> None:
    fixture_dir = _contributor_view_fixture_dir(tmp_path / "fixture-src")

    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path / "out"), "--output", "json", "rbac"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    current_assignment = next(
        item for item in payload["role_assignments"] if item["principal_id"] == "33333333-3333-3333-3333-333333333333"
    )
    assert current_assignment["role_name"] == "Contributor"


def test_cli_smoke_chains_escalation_path_contributor_view_json(tmp_path: Path) -> None:
    fixture_dir = _contributor_view_fixture_dir(tmp_path / "fixture-src")

    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path / "out"), "--output", "json", "chains", "escalation-path"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["backing_commands"] == ["permissions", "role-trusts"]
    assert len(payload["paths"]) == 3

    direct_row = next(
        item
        for item in payload["paths"]
        if item["path_concept"] == "current-foothold-direct-control"
    )
    app_permission_row = next(
        item for item in payload["paths"] if item["path_concept"] == "app-permission-reach"
    )
    trust_row = next(
        item for item in payload["paths"] if item["path_concept"] == "trust-expansion"
    )

    assert direct_row["stronger_outcome"] == "Contributor across subscription-wide scope"
    assert direct_row["evidence_commands"] == ["permissions"]
    assert "direct Azure control" in direct_row["note"]
    assert app_permission_row["clue_type"] == "app-to-service-principal"
    assert app_permission_row["stronger_outcome"] == "Owner across 2 visible scopes"
    assert app_permission_row["evidence_commands"] == ["role-trusts", "permissions"]
    assert "application-permission reach into service principal 'build-sp'" in app_permission_row["note"]
    assert "That would add Owner-level Azure control" in app_permission_row["note"]
    assert trust_row["clue_type"] == "federated-credential"
    assert trust_row["stronger_outcome"] == "Owner across 2 visible scopes"
    assert trust_row["evidence_commands"] == ["role-trusts", "permissions"]
    assert "build-sp" in trust_row["note"]
    assert "already has federated trust into service principal 'build-sp'" in trust_row["note"]


def test_cli_smoke_chains_escalation_path_contributor_view_table_output(tmp_path: Path) -> None:
    fixture_dir = _contributor_view_fixture_dir(tmp_path / "fixture-src")

    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path / "out"), "chains", "escalation-path"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    normalized_output = " ".join(result.stdout.split())
    assert "current foothold direct control" in normalized_output
    assert "Contributor across subscription-wide scope" in normalized_output
    assert "app-permission reach" in normalized_output
    assert "trust expansion" in normalized_output
    assert "build-sp" in normalized_output
    assert "That would add Owner-level Azure control" in normalized_output


def test_cli_smoke_chains_compute_control_table_output(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "chains", "compute-control"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )
    normalized_output = " ".join(result.stdout.split()).lower()

    assert result.exit_code == 0
    assert "azurefox chains" in result.stdout
    assert "reach from here" in result.stdout
    assert "compute foothold" in result.stdout
    assert "token path" in result.stdout
    assert "identity" in result.stdout
    assert "azure access" in result.stdout.lower()
    assert "proof status" in result.stdout
    assert "app-empty-mi" in result.stdout
    assert "aca-orders" in result.stdout
    assert "aci-public-api" in result.stdout
    assert "func-orders" in result.stdout
    assert "vm-web-01" in result.stdout
    assert "vmss-edge-01" in result.stdout
    assert "service token request" in result.stdout.lower()
    assert "public vm metadata token" in result.stdout.lower()
    assert "public exposure visible" in normalized_output
    assert "exploitation not proved" in normalized_output
    assert "public reachability alone does not prove that path" in normalized_output
    assert "does not yet show that start from the current foothold" in normalized_output
    assert "ask azure for its own token" in normalized_output
    assert "metadata service" in normalized_output
    assert "host-level execution or admin access" in normalized_output
    assert "Owner across subscription-wide scope" in result.stdout
    assert "mixed identities" in normalized_output
    assert "best current match" in normalized_output
    assert "act now" in normalized_output
    assert "review soon" in normalized_output
    assert "Claim boundary:" in result.stdout
    assert "Current gap:" in result.stdout
    assert "Takeaway:" not in result.stdout
    assert "narrowed candidates" not in normalized_output


def test_cli_smoke_deployment_path_operator_language_guard(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "--output", "json", "chains", "deployment-path"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    text = " ".join(
        str(item.get(field) or "")
        for item in payload["paths"]
        for field in ("why_care", "next_review", "confidence_boundary", "likely_impact")
    )

    banned = [
        "visible workload deployment reach",
        "visible configuration change reach",
        "visible recurring Azure execution",
        "visible secret-backed deployment support",
        "not that current credentials can run this path",
        "not yet proven",
        "has not yet proven",
    ]
    for phrase in banned:
        assert phrase not in text


def test_cli_smoke_chains_overview_table_output(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "chains"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    assert "azurefox chains" in result.stdout
    assert "allowed claim" in result.stdout
    assert "current gap" in result.stdout
    assert "credential-path" in result.stdout
    assert "deployment-path" in result.stdout
    assert "escalation-path" in result.stdout
    assert "compute-control" in result.stdout
    assert "implemented" in result.stdout
    assert "backing commands" in result.stdout


def test_cli_smoke_chains_help_matches_overview_json(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    overview = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "--output", "json", "chains"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )
    help_view = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "--output", "json", "chains", "help"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert overview.exit_code == 0
    assert help_view.exit_code == 0
    overview_payload = json.loads(overview.stdout)
    help_payload = json.loads(help_view.stdout)
    overview_payload["metadata"]["generated_at"] = "<generated_at>"
    help_payload["metadata"]["generated_at"] = "<generated_at>"
    assert overview_payload == help_payload


def test_cli_smoke_chains_overview_csv_output(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "--output", "csv", "chains"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    csv_path = tmp_path / "csv" / "chains.csv"
    rows = list(csv.DictReader(csv_path.read_text(encoding="utf-8").splitlines()))
    assert len(rows) == 4
    assert {row["family"] for row in rows} == {
        "credential-path",
        "deployment-path",
        "escalation-path",
        "compute-control",
    }
    assert {row["state"] for row in rows} == {"implemented"}


def test_cli_smoke_chains_help_csv_matches_overview(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"
    overview_dir = tmp_path / "overview"
    help_dir = tmp_path / "help"

    overview = runner.invoke(
        app,
        ["--outdir", str(overview_dir), "--output", "csv", "chains"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )
    help_view = runner.invoke(
        app,
        ["--outdir", str(help_dir), "--output", "csv", "chains", "help"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert overview.exit_code == 0
    overview_csv = (overview_dir / "csv" / "chains.csv").read_text(encoding="utf-8")
    assert help_view.exit_code == 0
    help_csv = (help_dir / "csv" / "chains.csv").read_text(encoding="utf-8")
    assert _strip_artifact_lines(overview.stdout) == _strip_artifact_lines(help_view.stdout)
    assert overview_csv == help_csv


def test_cli_smoke_loot_artifact_written_end_to_end(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "--output", "json", "tokens-credentials"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    json_payload = json.loads(
        (tmp_path / "json" / "tokens-credentials.json").read_text(encoding="utf-8")
    )
    loot_payload = json.loads(
        (tmp_path / "loot" / "tokens-credentials.json").read_text(encoding="utf-8")
    )

    assert loot_payload["metadata"] == {
        "schema_version": json_payload["metadata"]["schema_version"],
        "command": "tokens-credentials",
    }
    assert "generated_at" not in loot_payload["metadata"]
    assert loot_payload["surfaces"] == json_payload["surfaces"][:3]
    assert len(loot_payload["surfaces"]) == 3
    assert {row["priority"] for row in loot_payload["surfaces"]} == {"high"}
    assert loot_payload["findings"] == json_payload["findings"]
    assert "issues" not in loot_payload
    assert loot_payload["loot_scope"] == {
        "selection": "semantic-high-priority",
        "priority_band": "high",
        "source_count": len(json_payload["surfaces"]),
        "returned_count": 3,
    }


def test_cli_smoke_devops_accepts_organization_after_command(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        [
            "--outdir",
            str(tmp_path),
            "--output",
            "json",
            "devops",
            "--devops-organization",
            "contoso",
        ],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["metadata"]["command"] == "devops"
    assert payload["metadata"]["devops_organization"] == "contoso"


def test_cli_smoke_csv_row_mapping_for_inventory_style_commands(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    expectations = {
        "acr": (2, "acr-public-legacy"),
        "databases": (4, "sql-public-legacy"),
        "dns": (3, "corp.example.com"),
        "network-effective": (2, "vm-web-01"),
    }

    for command, (expected_rows, expected_first_name) in expectations.items():
        result = runner.invoke(
            app,
            ["--outdir", str(tmp_path), "--output", "csv", command],
            env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
        )

        assert result.exit_code == 0
        csv_path = tmp_path / "csv" / f"{command}.csv"
        rows = list(csv.DictReader(csv_path.read_text(encoding="utf-8").splitlines()))
        assert len(rows) == expected_rows
        first_name = rows[0].get("name") or rows[0].get("asset_name")
        assert first_name == expected_first_name


def test_cli_smoke_role_trusts_full_mode(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "--output", "json", "role-trusts", "--mode", "full"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["metadata"]["command"] == "role-trusts"
    assert payload["mode"] == "full"


def test_cli_smoke_rejects_removed_all_checks_command(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "--output", "json", "all-checks"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 2
    assert "No such command 'all-checks'" in result.stderr


def test_cli_smoke_container_apps_table_output(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "container-apps"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    assert "azurefox container-apps" in result.stdout
    assert "aca-orders" in result.stdout
    assert "aca-internal-jobs" in result.stdout
    assert "environment" in result.stdout.lower()
    assert "ingress" in result.stdout.lower()
    assert "identity" in result.stdout.lower()


def test_cli_smoke_container_instances_table_output(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "container-instances"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    assert "azurefox container-instances" in result.stdout
    assert "aci-public-api" in result.stdout
    assert "aci-internal-worker" in result.stdout
    assert "network" in result.stdout.lower()
    assert "runtime" in result.stdout.lower()
    assert "images" in result.stdout.lower()
