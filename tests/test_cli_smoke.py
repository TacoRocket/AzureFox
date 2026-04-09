from __future__ import annotations

import csv
import json
from pathlib import Path

from typer.testing import CliRunner

from azurefox.cli import app

runner = CliRunner()


def _strip_artifact_lines(output: str) -> str:
    return "\n".join(
        line for line in output.splitlines() if not line.startswith("[chains] ")
    ).strip()


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

    assert result.exit_code == 0
    assert "azurefox chains" in result.stdout
    assert "kvlabopen01" in result.stdout
    assert "priority" in result.stdout
    assert "target resolution" in result.stdout
    assert "next review" in result.stdout
    assert "high" in result.stdout
    assert "medium" in result.stdout
    assert "low" in result.stdout
    normalized_output = " ".join(result.stdout.split())
    assert "narrowed" in normalized_output
    assert "candidates" in normalized_output
    assert "Takeaway: 3 visible credential paths" in result.stdout


def test_cli_smoke_chains_deployment_path_table_output(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "chains", "deployment-path"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    assert "azurefox chains" in result.stdout
    assert "why care" in result.stdout
    assert "path type" in result.stdout
    assert "likely azure impact" in result.stdout
    assert "confidence boundary" in result.stdout
    assert "deploy-aks-prod" in result.stdout
    assert "deploy-appservice-prod" in result.stdout
    assert "deploy-artifact-app-p" in result.stdout
    assert "plan-infra-prod" in result.stdout
    assert "aa-hybrid-prod" in result.stdout
    assert "trusted input" in result.stdout
    assert "Automation account" in result.stdout
    assert "controllable change" in result.stdout
    assert "execution hub" in result.stdout
    assert "secret-backed support" in result.stdout
    assert "Check permissions for" in result.stdout
    assert "consequence grounding" in result.stdout
    assert "Takeaway: 6 visible deployment paths" in result.stdout


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
        "narrowed candidates",
        "visibility blocked",
    }
    assert {item["priority"] for item in payload["paths"]} == {"high", "low", "medium"}
    assert {item["path_concept"] for item in payload["paths"]} == {
        "controllable-change-path",
        "execution-hub",
        "secret-escalation-support",
    }
    support_row = next(item for item in payload["paths"] if item["asset_name"] == "aa-lab-quiet")
    assert support_row["priority"] == "low"
    assert "Another foothold" in support_row["why_care"]
    assert "target mapping is still missing" in support_row["next_review"]
    automation_row = next(
        item for item in payload["paths"] if item["asset_name"] == "aa-hybrid-prod"
    )
    assert automation_row["target_resolution"] == "visibility blocked"
    assert "run recurring Azure-facing execution" in automation_row["why_care"]
    aks_row = next(item for item in payload["paths"] if item["asset_name"] == "deploy-aks-prod")
    assert "permissions" in aks_row["evidence_commands"]
    assert "keyvault" in aks_row["evidence_commands"]


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
        "privesc",
        "permissions",
        "role-trusts",
    ]
    assert len(payload["paths"]) == 1
    row = payload["paths"][0]
    assert row["asset_name"] == "azurefox-lab-sp (current foothold)"
    assert row["path_concept"] == "current-foothold-direct-control"
    assert row["priority"] == "high"
    assert row["urgency"] == "pivot-now"
    assert row["stronger_outcome"] == "Owner across subscription-wide scope"
    assert row["target_resolution"] == "path-confirmed"
    assert row["evidence_commands"] == ["privesc", "permissions"]
    assert "not a speculative lead" in row["why_care"]
    assert "already holds high-impact RBAC" in row["confidence_boundary"]


def test_cli_smoke_chains_escalation_path_table_output(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "chains", "escalation-path"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    assert "azurefox chains" in result.stdout
    assert "starting foothold" in result.stdout
    assert "path type" in result.stdout
    assert "stronger outcome" in result.stdout
    assert "confidence boundary" in result.stdout
    assert "why care" in result.stdout
    normalized_output = " ".join(result.stdout.split())
    assert "azurefox-lab-sp" in normalized_output
    assert "(current" in normalized_output
    assert "foothold)" in normalized_output
    assert "current foothold direct control" in normalized_output
    assert "Owner across" in normalized_output
    assert "subscription-wide scope" in normalized_output
    assert "pivot-now" in result.stdout
    assert "Takeaway: 1 visible escalation paths" in result.stdout


def test_cli_smoke_chains_overview_table_output(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "chains"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    assert "azurefox chains" in result.stdout
    assert "credential-path" in result.stdout
    assert "deployment-path" in result.stdout
    assert "escalation-path" in result.stdout
    assert "workload-identity-path" in result.stdout
    assert "implemented" in result.stdout
    assert "planned" in result.stdout
    assert "backing commands" in result.stdout
    assert "Takeaway: 4 chain families listed; 3 implemented, 1 planned." in result.stdout


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
        "workload-identity-path",
    }
    assert {row["state"] for row in rows} == {"implemented", "planned"}


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


def test_cli_smoke_loot_keeps_top_ranked_targets_for_tokens_credentials(tmp_path: Path) -> None:
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
    assert loot_payload["surfaces"] == json_payload["surfaces"][:10]
    assert len(loot_payload["surfaces"]) == 10
    assert loot_payload["findings"] == json_payload["findings"]
    assert "issues" not in loot_payload
    assert loot_payload["loot_scope"] == {
        "selection": "top-ranked-targets",
        "source_count": len(json_payload["surfaces"]),
        "returned_count": 10,
        "limit": 10,
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
        "network-effective": (1, "vm-web-01"),
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
