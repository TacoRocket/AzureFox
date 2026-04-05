from __future__ import annotations

import csv
import json
from pathlib import Path

from typer.testing import CliRunner

from azurefox.cli import app

runner = CliRunner()


def test_cli_smoke_all_commands(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    commands = [
        "whoami",
        "inventory",
        "automation",
        "devops",
        "app-services",
        "acr",
        "databases",
        "dns",
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
        result = runner.invoke(
            app,
            ["--outdir", str(tmp_path), "--output", "json", command],
            env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
        )
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload["metadata"]["command"] == command
        if command == "role-trusts":
            assert payload["mode"] == "fast"
        assert (tmp_path / "loot" / f"{command}.json").exists()


def test_cli_smoke_all_checks_json_summary(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "--output", "json", "all-checks"],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["metadata"]["command"] == "all-checks"
    assert len(payload["results"]) == 34
    assert (tmp_path / "run-summary.json").exists()


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
        assert rows[0]["name"] == expected_first_name


def test_cli_smoke_section_filter(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        [
            "--outdir",
            str(tmp_path),
            "--output",
            "json",
            "all-checks",
            "--section",
            "identity",
        ],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    commands = {item["command"] for item in payload["results"]}
    assert commands == {
        "whoami",
        "rbac",
        "principals",
        "permissions",
        "privesc",
        "role-trusts",
        "cross-tenant",
        "lighthouse",
        "auth-policies",
        "managed-identities",
    }


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


def test_cli_smoke_all_checks_identity_full_role_trusts_mode(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        [
            "--outdir",
            str(tmp_path),
            "--output",
            "json",
            "all-checks",
            "--section",
            "identity",
            "--role-trusts-mode",
            "full",
        ],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    commands = {item["command"] for item in payload["results"]}
    assert "role-trusts" in commands


def test_cli_smoke_section_filter_config(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        [
            "--outdir",
            str(tmp_path),
            "--output",
            "json",
            "all-checks",
            "--section",
            "config",
        ],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    commands = {item["command"] for item in payload["results"]}
    assert commands == {"arm-deployments", "env-vars"}


def test_cli_smoke_section_filter_secrets(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        [
            "--outdir",
            str(tmp_path),
            "--output",
            "json",
            "all-checks",
            "--section",
            "secrets",
        ],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    commands = {item["command"] for item in payload["results"]}
    assert commands == {"keyvault", "tokens-credentials"}


def test_cli_smoke_section_filter_resource(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        [
            "--outdir",
            str(tmp_path),
            "--output",
            "json",
            "all-checks",
            "--section",
            "resource",
        ],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    commands = {item["command"] for item in payload["results"]}
    assert commands == {
        "automation",
        "devops",
        "acr",
        "api-mgmt",
        "databases",
        "resource-trusts",
    }


def test_cli_smoke_section_filter_network(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        [
            "--outdir",
            str(tmp_path),
            "--output",
            "json",
            "all-checks",
            "--section",
            "network",
        ],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    commands = {item["command"] for item in payload["results"]}
    assert commands == {"dns", "endpoints", "network-effective", "network-ports", "nics"}


def test_cli_smoke_section_filter_compute(tmp_path: Path) -> None:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"

    result = runner.invoke(
        app,
        [
            "--outdir",
            str(tmp_path),
            "--output",
            "json",
            "all-checks",
            "--section",
            "compute",
        ],
        env={"AZUREFOX_FIXTURE_DIR": str(fixture_dir)},
    )

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    commands = [item["command"] for item in payload["results"]]
    assert commands == [
        "workloads",
        "app-services",
        "functions",
        "aks",
        "vms",
        "vmss",
        "snapshots-disks",
    ]
