from __future__ import annotations

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
        "app-services",
        "acr",
        "aks",
        "api-mgmt",
        "functions",
        "arm-deployments",
        "endpoints",
        "env-vars",
        "network-ports",
        "tokens-credentials",
        "rbac",
        "principals",
        "permissions",
        "privesc",
        "role-trusts",
        "resource-trusts",
        "auth-policies",
        "managed-identities",
        "keyvault",
        "storage",
        "nics",
        "workloads",
        "vms",
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
    assert len(payload["results"]) == 25
    assert (tmp_path / "run-summary.json").exists()


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
        "auth-policies",
        "managed-identities",
    }


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
    assert commands == {"acr", "api-mgmt", "resource-trusts"}


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
    assert commands == {"endpoints", "network-ports", "nics"}


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
    assert commands == ["workloads", "app-services", "functions", "aks", "vms"]
