from __future__ import annotations

from typer.testing import CliRunner

from azurefox.cli import _normalize_argv, app

runner = CliRunner()


def test_help_command_generic() -> None:
    result = runner.invoke(app, ["help"])

    assert result.exit_code == 0
    assert "AzureFox Help" in result.stdout
    assert "azurefox -h <section>" in result.stdout
    assert (
        "permissions: Triage which visible principals hold "
        "high-impact RBAC roles."
    ) in result.stdout


def test_help_command_section() -> None:
    result = runner.invoke(app, ["help", "identity"])

    assert result.exit_code == 0
    assert "AzureFox Help :: identity" in result.stdout
    assert "Implemented commands:" in result.stdout
    assert (
        "permissions: Triage which visible principals hold "
        "high-impact RBAC roles."
    ) in result.stdout
    assert "ATT&CK cloud lenses:" in result.stdout


def test_help_command_command_topic() -> None:
    result = runner.invoke(app, ["help", "permissions"])

    assert result.exit_code == 0
    assert "AzureFox Help :: permissions" in result.stdout
    assert "Offensive question:" in result.stdout
    assert "ATT&CK cloud leads:" in result.stdout
    assert "Temporary Elevated Cloud Access" in result.stdout


def test_help_command_privesc_topic() -> None:
    result = runner.invoke(app, ["help", "privesc"])

    assert result.exit_code == 0
    assert "AzureFox Help :: privesc" in result.stdout
    assert "Cloud Instance Metadata API" in result.stdout
    assert "workload identity pivots" in result.stdout


def test_help_command_role_trusts_topic() -> None:
    result = runner.invoke(app, ["help", "role-trusts"])

    assert result.exit_code == 0
    assert "AzureFox Help :: role-trusts" in result.stdout
    assert "Trusted Relationship" in result.stdout
    assert "federated credentials" in result.stdout


def test_help_command_auth_policies_topic() -> None:
    result = runner.invoke(app, ["help", "auth-policies"])

    assert result.exit_code == 0
    assert "AzureFox Help :: auth-policies" in result.stdout
    assert "Conditional Access" in result.stdout
    assert "sign-in, consent, and identity hardening" in result.stdout


def test_help_command_keyvault_topic() -> None:
    result = runner.invoke(app, ["help", "keyvault"])

    assert result.exit_code == 0
    assert "AzureFox Help :: keyvault" in result.stdout
    assert "secret-management surface" in result.stdout
    assert "purge_protection_enabled" in result.stdout


def test_help_command_resource_trusts_topic() -> None:
    result = runner.invoke(app, ["help", "resource-trusts"])

    assert result.exit_code == 0
    assert "AzureFox Help :: resource-trusts" in result.stdout
    assert "public network paths" in result.stdout
    assert "resource_type" in result.stdout


def test_help_command_unknown_topic() -> None:
    result = runner.invoke(app, ["help", "banana"])

    assert result.exit_code == 2
    assert "Unknown help topic 'banana'" in result.stderr


def test_normalize_argv_help_shorthand() -> None:
    assert _normalize_argv(["azurefox", "-h"]) == ["azurefox", "help"]
    assert _normalize_argv(["azurefox", "-h", "identity"]) == ["azurefox", "help", "identity"]
    assert _normalize_argv(["azurefox", "--help", "permissions"]) == [
        "azurefox",
        "help",
        "permissions",
    ]
