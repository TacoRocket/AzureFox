from __future__ import annotations

import pytest
from typer.testing import CliRunner

from azurefox.cli import _normalize_argv, app

runner = CliRunner()


def test_help_command_generic() -> None:
    result = runner.invoke(app, ["help"])

    assert result.exit_code == 0
    assert "AzureFox Help" in result.stdout
    assert "azurefox -h <section>" in result.stdout
    assert "azurefox <command> --help" in result.stdout
    assert (
        "permissions: Triage which visible principals hold high-impact RBAC roles."
    ) in result.stdout
    assert "chains: Grouped family runner for higher-value preset paths" in result.stdout
    assert "Planned grouped commands:" not in result.stdout
    assert "all-checks" not in result.stdout
    assert "bounded weaker claims" in result.stdout
    assert "current scope did not confirm" in result.stdout


def test_help_command_section() -> None:
    result = runner.invoke(app, ["help", "identity"])

    assert result.exit_code == 0
    assert "AzureFox Help :: identity" in result.stdout
    assert "Implemented commands:" in result.stdout
    assert (
        "permissions: Triage which visible principals hold high-impact RBAC roles."
    ) in result.stdout
    assert "ATT&CK cloud lenses:" in result.stdout
    assert (
        "Guidance: Use the listed flat commands directly; grouped follow-up lives in chains"
        in result.stdout
    )


def test_help_command_command_topic() -> None:
    result = runner.invoke(app, ["help", "permissions"])

    assert result.exit_code == 0
    assert "AzureFox Help :: permissions" in result.stdout
    assert "Offensive question:" in result.stdout
    assert "ATT&CK cloud leads:" in result.stdout
    assert "Temporary Elevated Cloud Access" in result.stdout
    assert "proof strength separate from actionability" in result.stdout
    assert "names the current gap explicitly" in result.stdout


HELP_TOPICS_IDENTITY = (
    ("cross-tenant", ("outside-tenant trust", "attack_path")),
    ("rbac", ("Role-Based Access Control (RBAC)", "role_assignments")),
    (
        "role-trusts",
        (
            "Trusted Relationship",
            "federated credentials",
            "delegated or admin consent grants",
            "Fast mode is the default",
            "per-application owner and federated credential lookups",
            "usable_identity_result",
            "escalation_mechanism",
            "operator_signal",
            "next_review",
        ),
    ),
    (
        "auth-policies",
        (
            "Conditional Access",
            "guest, consent, app-creation, or sign-in abuse paths",
            "Unreadable policy surfaces stay explicit",
            "issues",
        ),
    ),
)

HELP_TOPICS_INFRA = (
    ("arm-deployments", ("linked templates", "outputs_count")),
    (
        "automation",
        (
            "Hybrid Worker",
            "published_runbook_count",
            "webhook_count",
            "encrypted_variable_count",
        ),
    ),
    (
        "devops",
        (
            "build definitions",
            "repository_host_type",
            "source_visibility_state",
            "execution_modes",
            "trusted_input_types",
            "trusted_input_refs",
            "primary_injection_surface",
            "injection_surface_types",
            "current_operator_injection_surface_types",
            "azure_service_connection_names",
            "current_operator_can_contribute_source",
            "missing_injection_point",
            "consequence_types",
            "--devops-organization",
        ),
    ),
    ("endpoints", ("ingress triage view", "exposure_family", "ingress_path")),
    (
        "acr",
        (
            "Azure Container Registry (ACR)",
            "login_server",
            "admin_user_enabled",
            "webhook_count",
            "replication_count",
            "network_rule_default_action",
        ),
    ),
    (
        "databases",
        (
            "engine",
            "fully_qualified_domain_name",
            "database_count",
            "high_availability_mode",
            "minimal_tls_version",
        ),
    ),
    (
        "dns",
        (
            "private VNet-linked namespace context",
            "name_servers",
            "registration_virtual_network_count",
            "private_endpoint_reference_count",
        ),
    ),
    (
        "application-gateway",
        (
            "shared public front doors",
            "listener_count",
            "request_routing_rule_count",
            "firewall_policy_id",
        ),
    ),
    (
        "storage",
        (
            "public_network_access",
            "allow_shared_key_access",
            "minimum_tls_version",
            "https_traffic_only_enabled",
        ),
    ),
    (
        "lighthouse",
        (
            "Azure Lighthouse",
            "managed_by_tenant_name",
            "eligible_authorization_count",
            "provisioning_state",
        ),
    ),
    (
        "snapshots-disks",
        (
            "highest-value offline-copy targets first",
            "attachment_state",
            "network_access_policy",
            "disk_encryption_set_id",
        ),
    ),
    ("network-effective", ("public-IP-backed assets", "not to prove full effective exposure")),
    (
        "network-ports",
        ("NIC-backed public endpoints", "allow_source_summary", "exposure_confidence"),
    ),
    (
        "nics",
        (
            "network interfaces (NICs)",
            "attached_asset_name",
            "public IP references",
            "network_security_group_id",
        ),
    ),
    ("keyvault", ("secret-management surface", "purge_protection_enabled")),
    ("resource-trusts", ("public network paths", "resource_type")),
)

HELP_TOPICS_WORKLOADS = (
    ("app-services", ("runtime stack", "workload_identity_type", "public_network_access")),
    ("functions", ("Functions runtime", "azure_webjobs_storage_value_type", "run_from_package")),
    (
        "aks",
        (
            "Azure Kubernetes Service",
            "private_cluster_enabled",
            "cluster_identity_type",
            "azure_rbac_enabled",
            "network_plugin",
            "oidc_issuer_enabled",
        ),
    ),
    (
        "api-mgmt",
        (
            "Application Programming Interface (API) Management",
            "gateway_hostnames",
            "virtual_network_type",
            "active_subscription_count",
            "named_value_secret_count",
        ),
    ),
    (
        "vmss",
        (
            "Virtual Machine Scale Sets",
            "instance_count",
            "orchestration_mode",
            "public_ip_configuration_count",
        ),
    ),
    ("vms", ("virtual machines (VMs)", "public_ips")),
    (
        "env-vars",
        ("Key Vault references", "pivot to next", "workload_identity_type", "setting_name"),
    ),
    ("tokens-credentials", ("pivot to next", "mint tokens", "operator_signal")),
    (
        "privesc",
        (
            "Cloud Instance Metadata API",
            "workload identity pivots",
            "starting_foothold",
            "operator_signal",
            "proven_path",
            "next_review",
        ),
    ),
    ("workloads", ("joined workload census", "identity_type", "ingress_paths")),
)


def _assert_help_topic_surface(topic: str, snippets: tuple[str, ...]) -> None:
    result = runner.invoke(app, ["help", topic])

    assert result.exit_code == 0
    assert f"AzureFox Help :: {topic}" in result.stdout
    for snippet in snippets:
        assert snippet in result.stdout


@pytest.mark.parametrize(("topic", "snippets"), HELP_TOPICS_IDENTITY)
def test_help_command_topic_surface_identity(topic: str, snippets: tuple[str, ...]) -> None:
    _assert_help_topic_surface(topic, snippets)


@pytest.mark.parametrize(("topic", "snippets"), HELP_TOPICS_INFRA)
def test_help_command_topic_surface_infra(topic: str, snippets: tuple[str, ...]) -> None:
    _assert_help_topic_surface(topic, snippets)


@pytest.mark.parametrize(("topic", "snippets"), HELP_TOPICS_WORKLOADS)
def test_help_command_topic_surface_workloads(topic: str, snippets: tuple[str, ...]) -> None:
    _assert_help_topic_surface(topic, snippets)


def test_help_command_chains_topic_sets_planned_runtime_expectations() -> None:
    result = runner.invoke(app, ["help", "chains"])

    assert result.exit_code == 0
    assert "AzureFox Help :: chains" in result.stdout
    assert "implemented command" in result.stdout
    assert (
        "credential-path, deployment-path, escalation-path, and compute-control are exposed now"
        in result.stdout
    )
    assert "escalation-path" in result.stdout
    assert "compute-control currently ships a narrow direct-token-opportunity v1" in result.stdout
    assert "compute-control" in result.stdout
    assert "credential-path" in result.stdout
    assert "claim_boundary" in result.stdout
    assert "current_gap" in result.stdout


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
    assert _normalize_argv(["azurefox", "dns", "--help"]) == ["azurefox", "help", "dns"]
    assert _normalize_argv(["azurefox", "dns", "-h"]) == ["azurefox", "help", "dns"]
    assert _normalize_argv(["azurefox", "chains", "--help"]) == [
        "azurefox",
        "help",
        "chains",
    ]
    assert _normalize_argv(["azurefox", "chains", "-h"]) == ["azurefox", "help", "chains"]


def test_normalize_argv_command_level_global_options() -> None:
    assert _normalize_argv(["azurefox", "dns", "--output", "json"]) == [
        "azurefox",
        "--output",
        "json",
        "dns",
    ]
    assert _normalize_argv(
        [
            "azurefox",
            "whoami",
            "--tenant",
            "tenant-1",
            "--subscription",
            "sub-1",
            "--debug",
        ]
    ) == [
        "azurefox",
        "--tenant",
        "tenant-1",
        "--subscription",
        "sub-1",
        "--debug",
        "whoami",
    ]
    assert _normalize_argv(
        ["azurefox", "custom-command", "--section", "identity", "--output", "json"]
    ) == ["azurefox", "custom-command", "--section", "identity", "--output", "json"]
