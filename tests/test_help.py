from __future__ import annotations

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
    assert "all-checks: Run the implemented AzureFox commands" in result.stdout


def test_help_command_section() -> None:
    result = runner.invoke(app, ["help", "identity"])

    assert result.exit_code == 0
    assert "AzureFox Help :: identity" in result.stdout
    assert "Implemented commands:" in result.stdout
    assert (
        "permissions: Triage which visible principals hold high-impact RBAC roles."
    ) in result.stdout
    assert "ATT&CK cloud lenses:" in result.stdout


def test_help_command_command_topic() -> None:
    result = runner.invoke(app, ["help", "permissions"])

    assert result.exit_code == 0
    assert "AzureFox Help :: permissions" in result.stdout
    assert "Offensive question:" in result.stdout
    assert "ATT&CK cloud leads:" in result.stdout
    assert "Temporary Elevated Cloud Access" in result.stdout


def test_help_command_arm_deployments_topic() -> None:
    result = runner.invoke(app, ["help", "arm-deployments"])

    assert result.exit_code == 0
    assert "AzureFox Help :: arm-deployments" in result.stdout
    assert "linked templates" in result.stdout
    assert "outputs_count" in result.stdout


def test_help_command_automation_topic() -> None:
    result = runner.invoke(app, ["help", "automation"])

    assert result.exit_code == 0
    assert "AzureFox Help :: automation" in result.stdout
    assert "Hybrid Worker" in result.stdout
    assert "published_runbook_count" in result.stdout
    assert "webhook_count" in result.stdout
    assert "encrypted_variable_count" in result.stdout


def test_help_command_devops_topic() -> None:
    result = runner.invoke(app, ["help", "devops"])

    assert result.exit_code == 0
    assert "AzureFox Help :: devops" in result.stdout
    assert "build definitions" in result.stdout
    assert "azure_service_connection_names" in result.stdout
    assert "secret_variable_names" in result.stdout
    assert "key_vault_group_names" in result.stdout
    assert "--devops-organization" in result.stdout


def test_help_command_endpoints_topic() -> None:
    result = runner.invoke(app, ["help", "endpoints"])

    assert result.exit_code == 0
    assert "AzureFox Help :: endpoints" in result.stdout
    assert "ingress triage view" in result.stdout
    assert "exposure_family" in result.stdout
    assert "ingress_path" in result.stdout


def test_help_command_cross_tenant_topic() -> None:
    result = runner.invoke(app, ["help", "cross-tenant"])

    assert result.exit_code == 0
    assert "AzureFox Help :: cross-tenant" in result.stdout
    assert "outside-tenant trust" in result.stdout
    assert "attack_path" in result.stdout


def test_help_command_app_services_topic() -> None:
    result = runner.invoke(app, ["help", "app-services"])

    assert result.exit_code == 0
    assert "AzureFox Help :: app-services" in result.stdout
    assert "runtime stack" in result.stdout
    assert "workload_identity_type" in result.stdout
    assert "public_network_access" in result.stdout


def test_help_command_acr_topic() -> None:
    result = runner.invoke(app, ["help", "acr"])

    assert result.exit_code == 0
    assert "AzureFox Help :: acr" in result.stdout
    assert "Azure Container Registry (ACR)" in result.stdout
    assert "login_server" in result.stdout
    assert "admin_user_enabled" in result.stdout
    assert "webhook_count" in result.stdout
    assert "replication_count" in result.stdout
    assert "network_rule_default_action" in result.stdout


def test_help_command_databases_topic() -> None:
    result = runner.invoke(app, ["help", "databases"])

    assert result.exit_code == 0
    assert "AzureFox Help :: databases" in result.stdout
    assert "engine" in result.stdout
    assert "fully_qualified_domain_name" in result.stdout
    assert "database_count" in result.stdout
    assert "high_availability_mode" in result.stdout
    assert "minimal_tls_version" in result.stdout


def test_help_command_dns_topic() -> None:
    result = runner.invoke(app, ["help", "dns"])

    assert result.exit_code == 0
    assert "AzureFox Help :: dns" in result.stdout
    assert "private VNet-linked namespace context" in result.stdout
    assert "name_servers" in result.stdout
    assert "registration_virtual_network_count" in result.stdout
    assert "private_endpoint_reference_count" in result.stdout


def test_help_command_application_gateway_topic() -> None:
    result = runner.invoke(app, ["help", "application-gateway"])

    assert result.exit_code == 0
    assert "AzureFox Help :: application-gateway" in result.stdout
    assert "shared public front doors" in result.stdout
    assert "listener_count" in result.stdout
    assert "request_routing_rule_count" in result.stdout
    assert "firewall_policy_id" in result.stdout


def test_help_command_storage_topic() -> None:
    result = runner.invoke(app, ["help", "storage"])

    assert result.exit_code == 0
    assert "AzureFox Help :: storage" in result.stdout
    assert "public_network_access" in result.stdout
    assert "allow_shared_key_access" in result.stdout
    assert "minimum_tls_version" in result.stdout
    assert "https_traffic_only_enabled" in result.stdout


def test_help_command_lighthouse_topic() -> None:
    result = runner.invoke(app, ["help", "lighthouse"])

    assert result.exit_code == 0
    assert "AzureFox Help :: lighthouse" in result.stdout
    assert "Azure Lighthouse" in result.stdout
    assert "managed_by_tenant_name" in result.stdout
    assert "eligible_authorization_count" in result.stdout
    assert "provisioning_state" in result.stdout


def test_help_command_snapshots_disks_topic() -> None:
    result = runner.invoke(app, ["help", "snapshots-disks"])

    assert result.exit_code == 0
    assert "AzureFox Help :: snapshots-disks" in result.stdout
    assert "highest-value offline-copy targets first" in result.stdout
    assert "attachment_state" in result.stdout
    assert "network_access_policy" in result.stdout
    assert "disk_encryption_set_id" in result.stdout


def test_help_command_network_effective_topic() -> None:
    result = runner.invoke(app, ["help", "network-effective"])

    assert result.exit_code == 0
    assert "AzureFox Help :: network-effective" in result.stdout
    assert "public-IP-backed assets" in result.stdout
    assert "not to prove full effective exposure" in result.stdout


def test_help_command_functions_topic() -> None:
    result = runner.invoke(app, ["help", "functions"])

    assert result.exit_code == 0
    assert "AzureFox Help :: functions" in result.stdout
    assert "Functions runtime" in result.stdout
    assert "azure_webjobs_storage_value_type" in result.stdout
    assert "run_from_package" in result.stdout


def test_help_command_aks_topic() -> None:
    result = runner.invoke(app, ["help", "aks"])

    assert result.exit_code == 0
    assert "AzureFox Help :: aks" in result.stdout
    assert "Azure Kubernetes Service" in result.stdout
    assert "private_cluster_enabled" in result.stdout
    assert "cluster_identity_type" in result.stdout
    assert "azure_rbac_enabled" in result.stdout
    assert "network_plugin" in result.stdout
    assert "oidc_issuer_enabled" in result.stdout


def test_help_command_api_mgmt_topic() -> None:
    result = runner.invoke(app, ["help", "api-mgmt"])

    assert result.exit_code == 0
    assert "AzureFox Help :: api-mgmt" in result.stdout
    assert "Application Programming Interface (API) Management" in result.stdout
    assert "gateway_hostnames" in result.stdout
    assert "virtual_network_type" in result.stdout
    assert "active_subscription_count" in result.stdout
    assert "named_value_secret_count" in result.stdout


def test_help_command_vmss_topic() -> None:
    result = runner.invoke(app, ["help", "vmss"])

    assert result.exit_code == 0
    assert "AzureFox Help :: vmss" in result.stdout
    assert "Virtual Machine Scale Sets" in result.stdout
    assert "instance_count" in result.stdout
    assert "orchestration_mode" in result.stdout
    assert "public_ip_configuration_count" in result.stdout


def test_help_command_network_ports_topic() -> None:
    result = runner.invoke(app, ["help", "network-ports"])

    assert result.exit_code == 0
    assert "AzureFox Help :: network-ports" in result.stdout
    assert "NIC-backed public endpoints" in result.stdout
    assert "allow_source_summary" in result.stdout
    assert "exposure_confidence" in result.stdout


def test_help_command_rbac_topic() -> None:
    result = runner.invoke(app, ["help", "rbac"])

    assert result.exit_code == 0
    assert "AzureFox Help :: rbac" in result.stdout
    assert "Role-Based Access Control (RBAC)" in result.stdout
    assert "role_assignments" in result.stdout


def test_help_command_nics_topic() -> None:
    result = runner.invoke(app, ["help", "nics"])

    assert result.exit_code == 0
    assert "AzureFox Help :: nics" in result.stdout
    assert "network interfaces (NICs)" in result.stdout
    assert "attached_asset_name" in result.stdout
    assert "public IP references" in result.stdout
    assert "network_security_group_id" in result.stdout


def test_help_command_vms_topic() -> None:
    result = runner.invoke(app, ["help", "vms"])

    assert result.exit_code == 0
    assert "AzureFox Help :: vms" in result.stdout
    assert "virtual machines (VMs)" in result.stdout
    assert "public_ips" in result.stdout


def test_help_command_all_checks_topic_sets_runtime_expectations() -> None:
    result = runner.invoke(app, ["help", "all-checks"])

    assert result.exit_code == 0
    assert "AzureFox Help :: all-checks" in result.stdout
    assert "materially longer than a single command" in result.stdout
    assert "grouped results" in result.stdout


def test_help_command_env_vars_topic() -> None:
    result = runner.invoke(app, ["help", "env-vars"])

    assert result.exit_code == 0
    assert "AzureFox Help :: env-vars" in result.stdout
    assert "Key Vault references" in result.stdout
    assert "workload_identity_type" in result.stdout
    assert "setting_name" in result.stdout


def test_help_command_tokens_credentials_topic() -> None:
    result = runner.invoke(app, ["help", "tokens-credentials"])

    assert result.exit_code == 0
    assert "AzureFox Help :: tokens-credentials" in result.stdout
    assert "mint tokens" in result.stdout
    assert "operator_signal" in result.stdout


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
    assert "delegated or admin consent grants" in result.stdout
    assert "Fast mode is the default" in result.stdout
    assert "per-application owner and federated credential lookups" in result.stdout


def test_help_command_auth_policies_topic() -> None:
    result = runner.invoke(app, ["help", "auth-policies"])

    assert result.exit_code == 0
    assert "AzureFox Help :: auth-policies" in result.stdout
    assert "Conditional Access" in result.stdout
    assert "sign-in, consent, and identity hardening" in result.stdout
    assert "Unreadable policy surfaces stay explicit" in result.stdout
    assert "issues" in result.stdout


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


def test_help_command_workloads_topic() -> None:
    result = runner.invoke(app, ["help", "workloads"])

    assert result.exit_code == 0
    assert "AzureFox Help :: workloads" in result.stdout
    assert "joined workload census" in result.stdout
    assert "identity_type" in result.stdout
    assert "ingress_paths" in result.stdout


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
        ["azurefox", "all-checks", "--section", "identity", "--output", "json"]
    ) == [
        "azurefox",
        "--output",
        "json",
        "all-checks",
        "--section",
        "identity",
    ]
