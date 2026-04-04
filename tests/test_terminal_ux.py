from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from azurefox.cli import app
from azurefox.render.table import render_table

runner = CliRunner()


def _fixture_env() -> dict[str, str]:
    fixture_dir = Path(__file__).resolve().parent / "fixtures" / "lab_tenant"
    return {"AZUREFOX_FIXTURE_DIR": str(fixture_dir)}


def test_role_trusts_table_mode_includes_narration_and_takeaway(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "role-trusts"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert (
        "Reviewing high-signal identity trust edges without implying delegated or admin consent."
        in result.stdout
    )
    assert "why it matters" in result.stdout
    assert "Takeaway: 4 trust edges surfaced in fast mode" in result.stdout
    assert "Delegated and admin" in result.stdout
    assert "out of scope for this command." in result.stdout


def test_auth_policies_table_mode_surfaces_findings_and_issues(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "auth-policies"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert "current read path" in result.stdout
    assert "Findings:" in result.stdout
    assert "Security defaults are disabled" in result.stdout
    assert "Takeaway: 4 policy rows, 5 findings, and 0 collection issues" in result.stdout


def test_keyvault_table_mode_labels_implicit_open_acl(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "keyvault"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert "implicit allow (ACL omitted)" in result.stdout


def test_app_services_table_mode_surfaces_runtime_and_posture(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "app-services"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert (
        "Reviewing App Service runtime, hostname, identity, and hardening posture." in result.stdout
    )
    assert "app service" in result.stdout
    assert "DOTNETCORE|8.0" in result.stdout
    assert "hostname; public=Enabled" in result.stdout
    assert "https=no" in result.stdout
    assert "ftps=AllAllowed" in result.stdout
    assert (
        "Takeaway: 2 App Service apps visible; 2 keep public network access enabled, "
        "1 enforce HTTPS-only, and 2 carry managed identity context."
    ) in result.stdout


def test_acr_table_mode_surfaces_login_server_and_posture(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "acr"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert (
        "Reviewing Azure Container Registry login servers, auth posture, and network exposure."
        in result.stdout
    )
    assert "registry" in result.stdout
    assert "acr-public-legacy" in result.stdout
    assert "login server" in result.stdout
    assert "acr-ops-01.azurecr.io" in result.stdout
    assert "admin=yes" in result.stdout
    assert "anon-pull=yes" in result.stdout
    assert "public=Enabled" in result.stdout
    assert "pe=1" in result.stdout
    assert (
        "Takeaway: 2 registries visible; 1 keep public network access enabled, "
        "1 allow admin-user auth, and 1 permit anonymous pull."
    ) in result.stdout


def test_databases_table_mode_surfaces_server_inventory_and_posture(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "databases"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert (
        "Reviewing Azure SQL server posture and visible user-database inventory."
        in result.stdout
    )
    assert "server" in result.stdout
    assert "sql-public-legacy" in result.stdout
    assert "AzureSql" in result.stdout
    assert "dbs=2" in result.stdout
    assert "orders,reporting" in result.stdout
    assert "public=Enabled" in result.stdout
    assert "tls=1.2" in result.stdout
    assert (
        "Takeaway: 2 Azure SQL servers visible; 1 keep public network access enabled, "
        "1 carry managed identity context, and 3 user databases are visible."
    ) in result.stdout


def test_dns_table_mode_surfaces_zone_inventory_and_namespace_context(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "dns"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert (
        "Reviewing public and private DNS zone inventory and namespace boundaries."
        in result.stdout
    )
    assert "zone" in result.stdout
    assert "corp.example.com" in result.stdout
    assert "records=9/10000" in result.stdout
    assert "ns=4" in result.stdout
    assert "vnet-links=2" in result.stdout
    assert (
        "Takeaway: 3 DNS zones visible; 2 public, 1 private, and 19 record sets are visible."
        in result.stdout
    )


def test_aks_table_mode_surfaces_endpoint_and_auth_posture(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "aks"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert (
        "Reviewing AKS control-plane endpoint, identity, auth posture, and network shape."
        in result.stdout
    )
    assert "cluster" in result.stdout
    assert "aks-public-legacy" in result.stdout
    assert "aks-ops-01" in result.stdout
    assert "k8s=1.29.4" in result.stdout
    assert "private-api=yes" in result.stdout
    assert "ServicePrincipal" in result.stdout
    assert "workload-id=yes" in result.stdout
    assert "azure-rbac=yes" in result.stdout
    assert "oidc=yes" in result.stdout
    assert "plugin=azure" in result.stdout
    assert "addons=1" in result.stdout
    assert "webapp-routing=yes" in result.stdout
    normalized_output = " ".join(result.stdout.split())
    assert (
        "Takeaway: 2 AKS clusters visible; 1 use private API endpoints, "
        "2 expose cluster identity context, 1 enable Azure RBAC, and 1 show Azure-side "
        "federation cues."
    ) in normalized_output


def test_api_mgmt_table_mode_surfaces_gateway_and_inventory(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "api-mgmt"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert (
        "Reviewing API Management gateway hostnames, identity, and service posture."
        in result.stdout
    )
    assert "service" in result.stdout
    assert "apim-edge-01" in result.stdout
    assert "named-values=2" in result.stdout
    assert "gateway=2" in result.stdout
    assert "public=Enabled" in result.stdout
    assert (
        "Takeaway: 1 API Management services visible; 1 keep public network access enabled, "
        "1 carry managed identity context, and 2 named values are visible."
    ) in result.stdout


def test_functions_table_mode_surfaces_runtime_and_deployment(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "functions"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert (
        "Reviewing Function App runtime, storage binding, identity, and deployment posture."
        in result.stdout
    )
    assert "function app" in result.stdout
    assert "func-orders" in result.stdout
    assert "functions=~4" in result.stdout
    assert "storage=plain-text" in result.stdout
    assert "kv-refs=1" in result.stdout
    assert "always-on=yes" in result.stdout
    assert (
        "Takeaway: 1 Function Apps visible; 1 carry managed identity context, "
        "0 show run-from-package deployment, and 1 include Key Vault-backed settings."
    ) in result.stdout


def test_nics_table_mode_surfaces_network_context(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "nics"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert (
        "Enumerating NIC attachments, IP context, and network boundary references." in result.stdout
    )
    assert "public ip refs" in result.stdout
    assert "subnet=vnet-app" in result.stdout
    assert "nsg-web" in result.stdout
    assert (
        "Takeaway: 2 NICs visible; 1 attached to visible assets and 1 reference public IP "
        "resources." in result.stdout
    )


def test_workloads_table_mode_surfaces_joined_workload_context(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "workloads"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert (
        "Joining workload assets with identity context and visible ingress paths." in result.stdout
    )
    assert "direct-vm-ip" in result.stdout
    assert "UserAssigned" in result.stdout
    assert "vm-web-01" in result.stdout
    assert (
        "Takeaway: 5 workloads visible; 4 with visible endpoint paths, 4 with identity context, "
        "across 2 compute and 3 web assets." in result.stdout
    )


def test_privesc_table_mode_surfaces_takeaway(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "privesc"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert "Triage likely privilege-escalation and workload identity abuse paths." in result.stdout
    assert "why it matters" in result.stdout
    assert "Takeaway: 2 privilege-escalation paths surfaced" in result.stdout


def test_principals_table_mode_uses_curated_columns(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "principals"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert "identity context" in result.stdout
    assert "current" in result.stdout
    assert "Takeaway: 2 principals visible" in result.stdout


def test_arm_deployments_table_mode_surfaces_scope_and_linked_refs(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "arm-deployments"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert "linked refs" in result.stdout
    assert "sub:22222222-2222-2222-2222-22222222" in result.stdout
    assert "rg:rg-secrets" in result.stdout
    assert "template=example.blob.core.windows" in result.stdout
    assert (
        "Takeaway: 3 deployments visible; 1 at subscription scope and 5 findings." in result.stdout
    )


def test_endpoints_table_mode_surfaces_reachability_context(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "endpoints"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert (
        "Mapping reachable IP and hostname surfaces from compute and web workloads."
        in result.stdout
    )
    assert "family" in result.stdout
    assert "direct-vm-ip" in result.stdout
    assert "app-public-api.azurewebsites.net" in result.stdout
    assert (
        "Takeaway: 4 reachable surfaces visible; 1 public-ip, 3 managed-web-hostname."
        in result.stdout
    )


def test_network_effective_table_mode_surfaces_prioritized_reachability(
    tmp_path: Path,
) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "network-effective"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert (
        "Prioritizing likely public-IP reachability by combining visible endpoint and NSG evidence."
        in result.stdout
    )
    assert "internet ports" in result.stdout
    assert "TCP/22" in result.stdout
    assert "TCP/443" in result.stdout
    assert (
        "Takeaway: 1 public-IP exposure summaries visible; 1 high, 0 medium, 0 low"
        in result.stdout
    )


def test_network_ports_table_mode_surfaces_allow_context(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "network-ports"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert (
        "Tracing likely inbound port exposure from visible NIC and subnet NSG rules."
        in result.stdout
    )
    assert "allow source" in result.stdout
    assert "nic-nsg:rg-workload/nsg-web/allow-ssh-internet" in result.stdout
    assert "AzureLoadBalancer via" in result.stdout
    assert "subnet-nsg:rg-workload/nsg-vnet-app" in result.stdout
    assert "Takeaway: 3 port exposure rows visible; 1 high, 1 low, 1 medium." in result.stdout


def test_env_vars_table_mode_surfaces_findings_and_takeaway(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "env-vars"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert "Reviewing App Service and Function App settings" in result.stdout
    assert "identity" in result.stdout
    assert "SystemAssigned" in result.stdout
    assert "sensitive-name" in result.stdout
    assert "Key Vault-backed configuration" in result.stdout
    assert "Takeaway: 4 settings across 2 workloads;" in result.stdout


def test_tokens_credentials_table_mode_surfaces_findings_and_takeaway(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "tokens-credentials"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert "Correlating token-minting workloads" in result.stdout
    assert "operator signal" in result.stdout
    assert "plain-text-secret" in result.stdout
    assert "deployment-history" in result.stdout
    assert "Takeaway: 11 token or credential surfaces across 6 assets;" in result.stdout


def test_auth_policies_partial_read_surfaces_collection_issue() -> None:
    payload = {
        "metadata": {"command": "auth-policies"},
        "auth_policies": [],
        "findings": [],
        "issues": [
            {
                "kind": "permission_denied",
                "message": "auth_policies.security_defaults: 403 Forbidden",
                "context": {"collector": "auth_policies.security_defaults"},
            }
        ],
    }
    rendered = render_table("auth-policies", payload)

    assert "Collection issues:" in rendered
    assert "permission_denied" in rendered
    assert "auth_policies.security_defaults" in rendered


def test_app_services_partial_read_surfaces_collection_issue() -> None:
    payload = {
        "metadata": {"command": "app-services"},
        "app_services": [
            {
                "name": "app-empty-mi",
                "default_hostname": "app-empty-mi.azurewebsites.net",
                "runtime_stack": "DOTNETCORE|8.0",
                "workload_identity_type": "SystemAssigned",
                "public_network_access": "Enabled",
                "https_only": False,
                "min_tls_version": None,
                "ftps_state": None,
                "client_cert_enabled": False,
                "summary": "test",
            }
        ],
        "findings": [],
        "issues": [
            {
                "kind": "permission_denied",
                "message": "app_services[rg-apps/app-empty-mi].configuration: 403 Forbidden",
                "context": {"collector": "app_services[rg-apps/app-empty-mi].configuration"},
            }
        ],
    }
    rendered = render_table("app-services", payload)

    assert "Collection issues:" in rendered
    assert "permission_denied" in rendered
    assert "app_services[rg-apps/app-empty-mi].configuration" in rendered


def test_acr_collection_issue_surfaces_in_table_output() -> None:
    payload = {
        "metadata": {"command": "acr"},
        "registries": [],
        "findings": [],
        "issues": [
            {
                "kind": "permission_denied",
                "message": "acr.registries: 403 Forbidden",
                "context": {"collector": "acr.registries"},
            }
        ],
    }
    rendered = render_table("acr", payload)

    assert "No records" in rendered
    assert "Collection issues:" in rendered
    assert "permission_denied" in rendered
    assert "acr.registries" in rendered


def test_databases_partial_read_surfaces_collection_issue() -> None:
    payload = {
        "metadata": {"command": "databases"},
        "database_servers": [
            {
                "name": "sql-public-legacy",
                "engine": "AzureSql",
                "fully_qualified_domain_name": "sql-public-legacy.database.windows.net",
                "workload_identity_type": None,
                "database_count": None,
                "user_database_names": [],
                "public_network_access": "Enabled",
                "minimal_tls_version": "1.2",
                "server_version": "12.0",
                "state": "Ready",
                "summary": "test",
            }
        ],
        "findings": [],
        "issues": [
            {
                "kind": "permission_denied",
                "message": "databases[rg-data/sql-public-legacy].databases: 403 Forbidden",
                "context": {"collector": "databases[rg-data/sql-public-legacy].databases"},
            }
        ],
    }
    rendered = render_table("databases", payload)

    assert "Collection issues:" in rendered
    assert "permission_denied" in rendered
    assert "databases[rg-data/sql-public-legacy].databases" in rendered
    assert "database visibility is unreadable from at" in rendered
    assert "least one visible server" in rendered


def test_dns_collection_issue_surfaces_in_table_output() -> None:
    payload = {
        "metadata": {"command": "dns"},
        "dns_zones": [],
        "findings": [],
        "issues": [
            {
                "kind": "permission_denied",
                "message": "dns.resources: 403 Forbidden",
                "context": {"collector": "dns.resources"},
            }
        ],
    }
    rendered = render_table("dns", payload)

    assert "No records" in rendered
    assert "Collection issues:" in rendered
    assert "permission_denied" in rendered
    assert "dns.resources" in rendered


def test_functions_partial_read_surfaces_collection_issue() -> None:
    payload = {
        "metadata": {"command": "functions"},
        "function_apps": [
            {
                "name": "func-orders",
                "default_hostname": "func-orders.azurewebsites.net",
                "runtime_stack": "PYTHON|3.11",
                "functions_extension_version": "~4",
                "workload_identity_type": "SystemAssigned, UserAssigned",
                "azure_webjobs_storage_value_type": None,
                "run_from_package": None,
                "key_vault_reference_count": None,
                "public_network_access": "Enabled",
                "https_only": True,
                "min_tls_version": "1.2",
                "ftps_state": "Disabled",
                "always_on": True,
                "summary": "test",
            }
        ],
        "findings": [],
        "issues": [
            {
                "kind": "permission_denied",
                "message": "functions[rg-apps/func-orders].app_settings: 403 Forbidden",
                "context": {"collector": "functions[rg-apps/func-orders].app_settings"},
            }
        ],
    }
    rendered = render_table("functions", payload)

    assert "Collection issues:" in rendered
    assert "permission_denied" in rendered
    assert "functions[rg-apps/func-orders].app_settings" in rendered


def test_api_mgmt_partial_read_surfaces_collection_issue() -> None:
    payload = {
        "metadata": {"command": "api-mgmt"},
        "api_management_services": [
            {
                "name": "apim-edge-01",
                "gateway_hostnames": ["apim-edge-01.azure-api.net"],
                "management_hostnames": ["apim-edge-01.management.azure-api.net"],
                "portal_hostnames": ["portal.apim-edge-01.contoso.com"],
                "workload_identity_type": "SystemAssigned",
                "api_count": None,
                "backend_count": 1,
                "named_value_count": None,
                "public_network_access": "Enabled",
                "virtual_network_type": "External",
                "gateway_enabled": True,
                "developer_portal_status": "Enabled",
                "summary": "test",
            }
        ],
        "findings": [],
        "issues": [
            {
                "kind": "permission_denied",
                "message": "api_mgmt[rg-apps/apim-edge-01].named_values: 403 Forbidden",
                "context": {"collector": "api_mgmt[rg-apps/apim-edge-01].named_values"},
            }
        ],
    }
    rendered = render_table("api-mgmt", payload)

    assert "Collection issues:" in rendered
    assert "permission_denied" in rendered
    assert "api_mgmt[rg-apps/apim-edge-01].named_values" in rendered
    assert "named value visibility is unreadable" in rendered
    assert "at least one visible service" in rendered


def test_aks_collection_issue_surfaces_in_table_output() -> None:
    payload = {
        "metadata": {"command": "aks"},
        "aks_clusters": [],
        "findings": [],
        "issues": [
            {
                "kind": "permission_denied",
                "message": "aks.managed_clusters: 403 Forbidden",
                "context": {"collector": "aks.managed_clusters"},
            }
        ],
    }
    rendered = render_table("aks", payload)

    assert "No records" in rendered
    assert "Collection issues:" in rendered
    assert "permission_denied" in rendered
    assert "aks.managed_clusters" in rendered
