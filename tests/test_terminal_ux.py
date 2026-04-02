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
    assert "Takeaway: 4 trust edges surfaced" in result.stdout
    assert "Delegated and admin consent grants" in result.stdout
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
        "Takeaway: 5 workloads visible; 4 with reachable endpoints, 4 with identity context, "
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
    assert "app_services.configuration" in rendered
