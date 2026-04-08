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
        "Reviewing high-signal identity trust edges and the clearest next review without implying"
        in result.stdout
    )
    assert "operator signal" in result.stdout
    assert "next review" in result.stdout
    assert "Trust expansion visible; privilege" in result.stdout
    assert "confirmation next." in result.stdout
    assert "Check permissions for Azure control" in result.stdout
    assert "service principal 'build-sp'." in result.stdout
    assert "Takeaway: 4 trust edges surfaced in fast mode" in result.stdout
    assert "privilege-confirmation follow-ons" in result.stdout
    assert "Delegated and admin" in result.stdout
    assert "out of scope for this" in result.stdout
    assert "command." in result.stdout


def test_auth_policies_table_mode_surfaces_findings_and_issues(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "auth-policies"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert "current credentials" in result.stdout
    assert "Findings:" in result.stdout
    assert "Security defaults are disabled" in result.stdout
    assert "Takeaway: 4 policy rows, 5 findings, and 0 credential-scope issues" in result.stdout


def test_lighthouse_table_mode_surfaces_cross_tenant_scope_and_access(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "lighthouse"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert (
        "Reviewing Azure Lighthouse delegations for cross-tenant management scope and "
        "high-impact access cues." in result.stdout
    )
    assert "managing tenant" in result.stdout
    assert "managed tenant" in result.stdout
    assert "subscription::22222222-2222-" in result.stdout
    assert "Contoso Corp." in result.stdout
    assert "AzureFox Lab Tenant" in result.stdout
    assert "strongest=Owner" in result.stdout
    assert "eligible=1" in result.stdout
    assert "eligible=0" in result.stdout
    assert (
        "Takeaway: 3 Azure Lighthouse delegation(s) visible; 1 are subscription-scoped, "
        "1 grant Owner or User Access Administrator, and 1 include eligible access."
        in " ".join(result.stdout.split())
    )


def test_cross_tenant_table_mode_surfaces_control_pivot_and_policy_cues(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "cross-tenant"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert (
        "Reviewing outside-tenant trust, delegated management, and tenant policy cues that most "
        "change control or pivot paths." in result.stdout
    )
    assert "control via lighthouse" in result.stdout
    assert "pivot via external-sp" in result.stdout
    assert "entry via policy" in result.stdout
    assert "Contoso Corp." in result.stdout
    assert "guest invites:" in result.stdout
    assert (
        "Takeaway: 4 cross-tenant signal(s) visible; 3 high priority, 2 delegated management, "
        "1 externally owned service principal, and 1 tenant policy cue."
        in " ".join(result.stdout.split())
    )


def test_keyvault_table_mode_labels_implicit_open_acl(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "keyvault"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert "implicit allow (ACL omitted)" in result.stdout


def test_automation_table_mode_surfaces_identity_worker_and_asset_cues(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "automation"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert (
        "Reviewing Azure Automation accounts for identity, execution, webhook, worker, "
        "and secure-asset posture." in result.stdout
    )
    assert "automation account" in result.stdout
    assert "aa-hybrid-prod" in result.stdout
    assert "published=6/7" in result.stdout
    assert "webhooks=2" in result.stdout
    assert "groups=1" in result.stdout
    assert "cred=2" in result.stdout
    assert "vars=5 (4 enc)" in result.stdout
    normalized_output = " ".join(result.stdout.split())
    assert (
        "Takeaway: 2 Automation account(s) visible; 1 carry managed identity context, "
        "1 expose webhook start paths, 1 show Hybrid Runbook Worker reach, and 7 "
        "published runbooks are visible."
    ) in normalized_output


def test_devops_table_mode_surfaces_named_change_paths(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "devops"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert (
        "Reviewing Azure DevOps build definitions for trusted source inputs, visible injection "
        "surfaces, and Azure-facing change paths." in result.stdout
    )
    assert "project" in result.stdout
    assert "pipeline" in result.stdout
    assert "source" in result.stdout
    assert "execution path" in result.stdout
    assert "injection" in result.stdout
    assert "control path" in result.stdout
    assert "impact point" in result.stdout
    assert "next review" in result.stdout
    assert "deploy-aks-prod" in result.stdout
    assert "azure-repos" in result.stdout
    assert "github" in result.stdout
    assert "state=visible" in result.stdout
    assert "why it matters" in result.stdout
    normalized_output = " ".join(result.stdout.split())
    assert (
        "Takeaway: 4 Azure DevOps build definition(s) surfaced; 1 expose a proven "
        "current-credential injection point, 1 add queue-only support without poisoning proof, "
        "3 point to visible Azure Repos sources, 1 point to external sources, 1 trust non-repo "
        "inputs, and 4 show Azure-facing service connections."
    ) in normalized_output


def test_app_services_table_mode_surfaces_runtime_and_posture(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "app-services"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert (
        "Reviewing App Service runtime, hostname, identity, and ingress cues that change "
        "follow-on paths." in result.stdout
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
        "Reviewing Azure Container Registry login, auth, network, and registry "
        "automation/trust cues." in result.stdout
    )
    assert "registry" in result.stdout
    assert "acr-public-legacy" in result.stdout
    assert "login server" in result.stdout
    assert "admin=yes" in result.stdout
    assert "anon-pull=yes" in result.stdout
    assert "public=Enabled" in result.stdout
    assert "webhooks=2" in result.stdout
    assert "enabled=1" in result.stdout
    assert "replications=2" in result.stdout
    assert "retention=30d" in result.stdout
    assert "trust=notary" in result.stdout
    assert "pe=1" in result.stdout
    normalized_output = " ".join(result.stdout.split())
    assert (
        "Takeaway: 2 registries visible; 1 keep public network access enabled, "
        "1 allow admin-user auth, 3 webhooks are visible, and 1 registry replicates "
        "content into additional regions."
    ) in normalized_output


def test_databases_table_mode_surfaces_server_inventory_and_posture(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "databases"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert (
        "Reviewing relational database server posture across Azure SQL, PostgreSQL Flexible, "
        "and MySQL Flexible." in result.stdout
    )
    assert "server" in result.stdout
    assert "pg-public-legacy" in result.stdout
    assert "mysql-ops-01" in result.stdout
    assert "sql-public-legacy" in result.stdout
    assert "MySqlFlexible" in result.stdout
    assert "AzureSql" in result.stdout
    assert "dbs=2" in result.stdout
    assert "orders,reporting" in result.stdout
    assert "public=Enabled" in result.stdout
    assert "ha=zone-redundant" in result.stdout
    assert "private-dns=yes" in result.stdout
    assert "tls=1.2" in result.stdout
    normalized_output = " ".join(result.stdout.split())
    assert "PostgreSqlFlexib" in result.stdout
    assert (
        "Takeaway: 4 relational database servers visible across 3 engine families; "
        "2 keep public network access enabled, 2 carry managed identity context, and "
        "6 user databases are visible."
    ) in normalized_output


def test_snapshots_disks_table_mode_surfaces_priority_first_targets(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "snapshots-disks"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert (
        "Reviewing managed disks and snapshots for offline-copy, sharing/export, and "
        "encryption posture with highest-value targets first." in result.stdout
    )
    assert "priority" in result.stdout
    assert "data-detached-legacy" in result.stdout
    assert "detached" in result.stdout
    assert "allow-all" in result.stdout
    assert "disk-access" in result.stdout
    normalized_output = " ".join(result.stdout.split())
    assert (
        "Takeaway: 4 disk-backed assets visible; 2 snapshots, 1 detached disk, and 2 show "
        "broader sharing or export posture."
    ) in normalized_output


def test_snapshots_disks_takeaway_counts_disk_access_as_broad_export_signal() -> None:
    payload = {
        "metadata": {"command": "snapshots-disks"},
        "snapshot_disk_assets": [
            {
                "name": "disk-access-only",
                "asset_kind": "disk",
                "attachment_state": "attached",
                "public_network_access": "Disabled",
                "network_access_policy": "AllowPrivate",
                "max_shares": 1,
                "disk_access_id": (
                    "/subscriptions/test/resourceGroups/rg/providers/"
                    "Microsoft.Compute/diskAccesses/access-01"
                ),
                "related_ids": [],
                "summary": "test",
            }
        ],
        "issues": [],
        "findings": [],
    }

    rendered = render_table("snapshots-disks", payload)

    assert "1 show broader sharing or export posture" in " ".join(rendered.split())


def test_storage_takeaway_keeps_partial_read_posture_explicit() -> None:
    payload = {
        "metadata": {"command": "storage"},
        "storage_assets": [
            {
                "name": "st-partial",
                "public_access": False,
                "public_network_access": None,
                "allow_shared_key_access": None,
                "related_ids": [],
                "summary": "test",
            }
        ],
        "findings": [],
        "issues": [],
    }

    rendered = render_table("storage", payload)
    normalized = " ".join(rendered.split())

    assert "1 have unreadable public-network posture" in normalized
    assert "1 have unreadable shared-key posture" in normalized


def test_dns_table_mode_surfaces_zone_inventory_and_namespace_context(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "dns"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert (
        "Reviewing public and private DNS zone inventory and namespace boundaries." in result.stdout
    )
    assert "zone" in result.stdout
    assert "corp.example.com" in result.stdout
    assert "records=9/10000" in result.stdout
    assert "ns=4" in result.stdout
    assert "vnet-links=2" in result.stdout
    assert "pe-refs=2" in result.stdout
    assert (
        "Takeaway: 3 DNS zones visible; 2 public, 1 private, 1 private zone(s) show visible "
        "private endpoint references, and 19 record sets are visible." in result.stdout
    )


def test_vmss_table_mode_surfaces_identity_and_frontend_cues(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "vmss"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert (
        "Reviewing Virtual Machine Scale Sets (VMSS) for fleet posture, identity, and "
        "frontend network cues." in result.stdout
    )
    assert "scale set" in result.stdout
    assert "location" in result.stdout
    assert "vmss-edge-01" in result.stdout
    assert "eastus" in result.stdout
    assert "instances=6" in result.stdout
    assert "Uniform" in result.stdout
    assert "public-ip=1" in result.stdout
    assert "subnet=app" in result.stdout
    normalized_output = " ".join(result.stdout.split())
    assert (
        "Takeaway: 2 VM scale sets visible; 1 show public frontend cues, 1 carry managed "
        "identity context, and 8 configured instances are visible."
    ) in normalized_output


def test_aks_table_mode_surfaces_endpoint_and_auth_posture(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "aks"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert (
        "Reviewing AKS control-plane endpoint, identity, auth posture, and Azure-side "
        "federation and addon cues." in result.stdout
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
        "Reviewing API Management gateway hostnames, identity, subscription, backend, and "
        "secret posture." in result.stdout
    )
    assert "service" in result.stdout
    assert "apim-edge-01" in result.stdout
    assert "sub-required=1/2" in result.stdout
    assert "subs=3" in result.stdout
    assert "backend-hosts=1" in result.stdout
    assert "named-values=2" in result.stdout
    assert "named-secrets=1" in result.stdout
    assert "kv-backed=1" in result.stdout
    assert "gateway=2" in result.stdout
    assert "public=Enabled" in result.stdout
    normalized_output = " ".join(result.stdout.split())
    assert (
        "Takeaway: 1 API Management services visible; 1 keep public network access enabled, "
        "1 carry managed identity context, and 2 named values are visible, including 1 marked "
        "secret."
    ) in normalized_output


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
        "Takeaway: 6 workloads visible; 4 with visible endpoint paths, 5 with identity context, "
        "across 3 compute and 3 web assets." in result.stdout
    )


def test_privesc_table_mode_surfaces_takeaway(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "privesc"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert "Triage likely privilege-escalation and workload identity abuse paths." in result.stdout
    assert "starting foothold" in result.stdout
    assert "operator signal" in result.stdout
    assert "proof boundary" in result.stdout
    assert "next review" in result.stdout
    assert "(current foothold)" in result.stdout
    assert "Takeaway: 2 privilege-escalation paths surfaced; 1 current-identity-rooted" in result.stdout


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
        "Takeaway: 1 public-IP exposure summaries visible; 1 high, 0 medium, 0 low" in result.stdout
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
    assert "credential or secret follow-on" in result.stdout
    assert "identity" in result.stdout
    assert "next review" in result.stdout
    assert "SystemAssigned" in result.stdout
    assert "sensitive-name" in result.stdout
    assert "Key Vault-backed configuration" in result.stdout
    assert "Check keyvault for" in result.stdout
    assert "Takeaway: 4 settings across 2 workloads;" in result.stdout


def test_tokens_credentials_table_mode_surfaces_findings_and_takeaway(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "tokens-credentials"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert "next likely follow-on" in result.stdout
    assert "operator signal" in result.stdout
    assert "next review" in result.stdout
    assert "plain-text-secret" in result.stdout
    assert "deployment-history" in result.stdout
    assert "Check env-vars" in result.stdout
    assert "Takeaway: 12 token or credential surfaces across 7 assets;" in result.stdout


def test_managed_identities_table_mode_surfaces_next_review(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "managed-identities"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert "operator signal" in result.stdout
    assert "next review" in result.stdout
    assert "Public VM workload pivot" in result.stdout
    assert "Check permissions for direct control" in result.stdout
    assert "Takeaway: 1 managed identities visible; 1 exposed workload pivots" in result.stdout


def test_permissions_table_mode_surfaces_next_review(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "permissions"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    assert (
        "Ranking principals by high-impact RBAC exposure and the next likely follow-on."
        in result.stdout
    )
    assert "operator signal" in result.stdout
    assert "next review" in result.stdout
    assert "Direct control visible; current foothold." in result.stdout
    assert "Check privesc" in result.stdout
    assert "Takeaway: 1 of 2 principals hold high-impact RBAC roles;" in result.stdout


def test_chains_table_mode_surfaces_priority_and_next_review(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "chains", "credential-path"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    normalized_output = " ".join(result.stdout.split())
    assert "priority" in result.stdout
    assert "urgency" in result.stdout
    assert "next review" in result.stdout
    assert "note" in result.stdout
    assert "review-soon" in normalized_output
    assert "bookmark" in normalized_output
    assert "func-orders" in result.stdout
    assert "app-public-api" in result.stdout
    assert "Check vault access" in normalized_output
    assert "connection clues." in normalized_output
    assert "Secret-shaped clue" in normalized_output


def test_deployment_chains_table_mode_surfaces_source_oriented_columns(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "chains", "deployment-path"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    normalized_output = " ".join(result.stdout.split())
    assert "likely azure impact" in result.stdout
    assert "next review" in result.stdout
    assert "why care" in result.stdout
    assert "priority" in result.stdout
    assert "urgency" in result.stdout
    assert "path type" in result.stdout
    assert "confidence boundary" in result.stdout
    assert "deploy-aks-prod" in result.stdout
    assert "deploy-appservice-prod" in result.stdout
    assert "deploy-artifact-app-p" in result.stdout
    assert "plan-infra-prod" in result.stdout
    assert "aa-hybrid-prod" in result.stdout
    assert "aa-lab-quiet" in result.stdout
    assert "pivot-now" in normalized_output
    assert "upstream producer control" in normalized_output
    assert "trusted input" in normalized_output
    assert "execution hub" in normalized_output
    assert "secret-backed support" in normalized_output


def test_deployment_chains_table_mode_renders_why_care_as_detail_rows(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "chains", "deployment-path"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    lines = result.stdout.splitlines()
    main_header_lines = [line for line in lines if "┃ priority" in line]
    detail_header_lines = [line for line in lines if line.startswith("┃ why care")]

    assert main_header_lines
    assert all("why care" not in line for line in main_header_lines)
    assert detail_header_lines
    assert "Current credentials can already poison that trusted input" in result.stdout
    assert "Current evidence only shows that the trusted input exists" in result.stdout
    assert len(detail_header_lines) == 6


def test_escalation_chains_table_mode_renders_defended_current_foothold_story(
    tmp_path: Path,
) -> None:
    result = runner.invoke(
        app,
        ["--outdir", str(tmp_path), "chains", "escalation-path"],
        env=_fixture_env(),
    )

    assert result.exit_code == 0
    normalized_output = " ".join(result.stdout.split())
    assert "azurefox chains" in result.stdout
    assert "starting foothold" in result.stdout
    assert "path type" in result.stdout
    assert "stronger outcome" in result.stdout
    assert "why care" in result.stdout
    assert "azurefox-lab-sp" in normalized_output
    assert "(current" in normalized_output
    assert "foothold)" in normalized_output
    assert "current foothold direct control" in normalized_output
    assert "Owner across" in normalized_output
    assert "subscription-wide scope" in normalized_output
    assert (
        "The current foothold already sits on subscription-wide scope high-impact Azure control"
        in normalized_output
    )
    assert "Takeaway: 1 visible escalation paths; 1 high, 1 pivot-now" in result.stdout


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

    assert "Credential-scope issues:" in rendered
    assert "permission_denied" in rendered
    assert "auth_policies.security_defaults" in rendered


def test_chains_partial_target_visibility_prefers_issue_over_candidate_list() -> None:
    payload = {
        "metadata": {"command": "chains"},
        "paths": [
            {
                "priority": "low",
                "asset_name": "app-public-api",
                "setting_name": "DB_PASSWORD",
                "target_service": "database",
                "target_resolution": "visibility blocked",
                "target_names": [],
                "target_visibility_issue": (
                    "permission_denied: databases.servers: current credentials do not show "
                    "database visibility for at least one visible server"
                ),
                "visible_path": "Credential-like setting -> likely database path",
                "summary": (
                    "AppService 'app-public-api' exposes credential-like setting "
                    "'DB_PASSWORD', and the visible naming suggests a database path. "
                    "AzureFox cannot name candidate database targets because current "
                    "credentials do not show enough target-side visibility."
                ),
            }
        ],
        "issues": [
            {
                "kind": "permission_denied",
                "message": (
                    "databases.servers: current credentials do not show database visibility "
                    "for at least one visible server"
                ),
                "context": {"collector": "databases.servers"},
            }
        ],
    }
    rendered = render_table("chains", payload)

    assert "low" in rendered
    assert "visibility blocked" in rendered
    assert "permission_denied: databases.servers" in rendered
    assert "sql-public-legacy" not in rendered
    assert "Credential-scope issues:" in rendered


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

    assert "Credential-scope issues:" in rendered
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
    assert "Credential-scope issues:" in rendered
    assert "permission_denied" in rendered
    assert "acr.registries" in rendered


def test_acr_partial_replication_read_stays_explicit_in_takeaway() -> None:
    payload = {
        "metadata": {"command": "acr"},
        "registries": [
            {
                "name": "acr-public-legacy",
                "login_server": "acr-public-legacy.azurecr.io",
                "webhook_count": 1,
                "enabled_webhook_count": 1,
                "webhook_action_types": ["push"],
                "replication_count": None,
                "replication_regions": [],
                "public_network_access": "Enabled",
                "admin_user_enabled": True,
                "summary": "test",
            }
        ],
        "findings": [],
        "issues": [
            {
                "kind": "permission_denied",
                "message": "acr[rg-containers/acr-public-legacy].replications: 403 Forbidden",
                "context": {"collector": "acr[rg-containers/acr-public-legacy].replications"},
            }
        ],
    }
    rendered = render_table("acr", payload)

    normalized_rendered = " ".join(rendered.split())
    assert (
        "current credentials do not show replication visibility on at least one visible registry"
        in normalized_rendered
    )
    assert "acr[rg-containers/acr-public-legacy].replications" in rendered


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

    assert "Credential-scope issues:" in rendered
    assert "permission_denied" in rendered
    assert "databases[rg-data/sql-public-legacy].databases" in rendered
    assert (
        "current credentials do not show database visibility on at least one visible server"
        in " ".join(rendered.split())
    )
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
    assert "Credential-scope issues:" in rendered
    assert "permission_denied" in rendered
    assert "dns.resources" in rendered


def test_application_gateway_table_surfaces_shared_edge_risk_and_waf_state() -> None:
    payload = {
        "metadata": {"command": "application-gateway"},
        "application_gateways": [
            {
                "name": "agw-shared-edge-01",
                "public_frontend_count": 1,
                "private_frontend_count": 0,
                "public_ip_addresses": ["20.30.40.50"],
                "subnet_ids": [
                    "/subscriptions/test/resourceGroups/rg-edge/providers/Microsoft.Network/virtualNetworks/vnet-edge/subnets/appgw"
                ],
                "listener_count": 4,
                "request_routing_rule_count": 4,
                "backend_pool_count": 3,
                "backend_target_count": 5,
                "waf_enabled": False,
                "waf_mode": None,
                "firewall_policy_id": None,
                "summary": "shared public front door with weak visible edge controls",
            }
        ],
        "findings": [],
        "issues": [],
    }
    rendered = render_table("application-gateway", payload)

    assert "public=1 (20.30.40.50)" in rendered
    assert "listeners=4" in rendered
    assert "pools=3" in rendered
    assert "disabled" in rendered
    assert "shared public front doors" in rendered


def test_application_gateway_collection_issue_surfaces_in_table_output() -> None:
    payload = {
        "metadata": {"command": "application-gateway"},
        "application_gateways": [],
        "findings": [],
        "issues": [
            {
                "kind": "permission_denied",
                "message": "application_gateway.gateways: 403 Forbidden",
                "context": {"collector": "application_gateway.gateways"},
            }
        ],
    }
    rendered = render_table("application-gateway", payload)

    assert "No records" in rendered
    assert "Credential-scope issues:" in rendered
    assert "permission_denied" in rendered
    assert "application_gateway.gateways" in rendered


def test_application_gateway_partial_read_keeps_public_frontend_without_ip_string() -> None:
    payload = {
        "metadata": {"command": "application-gateway"},
        "application_gateways": [
            {
                "name": "agw-shared-edge-01",
                "public_frontend_count": 1,
                "private_frontend_count": 0,
                "public_ip_addresses": [],
                "subnet_ids": [
                    "/subscriptions/test/resourceGroups/rg-edge/providers/Microsoft.Network/virtualNetworks/vnet-edge/subnets/appgw"
                ],
                "listener_count": 4,
                "request_routing_rule_count": 4,
                "backend_pool_count": 3,
                "backend_target_count": 5,
                "waf_enabled": False,
                "waf_mode": None,
                "firewall_policy_id": None,
                "summary": (
                    "Application Gateway 'agw-shared-edge-01' publishes 1 public frontend(s). "
                    "Visible routing breadth: 4 listener(s), 4 routing rule(s), 3 backend "
                    "pool(s), 5 backend target(s). Visible WAF protection is disabled. "
                    "This is a shared front door, so if the edge is weak the apps behind it "
                    "may deserve review next."
                ),
            }
        ],
        "findings": [],
        "issues": [
            {
                "kind": "permission_denied",
                "message": "application_gateway.public_ip_addresses: 403 Forbidden",
                "context": {"collector": "application_gateway.public_ip_addresses"},
            }
        ],
    }
    rendered = render_table("application-gateway", payload)

    assert "public=1; subnets=1" in rendered
    assert "20.30.40.50" not in rendered
    assert "Credential-scope issues:" in rendered


def test_application_gateway_takeaway_counts_backend_pool_breadth_as_shared_signal() -> None:
    payload = {
        "metadata": {"command": "application-gateway"},
        "application_gateways": [
            {
                "name": "agw-pool-heavy",
                "public_frontend_count": 1,
                "private_frontend_count": 0,
                "public_ip_addresses": ["20.30.40.70"],
                "listener_count": 1,
                "request_routing_rule_count": 1,
                "backend_pool_count": 3,
                "backend_target_count": 0,
                "waf_enabled": True,
                "waf_mode": "Prevention",
                "firewall_policy_id": None,
                "summary": "pool-heavy gateway",
            }
        ],
        "findings": [],
        "issues": [],
    }
    rendered = render_table("application-gateway", payload)

    assert "shared public front doors" in rendered


def test_dns_table_surfaces_private_endpoint_reference_count() -> None:
    payload = {
        "metadata": {"command": "dns"},
        "dns_zones": [
            {
                "name": "privatelink.database.windows.net",
                "zone_kind": "private",
                "record_set_count": 6,
                "max_record_set_count": 25000,
                "linked_virtual_network_count": 2,
                "registration_virtual_network_count": 1,
                "private_endpoint_reference_count": 2,
                "summary": "test",
            }
        ],
        "findings": [],
        "issues": [],
    }
    rendered = render_table("dns", payload)

    assert "namespace" in rendered
    assert "pe-refs=2" in rendered
    assert "private zone(s) show visible private endpoint references" in rendered


def test_storage_table_surfaces_depth_columns() -> None:
    payload = {
        "metadata": {"command": "storage"},
        "storage_assets": [
            {
                "name": "stlabpub01",
                "resource_group": "rg-data",
                "public_access": True,
                "public_network_access": "Enabled",
                "network_default_action": "Allow",
                "private_endpoint_enabled": False,
                "allow_shared_key_access": True,
                "minimum_tls_version": "TLS1_0",
                "https_traffic_only_enabled": False,
                "is_hns_enabled": False,
                "is_sftp_enabled": False,
                "nfs_v3_enabled": False,
                "dns_endpoint_type": "Standard",
                "container_count": 3,
                "file_share_count": 1,
                "queue_count": 2,
                "table_count": 0,
            }
        ],
        "findings": [],
        "issues": [],
    }
    rendered = render_table("storage", payload)

    assert "auth / transport" in rendered
    assert "protocols" in rendered
    assert "blob-public=yes" in rendered
    assert "public-net=enabled" in rendered
    assert "shared-key=yes" in rendered
    assert "https-only=no" in rendered
    assert "dns=standard" in rendered
    assert "blob=3" in rendered
    assert "allow shared-key access" in rendered


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

    assert "Credential-scope issues:" in rendered
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

    assert "Credential-scope issues:" in rendered
    assert "permission_denied" in rendered
    assert "api_mgmt[rg-apps/apim-edge-01].named_values" in rendered
    assert "current credentials do not show named values" in " ".join(rendered.split())
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
    assert "Credential-scope issues:" in rendered
    assert "permission_denied" in rendered
    assert "aks.managed_clusters" in rendered
