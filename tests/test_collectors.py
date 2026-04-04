from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from azurefox.collectors.commands import (
    collect_acr,
    collect_aks,
    collect_api_mgmt,
    collect_app_services,
    collect_arm_deployments,
    collect_auth_policies,
    collect_databases,
    collect_dns,
    collect_endpoints,
    collect_env_vars,
    collect_functions,
    collect_inventory,
    collect_keyvault,
    collect_managed_identities,
    collect_network_effective,
    collect_network_ports,
    collect_nics,
    collect_permissions,
    collect_principals,
    collect_privesc,
    collect_rbac,
    collect_resource_trusts,
    collect_role_trusts,
    collect_storage,
    collect_tokens_credentials,
    collect_vms,
    collect_whoami,
    collect_workloads,
)
from azurefox.collectors.provider import (
    AzureProvider,
    FixtureProvider,
    _acr_registry_summary,
    _aks_cluster_summary,
    _database_server_summary,
    _env_var_reference_target,
    _network_effective_row_from_endpoint,
    _network_scope_label,
    _normalized_arm_enum,
    _principal_from_claims,
    _web_asset_kind,
)
from azurefox.config import GlobalOptions
from azurefox.models.common import OutputMode, RoleTrustsMode


class MetadataFixtureProvider(FixtureProvider):
    def metadata_context(self) -> dict[str, str | None]:
        return {
            "tenant_id": "tenant-from-provider",
            "subscription_id": "subscription-from-provider",
            "token_source": "azure_cli",
        }


class PartialAuthPoliciesFixtureProvider(FixtureProvider):
    def auth_policies(self) -> dict:
        return {
            "auth_policies": [
                {
                    "policy_type": "authorization-policy",
                    "name": "Authorization Policy",
                    "state": "configured",
                    "scope": "tenant",
                    "controls": [
                        "guest-invites:everyone",
                        "users-can-register-apps",
                        "user-consent:self-service",
                    ],
                    "summary": (
                        "guest invites: everyone; users can register apps; "
                        "self-service permission grant policies assigned"
                    ),
                    "related_ids": ["authorizationPolicy"],
                }
            ],
            "issues": [
                {
                    "kind": "permission_denied",
                    "message": "auth_policies.security_defaults: 403 Forbidden",
                    "context": {"collector": "auth_policies.security_defaults"},
                }
            ],
        }


class ConditionalAccessUnreadableFixtureProvider(FixtureProvider):
    def auth_policies(self) -> dict:
        return {
            "auth_policies": [
                {
                    "policy_type": "security-defaults",
                    "name": "Security Defaults",
                    "state": "disabled",
                    "scope": "tenant",
                    "controls": [],
                    "summary": "Security defaults are disabled for the tenant.",
                    "related_ids": ["security-defaults"],
                },
                {
                    "policy_type": "authorization-policy",
                    "name": "Authorization Policy",
                    "state": "configured",
                    "scope": "tenant",
                    "controls": [
                        "guest-invites:everyone",
                        "users-can-register-apps",
                        "user-consent:self-service",
                    ],
                    "summary": (
                        "guest invites: everyone; users can register apps; "
                        "self-service permission grant policies assigned"
                    ),
                    "related_ids": ["authorizationPolicy"],
                },
            ],
            "issues": [
                {
                    "kind": "permission_denied",
                    "message": "auth_policies.conditional_access: 403 Forbidden",
                    "context": {"collector": "auth_policies.conditional_access"},
                }
            ],
        }


class FakeRoleTrustsGraph:
    def list_service_principals(self) -> list[dict]:
        return [
            {
                "id": "66666666-6666-6666-6666-666666666666",
                "appId": "55555555-5555-5555-5555-555555555550",
                "displayName": "build-sp",
                "servicePrincipalType": "Application",
            },
            {
                "id": "99999999-9999-9999-9999-999999999999",
                "appId": "99999999-9999-9999-9999-999999999990",
                "displayName": "reporting-sp",
                "servicePrincipalType": "Application",
            },
            {
                "id": "00000003-0000-0000-c000-000000000000",
                "appId": "00000003-0000-0000-c000-000000000000",
                "displayName": "Microsoft Graph",
                "servicePrincipalType": "Application",
            },
        ]

    def list_applications(self) -> list[dict]:
        return [
            {
                "id": "55555555-5555-5555-5555-555555555555",
                "appId": "55555555-5555-5555-5555-555555555550",
                "displayName": "build-app",
            }
        ]

    def get_application_by_app_id(self, app_id: str) -> dict | None:
        if app_id == "55555555-5555-5555-5555-555555555550":
            return {
                "id": "55555555-5555-5555-5555-555555555555",
                "appId": "55555555-5555-5555-5555-555555555550",
                "displayName": "build-app",
            }
        return None

    def list_application_federated_credentials(self, application_id: str) -> list[dict]:
        if application_id != "55555555-5555-5555-5555-555555555555":
            return []
        return [
            {
                "id": "fic-build-main",
                "issuer": "https://token.actions.githubusercontent.com",
                "subject": "repo:TacoRocket/AzureFox:ref:refs/heads/main",
            }
        ]

    def list_application_owners(self, application_id: str) -> list[dict]:
        if application_id != "55555555-5555-5555-5555-555555555555":
            return []
        return [
            {
                "id": "77777777-7777-7777-7777-777777777777",
                "userPrincipalName": "ci-admin@lab.local",
                "@odata.type": "#microsoft.graph.user",
            }
        ]

    def list_service_principal_owners(self, service_principal_id: str) -> list[dict]:
        if service_principal_id != "66666666-6666-6666-6666-666666666666":
            return []
        return [
            {
                "id": "88888888-8888-8888-8888-888888888888",
                "displayName": "automation-runner",
                "appId": "88888888-8888-8888-8888-888888888880",
            }
        ]

    def list_app_role_assignments(self, service_principal_id: str) -> list[dict]:
        if service_principal_id != "99999999-9999-9999-9999-999999999999":
            return []
        return [
            {
                "id": "app-role-graph-1",
                "resourceId": "00000003-0000-0000-c000-000000000000",
            }
        ]

    def get_service_principal(self, service_principal_id: str) -> dict:
        for item in self.list_service_principals():
            if item["id"] == service_principal_id:
                return item
        raise AssertionError(f"unexpected service principal lookup: {service_principal_id}")


class BrokenStorageList:
    def list(self, _resource_group: str, _account_name: str):
        raise PermissionError("403 Forbidden")


class FakeStorageAccounts:
    def list(self):
        account = type("StorageAccount", (), {})()
        account.id = (
            "/subscriptions/test/resourceGroups/rg-storage/providers/"
            "Microsoft.Storage/storageAccounts/stpartial01"
        )
        account.name = "stpartial01"
        account.location = "eastus"
        account.allow_blob_public_access = False
        account.network_rule_set = None
        account.private_endpoint_connections = []
        return [account]


class FakeStorageClient:
    def __init__(self) -> None:
        self.storage_accounts = FakeStorageAccounts()
        self.blob_containers = BrokenStorageList()
        self.file_shares = BrokenStorageList()
        self.queue = BrokenStorageList()
        self.table = BrokenStorageList()


class PartialAppServicesFixtureProvider(FixtureProvider):
    def app_services(self) -> dict:
        data = self._read("app_services")
        return {
            "app_services": [data["app_services"][0]],
            "issues": [
                {
                    "kind": "permission_denied",
                    "message": "app_services[rg-apps/app-empty-mi].configuration: 403 Forbidden",
                    "context": {"collector": "app_services[rg-apps/app-empty-mi].configuration"},
                }
            ],
        }


class PartialFunctionsFixtureProvider(FixtureProvider):
    def functions(self) -> dict:
        data = self._read("functions")
        row = dict(data["function_apps"][0])
        row["azure_webjobs_storage_value_type"] = None
        row["azure_webjobs_storage_reference_target"] = None
        row["run_from_package"] = None
        row["key_vault_reference_count"] = None
        return {
            "function_apps": [row],
            "issues": [
                {
                    "kind": "permission_denied",
                    "message": "functions[rg-apps/func-orders].app_settings: 403 Forbidden",
                    "context": {"collector": "functions[rg-apps/func-orders].app_settings"},
                }
            ],
        }


class PartialApiMgmtFixtureProvider(FixtureProvider):
    def api_mgmt(self) -> dict:
        data = self._read("api_mgmt")
        row = dict(data["api_management_services"][0])
        row["api_count"] = None
        row["api_subscription_required_count"] = None
        row["backend_count"] = None
        row["backend_hostnames"] = []
        row["named_value_count"] = None
        row["named_value_secret_count"] = None
        row["named_value_key_vault_count"] = None
        return {
            "api_management_services": [row],
            "issues": [
                {
                    "kind": "permission_denied",
                    "message": "api_mgmt[rg-apps/apim-edge-01].apis: 403 Forbidden",
                    "context": {"collector": "api_mgmt[rg-apps/apim-edge-01].apis"},
                },
                {
                    "kind": "permission_denied",
                    "message": "api_mgmt[rg-apps/apim-edge-01].backends: 403 Forbidden",
                    "context": {"collector": "api_mgmt[rg-apps/apim-edge-01].backends"},
                },
                {
                    "kind": "permission_denied",
                    "message": "api_mgmt[rg-apps/apim-edge-01].named_values: 403 Forbidden",
                    "context": {"collector": "api_mgmt[rg-apps/apim-edge-01].named_values"},
                },
            ],
        }


class NetworkEffectiveSnapshotFixtureProvider(FixtureProvider):
    def __init__(self, fixture_dir: Path) -> None:
        super().__init__(fixture_dir)
        self.endpoint_calls = 0
        self.seen_endpoint_data: dict | None = None

    def endpoints(self) -> dict:
        self.endpoint_calls += 1
        return {
            "endpoints": [
                {
                    "source_asset_id": (
                        "/subscriptions/test/resourceGroups/rg/providers/Microsoft.Compute/"
                        "virtualMachines/vm-01"
                    ),
                    "source_asset_name": "vm-01",
                    "source_asset_kind": "VM",
                    "endpoint": "1.2.3.4",
                    "endpoint_type": "ip",
                    "exposure_family": "public-ip",
                    "ingress_path": "public-ip",
                    "related_ids": [],
                }
            ],
            "issues": [
                {
                    "kind": "permission_denied",
                    "message": "endpoints.vm-01: 403 Forbidden",
                    "context": {"collector": "endpoints.vm-01"},
                }
            ],
        }

    def network_ports(self, endpoint_data: dict | None = None) -> dict:
        self.seen_endpoint_data = endpoint_data
        endpoint = (endpoint_data or {}).get("endpoints", [])[0]
        return {
            "network_ports": [
                {
                    "asset_id": endpoint.get("source_asset_id"),
                    "asset_name": endpoint.get("source_asset_name"),
                    "endpoint": endpoint.get("endpoint"),
                    "protocol": "tcp",
                    "port": "443",
                    "allow_source_summary": "0.0.0.0/0 via nic-nsg:rg/nsg-web/allow-https",
                    "exposure_confidence": "high",
                    "summary": "test",
                    "related_ids": [],
                }
            ],
            "issues": [*((endpoint_data or {}).get("issues", []))],
        }


class PartialAksFixtureProvider(FixtureProvider):
    def aks(self) -> dict:
        return {
            "aks_clusters": [],
            "issues": [
                {
                    "kind": "permission_denied",
                    "message": "aks.managed_clusters: 403 Forbidden",
                    "context": {"collector": "aks.managed_clusters"},
                }
            ],
        }


class PartialAcrFixtureProvider(FixtureProvider):
    def acr(self) -> dict:
        return {
            "registries": [],
            "issues": [
                {
                    "kind": "permission_denied",
                    "message": "acr.registries: 403 Forbidden",
                    "context": {"collector": "acr.registries"},
                }
            ],
        }


class PartialAcrDepthFixtureProvider(FixtureProvider):
    def acr(self) -> dict:
        data = self._read("acr")
        row = dict(data["registries"][0])
        row["webhook_count"] = None
        row["enabled_webhook_count"] = None
        row["webhook_action_types"] = []
        row["broad_webhook_scope_count"] = None
        row["replication_count"] = None
        row["replication_regions"] = []
        return {
            "registries": [row],
            "issues": [
                {
                    "kind": "permission_denied",
                    "message": "acr[rg-containers/acr-public-legacy].webhooks: 403 Forbidden",
                    "context": {
                        "collector": "acr[rg-containers/acr-public-legacy].webhooks"
                    },
                },
                {
                    "kind": "permission_denied",
                    "message": "acr[rg-containers/acr-public-legacy].replications: 403 Forbidden",
                    "context": {
                        "collector": "acr[rg-containers/acr-public-legacy].replications"
                    },
                },
            ],
        }


class PartialDatabasesFixtureProvider(FixtureProvider):
    def databases(self) -> dict:
        data = self._read("databases")
        row = dict(data["database_servers"][0])
        row["database_count"] = None
        row["user_database_names"] = []
        return {
            "database_servers": [row],
            "issues": [
                {
                    "kind": "permission_denied",
                    "message": "databases[rg-data/sql-public-legacy].databases: 403 Forbidden",
                    "context": {
                        "collector": "databases[rg-data/sql-public-legacy].databases"
                    },
                }
            ],
        }


class PartialDnsFixtureProvider(FixtureProvider):
    def dns(self) -> dict:
        return {
            "dns_zones": [],
            "issues": [
                {
                    "kind": "permission_denied",
                    "message": "dns.resources: 403 Forbidden",
                    "context": {"collector": "dns.resources"},
                }
            ],
        }


def test_collect_whoami(fixture_provider, options) -> None:
    output = collect_whoami(fixture_provider, options)
    assert output.principal is not None
    assert output.principal.id == "33333333-3333-3333-3333-333333333333"


def test_principal_from_claims_prefers_user_for_delegated_tokens() -> None:
    principal = _principal_from_claims(
        {
            "oid": "1058bd62-c9bd-4332-b6c4-bcf3f90f1c4e",
            "appid": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
            "scp": "user_impersonation",
            "name": "Colby Farley",
            "tid": "tenant-id",
        },
        tenant_id="tenant-id",
    )

    assert principal.id == "1058bd62-c9bd-4332-b6c4-bcf3f90f1c4e"
    assert principal.principal_type == "User"


def test_principal_from_claims_keeps_app_tokens_as_service_principals() -> None:
    principal = _principal_from_claims(
        {
            "oid": "52dae25a-117d-4e2b-8a15-81ee220c1b7a",
            "appid": "deferred-client-id",
            "idtyp": "app",
            "name": "af-roletrust-client",
            "tid": "tenant-id",
        },
        tenant_id="tenant-id",
    )

    assert principal.id == "52dae25a-117d-4e2b-8a15-81ee220c1b7a"
    assert principal.principal_type == "ServicePrincipal"


def test_collect_inventory(fixture_provider, options) -> None:
    output = collect_inventory(fixture_provider, options)
    assert output.resource_group_count == 4
    assert output.resource_count == 30


def test_collect_app_services(fixture_provider, options) -> None:
    output = collect_app_services(fixture_provider, options)
    assert len(output.app_services) == 2
    assert len(output.findings) == 0
    assert output.app_services[0].name == "app-empty-mi"
    assert output.app_services[0].runtime_stack == "DOTNETCORE|8.0"
    assert output.app_services[0].https_only is False
    assert output.app_services[1].client_cert_enabled is True


def test_collect_acr(fixture_provider, options) -> None:
    output = collect_acr(fixture_provider, options)
    assert len(output.registries) == 2
    assert len(output.findings) == 0
    assert output.registries[0].name == "acr-public-legacy"
    assert output.registries[0].admin_user_enabled is True
    assert output.registries[0].anonymous_pull_enabled is True
    assert output.registries[0].webhook_count == 2
    assert output.registries[0].enabled_webhook_count == 1
    assert output.registries[0].webhook_action_types == ["delete", "push"]
    assert output.registries[0].broad_webhook_scope_count == 1
    assert len(output.registries[0].related_ids) == 3
    assert output.registries[1].name == "acr-ops-01"
    assert output.registries[1].private_endpoint_connection_count == 1
    assert output.registries[1].replication_count == 2
    assert output.registries[1].replication_regions == ["northeurope", "westus2"]
    assert output.registries[1].retention_policy_days == 30
    assert output.registries[1].trust_policy_status == "enabled"
    assert len(output.registries[1].related_ids) == 5
    assert output.registries[1].workload_identity_type == "SystemAssigned"


def test_collect_databases(fixture_provider, options) -> None:
    output = collect_databases(fixture_provider, options)
    assert len(output.database_servers) == 4
    assert len(output.findings) == 0
    assert output.database_servers[0].name == "sql-public-legacy"
    assert output.database_servers[0].engine == "AzureSql"
    assert output.database_servers[0].database_count == 2
    assert output.database_servers[0].public_network_access == "Enabled"
    assert output.database_servers[1].name == "sql-ops-01"
    assert output.database_servers[1].workload_identity_type == "SystemAssigned"
    assert output.database_servers[1].user_database_names == ["appdb"]
    assert output.database_servers[2].engine == "PostgreSqlFlexible"
    assert output.database_servers[2].name == "pg-public-legacy"
    assert output.database_servers[2].database_count == 2
    assert output.database_servers[2].public_network_access == "Enabled"
    assert output.database_servers[3].name == "mysql-ops-01"
    assert output.database_servers[3].engine == "MySqlFlexible"
    assert output.database_servers[3].high_availability_mode == "zone-redundant"
    assert output.database_servers[3].private_dns_zone_resource_id is not None
    assert output.database_servers[3].workload_identity_type == "SystemAssigned"
    assert output.database_servers[3].user_database_names == ["inventory"]


def test_collect_databases_keeps_nested_inventory_issue_explicit(
    fixture_dir: Path, options
) -> None:
    provider = PartialDatabasesFixtureProvider(fixture_dir)

    output = collect_databases(provider, options)

    assert len(output.database_servers) == 1
    assert output.database_servers[0].database_count is None
    assert output.issues[0].kind == "permission_denied"
    assert (
        output.issues[0].context["collector"]
        == "databases[rg-data/sql-public-legacy].databases"
    )


def test_collect_dns(fixture_provider, options) -> None:
    output = collect_dns(fixture_provider, options)
    assert len(output.dns_zones) == 3
    assert len(output.findings) == 0
    assert output.dns_zones[0].name == "corp.example.com"
    assert output.dns_zones[0].zone_kind == "public"
    assert len(output.dns_zones[0].name_servers) == 4
    assert output.dns_zones[2].name == "privatelink.database.windows.net"
    assert output.dns_zones[2].zone_kind == "private"
    assert output.dns_zones[2].linked_virtual_network_count == 2
    assert output.dns_zones[2].registration_virtual_network_count == 1


def test_collect_dns_keeps_command_level_issue_explicit(
    fixture_dir: Path, options
) -> None:
    provider = PartialDnsFixtureProvider(fixture_dir)

    output = collect_dns(provider, options)

    assert output.dns_zones == []
    assert output.issues[0].kind == "permission_denied"
    assert output.issues[0].context["collector"] == "dns.resources"


def test_collect_network_effective(fixture_provider, options) -> None:
    output = collect_network_effective(fixture_provider, options)
    assert len(output.effective_exposures) == 1
    assert len(output.findings) == 0
    assert output.effective_exposures[0].asset_name == "vm-web-01"
    assert output.effective_exposures[0].effective_exposure == "high"
    assert output.effective_exposures[0].internet_exposed_ports == ["TCP/22"]
    assert output.effective_exposures[0].constrained_ports == ["TCP/443", "TCP/8080"]


def test_collect_network_effective_reuses_one_endpoint_snapshot_and_keeps_issues(
    fixture_dir: Path, options
) -> None:
    provider = NetworkEffectiveSnapshotFixtureProvider(fixture_dir)

    output = collect_network_effective(provider, options)

    assert provider.endpoint_calls == 1
    assert provider.seen_endpoint_data is not None
    assert provider.seen_endpoint_data["issues"][0]["context"]["collector"] == "endpoints.vm-01"
    assert len(output.effective_exposures) == 1
    assert output.effective_exposures[0].asset_name == "vm-01"
    assert output.issues[0].context["collector"] == "endpoints.vm-01"


def test_network_effective_no_nsg_observation_stays_cautious() -> None:
    asset_id = (
        "/subscriptions/test/resourceGroups/rg/providers/Microsoft.Compute/"
        "virtualMachines/vm-01"
    )
    row = _network_effective_row_from_endpoint(
        endpoint={
            "source_asset_id": asset_id,
            "source_asset_name": "vm-01",
            "endpoint": "1.2.3.4",
            "endpoint_type": "ip",
            "related_ids": [],
        },
        network_ports=[
            {
                "asset_id": asset_id,
                "asset_name": "vm-01",
                "endpoint": "1.2.3.4",
                "protocol": "any",
                "port": "any",
                "allow_source_summary": "no Azure NSG visible on NIC or subnet",
                "exposure_confidence": "low",
                "summary": "test",
                "related_ids": [],
            }
        ],
    )

    assert row["effective_exposure"] == "low"
    assert row["internet_exposed_ports"] == []
    assert row["constrained_ports"] == []
    assert "no Azure NSG was visible" in row["summary"]


def test_network_effective_treats_cidr_internet_sources_as_broad() -> None:
    asset_id = (
        "/subscriptions/test/resourceGroups/rg/providers/Microsoft.Compute/"
        "virtualMachines/vm-01"
    )
    row = _network_effective_row_from_endpoint(
        endpoint={
            "source_asset_id": asset_id,
            "source_asset_name": "vm-01",
            "endpoint": "1.2.3.4",
            "endpoint_type": "ip",
            "related_ids": [],
        },
        network_ports=[
            {
                "asset_id": asset_id,
                "asset_name": "vm-01",
                "endpoint": "1.2.3.4",
                "protocol": "tcp",
                "port": "443",
                "allow_source_summary": "0.0.0.0/0 via nic-nsg:rg/nsg-web/allow-https",
                "exposure_confidence": "high",
                "summary": "test",
                "related_ids": [],
            }
        ],
    )

    assert row["effective_exposure"] == "high"
    assert row["internet_exposed_ports"] == ["TCP/443"]
    assert row["constrained_ports"] == []
    assert "internet-facing allow evidence on TCP/443" in row["summary"]


def test_collect_acr_keeps_command_level_issue_explicit(
    fixture_dir: Path, options
) -> None:
    provider = PartialAcrFixtureProvider(fixture_dir)

    output = collect_acr(provider, options)

    assert output.registries == []
    assert output.issues[0].kind == "permission_denied"
    assert output.issues[0].context["collector"] == "acr.registries"


def test_collect_acr_keeps_nested_depth_visibility_explicit(
    fixture_dir: Path, options
) -> None:
    provider = PartialAcrDepthFixtureProvider(fixture_dir)

    output = collect_acr(provider, options)

    assert len(output.registries) == 1
    assert output.registries[0].webhook_count is None
    assert output.registries[0].enabled_webhook_count is None
    assert output.registries[0].webhook_action_types == []
    assert output.registries[0].replication_count is None
    assert output.registries[0].replication_regions == []
    assert [issue.context["collector"] for issue in output.issues] == [
        "acr[rg-containers/acr-public-legacy].webhooks",
        "acr[rg-containers/acr-public-legacy].replications",
    ]


def test_acr_registry_summary_rolls_up_management_plane_depth_cues() -> None:
    registry = SimpleNamespace(
        id="/subscriptions/test/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/acr-01",
        name="acr-01",
        location="eastus",
        provisioning_state="Succeeded",
        login_server="acr-01.azurecr.io",
        sku=SimpleNamespace(name="Premium"),
        public_network_access="Enabled",
        network_rule_bypass_options="AzureServices",
        network_rule_set=SimpleNamespace(default_action="Allow"),
        admin_user_enabled=True,
        anonymous_pull_enabled=False,
        data_endpoint_enabled=True,
        private_endpoint_connections=[],
        identity=SimpleNamespace(
            type="SystemAssigned",
            principal_id="principal-1",
            client_id="client-1",
            user_assigned_identities={},
        ),
        policies=SimpleNamespace(
            quarantine_policy=SimpleNamespace(status="disabled"),
            retention_policy=SimpleNamespace(status="enabled", days=15),
            trust_policy=SimpleNamespace(status="enabled", type="Notary"),
        ),
    )
    webhooks = [
        SimpleNamespace(
            id="/subscriptions/test/.../webhooks/push-all",
            status="enabled",
            scope="samples/*",
            actions=["push"],
        ),
        SimpleNamespace(
            id="/subscriptions/test/.../webhooks/delete-all",
            status="disabled",
            scope="",
            actions=["delete"],
        ),
    ]
    replications = [
        SimpleNamespace(
            id="/subscriptions/test/.../replications/westus2",
            location="westus2",
        )
    ]

    summary = _acr_registry_summary(registry, webhooks, replications)

    assert summary["webhook_count"] == 2
    assert summary["enabled_webhook_count"] == 1
    assert summary["webhook_action_types"] == ["delete", "push"]
    assert summary["broad_webhook_scope_count"] == 2
    assert summary["replication_regions"] == ["westus2"]
    assert summary["retention_policy_days"] == 15
    assert summary["trust_policy_type"] == "notary"
    assert "/subscriptions/test/.../webhooks/push-all" in summary["related_ids"]
    assert "/subscriptions/test/.../replications/westus2" in summary["related_ids"]
    assert "Depth cues:" in summary["summary"]


def test_normalized_arm_enum_splits_camel_case_values() -> None:
    assert _normalized_arm_enum("ZoneRedundant") == "zone-redundant"
    assert _normalized_arm_enum("SameZone") == "same-zone"


def test_database_server_summary_normalizes_flexible_server_ha_mode() -> None:
    server = SimpleNamespace(
        id=(
            "/subscriptions/test/resourceGroups/rg-data/providers/"
            "Microsoft.DBforPostgreSQL/flexibleServers/pg-01"
        ),
        name="pg-01",
        fully_qualified_domain_name="pg-01.postgres.database.azure.com",
        version="16",
        public_network_access="Enabled",
        high_availability=SimpleNamespace(mode="ZoneRedundant"),
        network=SimpleNamespace(
            delegated_subnet_resource_id=(
                "/subscriptions/test/resourceGroups/rg-data/providers/"
                "Microsoft.Network/virtualNetworks/data-vnet/subnets/postgres-flex"
            ),
            private_dns_zone_arm_resource_id=(
                "/subscriptions/test/resourceGroups/rg-data/providers/"
                "Microsoft.Network/privateDnsZones/postgres.database.azure.com"
            ),
        ),
    )

    summary = _database_server_summary(server, [], engine="PostgreSqlFlexible")

    assert summary["high_availability_mode"] == "zone-redundant"
    assert "HA zone-redundant" in summary["summary"]


def test_collect_aks(fixture_provider, options) -> None:
    output = collect_aks(fixture_provider, options)
    assert len(output.aks_clusters) == 2
    assert len(output.findings) == 0
    assert output.aks_clusters[0].name == "aks-public-legacy"
    assert output.aks_clusters[0].cluster_identity_type == "ServicePrincipal"
    assert output.aks_clusters[0].cluster_client_id == "99990000-0000-0000-0000-000000000021"
    assert output.aks_clusters[1].name == "aks-ops-01"
    assert output.aks_clusters[1].private_cluster_enabled is True
    assert output.aks_clusters[1].azure_rbac_enabled is True
    assert output.aks_clusters[1].agent_pool_count == 2
    assert output.aks_clusters[1].oidc_issuer_enabled is True
    assert (
        output.aks_clusters[1].oidc_issuer_url
        == "https://oidc.prod-aks.azure.example/aks-ops-01"
    )
    assert output.aks_clusters[1].workload_identity_enabled is True
    assert output.aks_clusters[1].addon_names == ["azureKeyvaultSecretsProvider"]
    assert output.aks_clusters[1].web_app_routing_enabled is True
    assert output.aks_clusters[1].web_app_routing_dns_zone_count == 1


def test_aks_cluster_summary_rolls_up_azure_native_depth_cues() -> None:
    cluster = SimpleNamespace(
        id="/subscriptions/test/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks-01",
        name="aks-01",
        location="eastus",
        provisioning_state="Succeeded",
        kubernetes_version="1.29.4",
        sku=SimpleNamespace(tier="Standard"),
        node_resource_group="MC_rg_aks-01_eastus",
        fqdn="aks-01.hcp.eastus.azmk8s.io",
        private_fqdn="aks-01.privatelink.eastus.azmk8s.io",
        identity=SimpleNamespace(
            type="SystemAssigned",
            principal_id="principal-1",
            client_id="client-1",
            user_assigned_identities={},
        ),
        service_principal_profile=None,
        aad_profile=SimpleNamespace(managed=True, enable_azure_rbac=True),
        api_server_access_profile=SimpleNamespace(
            enable_private_cluster=True,
            enable_private_cluster_public_fqdn=False,
        ),
        network_profile=SimpleNamespace(
            network_plugin="azure",
            network_policy="calico",
            outbound_type="loadBalancer",
        ),
        oidc_issuer_profile=SimpleNamespace(
            enabled=True,
            issuer_url="https://issuer.example",
        ),
        security_profile=SimpleNamespace(
            workload_identity=SimpleNamespace(enabled=True)
        ),
        ingress_profile=SimpleNamespace(
            web_app_routing=SimpleNamespace(
                enabled=True,
                dns_zone_resource_ids=["/dns/zone1"],
            )
        ),
        addon_profiles={
            "azureKeyvaultSecretsProvider": SimpleNamespace(enabled=True),
            "httpApplicationRouting": SimpleNamespace(enabled=False),
        },
        agent_pool_profiles=[SimpleNamespace(name="systempool")],
        disable_local_accounts=True,
    )

    summary = _aks_cluster_summary(cluster)

    assert summary["oidc_issuer_enabled"] is True
    assert summary["oidc_issuer_url"] == "https://issuer.example"
    assert summary["workload_identity_enabled"] is True
    assert summary["addon_names"] == ["azureKeyvaultSecretsProvider"]
    assert summary["web_app_routing_enabled"] is True
    assert summary["web_app_routing_dns_zone_count"] == 1


def test_collect_aks_keeps_command_level_issue_explicit(
    fixture_dir: Path, options
) -> None:
    provider = PartialAksFixtureProvider(fixture_dir)

    output = collect_aks(provider, options)

    assert output.aks_clusters == []
    assert output.issues[0].kind == "permission_denied"
    assert output.issues[0].context["collector"] == "aks.managed_clusters"


def test_collect_api_mgmt(fixture_provider, options) -> None:
    output = collect_api_mgmt(fixture_provider, options)
    assert len(output.api_management_services) == 1
    assert len(output.findings) == 0
    assert output.api_management_services[0].name == "apim-edge-01"
    assert output.api_management_services[0].api_count == 2
    assert output.api_management_services[0].api_subscription_required_count == 1
    assert output.api_management_services[0].subscription_count == 3
    assert output.api_management_services[0].active_subscription_count == 2
    assert output.api_management_services[0].backend_hostnames == [
        "orders-internal.contoso.local"
    ]
    assert output.api_management_services[0].named_value_count == 2
    assert output.api_management_services[0].named_value_secret_count == 1
    assert output.api_management_services[0].named_value_key_vault_count == 1
    assert (
        output.api_management_services[0].public_ip_address_id
        == (
            "/subscriptions/22222222-2222-2222-2222-222222222222/resourceGroups/rg-apps/"
            "providers/Microsoft.Network/publicIPAddresses/pip-apim-edge-01"
        )
    )
    assert output.api_management_services[0].public_ip_addresses == ["52.170.20.30"]


def test_collect_api_mgmt_keeps_partial_visibility_explicit(
    fixture_dir: Path, options
) -> None:
    provider = PartialApiMgmtFixtureProvider(fixture_dir)

    output = collect_api_mgmt(provider, options)

    assert len(output.api_management_services) == 1
    assert output.api_management_services[0].name == "apim-edge-01"
    assert output.api_management_services[0].api_count is None
    assert output.api_management_services[0].api_subscription_required_count is None
    assert output.api_management_services[0].backend_count is None
    assert output.api_management_services[0].backend_hostnames == []
    assert output.api_management_services[0].named_value_count is None
    assert output.api_management_services[0].named_value_secret_count is None
    assert output.api_management_services[0].named_value_key_vault_count is None
    assert [issue.context["collector"] for issue in output.issues] == [
        "api_mgmt[rg-apps/apim-edge-01].apis",
        "api_mgmt[rg-apps/apim-edge-01].backends",
        "api_mgmt[rg-apps/apim-edge-01].named_values",
    ]


def test_collect_app_services_keeps_partial_visibility_explicit(
    fixture_dir: Path, options
) -> None:
    provider = PartialAppServicesFixtureProvider(fixture_dir)

    output = collect_app_services(provider, options)

    assert len(output.app_services) == 1
    assert output.app_services[0].name == "app-empty-mi"
    assert output.app_services[0].runtime_stack == "DOTNETCORE|8.0"
    assert output.issues[0].kind == "permission_denied"
    assert output.issues[0].context["collector"] == (
        "app_services[rg-apps/app-empty-mi].configuration"
    )


def test_collect_functions(fixture_provider, options) -> None:
    output = collect_functions(fixture_provider, options)
    assert len(output.function_apps) == 1
    assert len(output.findings) == 0
    assert output.function_apps[0].name == "func-orders"
    assert output.function_apps[0].functions_extension_version == "~4"
    assert output.function_apps[0].azure_webjobs_storage_value_type == "plain-text"
    assert output.function_apps[0].run_from_package is None


def test_collect_functions_keeps_partial_visibility_explicit(
    fixture_dir: Path, options
) -> None:
    provider = PartialFunctionsFixtureProvider(fixture_dir)

    output = collect_functions(provider, options)

    assert len(output.function_apps) == 1
    assert output.function_apps[0].name == "func-orders"
    assert output.function_apps[0].azure_webjobs_storage_value_type is None
    assert output.issues[0].kind == "permission_denied"
    assert output.issues[0].context["collector"] == "functions[rg-apps/func-orders].app_settings"


def test_collect_arm_deployments(fixture_provider, options) -> None:
    output = collect_arm_deployments(fixture_provider, options)
    assert len(output.deployments) == 3
    assert len(output.findings) == 5
    assert output.deployments[0].scope_type == "subscription"


def test_collect_endpoints(fixture_provider, options) -> None:
    output = collect_endpoints(fixture_provider, options)
    assert len(output.endpoints) == 4
    assert len(output.findings) == 0
    assert output.endpoints[0].endpoint == "52.160.10.20"
    assert output.endpoints[0].ingress_path == "direct-vm-ip"
    assert any(item.endpoint == "app-public-api.azurewebsites.net" for item in output.endpoints)


def test_collect_env_vars(fixture_provider, options) -> None:
    output = collect_env_vars(fixture_provider, options)
    assert len(output.env_vars) == 4
    assert len(output.findings) == 2
    assert output.env_vars[0].setting_name == "DB_PASSWORD"
    assert output.env_vars[0].workload_identity_type == "SystemAssigned"
    assert output.env_vars[1].key_vault_reference_identity == "SystemAssigned"


def test_collect_tokens_credentials(fixture_provider, options) -> None:
    output = collect_tokens_credentials(fixture_provider, options)
    assert len(output.surfaces) == 11
    assert len(output.findings) == 11
    assert len({finding.id for finding in output.findings}) == len(output.findings)
    assert output.surfaces[0].surface_type == "plain-text-secret"
    assert output.surfaces[1].operator_signal == "setting=AzureWebJobsStorage"
    assert any(item.asset_name == "app-empty-mi" for item in output.surfaces)
    assert any(
        item.surface_type == "managed-identity-token" and item.access_path == "imds"
        for item in output.surfaces
    )


def test_web_asset_kind_filters_out_of_scope_site_kinds() -> None:
    assert _web_asset_kind("app,linux") == "AppService"
    assert _web_asset_kind("functionapp,linux") == "FunctionApp"
    assert _web_asset_kind("workflowapp,linux") is None


def test_env_var_reference_target_supports_secret_uri_form() -> None:
    value = (
        "@Microsoft.KeyVault(SecretUri=https://kvlabopen01.vault.azure.net/secrets/payment-api-key)"
    )

    assert _env_var_reference_target(value) == (
        "kvlabopen01.vault.azure.net/secrets/payment-api-key"
    )


def test_env_var_reference_target_supports_vaultname_form() -> None:
    value = (
        "@Microsoft.KeyVault(VaultName=kvlabopen01;SecretName=payment-api-key;SecretVersion=123abc)"
    )

    assert _env_var_reference_target(value) == (
        "kvlabopen01.vault.azure.net/secrets/payment-api-key/123abc"
    )


def test_collect_inventory_metadata_falls_back_to_provider_context(
    fixture_dir: Path, tmp_path: Path
) -> None:
    provider = MetadataFixtureProvider(fixture_dir)
    options = GlobalOptions(
        tenant=None,
        subscription=None,
        output=OutputMode.JSON,
        outdir=tmp_path,
        debug=False,
        role_trusts_mode=RoleTrustsMode.FAST,
    )

    output = collect_inventory(provider, options)

    assert output.metadata.tenant_id == "tenant-from-provider"
    assert output.metadata.subscription_id == "subscription-from-provider"
    assert output.metadata.token_source == "azure_cli"


def test_collect_auth_policies(fixture_provider, options) -> None:
    output = collect_auth_policies(fixture_provider, options)
    assert len(output.auth_policies) == 4
    assert len(output.findings) == 5
    assert output.auth_policies[0].policy_type == "security-defaults"


def test_collect_auth_policies_keeps_partial_visibility_explicit(
    fixture_dir: Path, options
) -> None:
    provider = PartialAuthPoliciesFixtureProvider(fixture_dir)

    output = collect_auth_policies(provider, options)

    assert len(output.auth_policies) == 1
    assert [finding.id for finding in output.findings] == [
        "auth-policy-users-can-register-apps",
        "auth-policy-guest-invites-everyone",
        "auth-policy-user-consent-enabled",
    ]
    assert output.issues[0].kind == "permission_denied"
    assert output.issues[0].context["collector"] == "auth_policies.security_defaults"


def test_collect_auth_policies_does_not_imply_missing_enforcement_when_ca_unreadable(
    fixture_dir: Path, options
) -> None:
    provider = ConditionalAccessUnreadableFixtureProvider(fixture_dir)

    output = collect_auth_policies(provider, options)

    finding_ids = [finding.id for finding in output.findings]
    assert "auth-policy-security-defaults-disabled" in finding_ids
    assert "auth-policy-users-can-register-apps" in finding_ids
    assert "auth-policy-no-active-enforcement-visible" not in finding_ids
    assert output.issues[0].context["collector"] == "auth_policies.conditional_access"


def test_collect_rbac(fixture_provider, options) -> None:
    output = collect_rbac(fixture_provider, options)
    assert len(output.role_assignments) == 2
    assert "Owner" in output.role_distribution()


def test_collect_principals(fixture_provider, options) -> None:
    output = collect_principals(fixture_provider, options)
    assert len(output.principals) == 2
    assert output.principals[0].is_current_identity is True
    assert "ua-app" in output.principals[0].identity_names


def test_collect_permissions(fixture_provider, options) -> None:
    output = collect_permissions(fixture_provider, options)
    assert len(output.permissions) == 2
    assert output.permissions[0].privileged is True
    assert output.permissions[0].high_impact_roles == ["Owner"]


def test_collect_privesc(fixture_provider, options) -> None:
    output = collect_privesc(fixture_provider, options)
    assert len(output.paths) == 2
    assert output.paths[0].path_type == "direct-role-abuse"
    assert output.paths[1].asset == "vm-web-01"


def test_collect_role_trusts(fixture_provider, options) -> None:
    output = collect_role_trusts(fixture_provider, options)
    assert output.mode == "fast"
    assert len(output.trusts) == 4
    assert output.trusts[0].trust_type == "app-owner"
    assert output.trusts[2].evidence_type == "graph-federated-credential"


def test_collect_role_trusts_enumerates_graph_edges_without_principal_seed(options) -> None:
    provider = object.__new__(AzureProvider)
    provider.graph = FakeRoleTrustsGraph()
    provider.metadata_context = lambda: {
        "tenant_id": "tenant-from-provider",
        "subscription_id": "subscription-from-provider",
        "token_source": "azure_cli",
    }

    output = collect_role_trusts(provider, options)

    assert len(output.trusts) == 4
    assert any(item.source_name == "build-app" for item in output.trusts)
    assert any(item.source_name == "reporting-sp" for item in output.trusts)
    assert any(item.target_name == "Microsoft Graph" for item in output.trusts)


class FakeRoleTrustsFullGraph(FakeRoleTrustsGraph):
    def list_applications(self) -> list[dict]:
        return [
            *super().list_applications(),
            {
                "id": "12121212-1212-1212-1212-121212121212",
                "appId": "12121212-1212-1212-1212-121212121210",
                "displayName": "orphan-build-app",
            },
        ]

    def get_application_by_app_id(self, app_id: str) -> dict | None:
        if app_id == "12121212-1212-1212-1212-121212121210":
            return {
                "id": "12121212-1212-1212-1212-121212121212",
                "appId": "12121212-1212-1212-1212-121212121210",
                "displayName": "orphan-build-app",
            }
        return super().get_application_by_app_id(app_id)

    def list_application_federated_credentials(self, application_id: str) -> list[dict]:
        if application_id == "12121212-1212-1212-1212-121212121212":
            return [
                {
                    "id": "fic-orphan-prod",
                    "issuer": "https://token.actions.githubusercontent.com",
                    "subject": "repo:TacoRocket/legacy-ci:environment:prod",
                }
            ]
        return super().list_application_federated_credentials(application_id)

    def list_application_owners(self, application_id: str) -> list[dict]:
        if application_id == "12121212-1212-1212-1212-121212121212":
            return [
                {
                    "id": "13131313-1313-1313-1313-131313131313",
                    "userPrincipalName": "ops-admin@lab.local",
                    "@odata.type": "#microsoft.graph.user",
                }
            ]
        return super().list_application_owners(application_id)


def test_collect_role_trusts_full_mode_surfaces_extra_application_edges(options) -> None:
    provider = object.__new__(AzureProvider)
    provider.graph = FakeRoleTrustsFullGraph()
    provider.metadata_context = lambda: {
        "tenant_id": "tenant-from-provider",
        "subscription_id": "subscription-from-provider",
        "token_source": "azure_cli",
    }

    fast_options = GlobalOptions(
        tenant=options.tenant,
        subscription=options.subscription,
        output=options.output,
        outdir=options.outdir,
        debug=options.debug,
        role_trusts_mode=RoleTrustsMode.FAST,
    )
    full_options = GlobalOptions(
        tenant=options.tenant,
        subscription=options.subscription,
        output=options.output,
        outdir=options.outdir,
        debug=options.debug,
        role_trusts_mode=RoleTrustsMode.FULL,
    )

    fast_output = collect_role_trusts(provider, fast_options)
    full_output = collect_role_trusts(provider, full_options)

    assert fast_output.mode == "fast"
    assert full_output.mode == "full"
    assert len(fast_output.trusts) == 4
    assert len(full_output.trusts) == 6
    assert not any(item.target_name == "orphan-build-app" for item in fast_output.trusts)
    assert any(item.target_name == "orphan-build-app" for item in full_output.trusts)


def test_collect_managed_identities(fixture_provider, options) -> None:
    output = collect_managed_identities(fixture_provider, options)
    assert len(output.identities) == 1
    assert len(output.findings) == 1


def test_collect_keyvault(fixture_provider, options) -> None:
    output = collect_keyvault(fixture_provider, options)
    assert len(output.key_vaults) == 4
    assert len(output.findings) == 4
    assert output.key_vaults[0].public_network_access == "Enabled"
    assert output.key_vaults[0].network_default_action is None
    assert output.findings[0].id.startswith("keyvault-public-network-open-")
    assert output.findings[2].id.startswith("keyvault-public-network-enabled-")
    assert output.findings[3].id.startswith("keyvault-public-network-with-private-endpoint-")


def test_collect_resource_trusts(fixture_provider, options) -> None:
    output = collect_resource_trusts(fixture_provider, options)
    assert len(output.resource_trusts) == 8
    assert len(output.findings) == 5
    assert output.resource_trusts[0].resource_type == "KeyVault"
    assert any(
        item.resource_name == "kvlabopen01"
        and item.trust_type == "public-network"
        and item.exposure == "high"
        for item in output.resource_trusts
    )
    assert not any("purge-protection-disabled" in finding.id for finding in output.findings)
    assert any(
        item.resource_name == "kvlabdeny01" and item.trust_type == "public-network"
        for item in output.resource_trusts
    )


def test_collect_storage(fixture_provider, options) -> None:
    output = collect_storage(fixture_provider, options)
    assert len(output.storage_assets) == 2
    assert len(output.findings) == 2


def test_collect_storage_keeps_child_enumeration_failures_explicit(options) -> None:
    provider = object.__new__(AzureProvider)
    provider.clients = type("Clients", (), {"storage": FakeStorageClient()})()
    provider.metadata_context = lambda: {
        "tenant_id": "tenant-from-provider",
        "subscription_id": "subscription-from-provider",
        "token_source": "azure_cli",
    }

    output = collect_storage(provider, options)

    assert len(output.storage_assets) == 1
    assert output.storage_assets[0].container_count is None
    assert output.storage_assets[0].file_share_count is None
    assert len(output.issues) == 4


def test_collect_nics(fixture_provider, options) -> None:
    output = collect_nics(fixture_provider, options)
    assert len(output.nic_assets) == 2
    assert len(output.findings) == 0
    assert output.nic_assets[0].attached_asset_name == "vm-web-01"
    assert output.nic_assets[0].public_ip_ids[0].endswith("/publicIPAddresses/pip-web-01")
    assert output.nic_assets[0].vnet_ids[0].endswith("/virtualNetworks/vnet-workload")


def test_collect_network_ports(fixture_provider, options) -> None:
    output = collect_network_ports(fixture_provider, options)
    assert len(output.network_ports) == 3
    assert len(output.findings) == 0
    assert output.network_ports[0].port == "22"
    assert output.network_ports[0].exposure_confidence == "high"
    assert any("subnet-nsg" in item.allow_source_summary for item in output.network_ports)


def test_network_ports_does_not_claim_missing_nsg_when_subnet_nsg_is_visible() -> None:
    provider = object.__new__(AzureProvider)
    provider.endpoints = lambda: {
        "endpoints": [
            {
                "endpoint": "52.160.10.20",
                "endpoint_type": "ip",
                "source_asset_id": (
                    "/subscriptions/test/resourceGroups/rg/providers/"
                    "Microsoft.Compute/virtualMachines/vm-web-01"
                ),
                "source_asset_name": "vm-web-01",
                "source_asset_kind": "VM",
                "exposure_family": "public-ip",
                "ingress_path": "direct-vm-ip",
                "summary": "test",
                "related_ids": [],
            }
        ],
        "issues": [],
    }
    provider.nics = lambda: {
        "nic_assets": [
            {
                "id": (
                    "/subscriptions/test/resourceGroups/rg/providers/"
                    "Microsoft.Network/networkInterfaces/nic-web-01"
                ),
                "name": "nic-web-01",
                "attached_asset_id": (
                    "/subscriptions/test/resourceGroups/rg/providers/"
                    "Microsoft.Compute/virtualMachines/vm-web-01"
                ),
                "attached_asset_name": "vm-web-01",
                "private_ips": ["10.0.0.4"],
                "public_ip_ids": [],
                "subnet_ids": [
                    "/subscriptions/test/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet-app/subnets/subnet-web"
                ],
                "vnet_ids": [
                    "/subscriptions/test/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet-app"
                ],
                "network_security_group_id": None,
            }
        ],
        "issues": [],
    }
    provider._resolve_subnet_nsg_id = lambda subnet_id, cache: (
        "/subscriptions/test/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-subnet",
        [],
    )
    provider._resolve_nsg_inbound_allow_rules = lambda nsg_id, cache: ([], [])

    output = AzureProvider.network_ports(provider)

    assert output["issues"] == []
    assert output["network_ports"] == []


def test_network_ports_joins_arm_ids_case_insensitively() -> None:
    provider = object.__new__(AzureProvider)
    provider.endpoints = lambda: {
        "endpoints": [
            {
                "endpoint": "172.202.2.192",
                "endpoint_type": "ip",
                "source_asset_id": (
                    "/subscriptions/test/resourceGroups/RG-WORKLOAD/providers/"
                    "Microsoft.Compute/virtualMachines/vm-web-01"
                ),
                "source_asset_name": "vm-web-01",
                "source_asset_kind": "VM",
                "exposure_family": "public-ip",
                "ingress_path": "direct-vm-ip",
                "summary": "test",
                "related_ids": [],
            }
        ],
        "issues": [],
    }
    provider.nics = lambda: {
        "nic_assets": [
            {
                "id": (
                    "/subscriptions/test/resourceGroups/rg-workload/providers/"
                    "Microsoft.Network/networkInterfaces/nic-web-01"
                ),
                "name": "nic-web-01",
                "attached_asset_id": (
                    "/subscriptions/test/resourceGroups/rg-workload/providers/"
                    "Microsoft.Compute/virtualMachines/vm-web-01"
                ),
                "attached_asset_name": "vm-web-01",
                "private_ips": ["10.0.0.4"],
                "public_ip_ids": [],
                "subnet_ids": [],
                "vnet_ids": [],
                "network_security_group_id": (
                    "/subscriptions/test/resourceGroups/rg-workload/providers/"
                    "Microsoft.Network/networkSecurityGroups/nsg-web"
                ),
            }
        ],
        "issues": [],
    }
    provider._resolve_subnet_nsg_id = lambda subnet_id, cache: (None, [])
    provider._resolve_nsg_inbound_allow_rules = lambda nsg_id, cache: (
        [
            {
                "name": "allow-ssh-internet",
                "protocol": "TCP",
                "ports": ["22"],
                "sources": ["Any"],
            }
        ],
        [],
    )

    output = AzureProvider.network_ports(provider)

    assert output["issues"] == []
    assert len(output["network_ports"]) == 1
    assert output["network_ports"][0]["asset_name"] == "vm-web-01"
    assert output["network_ports"][0]["port"] == "22"


def test_network_scope_label_includes_resource_group() -> None:
    label = _network_scope_label(
        "subnet",
        "/subscriptions/test/resourceGroups/rg-workload/providers/Microsoft.Network/networkSecurityGroups/nsg-vnet-app",
        "allow-https-lb",
    )

    assert label == "subnet-nsg:rg-workload/nsg-vnet-app/allow-https-lb"


def test_collect_vms(fixture_provider, options) -> None:
    output = collect_vms(fixture_provider, options)
    assert len(output.vm_assets) == 2
    assert len(output.findings) == 1


def test_collect_workloads(fixture_provider, options) -> None:
    output = collect_workloads(fixture_provider, options)
    assert len(output.workloads) == 5
    assert len(output.findings) == 0
    assert output.workloads[0].asset_name == "vm-web-01"
    assert output.workloads[0].identity_type == "UserAssigned"
    assert output.workloads[0].endpoints == ["52.160.10.20"]
    assert output.workloads[-1].asset_name == "vmss-api"
    assert output.workloads[-1].endpoints == []
