from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from azurefox.collectors.commands import (
    _vm_asset_sort_key,
    collect_acr,
    collect_aks,
    collect_api_mgmt,
    collect_app_services,
    collect_application_gateway,
    collect_arm_deployments,
    collect_auth_policies,
    collect_automation,
    collect_cross_tenant,
    collect_databases,
    collect_devops,
    collect_dns,
    collect_endpoints,
    collect_env_vars,
    collect_functions,
    collect_inventory,
    collect_keyvault,
    collect_lighthouse,
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
    collect_vmss,
    collect_whoami,
    collect_workloads,
)
from azurefox.collectors.provider import (
    AzureProvider,
    FixtureProvider,
    _acr_registry_summary,
    _aks_cluster_summary,
    _database_server_summary,
    _devops_pipeline_summary,
    _env_var_reference_target,
    _network_effective_row_from_endpoint,
    _network_scope_label,
    _normalized_arm_enum,
    _principal_from_claims,
    _principal_sort_key,
    _privesc_sort_key,
    _vmss_summary,
    _web_asset_kind,
)
from azurefox.config import GlobalOptions
from azurefox.devops_hints import devops_next_review_hint
from azurefox.env_var_hints import env_var_next_review_hint
from azurefox.models.common import OutputMode, RoleTrustsMode


class MetadataFixtureProvider(FixtureProvider):
    def metadata_context(self) -> dict[str, str | None]:
        return {
            "tenant_id": "tenant-from-provider",
            "subscription_id": "subscription-from-provider",
            "token_source": "azure_cli",
        }


class DriftOrderingFixtureProvider(MetadataFixtureProvider):
    def app_services(self) -> dict:
        return {
            "app_services": [
                {
                    "id": "app-1",
                    "name": "zzz-hardened-id",
                    "default_hostname": "zzz-hardened-id.azurewebsites.net",
                    "public_network_access": "Enabled",
                    "https_only": True,
                    "client_cert_enabled": True,
                    "min_tls_version": "1.2",
                    "ftps_state": "Disabled",
                    "runtime_stack": "NODE|20-lts",
                    "workload_identity_type": "SystemAssigned",
                    "summary": "hardened identity-backed app",
                    "related_ids": [],
                },
                {
                    "id": "app-2",
                    "name": "mmm-weak-id",
                    "default_hostname": "mmm-weak-id.azurewebsites.net",
                    "public_network_access": "Enabled",
                    "https_only": False,
                    "client_cert_enabled": False,
                    "min_tls_version": "1.0",
                    "ftps_state": "AllAllowed",
                    "runtime_stack": "DOTNETCORE|8.0",
                    "workload_identity_type": "SystemAssigned",
                    "summary": "weaker identity-backed app",
                    "related_ids": [],
                },
                {
                    "id": "app-3",
                    "name": "aaa-weak-no-id",
                    "default_hostname": "aaa-weak-no-id.azurewebsites.net",
                    "public_network_access": "Enabled",
                    "https_only": False,
                    "client_cert_enabled": False,
                    "min_tls_version": "1.0",
                    "ftps_state": "AllAllowed",
                    "runtime_stack": "PYTHON|3.11",
                    "workload_identity_type": None,
                    "summary": "weaker non-identity app",
                    "related_ids": [],
                },
            ],
            "issues": [],
        }

    def acr(self) -> dict:
        return {
            "registries": [
                {
                    "id": "acr-public",
                    "name": "acr-public",
                    "public_network_access": "Enabled",
                    "admin_user_enabled": True,
                    "anonymous_pull_enabled": False,
                    "enabled_webhook_count": 0,
                    "replication_count": 0,
                    "broad_webhook_scope_count": 0,
                    "quarantine_policy_status": "enabled",
                    "retention_policy_status": "enabled",
                    "trust_policy_status": "enabled",
                    "summary": "public registry",
                },
                {
                    "id": "acr-webhooks",
                    "name": "acr-webhooks",
                    "public_network_access": "Disabled",
                    "admin_user_enabled": True,
                    "anonymous_pull_enabled": False,
                    "enabled_webhook_count": 2,
                    "replication_count": 0,
                    "broad_webhook_scope_count": 1,
                    "quarantine_policy_status": "enabled",
                    "retention_policy_status": "enabled",
                    "trust_policy_status": "enabled",
                    "summary": "admin-backed registry with webhook depth",
                },
                {
                    "id": "acr-replication",
                    "name": "acr-replication",
                    "public_network_access": "Disabled",
                    "admin_user_enabled": True,
                    "anonymous_pull_enabled": False,
                    "enabled_webhook_count": 0,
                    "replication_count": 2,
                    "broad_webhook_scope_count": 0,
                    "quarantine_policy_status": "enabled",
                    "retention_policy_status": "enabled",
                    "trust_policy_status": "enabled",
                    "summary": "admin-backed registry with replication depth",
                },
                {
                    "id": "acr-governance-weak",
                    "name": "acr-governance-weak",
                    "public_network_access": "Disabled",
                    "admin_user_enabled": True,
                    "anonymous_pull_enabled": False,
                    "enabled_webhook_count": 0,
                    "replication_count": 0,
                    "broad_webhook_scope_count": 0,
                    "quarantine_policy_status": "disabled",
                    "retention_policy_status": "disabled",
                    "trust_policy_status": "disabled",
                    "summary": "admin-backed registry with weak governance",
                },
            ],
            "issues": [],
        }

    def databases(self) -> dict:
        return {
            "database_servers": [
                {
                    "id": "db-public-many",
                    "name": "db-public-many",
                    "engine": "AzureSql",
                    "fully_qualified_domain_name": "db-public-many.database.windows.net",
                    "public_network_access": "Enabled",
                    "minimal_tls_version": "1.2",
                    "database_count": 3,
                    "workload_identity_type": None,
                    "summary": "public server with more visible databases",
                },
                {
                    "id": "db-private-identity",
                    "name": "db-private-identity",
                    "engine": "AzureSql",
                    "fully_qualified_domain_name": "db-private-identity.database.windows.net",
                    "public_network_access": "Disabled",
                    "minimal_tls_version": "1.0",
                    "database_count": 9,
                    "workload_identity_type": "SystemAssigned",
                    "summary": "private identity-backed server",
                },
                {
                    "id": "db-public-weak-tls",
                    "name": "db-public-weak-tls",
                    "engine": "AzureSql",
                    "fully_qualified_domain_name": "db-public-weak-tls.database.windows.net",
                    "public_network_access": "Enabled",
                    "minimal_tls_version": "1.0",
                    "database_count": 1,
                    "workload_identity_type": None,
                    "summary": "public server with weaker TLS",
                },
                {
                    "id": "db-public-identity",
                    "name": "db-public-identity",
                    "engine": "AzureSql",
                    "fully_qualified_domain_name": "db-public-identity.database.windows.net",
                    "public_network_access": "Enabled",
                    "minimal_tls_version": "1.2",
                    "database_count": 1,
                    "workload_identity_type": "SystemAssigned",
                    "summary": "public identity-backed server",
                },
            ],
            "issues": [],
        }

    def application_gateway(self) -> dict:
        return {
            "application_gateways": [
                {
                    "id": "agw-public-prevention",
                    "name": "zzz-public-prevention",
                    "public_frontend_count": 1,
                    "listener_count": 5,
                    "request_routing_rule_count": 5,
                    "backend_pool_count": 4,
                    "backend_target_count": 6,
                    "waf_enabled": True,
                    "waf_mode": "Prevention",
                    "firewall_policy_id": "/policy/prevention",
                    "summary": "public gateway with prevention mode",
                    "related_ids": [],
                },
                {
                    "id": "agw-public-weak",
                    "name": "mmm-public-weak",
                    "public_frontend_count": 1,
                    "listener_count": 4,
                    "request_routing_rule_count": 4,
                    "backend_pool_count": 3,
                    "backend_target_count": 5,
                    "waf_enabled": False,
                    "waf_mode": None,
                    "firewall_policy_id": None,
                    "summary": "public gateway with weak shared edge posture",
                    "related_ids": [],
                },
                {
                    "id": "agw-public-tiny-weak",
                    "name": "bbb-public-tiny-weak",
                    "public_frontend_count": 1,
                    "listener_count": 1,
                    "request_routing_rule_count": 1,
                    "backend_pool_count": 1,
                    "backend_target_count": 1,
                    "waf_enabled": False,
                    "waf_mode": None,
                    "firewall_policy_id": None,
                    "summary": "tiny public gateway with weak edge posture",
                    "related_ids": [],
                },
                {
                    "id": "agw-internal",
                    "name": "aaa-internal-detection",
                    "public_frontend_count": 0,
                    "listener_count": 6,
                    "request_routing_rule_count": 6,
                    "backend_pool_count": 4,
                    "backend_target_count": 8,
                    "waf_enabled": True,
                    "waf_mode": "Detection",
                    "firewall_policy_id": None,
                    "summary": "internal gateway with broader routing",
                    "related_ids": [],
                },
            ],
            "issues": [],
        }

    def aks(self) -> dict:
        return {
            "aks_clusters": [
                {
                    "id": "aks-public-auth-cues",
                    "name": "aks-public-auth-cues",
                    "fqdn": "aks-public-auth-cues.example",
                    "private_cluster_enabled": False,
                    "cluster_identity_type": None,
                    "oidc_issuer_enabled": False,
                    "workload_identity_enabled": False,
                    "addon_names": [],
                    "aad_managed": False,
                    "azure_rbac_enabled": False,
                    "local_accounts_disabled": False,
                    "summary": "public cluster with weaker auth cues",
                },
                {
                    "id": "aks-private-federated",
                    "name": "aks-private-federated",
                    "fqdn": "aks-private-federated.example",
                    "private_cluster_enabled": True,
                    "cluster_identity_type": "SystemAssigned",
                    "oidc_issuer_enabled": True,
                    "workload_identity_enabled": True,
                    "addon_names": ["azureKeyvaultSecretsProvider"],
                    "aad_managed": True,
                    "azure_rbac_enabled": True,
                    "local_accounts_disabled": True,
                    "summary": "private cluster with rich cues",
                },
                {
                    "id": "aks-public-addon",
                    "name": "aks-public-addon",
                    "fqdn": "aks-public-addon.example",
                    "private_cluster_enabled": False,
                    "cluster_identity_type": "SystemAssigned",
                    "oidc_issuer_enabled": False,
                    "workload_identity_enabled": False,
                    "addon_names": ["azureKeyvaultSecretsProvider"],
                    "aad_managed": True,
                    "azure_rbac_enabled": True,
                    "local_accounts_disabled": True,
                    "summary": "public cluster with addon cues",
                },
                {
                    "id": "aks-public-federated",
                    "name": "aks-public-federated",
                    "fqdn": "aks-public-federated.example",
                    "private_cluster_enabled": False,
                    "cluster_identity_type": "SystemAssigned",
                    "oidc_issuer_enabled": True,
                    "workload_identity_enabled": True,
                    "addon_names": [],
                    "aad_managed": True,
                    "azure_rbac_enabled": True,
                    "local_accounts_disabled": True,
                    "summary": "public cluster with federation cues",
                },
            ],
            "issues": [],
        }

    def nics(self) -> dict:
        return {
            "nic_assets": [
                {
                    "id": "nic-routine",
                    "name": "nic-routine",
                    "attached_asset_id": "vm-routine",
                    "attached_asset_name": "vm-routine",
                    "private_ips": ["10.0.0.5"],
                    "public_ip_ids": [],
                    "subnet_ids": ["subnet-a"],
                    "vnet_ids": ["vnet-a"],
                    "network_security_group_id": None,
                },
                {
                    "id": "nic-unattached",
                    "name": "nic-unattached",
                    "attached_asset_id": None,
                    "attached_asset_name": None,
                    "private_ips": ["10.0.1.5", "10.0.1.6"],
                    "public_ip_ids": [],
                    "subnet_ids": ["subnet-b"],
                    "vnet_ids": ["vnet-a"],
                    "network_security_group_id": "nsg-b",
                },
                {
                    "id": "nic-public",
                    "name": "nic-public",
                    "attached_asset_id": "vm-edge",
                    "attached_asset_name": "vm-edge",
                    "private_ips": ["10.0.2.5"],
                    "public_ip_ids": ["pip-edge"],
                    "subnet_ids": ["subnet-edge"],
                    "vnet_ids": ["vnet-a"],
                    "network_security_group_id": "nsg-edge",
                },
            ],
            "issues": [],
        }

    def functions(self) -> dict:
        return {
            "function_apps": [
                {
                    "id": "func-1",
                    "name": "aaa-plain-no-id",
                    "default_hostname": "aaa-plain-no-id.azurewebsites.net",
                    "public_network_access": "Enabled",
                    "https_only": True,
                    "client_cert_enabled": False,
                    "min_tls_version": "1.2",
                    "ftps_state": "Disabled",
                    "runtime_stack": "PYTHON|3.11",
                    "functions_extension_version": "~4",
                    "always_on": False,
                    "workload_identity_type": None,
                    "azure_webjobs_storage_value_type": "plain-text",
                    "run_from_package": None,
                    "key_vault_reference_count": 0,
                    "summary": "plain storage without identity",
                    "related_ids": [],
                },
                {
                    "id": "func-2",
                    "name": "zzz-identity-plain-signal",
                    "default_hostname": "zzz-identity-plain-signal.azurewebsites.net",
                    "public_network_access": "Enabled",
                    "https_only": True,
                    "client_cert_enabled": False,
                    "min_tls_version": "1.2",
                    "ftps_state": "Disabled",
                    "runtime_stack": "PYTHON|3.11",
                    "functions_extension_version": "~4",
                    "always_on": True,
                    "workload_identity_type": "SystemAssigned",
                    "azure_webjobs_storage_value_type": "plain-text",
                    "run_from_package": True,
                    "key_vault_reference_count": 2,
                    "summary": "identity-backed function with multiple deployment signals",
                    "related_ids": [],
                },
                {
                    "id": "func-3",
                    "name": "bbb-identity-quiet",
                    "default_hostname": "bbb-identity-quiet.azurewebsites.net",
                    "public_network_access": "Enabled",
                    "https_only": True,
                    "client_cert_enabled": False,
                    "min_tls_version": "1.2",
                    "ftps_state": "Disabled",
                    "runtime_stack": "PYTHON|3.11",
                    "functions_extension_version": "~4",
                    "always_on": True,
                    "workload_identity_type": "SystemAssigned",
                    "azure_webjobs_storage_value_type": "keyvault-ref",
                    "run_from_package": None,
                    "key_vault_reference_count": 0,
                    "summary": "identity-backed function with quieter deployment posture",
                    "related_ids": [],
                },
                {
                    "id": "func-4",
                    "name": "ccc-identity-plain",
                    "default_hostname": "ccc-identity-plain.azurewebsites.net",
                    "public_network_access": "Enabled",
                    "https_only": True,
                    "client_cert_enabled": False,
                    "min_tls_version": "1.2",
                    "ftps_state": "Disabled",
                    "runtime_stack": "PYTHON|3.11",
                    "functions_extension_version": "~4",
                    "always_on": True,
                    "workload_identity_type": "SystemAssigned",
                    "azure_webjobs_storage_value_type": "plain-text",
                    "run_from_package": None,
                    "key_vault_reference_count": 0,
                    "summary": "identity-backed function with plain storage",
                    "related_ids": [],
                },
            ],
            "issues": [],
        }

    def arm_deployments(self) -> dict:
        return {
            "deployments": [
                {
                    "id": "dep-1",
                    "name": "zzz-sub-routine",
                    "scope": "/subscriptions/test",
                    "scope_type": "subscription",
                    "resource_group": None,
                    "provisioning_state": "Succeeded",
                    "outputs_count": 0,
                    "output_resource_count": 0,
                    "providers": [],
                    "template_link": None,
                    "parameters_link": None,
                    "summary": "routine subscription deployment",
                    "related_ids": [],
                },
                {
                    "id": "dep-2",
                    "name": "aaa-rg-linked",
                    "scope": "/subscriptions/test/resourceGroups/rg-apps",
                    "scope_type": "resource_group",
                    "resource_group": "rg-apps",
                    "provisioning_state": "Succeeded",
                    "outputs_count": 2,
                    "output_resource_count": 3,
                    "providers": ["Microsoft.Web"],
                    "template_link": "https://example.invalid/templates/app.json",
                    "parameters_link": "https://example.invalid/parameters/app.json",
                    "summary": "linked deployment with outputs",
                    "related_ids": [],
                },
                {
                    "id": "dep-3",
                    "name": "mmm-rg-failed",
                    "scope": "/subscriptions/test/resourceGroups/rg-apps",
                    "scope_type": "resource_group",
                    "resource_group": "rg-apps",
                    "provisioning_state": "Failed",
                    "outputs_count": 0,
                    "output_resource_count": 0,
                    "providers": ["Microsoft.Web"],
                    "template_link": None,
                    "parameters_link": None,
                    "summary": "failed deployment",
                    "related_ids": [],
                },
            ],
            "issues": [],
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


class PartialApplicationGatewayFixtureProvider(FixtureProvider):
    def application_gateway(self) -> dict:
        data = self._read("application_gateway")
        row = dict(data["application_gateways"][0])
        row["public_ip_addresses"] = []
        row["summary"] = (
            "Application Gateway 'agw-shared-edge-01' publishes 1 public frontend(s). "
            "Visible routing breadth: 4 listener(s), 4 routing rule(s), 3 backend pool(s), "
            "5 backend target(s). Visible WAF protection is disabled. This is a shared front "
            "door, so if the edge is weak the apps behind it may deserve review next."
        )
        return {
            "application_gateways": [row],
            "issues": [
                {
                    "kind": "permission_denied",
                    "message": "application_gateway.public_ip_addresses: 403 Forbidden",
                    "context": {"collector": "application_gateway.public_ip_addresses"},
                }
            ],
        }


def test_collect_whoami(fixture_provider, options) -> None:
    output = collect_whoami(fixture_provider, options)
    assert output.principal is not None
    assert output.principal.id == "33333333-3333-3333-3333-333333333333"


def test_collect_automation(fixture_provider, options) -> None:
    output = collect_automation(fixture_provider, options)
    assert len(output.automation_accounts) == 2
    assert output.automation_accounts[0].name == "aa-hybrid-prod"
    assert output.automation_accounts[0].hybrid_worker_group_count == 1
    assert output.automation_accounts[0].webhook_count == 2
    assert output.automation_accounts[0].identity_type == "SystemAssigned"
    assert output.automation_accounts[1].name == "aa-lab-quiet"
    assert output.metadata.command == "automation"


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


def test_collect_app_services_sorts_identity_and_weaker_hardening_first(options) -> None:
    output = collect_app_services(DriftOrderingFixtureProvider(Path(".")), options)

    assert [item.name for item in output.app_services] == [
        "mmm-weak-id",
        "zzz-hardened-id",
        "aaa-weak-no-id",
    ]


def test_collect_acr_sorts_permissive_posture_then_webhooks_replication_and_governance(
    options,
) -> None:
    output = collect_acr(DriftOrderingFixtureProvider(Path(".")), options)

    assert [item.name for item in output.registries] == [
        "acr-public",
        "acr-webhooks",
        "acr-replication",
        "acr-governance-weak",
    ]


def test_collect_databases_sorts_exposure_then_tls_then_database_count_then_identity(
    options,
) -> None:
    output = collect_databases(DriftOrderingFixtureProvider(Path(".")), options)

    assert [item.name for item in output.database_servers] == [
        "db-public-weak-tls",
        "db-public-many",
        "db-public-identity",
        "db-private-identity",
    ]


def test_collect_aks_sorts_public_control_plane_then_identity_federation_addons_and_auth(
    options,
) -> None:
    output = collect_aks(DriftOrderingFixtureProvider(Path(".")), options)

    assert [item.name for item in output.aks_clusters] == [
        "aks-public-federated",
        "aks-public-addon",
        "aks-public-auth-cues",
        "aks-private-federated",
    ]


def test_collect_nics_sorts_public_then_unusual_attachment_then_boundary_context(options) -> None:
    output = collect_nics(DriftOrderingFixtureProvider(Path(".")), options)

    assert [item.name for item in output.nic_assets] == [
        "nic-public",
        "nic-unattached",
        "nic-routine",
    ]


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
    assert output.database_servers[1].engine == "PostgreSqlFlexible"
    assert output.database_servers[1].name == "pg-public-legacy"
    assert output.database_servers[1].database_count == 2
    assert output.database_servers[1].public_network_access == "Enabled"
    assert output.database_servers[2].name == "sql-ops-01"
    assert output.database_servers[2].workload_identity_type == "SystemAssigned"
    assert output.database_servers[2].user_database_names == ["appdb"]
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


def test_azure_provider_databases_uses_postgresql_flexible_list_surface() -> None:
    provider = AzureProvider.__new__(AzureProvider)
    provider.clients = SimpleNamespace(
        sql=SimpleNamespace(servers=SimpleNamespace(list=lambda: [])),
        postgresql_flexible=SimpleNamespace(
            servers=SimpleNamespace(
                list=lambda: [
                    SimpleNamespace(
                        id=(
                            "/subscriptions/test/resourceGroups/rg-data/providers/"
                            "Microsoft.DBforPostgreSQL/flexibleServers/pg-live"
                        ),
                        name="pg-live",
                        fully_qualified_domain_name="pg-live.postgres.database.azure.com",
                        version="16",
                        public_network_access="Enabled",
                    )
                ]
            ),
            databases=SimpleNamespace(
                list_by_server=lambda resource_group, server_name: [
                    SimpleNamespace(name="postgres"),
                    SimpleNamespace(name="app"),
                    SimpleNamespace(name="orders"),
                ]
            ),
        ),
        mysql_flexible=SimpleNamespace(servers=SimpleNamespace(list=lambda: [])),
    )

    data = provider.databases()

    assert data["issues"] == []
    assert len(data["database_servers"]) == 1
    row = data["database_servers"][0]
    assert row["engine"] == "PostgreSqlFlexible"
    assert row["name"] == "pg-live"
    assert row["database_count"] == 2
    assert row["user_database_names"] == ["app", "orders"]


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
    assert output.dns_zones[2].private_endpoint_reference_count == 2


def test_collect_dns_keeps_command_level_issue_explicit(
    fixture_dir: Path, options
) -> None:
    provider = PartialDnsFixtureProvider(fixture_dir)

    output = collect_dns(provider, options)

    assert output.dns_zones == []
    assert output.issues[0].kind == "permission_denied"
    assert output.issues[0].context["collector"] == "dns.resources"


def test_azure_provider_dns_hydrates_zone_details_when_arm_list_is_thin() -> None:
    provider = AzureProvider.__new__(AzureProvider)
    get_by_id_calls: list[tuple[str, str]] = []
    public_zone_id = (
        "/subscriptions/test/resourceGroups/rg-network/providers/"
        "Microsoft.Network/dnszones/corp.example.com"
    )
    private_zone_id = (
        "/subscriptions/test/resourceGroups/rg-network/providers/"
        "Microsoft.Network/privateDnsZones/privatelink.database.windows.net"
    )
    public_zone = SimpleNamespace(
        id=public_zone_id,
        type="Microsoft.Network/dnszones",
        name="corp.example.com",
        location="global",
        properties={},
    )
    private_zone = SimpleNamespace(
        id=private_zone_id,
        type="Microsoft.Network/privateDnsZones",
        name="privatelink.database.windows.net",
        location="global",
        properties={"numberOfRecordSets": 6},
    )
    hydrated_public_zone = SimpleNamespace(
        **{
            **public_zone.__dict__,
            "properties": {
                "numberOfRecordSets": 9,
                "nameServers": ["ns1", "ns2", "ns3", "ns4"],
            },
        }
    )
    hydrated_private_zone = SimpleNamespace(
        **{
            **private_zone.__dict__,
            "properties": {
                "numberOfRecordSets": 6,
                "numberOfVirtualNetworkLinks": 2,
                "numberOfVirtualNetworkLinksWithRegistration": 1,
            },
        }
    )
    hydrated_by_id = {
        public_zone_id: hydrated_public_zone,
        private_zone_id: hydrated_private_zone,
    }
    provider.clients = SimpleNamespace(
        resource=SimpleNamespace(
            resources=SimpleNamespace(
                list=lambda: [public_zone, private_zone],
                get_by_id=lambda resource_id, api_version: (
                    get_by_id_calls.append((resource_id, api_version))
                    or hydrated_by_id[resource_id]
                ),
            )
        ),
        network=SimpleNamespace(
            private_endpoints=SimpleNamespace(list_by_subscription=lambda: []),
        ),
    )

    data = provider.dns()

    assert data["issues"] == []
    assert get_by_id_calls == [
        (public_zone_id, "2018-05-01"),
        (private_zone_id, "2020-06-01"),
    ]
    assert data["dns_zones"][0]["record_set_count"] == 9
    assert data["dns_zones"][0]["name_servers"] == ["ns1", "ns2", "ns3", "ns4"]
    assert data["dns_zones"][1]["linked_virtual_network_count"] == 2
    assert data["dns_zones"][1]["registration_virtual_network_count"] == 1


def test_collect_application_gateway(fixture_provider, options) -> None:
    output = collect_application_gateway(fixture_provider, options)

    assert len(output.application_gateways) == 3
    assert len(output.findings) == 0
    assert output.application_gateways[0].name == "agw-shared-edge-01"
    assert output.application_gateways[0].public_frontend_count == 1
    assert output.application_gateways[0].listener_count == 4
    assert output.application_gateways[0].request_routing_rule_count == 4
    assert output.application_gateways[0].backend_pool_count == 3
    assert output.application_gateways[0].backend_target_count == 5
    assert output.application_gateways[0].waf_enabled is False
    assert output.application_gateways[2].name == "agw-internal-payments"
    assert output.application_gateways[2].public_frontend_count == 0


def test_collect_application_gateway_sorts_public_then_shared_breadth_then_waf(options) -> None:
    output = collect_application_gateway(DriftOrderingFixtureProvider(Path(".")), options)

    assert [item.name for item in output.application_gateways] == [
        "zzz-public-prevention",
        "mmm-public-weak",
        "bbb-public-tiny-weak",
        "aaa-internal-detection",
    ]


def test_collect_application_gateway_keeps_command_level_issue_explicit(
    fixture_dir: Path, options
) -> None:
    provider = PartialApplicationGatewayFixtureProvider(fixture_dir)

    output = collect_application_gateway(provider, options)

    assert len(output.application_gateways) == 1
    assert output.application_gateways[0].public_ip_addresses == []
    assert "20.30.40.50" not in output.application_gateways[0].summary
    assert output.issues[0].kind == "permission_denied"
    assert output.issues[0].context["collector"] == "application_gateway.public_ip_addresses"


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


def test_azure_provider_acr_hydrates_registry_when_list_surface_is_thin() -> None:
    provider = AzureProvider.__new__(AzureProvider)
    get_calls: list[tuple[str, str]] = []
    thin_registry = SimpleNamespace(
        id=(
            "/subscriptions/test/resourceGroups/rg/providers/"
            "Microsoft.ContainerRegistry/registries/acr-live"
        ),
        name="acr-live",
        location="eastus",
        provisioning_state="Succeeded",
        login_server="acr-live.azurecr.io",
        sku=SimpleNamespace(name="Premium"),
        public_network_access=None,
        network_rule_bypass_options="AzureServices",
        network_rule_set=SimpleNamespace(default_action="Allow"),
        admin_user_enabled=False,
        anonymous_pull_enabled=False,
        data_endpoint_enabled=False,
        private_endpoint_connections=[],
        identity=None,
        policies=None,
    )
    hydrated_registry = SimpleNamespace(
        **{
            **thin_registry.__dict__,
            "public_network_access": "Enabled",
            "identity": SimpleNamespace(
                type="SystemAssigned",
                principal_id="principal-1",
                client_id="client-1",
                user_assigned_identities={},
            ),
        }
    )
    provider.clients = SimpleNamespace(
        container_registry=SimpleNamespace(
            registries=SimpleNamespace(
                list=lambda: [thin_registry],
                get=lambda resource_group, registry_name: (
                    get_calls.append((resource_group, registry_name)) or hydrated_registry
                ),
            ),
            webhooks=SimpleNamespace(list=lambda resource_group, registry_name: []),
            replications=SimpleNamespace(list=lambda resource_group, registry_name: []),
        )
    )

    data = provider.acr()

    assert data["issues"] == []
    assert get_calls == [("rg", "acr-live")]
    assert data["registries"][0]["public_network_access"] == "Enabled"
    assert data["registries"][0]["workload_identity_type"] == "SystemAssigned"


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


def test_azure_provider_aks_hydrates_cluster_when_list_surface_is_thin() -> None:
    provider = AzureProvider.__new__(AzureProvider)
    get_calls: list[tuple[str, str]] = []
    thin_cluster = SimpleNamespace(
        id=(
            "/subscriptions/test/resourceGroups/rg-aks/providers/"
            "Microsoft.ContainerService/managedClusters/aks-live"
        ),
        name="aks-live",
        location="eastus",
        provisioning_state="Succeeded",
        kubernetes_version="1.29.4",
        sku=SimpleNamespace(tier="Standard"),
        node_resource_group="MC_rg-aks_aks-live_eastus",
        fqdn="aks-live.hcp.eastus.azmk8s.io",
        private_fqdn=None,
        identity=SimpleNamespace(
            type="SystemAssigned",
            principal_id="principal-1",
            client_id="client-1",
            user_assigned_identities={},
        ),
        service_principal_profile=None,
        aad_profile=SimpleNamespace(managed=True, enable_azure_rbac=True),
        api_server_access_profile=None,
        network_profile=SimpleNamespace(
            network_plugin="azure",
            network_policy="calico",
            outbound_type="loadBalancer",
        ),
        oidc_issuer_profile=SimpleNamespace(
            enabled=True,
            issuer_url="https://issuer.example",
        ),
        security_profile=None,
        ingress_profile=None,
        addon_profiles={},
        agent_pool_profiles=[SimpleNamespace(name="systempool")],
        disable_local_accounts=True,
    )
    hydrated_cluster = SimpleNamespace(
        **{
            **thin_cluster.__dict__,
            "private_fqdn": "aks-live.privatelink.eastus.azmk8s.io",
            "api_server_access_profile": SimpleNamespace(
                enable_private_cluster=True,
                enable_private_cluster_public_fqdn=False,
            ),
            "security_profile": SimpleNamespace(
                workload_identity=SimpleNamespace(enabled=True)
            ),
            "ingress_profile": SimpleNamespace(
                web_app_routing=SimpleNamespace(
                    enabled=True,
                    dns_zone_resource_ids=["/dns/zone1"],
                )
            ),
        }
    )
    provider.clients = SimpleNamespace(
        containerservice=SimpleNamespace(
            managed_clusters=SimpleNamespace(
                list=lambda: [thin_cluster],
                get=lambda resource_group, resource_name: (
                    get_calls.append((resource_group, resource_name)) or hydrated_cluster
                ),
            )
        )
    )

    data = provider.aks()

    assert data["issues"] == []
    assert get_calls == [("rg-aks", "aks-live")]
    row = data["aks_clusters"][0]
    assert row["private_cluster_enabled"] is True
    assert row["workload_identity_enabled"] is True
    assert row["web_app_routing_enabled"] is True


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


def test_collect_functions_sorts_identity_plain_storage_and_signal_strength(options) -> None:
    output = collect_functions(DriftOrderingFixtureProvider(Path(".")), options)

    assert [item.name for item in output.function_apps] == [
        "zzz-identity-plain-signal",
        "ccc-identity-plain",
        "bbb-identity-quiet",
        "aaa-plain-no-id",
    ]


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
    assert output.deployments[0].name == "app-failed"
    assert output.deployments[1].name == "sub-foundation"
    assert output.deployments[2].name == "kv-secrets"


def test_collect_arm_deployments_sorts_failures_and_linked_rows_first(options) -> None:
    output = collect_arm_deployments(DriftOrderingFixtureProvider(Path(".")), options)

    assert [item.name for item in output.deployments] == [
        "mmm-rg-failed",
        "aaa-rg-linked",
        "zzz-sub-routine",
    ]


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
    assert "tokens-credentials first" in output.env_vars[0].summary
    assert output.env_vars[1].key_vault_reference_identity == "SystemAssigned"
    assert "Check keyvault" in output.env_vars[1].summary


def test_collect_tokens_credentials(fixture_provider, options) -> None:
    output = collect_tokens_credentials(fixture_provider, options)
    assert len(output.surfaces) == 12
    assert len(output.findings) == 12
    assert len({finding.id for finding in output.findings}) == len(output.findings)
    assert output.surfaces[0].surface_type == "plain-text-secret"
    assert output.surfaces[1].operator_signal == "setting=AzureWebJobsStorage"
    assert "Check env-vars" in output.surfaces[0].summary
    assert any(item.asset_name == "app-empty-mi" for item in output.surfaces)
    assert any(item.asset_name == "vmss-edge-01" for item in output.surfaces)
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


def test_devops_pipeline_summary_surfaces_partial_read_refs() -> None:
    pipeline, issues = _devops_pipeline_summary(
        organization="contoso",
        project={"name": "prod-platform", "id": "project-1"},
        definition={
            "id": 17,
            "name": "deploy-prod",
            "repository": {"name": "platform-api", "type": "TfsGit"},
            "process": {
                "phases": [
                    {
                        "steps": [
                            {
                                "inputs": {
                                    "connectedServiceNameARM": "prod-subscription",
                                }
                            }
                        ]
                    }
                ]
            },
            "variableGroups": [91, 92],
        },
        service_endpoints_by_id={},
        service_endpoints_by_name={},
        variable_groups_by_id={
            91: {
                "id": 91,
                "name": "prod-release",
                "variables": {"DB_PASSWORD": {"isSecret": True}},
            }
        },
    )

    assert pipeline["partial_read"] is True
    assert "partial-read" in pipeline["risk_cues"]
    assert (
        "Restore service-connection or variable-group visibility before choosing the next Azure "
        "follow-up."
        in pipeline["summary"]
    )
    assert len(issues) == 2
    assert issues[0]["kind"] == "partial_collection"
    assert "unresolved variable group refs" in issues[0]["message"]


def test_devops_next_review_hint_prefers_target_then_keyvault() -> None:
    hint = devops_next_review_hint(
        target_clues=["AKS/Kubernetes", "ACR/Containers"],
        key_vault_names=["kv-prod-shared"],
        key_vault_group_names=["prod-kv-release"],
        azure_service_connection_names=["prod-subscription"],
        partial_read=False,
    )

    assert hint == (
        "Check aks for the named deployment target; review permissions and role-trusts for "
        "Azure control; review keyvault for the vault-backed support."
    )


def test_env_var_next_review_hint_prefers_keyvault_then_identity() -> None:
    hint = env_var_next_review_hint(
        setting_name="PAYMENT_API_KEY",
        value_type="keyvault-ref",
        looks_sensitive=True,
        reference_target="kvlabopen01.vault.azure.net/secrets/payment-api-key",
        workload_identity_type="SystemAssigned, UserAssigned",
    )

    assert hint == (
        "Check keyvault for the referenced secret path; review managed-identities for the "
        "workload token path."
    )


def test_tokens_credential_next_review_hint_prefers_endpoints_for_public_imds() -> None:
    from azurefox.tokens_credential_hints import tokens_credential_next_review_hint

    hint = tokens_credential_next_review_hint(
        surface_type="managed-identity-token",
        access_path="imds",
        operator_signal="public-ip=52.160.10.20; identities=1",
    )

    assert hint == (
        "Check endpoints for the ingress path, then managed-identities and permissions for "
        "Azure control."
    )


def test_collect_managed_identities_surfaces_handoff_fields(fixture_provider, options) -> None:
    output = collect_managed_identities(fixture_provider, options)

    assert (
        output.identities[0].operator_signal
        == "Public VM workload pivot; direct control visible."
    )
    assert (
        output.identities[0].next_review
        == "Check permissions for direct control on this identity, then vms for the host "
        "context behind the workload pivot."
    )
    assert "Current scope already shows direct control" in (output.identities[0].summary or "")


def test_collect_managed_identities_sorts_and_blocks_visibility() -> None:
    class StubProvider:
        def metadata_context(self) -> dict[str, str | None]:
            return {"tenant_id": None, "subscription_id": None, "token_source": None}

        def managed_identities(self) -> dict:
            return {
                "identities": [
                    {
                        "id": "identity-public-vm",
                        "name": "ua-prod",
                        "identity_type": "userAssigned",
                        "principal_id": "principal-1",
                        "client_id": None,
                        "attached_to": [
                            "/subscriptions/test/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-edge"
                        ],
                        "scope_ids": ["/subscriptions/test"],
                    },
                    {
                        "id": "identity-web-blocked",
                        "name": "app-edge-system",
                        "identity_type": "systemAssigned",
                        "principal_id": None,
                        "client_id": None,
                        "attached_to": [
                            "/subscriptions/test/resourceGroups/rg/providers/Microsoft.Web/sites/app-edge"
                        ],
                        "scope_ids": ["/subscriptions/test"],
                    },
                ],
                "role_assignments": [
                    {
                        "id": "ra-1",
                        "scope_id": "/subscriptions/test",
                        "principal_id": "principal-1",
                        "principal_type": "ServicePrincipal",
                        "role_definition_id": "rd-owner",
                        "role_name": "Owner",
                    }
                ],
                "issues": [],
            }

        def vms(self) -> dict:
            return {
                "vm_assets": [
                    {
                        "id": (
                            "/subscriptions/test/resourceGroups/rg/providers/Microsoft.Compute/"
                            "virtualMachines/vm-edge"
                        ),
                        "name": "vm-edge",
                        "public_ips": ["52.160.10.20"],
                    }
                ],
                "issues": [],
            }

        def vmss(self) -> dict:
            return {"vmss_assets": [], "issues": []}

    options = GlobalOptions(
        tenant=None,
        subscription=None,
        output=OutputMode.JSON,
        outdir=Path("/tmp"),
        debug=False,
        role_trusts_mode=RoleTrustsMode.FAST,
    )

    output = collect_managed_identities(StubProvider(), options)

    assert [item.name for item in output.identities] == ["ua-prod", "app-edge-system"]
    assert (
        output.identities[0].operator_signal
        == "Public VM workload pivot; direct control visible."
    )
    assert output.identities[1].operator_signal == "Web workload pivot; visibility blocked."
    assert (
        output.identities[1].next_review
        == "Check env-vars for the backing workload context; current scope does not yet show "
        "direct control on this identity."
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


def test_collect_devops_metadata_keeps_org_from_options(
    fixture_dir: Path, tmp_path: Path
) -> None:
    provider = MetadataFixtureProvider(fixture_dir)
    options = GlobalOptions(
        tenant=None,
        subscription=None,
        output=OutputMode.JSON,
        outdir=tmp_path,
        debug=False,
        devops_organization="contoso",
        role_trusts_mode=RoleTrustsMode.FAST,
    )

    output = collect_devops(provider, options)

    assert output.metadata.devops_organization == "contoso"


def test_collect_auth_policies(fixture_provider, options) -> None:
    output = collect_auth_policies(fixture_provider, options)
    assert len(output.auth_policies) == 4
    assert len(output.findings) == 5
    assert output.auth_policies[0].policy_type == "security-defaults"
    assert output.auth_policies[1].policy_type == "authorization-policy"
    assert output.auth_policies[2].name == "CA002: Block legacy auth"
    assert output.auth_policies[3].name == "CA001: Require multi-factor authentication for admins"


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


def test_principal_sort_key_prioritizes_high_impact_then_workload_attachment() -> None:
    principals = [
        {
            "id": "reader-workload",
            "display_name": "reader-workload",
            "role_names": ["Reader"],
            "attached_to": [
                "/subscriptions/test/resourceGroups/rg/providers/Microsoft.Compute/"
                "virtualMachines/vm-a"
            ],
            "scope_ids": ["/subscriptions/test"],
            "role_assignment_count": 1,
        },
        {
            "id": "owner-user",
            "display_name": "owner-user",
            "role_names": ["Owner"],
            "attached_to": [],
            "scope_ids": ["/subscriptions/test"],
            "role_assignment_count": 1,
        },
        {
            "id": "alpha-reader",
            "display_name": "alpha-reader",
            "role_names": ["Reader"],
            "attached_to": [],
            "scope_ids": ["/subscriptions/test"],
            "role_assignment_count": 1,
        },
    ]

    ordered = sorted(principals, key=_principal_sort_key)

    assert [item["id"] for item in ordered] == [
        "owner-user",
        "reader-workload",
        "alpha-reader",
    ]


def test_collect_permissions(fixture_provider, options) -> None:
    output = collect_permissions(fixture_provider, options)
    assert len(output.permissions) == 2
    assert output.permissions[0].privileged is True
    assert output.permissions[0].high_impact_roles == ["Owner"]
    assert output.permissions[0].operator_signal == "Direct control visible; current foothold."
    assert (
        output.permissions[0].next_review
        == "Check privesc for the direct abuse or escalation path behind this current identity."
    )
    assert "direct control visible" in (output.permissions[0].summary or "").lower()


def test_collect_permissions_prefers_workload_pivot_then_trust_expansion() -> None:
    class StubProvider:
        def permissions(self) -> dict:
            return {
                "permissions": [
                    {
                        "principal_id": "current-sp",
                        "display_name": "current-sp",
                        "principal_type": "ServicePrincipal",
                        "high_impact_roles": ["Owner"],
                        "all_role_names": ["Owner"],
                        "role_assignment_count": 1,
                        "scope_count": 1,
                        "scope_ids": ["/subscriptions/test"],
                        "privileged": True,
                        "is_current_identity": True,
                    },
                    {
                        "principal_id": "workload-sp",
                        "display_name": "workload-sp",
                        "principal_type": "ServicePrincipal",
                        "high_impact_roles": ["Contributor"],
                        "all_role_names": ["Contributor"],
                        "role_assignment_count": 2,
                        "scope_count": 1,
                        "scope_ids": ["/subscriptions/test"],
                        "privileged": True,
                        "is_current_identity": False,
                    },
                    {
                        "principal_id": "attachment-only-sp",
                        "display_name": "attachment-only-sp",
                        "principal_type": "ServicePrincipal",
                        "high_impact_roles": ["Contributor"],
                        "all_role_names": ["Contributor"],
                        "role_assignment_count": 2,
                        "scope_count": 1,
                        "scope_ids": ["/subscriptions/test"],
                        "privileged": True,
                        "is_current_identity": False,
                    },
                    {
                        "principal_id": "trust-sp",
                        "display_name": "trust-sp",
                        "principal_type": "ServicePrincipal",
                        "high_impact_roles": ["Contributor"],
                        "all_role_names": ["Contributor"],
                        "role_assignment_count": 3,
                        "scope_count": 1,
                        "scope_ids": ["/subscriptions/test"],
                        "privileged": True,
                        "is_current_identity": False,
                    },
                ],
                "issues": [],
            }

        def principals(self) -> dict:
            return {
                "principals": [
                    {
                        "id": "current-sp",
                        "principal_type": "ServicePrincipal",
                        "display_name": "current-sp",
                        "sources": ["rbac", "whoami"],
                        "scope_ids": ["/subscriptions/test"],
                        "role_names": ["Owner"],
                        "role_assignment_count": 1,
                        "identity_names": [],
                        "identity_types": [],
                        "attached_to": [],
                        "is_current_identity": True,
                    },
                    {
                        "id": "workload-sp",
                        "principal_type": "ServicePrincipal",
                        "display_name": "workload-sp",
                        "sources": ["rbac", "managed-identities"],
                        "scope_ids": ["/subscriptions/test"],
                        "role_names": ["Contributor"],
                        "role_assignment_count": 2,
                        "identity_names": ["ua-orders"],
                        "identity_types": ["userAssigned"],
                        "attached_to": [
                            "/subscriptions/test/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-edge"
                        ],
                        "is_current_identity": False,
                    },
                    {
                        "id": "attachment-only-sp",
                        "principal_type": "ServicePrincipal",
                        "display_name": "attachment-only-sp",
                        "sources": ["rbac", "managed-identities"],
                        "scope_ids": ["/subscriptions/test"],
                        "role_names": ["Contributor"],
                        "role_assignment_count": 2,
                        "identity_names": [],
                        "identity_types": [],
                        "attached_to": [
                            "/subscriptions/test/resourceGroups/rg/providers/Microsoft.Web/sites/app-edge"
                        ],
                        "is_current_identity": False,
                    },
                    {
                        "id": "trust-sp",
                        "principal_type": "ServicePrincipal",
                        "display_name": "trust-sp",
                        "sources": ["rbac"],
                        "scope_ids": ["/subscriptions/test"],
                        "role_names": ["Contributor"],
                        "role_assignment_count": 3,
                        "identity_names": [],
                        "identity_types": [],
                        "attached_to": [],
                        "is_current_identity": False,
                    },
                ],
                "issues": [],
            }

        def metadata_context(self) -> dict[str, str | None]:
            return {"tenant_id": None, "subscription_id": None, "token_source": None}

    options = GlobalOptions(
        tenant=None,
        subscription=None,
        output=OutputMode.JSON,
        outdir=Path("/tmp"),
        debug=False,
        role_trusts_mode=RoleTrustsMode.FAST,
    )

    output = collect_permissions(StubProvider(), options)

    assert [item.principal_id for item in output.permissions] == [
        "current-sp",
        "workload-sp",
        "attachment-only-sp",
        "trust-sp",
    ]
    assert (
        output.permissions[1].operator_signal
        == "Direct control visible; workload pivot visible."
    )
    assert (
        output.permissions[1].next_review
        == "Check managed-identities for the workload pivot behind this direct control row."
    )
    assert (
        output.permissions[2].operator_signal
        == "Direct control visible; workload pivot visible."
    )
    assert (
        output.permissions[2].next_review
        == "Check managed-identities for the workload pivot behind this direct control row."
    )
    assert (
        output.permissions[3].operator_signal
        == "Direct control visible; trust expansion follow-on."
    )
    assert (
        output.permissions[3].next_review
        == "Check role-trusts for trust expansion around who can influence this principal."
    )


def test_collect_privesc(fixture_provider, options) -> None:
    output = collect_privesc(fixture_provider, options)
    assert len(output.paths) == 2
    assert output.paths[0].path_type == "direct-role-abuse"
    assert output.paths[1].asset == "vm-web-01"


def test_privesc_sort_key_prioritizes_severity_then_current_identity_then_path_type() -> None:
    paths = [
        {
            "severity": "medium",
            "current_identity": False,
            "path_type": "direct-role-abuse",
            "principal": "medium-row",
            "asset": None,
        },
        {
            "severity": "high",
            "current_identity": False,
            "path_type": "public-identity-pivot",
            "principal": "public-pivot",
            "asset": "vm-edge-01",
        },
        {
            "severity": "high",
            "current_identity": True,
            "path_type": "direct-role-abuse",
            "principal": "current-owner",
            "asset": None,
        },
    ]

    ordered = sorted(paths, key=_privesc_sort_key)

    assert [item["principal"] for item in ordered] == [
        "current-owner",
        "public-pivot",
        "medium-row",
    ]


def test_collect_role_trusts(fixture_provider, options) -> None:
    output = collect_role_trusts(fixture_provider, options)
    assert output.mode == "fast"
    assert len(output.trusts) == 4
    assert output.trusts[0].trust_type == "federated-credential"
    assert output.trusts[1].trust_type == "service-principal-owner"
    assert output.trusts[2].trust_type == "app-owner"


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
    assert output.key_vaults[1].name == "kvlabdeny01"
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
    assert output.storage_assets[0].name == "stlabpub01"
    assert output.storage_assets[0].public_network_access == "Enabled"
    assert output.storage_assets[0].allow_shared_key_access is True
    assert output.storage_assets[1].name == "stlabpriv01"
    assert output.storage_assets[1].minimum_tls_version == "TLS1_2"
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
    assert output.storage_assets[0].public_network_access is None
    assert output.storage_assets[0].allow_shared_key_access is None
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
    assert len(output.vm_assets) == 1
    assert output.vm_assets[0].name == "vm-web-01"
    assert len(output.findings) == 1


def test_vm_asset_sort_key_prioritizes_public_and_identity_cues() -> None:
    vm_assets = [
        {
            "id": "quiet-vmss",
            "name": "quiet-vmss",
            "vm_type": "vmss",
            "public_ips": [],
            "identity_ids": [],
        },
        {
            "id": "identity-vmss",
            "name": "identity-vmss",
            "vm_type": "vmss",
            "public_ips": [],
            "identity_ids": [
                "/subscriptions/test/resourceGroups/rg/providers/Microsoft.ManagedIdentity/"
                "userAssignedIdentities/id-a"
            ],
        },
        {
            "id": "public-vm",
            "name": "public-vm",
            "vm_type": "vm",
            "public_ips": ["52.160.10.20"],
            "identity_ids": [
                "/subscriptions/test/resourceGroups/rg/providers/Microsoft.ManagedIdentity/"
                "userAssignedIdentities/id-b"
            ],
        },
    ]

    ordered = sorted(vm_assets, key=_vm_asset_sort_key)

    assert [item["id"] for item in ordered] == [
        "public-vm",
        "identity-vmss",
        "quiet-vmss",
    ]


def test_collect_vmss(fixture_provider, options) -> None:
    output = collect_vmss(fixture_provider, options)
    assert len(output.vmss_assets) == 2
    assert output.issues == []
    assert output.vmss_assets[0].name == "vmss-edge-01"
    assert output.vmss_assets[0].public_ip_configuration_count == 1
    assert output.vmss_assets[0].identity_type == "SystemAssigned"
    assert output.vmss_assets[1].name == "vmss-batch-01"


def test_collect_lighthouse(fixture_provider, options) -> None:
    output = collect_lighthouse(fixture_provider, options)
    assert len(output.lighthouse_delegations) == 3
    assert output.issues == []
    assert output.lighthouse_delegations[0].scope_type == "subscription"
    assert output.lighthouse_delegations[0].strongest_role_name == "Owner"
    assert output.lighthouse_delegations[0].managed_by_tenant_name == "Contoso Corp."
    assert output.lighthouse_delegations[1].scope_type == "resource_group"
    assert output.lighthouse_delegations[2].strongest_role_name == "Reader"


def test_collect_cross_tenant(fixture_provider, options) -> None:
    output = collect_cross_tenant(fixture_provider, options)
    assert len(output.cross_tenant_paths) == 4
    assert output.issues == []
    assert output.cross_tenant_paths[0].signal_type == "lighthouse"
    assert output.cross_tenant_paths[0].priority == "high"
    assert output.cross_tenant_paths[1].signal_type == "external-sp"
    assert output.cross_tenant_paths[1].attack_path == "pivot"
    assert output.cross_tenant_paths[3].signal_type == "lighthouse"


def test_cross_tenant_surfaces_external_service_principal_without_principal_join() -> None:
    provider = AzureProvider.__new__(AzureProvider)
    provider.session = SimpleNamespace(tenant_id="11111111-1111-1111-1111-111111111111")
    provider.graph = SimpleNamespace(
        list_service_principals=lambda: [
            {
                "id": "sp-external-readable",
                "appId": "app-external-readable",
                "displayName": "external-readable-app",
                "appOwnerOrganizationId": "77777777-7777-7777-7777-777777777777",
            }
        ]
    )
    provider.lighthouse = lambda: {"lighthouse_delegations": [], "issues": []}
    provider.auth_policies = lambda: {"auth_policies": [], "issues": []}
    provider.principals = lambda: {"principals": [], "issues": []}

    data = provider.cross_tenant()

    assert data["issues"] == []
    assert len(data["cross_tenant_paths"]) == 1
    row = data["cross_tenant_paths"][0]
    assert row["signal_type"] == "external-sp"
    assert row["priority"] == "low"
    assert row["posture"] == "roles=none-visible; assignments=0; scopes=0"
    assert "no Azure role assignments are visible through the current read path" in row["summary"]


def test_collect_cross_tenant_keeps_subscription_lighthouse_ahead_of_resource_group_ties(
    options,
) -> None:
    provider = SimpleNamespace(
        metadata_context=lambda: {},
        cross_tenant=lambda: {
            "cross_tenant_paths": [
                {
                    "id": "rg-owner",
                    "signal_type": "lighthouse",
                    "name": "RG owner delegation",
                    "tenant_id": "22222222-2222-2222-2222-222222222222",
                    "tenant_name": None,
                    "scope": "resource-group::rg-platform",
                    "posture": "strongest=Owner",
                    "attack_path": "control",
                    "priority": "medium",
                    "summary": "Outside tenant can manage a resource group.",
                    "related_ids": ["rg-owner"],
                },
                {
                    "id": "sub-contributor",
                    "signal_type": "lighthouse",
                    "name": "Subscription contributor delegation",
                    "tenant_id": "99999999-9999-9999-9999-999999999999",
                    "tenant_name": None,
                    "scope": "subscription::lab-subscription",
                    "posture": "strongest=Contributor",
                    "attack_path": "control",
                    "priority": "medium",
                    "summary": "Outside tenant can manage the subscription.",
                    "related_ids": ["sub-contributor"],
                },
            ],
            "issues": [],
        },
    )

    output = collect_cross_tenant(provider, options)

    assert output.cross_tenant_paths[0].id == "sub-contributor"
    assert output.cross_tenant_paths[1].id == "rg-owner"


def test_vmss_summary_emits_partial_issue_when_network_profile_is_missing() -> None:
    vmss = SimpleNamespace(
        id=(
            "/subscriptions/test/resourceGroups/rg/providers/Microsoft.Compute/"
            "virtualMachineScaleSets/vmss-partial"
        ),
        name="vmss-partial",
        location="eastus",
        sku=SimpleNamespace(name="Standard_D2s_v5", capacity=3),
        identity=None,
        upgrade_policy=SimpleNamespace(mode="Manual"),
        orchestration_mode="Flexible",
        overprovision=False,
        single_placement_group=True,
        zone_balance=False,
        zones=[],
        virtual_machine_profile=None,
    )

    asset, issues = _vmss_summary(vmss)

    assert asset["name"] == "vmss-partial"
    assert "Frontend and subnet cues were not fully returned" in asset["summary"]
    assert issues[0]["kind"] == "partial_collection"
    assert issues[0]["context"]["asset_name"] == "vmss-partial"


def test_vmss_summary_emits_partial_issue_when_nic_configs_are_missing() -> None:
    vmss = SimpleNamespace(
        id=(
            "/subscriptions/test/resourceGroups/rg/providers/Microsoft.Compute/"
            "virtualMachineScaleSets/vmss-partial-nics"
        ),
        name="vmss-partial-nics",
        location="eastus",
        sku=SimpleNamespace(name="Standard_D2s_v5", capacity=3),
        identity=None,
        upgrade_policy=SimpleNamespace(mode="Manual"),
        orchestration_mode="Flexible",
        overprovision=False,
        single_placement_group=True,
        zone_balance=False,
        zones=[],
        virtual_machine_profile=SimpleNamespace(
            network_profile=SimpleNamespace(network_interface_configurations=None)
        ),
    )

    asset, issues = _vmss_summary(vmss)

    assert asset["name"] == "vmss-partial-nics"
    assert "Frontend and subnet cues were not fully returned" in asset["summary"]
    assert issues[0]["kind"] == "partial_collection"
    assert issues[0]["context"]["collector"] == "vmss.network_interface_configurations"


def test_collect_workloads(fixture_provider, options) -> None:
    output = collect_workloads(fixture_provider, options)
    assert len(output.workloads) == 6
    assert len(output.findings) == 0
    assert output.workloads[0].asset_name == "vm-web-01"
    assert output.workloads[0].identity_type == "UserAssigned"
    assert output.workloads[0].endpoints == ["52.160.10.20"]
    assert output.workloads[-2].asset_name == "vmss-edge-01"
    assert output.workloads[-1].asset_name == "vmss-batch-01"
    assert output.workloads[-1].endpoints == []
