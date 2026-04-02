from __future__ import annotations

from pathlib import Path

from azurefox.collectors.commands import (
    collect_api_mgmt,
    collect_app_services,
    collect_arm_deployments,
    collect_auth_policies,
    collect_endpoints,
    collect_env_vars,
    collect_functions,
    collect_inventory,
    collect_keyvault,
    collect_managed_identities,
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
    _env_var_reference_target,
    _network_scope_label,
    _principal_from_claims,
    _web_asset_kind,
)
from azurefox.config import GlobalOptions
from azurefox.models.common import OutputMode


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
        return {
            "api_management_services": [row],
            "issues": [
                {
                    "kind": "permission_denied",
                    "message": "api_mgmt[rg-apps/apim-edge-01].apis: 403 Forbidden",
                    "context": {"collector": "api_mgmt[rg-apps/apim-edge-01].apis"},
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
    assert output.resource_count == 28


def test_collect_app_services(fixture_provider, options) -> None:
    output = collect_app_services(fixture_provider, options)
    assert len(output.app_services) == 2
    assert len(output.findings) == 0
    assert output.app_services[0].name == "app-empty-mi"
    assert output.app_services[0].runtime_stack == "DOTNETCORE|8.0"
    assert output.app_services[0].https_only is False
    assert output.app_services[1].client_cert_enabled is True


def test_collect_api_mgmt(fixture_provider, options) -> None:
    output = collect_api_mgmt(fixture_provider, options)
    assert len(output.api_management_services) == 1
    assert len(output.findings) == 0
    assert output.api_management_services[0].name == "apim-edge-01"
    assert output.api_management_services[0].api_count == 2
    assert output.api_management_services[0].named_value_count == 2
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
    assert output.issues[0].kind == "permission_denied"
    assert output.issues[0].context["collector"] == "api_mgmt[rg-apps/apim-edge-01].apis"


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
    assert len(output.trusts) == 4
    assert output.trusts[0].trust_type == "app-owner"
    assert output.trusts[2].evidence_type == "graph-federated-credential"


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
