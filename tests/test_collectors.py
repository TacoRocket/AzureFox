from __future__ import annotations

from pathlib import Path

from azurefox.collectors.commands import (
    collect_arm_deployments,
    collect_auth_policies,
    collect_env_vars,
    collect_inventory,
    collect_keyvault,
    collect_managed_identities,
    collect_permissions,
    collect_principals,
    collect_privesc,
    collect_rbac,
    collect_resource_trusts,
    collect_role_trusts,
    collect_storage,
    collect_vms,
    collect_whoami,
)
from azurefox.collectors.provider import (
    FixtureProvider,
    _env_var_reference_target,
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
    assert output.resource_count == 27


def test_collect_arm_deployments(fixture_provider, options) -> None:
    output = collect_arm_deployments(fixture_provider, options)
    assert len(output.deployments) == 3
    assert len(output.findings) == 5
    assert output.deployments[0].scope_type == "subscription"


def test_collect_env_vars(fixture_provider, options) -> None:
    output = collect_env_vars(fixture_provider, options)
    assert len(output.env_vars) == 4
    assert len(output.findings) == 2
    assert output.env_vars[0].setting_name == "DB_PASSWORD"
    assert output.env_vars[0].workload_identity_type == "SystemAssigned"
    assert output.env_vars[1].key_vault_reference_identity == "SystemAssigned"


def test_web_asset_kind_filters_out_of_scope_site_kinds() -> None:
    assert _web_asset_kind("app,linux") == "AppService"
    assert _web_asset_kind("functionapp,linux") == "FunctionApp"
    assert _web_asset_kind("workflowapp,linux") is None


def test_env_var_reference_target_supports_secret_uri_form() -> None:
    value = (
        "@Microsoft.KeyVault(SecretUri="
        "https://kvlabopen01.vault.azure.net/secrets/payment-api-key)"
    )

    assert _env_var_reference_target(value) == (
        "kvlabopen01.vault.azure.net/secrets/payment-api-key"
    )


def test_env_var_reference_target_supports_vaultname_form() -> None:
    value = (
        "@Microsoft.KeyVault(VaultName=kvlabopen01;SecretName=payment-api-key;"
        "SecretVersion=123abc)"
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
    assert len(output.key_vaults) == 2
    assert len(output.findings) == 2
    assert output.key_vaults[0].public_network_access == "Enabled"


def test_collect_resource_trusts(fixture_provider, options) -> None:
    output = collect_resource_trusts(fixture_provider, options)
    assert len(output.resource_trusts) == 5
    assert len(output.findings) == 4
    assert output.resource_trusts[0].resource_type == "KeyVault"


def test_collect_storage(fixture_provider, options) -> None:
    output = collect_storage(fixture_provider, options)
    assert len(output.storage_assets) == 2
    assert len(output.findings) == 2


def test_collect_vms(fixture_provider, options) -> None:
    output = collect_vms(fixture_provider, options)
    assert len(output.vm_assets) == 2
    assert len(output.findings) == 1
