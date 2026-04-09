from __future__ import annotations

from azurefox.models.common import (
    SCHEMA_VERSION,
    AcrRegistryAsset,
    AksClusterAsset,
    ApiMgmtServiceAsset,
    AppServiceAsset,
    ArmDeploymentSummary,
    AuthPolicySummary,
    DatabaseServerAsset,
    DnsZoneAsset,
    EndpointSummary,
    EnvVarSummary,
    FunctionAppAsset,
    ManagedIdentity,
    NetworkEffectiveSummary,
    NetworkPortSummary,
    PermissionSummary,
    PrincipalSummary,
    PrivescPathSummary,
    ResourceTrustSummary,
    RoleTrustSummary,
    StorageAsset,
    VmAsset,
    WebWorkloadSummary,
)


def test_schema_version() -> None:
    assert SCHEMA_VERSION == "1.3.0"


def test_arm_deployment_summary_defaults() -> None:
    deployment = ArmDeploymentSummary(
        id="d-1",
        name="dep-1",
        scope="/subscriptions/s1",
        scope_type="subscription",
        summary="test",
    )
    assert deployment.resource_group is None
    assert deployment.providers == []
    assert deployment.related_ids == []


def test_app_service_asset_defaults() -> None:
    asset = AppServiceAsset(id="app-1", name="app01", summary="test")
    assert asset.resource_group is None
    assert asset.default_hostname is None
    assert asset.https_only is False
    assert asset.client_cert_enabled is False
    assert asset.workload_identity_ids == []
    assert asset.related_ids == []


def test_aks_cluster_asset_defaults() -> None:
    asset = AksClusterAsset(id="aks-1", name="aks01", summary="test")
    assert asset.resource_group is None
    assert asset.private_cluster_enabled is None
    assert asset.cluster_identity_ids == []
    assert asset.agent_pool_count is None
    assert asset.oidc_issuer_enabled is None
    assert asset.oidc_issuer_url is None
    assert asset.workload_identity_enabled is None
    assert asset.addon_names == []
    assert asset.web_app_routing_enabled is None
    assert asset.web_app_routing_dns_zone_count is None
    assert asset.related_ids == []


def test_api_mgmt_service_asset_defaults() -> None:
    asset = ApiMgmtServiceAsset(id="apim-1", name="apim01", summary="test")
    assert asset.resource_group is None
    assert asset.gateway_hostnames == []
    assert asset.public_ip_address_id is None
    assert asset.public_ip_addresses == []
    assert asset.api_count is None
    assert asset.api_subscription_required_count is None
    assert asset.subscription_count is None
    assert asset.active_subscription_count is None
    assert asset.gateway_enabled is None
    assert asset.backend_hostnames == []
    assert asset.named_value_secret_count is None
    assert asset.named_value_key_vault_count is None
    assert asset.related_ids == []


def test_acr_registry_asset_defaults() -> None:
    asset = AcrRegistryAsset(id="acr-1", name="acr01", summary="test")
    assert asset.resource_group is None
    assert asset.login_server is None
    assert asset.admin_user_enabled is None
    assert asset.private_endpoint_connection_count == 0
    assert asset.webhook_count is None
    assert asset.webhook_action_types == []
    assert asset.replication_regions == []
    assert asset.retention_policy_days is None
    assert asset.trust_policy_status is None
    assert asset.workload_identity_ids == []
    assert asset.related_ids == []


def test_database_server_asset_defaults() -> None:
    asset = DatabaseServerAsset(id="sql-1", name="sql01", engine="AzureSql", summary="test")
    assert asset.resource_group is None
    assert asset.fully_qualified_domain_name is None
    assert asset.high_availability_mode is None
    assert asset.delegated_subnet_resource_id is None
    assert asset.private_dns_zone_resource_id is None
    assert asset.database_count is None
    assert asset.user_database_names == []
    assert asset.workload_identity_ids == []
    assert asset.related_ids == []


def test_dns_zone_asset_defaults() -> None:
    asset = DnsZoneAsset(id="dns-1", name="example.com", zone_kind="public", summary="test")
    assert asset.resource_group is None
    assert asset.record_set_count is None
    assert asset.name_servers == []
    assert asset.linked_virtual_network_count is None
    assert asset.related_ids == []


def test_function_app_asset_defaults() -> None:
    asset = FunctionAppAsset(id="func-1", name="func01", summary="test")
    assert asset.resource_group is None
    assert asset.functions_extension_version is None
    assert asset.always_on is None
    assert asset.azure_webjobs_storage_value_type is None
    assert asset.run_from_package is None
    assert asset.related_ids == []


def test_env_var_summary_defaults() -> None:
    env_var = EnvVarSummary(
        asset_id="app-1",
        asset_name="app",
        asset_kind="AppService",
        setting_name="API_URL",
        value_type="plain-text",
        summary="test",
    )
    assert env_var.workload_identity_type is None
    assert env_var.workload_identity_ids == []
    assert env_var.key_vault_reference_identity is None
    assert env_var.looks_sensitive is False
    assert env_var.reference_target is None
    assert env_var.related_ids == []


def test_endpoint_summary_defaults() -> None:
    endpoint = EndpointSummary(
        endpoint="1.2.3.4",
        endpoint_type="ip",
        source_asset_id="vm-1",
        source_asset_name="vm01",
        source_asset_kind="VM",
        exposure_family="public-ip",
        ingress_path="direct-vm-ip",
        summary="test",
    )
    assert endpoint.related_ids == []


def test_network_port_summary_defaults() -> None:
    network_port = NetworkPortSummary(
        asset_id="vm-1",
        asset_name="vm01",
        endpoint="1.2.3.4",
        protocol="TCP",
        port="22",
        allow_source_summary="Any via nic-nsg:nsg01/allow-ssh",
        exposure_confidence="high",
        summary="test",
    )
    assert network_port.related_ids == []


def test_network_effective_summary_defaults() -> None:
    summary = NetworkEffectiveSummary(
        asset_id="vm-1",
        asset_name="vm01",
        endpoint="1.2.3.4",
        endpoint_type="ip",
        effective_exposure="medium",
        summary="test",
    )
    assert summary.internet_exposed_ports == []
    assert summary.constrained_ports == []
    assert summary.observed_paths == []
    assert summary.related_ids == []


def test_managed_identity_defaults() -> None:
    identity = ManagedIdentity(id="id-1", name="mi-1", identity_type="userAssigned")
    assert identity.attached_to == []
    assert identity.scope_ids == []
    assert identity.operator_signal is None
    assert identity.next_review is None
    assert identity.summary is None


def test_principal_summary_defaults() -> None:
    principal = PrincipalSummary(id="p-1", principal_type="User")
    assert principal.sources == []
    assert principal.attached_to == []
    assert principal.is_current_identity is False


def test_permission_summary_defaults() -> None:
    permission = PermissionSummary(principal_id="p-1", principal_type="User")
    assert permission.high_impact_roles == []
    assert permission.scope_ids == []
    assert permission.privileged is False
    assert permission.operator_signal is None
    assert permission.next_review is None
    assert permission.summary is None


def test_privesc_path_defaults() -> None:
    path = PrivescPathSummary(
        principal="svc-app",
        principal_id="p-1",
        principal_type="ServicePrincipal",
        path_type="direct-role-abuse",
        severity="high",
        summary="test",
    )
    assert path.starting_foothold is None
    assert path.asset is None
    assert path.impact_roles == []
    assert path.operator_signal is None
    assert path.proven_path is None
    assert path.missing_proof is None
    assert path.next_review is None
    assert path.related_ids == []


def test_role_trust_summary_defaults() -> None:
    trust = RoleTrustSummary(
        trust_type="app-owner",
        source_object_id="src-1",
        source_type="User",
        target_object_id="dst-1",
        target_type="Application",
        evidence_type="graph-owner",
        confidence="confirmed",
        summary="test",
    )
    assert trust.source_name is None
    assert trust.control_primitive is None
    assert trust.controlled_object_type is None
    assert trust.controlled_object_name is None
    assert trust.escalation_mechanism is None
    assert trust.usable_identity_result is None
    assert trust.defender_cut_point is None
    assert trust.operator_signal is None
    assert trust.next_review is None
    assert trust.related_ids == []


def test_resource_trust_summary_defaults() -> None:
    trust = ResourceTrustSummary(
        resource_id="r-1",
        resource_type="StorageAccount",
        trust_type="public-network",
        target="public-network",
        exposure="high",
        confidence="confirmed",
        summary="test",
    )
    assert trust.resource_name is None
    assert trust.related_ids == []


def test_auth_policy_summary_defaults() -> None:
    policy = AuthPolicySummary(
        policy_type="security-defaults",
        name="Security Defaults",
        state="enabled",
        summary="test",
    )
    assert policy.scope is None
    assert policy.controls == []
    assert policy.related_ids == []


def test_storage_asset_defaults() -> None:
    asset = StorageAsset(id="s-1", name="st01")
    assert asset.public_access is False
    assert asset.private_endpoint_enabled is False
    assert asset.container_count is None


def test_vm_asset_defaults() -> None:
    vm = VmAsset(id="v-1", name="vm01")
    assert vm.private_ips == []
    assert vm.public_ips == []


def test_web_workload_summary_defaults() -> None:
    workload = WebWorkloadSummary(
        asset_id="app-1",
        asset_name="app01",
        asset_kind="AppService",
    )
    assert workload.workload_identity_ids == []
    assert workload.default_hostname is None
