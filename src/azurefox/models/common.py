from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0.0"


class OutputMode(StrEnum):
    TABLE = "table"
    JSON = "json"
    CSV = "csv"


class RoleTrustsMode(StrEnum):
    FAST = "fast"
    FULL = "full"


class CommandMetadata(BaseModel):
    schema_version: str = SCHEMA_VERSION
    command: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    tenant_id: str | None = None
    subscription_id: str | None = None
    token_source: str | None = None


class CollectionIssue(BaseModel):
    kind: str
    message: str
    context: dict[str, str] = Field(default_factory=dict)


class SubscriptionRef(BaseModel):
    id: str
    display_name: str | None = None
    state: str | None = None


class ScopeRef(BaseModel):
    id: str
    scope_type: str
    display_name: str | None = None


class Principal(BaseModel):
    id: str
    principal_type: str
    display_name: str | None = None
    tenant_id: str | None = None


class PrincipalSummary(BaseModel):
    id: str
    principal_type: str
    display_name: str | None = None
    tenant_id: str | None = None
    sources: list[str] = Field(default_factory=list)
    scope_ids: list[str] = Field(default_factory=list)
    role_names: list[str] = Field(default_factory=list)
    role_assignment_count: int = 0
    identity_names: list[str] = Field(default_factory=list)
    identity_types: list[str] = Field(default_factory=list)
    attached_to: list[str] = Field(default_factory=list)
    is_current_identity: bool = False


class PermissionSummary(BaseModel):
    principal_id: str
    display_name: str | None = None
    principal_type: str
    high_impact_roles: list[str] = Field(default_factory=list)
    all_role_names: list[str] = Field(default_factory=list)
    role_assignment_count: int = 0
    scope_count: int = 0
    scope_ids: list[str] = Field(default_factory=list)
    privileged: bool = False
    is_current_identity: bool = False


class PrivescPathSummary(BaseModel):
    principal: str
    principal_id: str
    principal_type: str
    path_type: str
    asset: str | None = None
    impact_roles: list[str] = Field(default_factory=list)
    severity: str
    current_identity: bool = False
    summary: str
    related_ids: list[str] = Field(default_factory=list)


class RoleTrustSummary(BaseModel):
    trust_type: str
    source_object_id: str
    source_name: str | None = None
    source_type: str
    target_object_id: str
    target_name: str | None = None
    target_type: str
    evidence_type: str
    confidence: str
    summary: str
    related_ids: list[str] = Field(default_factory=list)


class ResourceTrustSummary(BaseModel):
    resource_id: str
    resource_name: str | None = None
    resource_type: str
    trust_type: str
    target: str
    exposure: str
    confidence: str
    summary: str
    related_ids: list[str] = Field(default_factory=list)


class ArmDeploymentSummary(BaseModel):
    id: str
    name: str
    scope: str
    scope_type: str
    resource_group: str | None = None
    provisioning_state: str | None = None
    mode: str | None = None
    timestamp: str | None = None
    duration: str | None = None
    outputs_count: int = 0
    output_resource_count: int = 0
    providers: list[str] = Field(default_factory=list)
    template_link: str | None = None
    parameters_link: str | None = None
    summary: str
    related_ids: list[str] = Field(default_factory=list)


class EnvVarSummary(BaseModel):
    asset_id: str
    asset_name: str
    asset_kind: str
    resource_group: str | None = None
    location: str | None = None
    workload_identity_type: str | None = None
    workload_principal_id: str | None = None
    workload_client_id: str | None = None
    workload_identity_ids: list[str] = Field(default_factory=list)
    key_vault_reference_identity: str | None = None
    setting_name: str
    value_type: str
    looks_sensitive: bool = False
    reference_target: str | None = None
    summary: str
    related_ids: list[str] = Field(default_factory=list)


class TokenCredentialSurfaceSummary(BaseModel):
    asset_id: str
    asset_name: str
    asset_kind: str
    resource_group: str | None = None
    location: str | None = None
    surface_type: str
    access_path: str
    priority: str
    operator_signal: str
    summary: str
    related_ids: list[str] = Field(default_factory=list)


class AuthPolicySummary(BaseModel):
    policy_type: str
    name: str
    state: str
    scope: str | None = None
    controls: list[str] = Field(default_factory=list)
    summary: str
    related_ids: list[str] = Field(default_factory=list)


class RoleAssignment(BaseModel):
    id: str
    scope_id: str
    principal_id: str
    principal_type: str | None = None
    role_definition_id: str | None = None
    role_name: str | None = None


class ManagedIdentity(BaseModel):
    id: str
    name: str
    identity_type: str
    principal_id: str | None = None
    client_id: str | None = None
    attached_to: list[str] = Field(default_factory=list)
    scope_ids: list[str] = Field(default_factory=list)


class KeyVaultAsset(BaseModel):
    id: str
    name: str
    resource_group: str | None = None
    location: str | None = None
    vault_uri: str | None = None
    tenant_id: str | None = None
    sku_name: str | None = None
    public_network_access: str | None = None
    network_default_action: str | None = None
    private_endpoint_enabled: bool = False
    purge_protection_enabled: bool = False
    soft_delete_enabled: bool = False
    enable_rbac_authorization: bool = False
    access_policy_count: int = 0


class StorageAsset(BaseModel):
    id: str
    name: str
    resource_group: str | None = None
    location: str | None = None
    public_access: bool = False
    anonymous_access_indicators: list[str] = Field(default_factory=list)
    network_default_action: str | None = None
    private_endpoint_enabled: bool = False
    container_count: int | None = None
    file_share_count: int | None = None
    queue_count: int | None = None
    table_count: int | None = None


class EndpointSummary(BaseModel):
    endpoint: str
    endpoint_type: str
    source_asset_id: str
    source_asset_name: str
    source_asset_kind: str
    exposure_family: str
    ingress_path: str
    summary: str
    related_ids: list[str] = Field(default_factory=list)


class NetworkPortSummary(BaseModel):
    asset_id: str
    asset_name: str
    endpoint: str
    protocol: str
    port: str
    allow_source_summary: str
    exposure_confidence: str
    summary: str
    related_ids: list[str] = Field(default_factory=list)


class NetworkEffectiveSummary(BaseModel):
    asset_id: str
    asset_name: str
    endpoint: str
    endpoint_type: str
    effective_exposure: str
    internet_exposed_ports: list[str] = Field(default_factory=list)
    constrained_ports: list[str] = Field(default_factory=list)
    observed_paths: list[str] = Field(default_factory=list)
    summary: str
    related_ids: list[str] = Field(default_factory=list)


class NicAsset(BaseModel):
    id: str
    name: str
    attached_asset_id: str | None = None
    attached_asset_name: str | None = None
    private_ips: list[str] = Field(default_factory=list)
    public_ip_ids: list[str] = Field(default_factory=list)
    subnet_ids: list[str] = Field(default_factory=list)
    vnet_ids: list[str] = Field(default_factory=list)
    network_security_group_id: str | None = None


class VmAsset(BaseModel):
    id: str
    name: str
    resource_group: str | None = None
    location: str | None = None
    vm_type: str = "vm"
    power_state: str | None = None
    private_ips: list[str] = Field(default_factory=list)
    public_ips: list[str] = Field(default_factory=list)
    identity_ids: list[str] = Field(default_factory=list)
    nic_ids: list[str] = Field(default_factory=list)


class WorkloadSummary(BaseModel):
    asset_id: str
    asset_name: str
    asset_kind: str
    resource_group: str | None = None
    location: str | None = None
    identity_type: str | None = None
    identity_principal_id: str | None = None
    identity_client_id: str | None = None
    identity_ids: list[str] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)
    ingress_paths: list[str] = Field(default_factory=list)
    exposure_families: list[str] = Field(default_factory=list)
    summary: str
    related_ids: list[str] = Field(default_factory=list)


class AppServiceAsset(BaseModel):
    id: str
    name: str
    resource_group: str | None = None
    location: str | None = None
    state: str | None = None
    default_hostname: str | None = None
    app_service_plan_id: str | None = None
    public_network_access: str | None = None
    https_only: bool = False
    client_cert_enabled: bool = False
    min_tls_version: str | None = None
    ftps_state: str | None = None
    runtime_stack: str | None = None
    workload_identity_type: str | None = None
    workload_principal_id: str | None = None
    workload_client_id: str | None = None
    workload_identity_ids: list[str] = Field(default_factory=list)
    summary: str
    related_ids: list[str] = Field(default_factory=list)


class FunctionAppAsset(BaseModel):
    id: str
    name: str
    resource_group: str | None = None
    location: str | None = None
    state: str | None = None
    default_hostname: str | None = None
    app_service_plan_id: str | None = None
    public_network_access: str | None = None
    https_only: bool = False
    client_cert_enabled: bool = False
    min_tls_version: str | None = None
    ftps_state: str | None = None
    runtime_stack: str | None = None
    functions_extension_version: str | None = None
    always_on: bool | None = None
    workload_identity_type: str | None = None
    workload_principal_id: str | None = None
    workload_client_id: str | None = None
    workload_identity_ids: list[str] = Field(default_factory=list)
    azure_webjobs_storage_value_type: str | None = None
    azure_webjobs_storage_reference_target: str | None = None
    run_from_package: bool | None = None
    key_vault_reference_count: int | None = None
    summary: str
    related_ids: list[str] = Field(default_factory=list)


class AksClusterAsset(BaseModel):
    id: str
    name: str
    resource_group: str | None = None
    location: str | None = None
    provisioning_state: str | None = None
    kubernetes_version: str | None = None
    sku_tier: str | None = None
    node_resource_group: str | None = None
    fqdn: str | None = None
    private_fqdn: str | None = None
    private_cluster_enabled: bool | None = None
    public_fqdn_enabled: bool | None = None
    cluster_identity_type: str | None = None
    cluster_principal_id: str | None = None
    cluster_client_id: str | None = None
    cluster_identity_ids: list[str] = Field(default_factory=list)
    aad_managed: bool | None = None
    azure_rbac_enabled: bool | None = None
    local_accounts_disabled: bool | None = None
    network_plugin: str | None = None
    network_policy: str | None = None
    outbound_type: str | None = None
    agent_pool_count: int | None = None
    oidc_issuer_enabled: bool | None = None
    oidc_issuer_url: str | None = None
    workload_identity_enabled: bool | None = None
    addon_names: list[str] = Field(default_factory=list)
    web_app_routing_enabled: bool | None = None
    web_app_routing_dns_zone_count: int | None = None
    summary: str
    related_ids: list[str] = Field(default_factory=list)


class ApiMgmtServiceAsset(BaseModel):
    id: str
    name: str
    resource_group: str | None = None
    location: str | None = None
    state: str | None = None
    sku_name: str | None = None
    sku_capacity: int | None = None
    public_network_access: str | None = None
    virtual_network_type: str | None = None
    public_ip_address_id: str | None = None
    public_ip_addresses: list[str] = Field(default_factory=list)
    private_ip_addresses: list[str] = Field(default_factory=list)
    gateway_hostnames: list[str] = Field(default_factory=list)
    management_hostnames: list[str] = Field(default_factory=list)
    portal_hostnames: list[str] = Field(default_factory=list)
    workload_identity_type: str | None = None
    workload_principal_id: str | None = None
    workload_client_id: str | None = None
    workload_identity_ids: list[str] = Field(default_factory=list)
    gateway_enabled: bool | None = None
    developer_portal_status: str | None = None
    legacy_portal_status: str | None = None
    api_count: int | None = None
    api_subscription_required_count: int | None = None
    subscription_count: int | None = None
    active_subscription_count: int | None = None
    backend_count: int | None = None
    backend_hostnames: list[str] = Field(default_factory=list)
    named_value_count: int | None = None
    named_value_secret_count: int | None = None
    named_value_key_vault_count: int | None = None
    summary: str
    related_ids: list[str] = Field(default_factory=list)


class AcrRegistryAsset(BaseModel):
    id: str
    name: str
    resource_group: str | None = None
    location: str | None = None
    state: str | None = None
    login_server: str | None = None
    sku_name: str | None = None
    public_network_access: str | None = None
    network_rule_default_action: str | None = None
    network_rule_bypass_options: str | None = None
    admin_user_enabled: bool | None = None
    anonymous_pull_enabled: bool | None = None
    data_endpoint_enabled: bool | None = None
    private_endpoint_connection_count: int = 0
    workload_identity_type: str | None = None
    workload_principal_id: str | None = None
    workload_client_id: str | None = None
    workload_identity_ids: list[str] = Field(default_factory=list)
    summary: str
    related_ids: list[str] = Field(default_factory=list)


class DatabaseServerAsset(BaseModel):
    id: str
    name: str
    resource_group: str | None = None
    location: str | None = None
    state: str | None = None
    engine: str
    fully_qualified_domain_name: str | None = None
    server_version: str | None = None
    public_network_access: str | None = None
    minimal_tls_version: str | None = None
    database_count: int | None = None
    user_database_names: list[str] = Field(default_factory=list)
    workload_identity_type: str | None = None
    workload_principal_id: str | None = None
    workload_client_id: str | None = None
    workload_identity_ids: list[str] = Field(default_factory=list)
    summary: str
    related_ids: list[str] = Field(default_factory=list)


class DnsZoneAsset(BaseModel):
    id: str
    name: str
    resource_group: str | None = None
    location: str | None = None
    zone_kind: str
    record_set_count: int | None = None
    max_record_set_count: int | None = None
    name_servers: list[str] = Field(default_factory=list)
    linked_virtual_network_count: int | None = None
    registration_virtual_network_count: int | None = None
    summary: str
    related_ids: list[str] = Field(default_factory=list)


class WebWorkloadSummary(BaseModel):
    asset_id: str
    asset_name: str
    asset_kind: str
    resource_group: str | None = None
    location: str | None = None
    workload_identity_type: str | None = None
    workload_principal_id: str | None = None
    workload_client_id: str | None = None
    workload_identity_ids: list[str] = Field(default_factory=list)
    default_hostname: str | None = None


def is_private_network_prefix(value: str) -> bool:
    text = value.strip()
    if not text:
        return False
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return False
    return network.is_private


class Finding(BaseModel):
    id: str
    severity: str
    title: str
    description: str
    related_ids: list[str] = Field(default_factory=list)
