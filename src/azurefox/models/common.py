from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field, model_validator

SCHEMA_VERSION = "1.3.0"


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
    devops_organization: str | None = None
    token_source: str | None = None
    auth_mode: str | None = None


class CollectionIssue(BaseModel):
    kind: str
    message: str
    scope: str | None = None
    context: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _populate_scope_from_context(self) -> CollectionIssue:
        if self.scope:
            return self
        collector = self.context.get("collector")
        if collector:
            self.scope = collector
        return self


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
    operator_signal: str | None = None
    next_review: str | None = None
    summary: str | None = None


class PrivescPathSummary(BaseModel):
    starting_foothold: str | None = None
    principal: str
    principal_id: str
    principal_type: str
    path_type: str
    asset: str | None = None
    impact_roles: list[str] = Field(default_factory=list)
    severity: str
    current_identity: bool = False
    operator_signal: str | None = None
    proven_path: str | None = None
    missing_proof: str | None = None
    next_review: str | None = None
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
    control_primitive: str | None = None
    controlled_object_type: str | None = None
    controlled_object_name: str | None = None
    escalation_mechanism: str | None = None
    usable_identity_result: str | None = None
    defender_cut_point: str | None = None
    operator_signal: str | None = None
    next_review: str | None = None
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


class LighthouseDelegationAsset(BaseModel):
    id: str
    name: str
    scope_id: str
    scope_type: str
    scope_display_name: str | None = None
    resource_group: str | None = None
    managed_by_tenant_id: str | None = None
    managed_by_tenant_name: str | None = None
    managee_tenant_id: str | None = None
    managee_tenant_name: str | None = None
    registration_definition_id: str | None = None
    registration_definition_name: str | None = None
    description: str | None = None
    authorization_count: int = 0
    eligible_authorization_count: int = 0
    principal_count: int = 0
    eligible_principal_count: int = 0
    role_names: list[str] = Field(default_factory=list)
    eligible_role_names: list[str] = Field(default_factory=list)
    strongest_role_name: str | None = None
    has_user_access_administrator: bool = False
    has_owner_role: bool = False
    has_delegated_role_assignments: bool = False
    provisioning_state: str | None = None
    definition_provisioning_state: str | None = None
    plan_name: str | None = None
    plan_product: str | None = None
    plan_publisher: str | None = None
    summary: str
    related_ids: list[str] = Field(default_factory=list)


class CrossTenantPathSummary(BaseModel):
    id: str
    signal_type: str
    name: str
    tenant_id: str | None = None
    tenant_name: str | None = None
    scope: str | None = None
    posture: str | None = None
    attack_path: str
    priority: str
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
    operator_signal: str | None = None
    next_review: str | None = None
    summary: str | None = None


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
    public_network_access: str | None = None
    network_default_action: str | None = None
    private_endpoint_enabled: bool = False
    allow_shared_key_access: bool | None = None
    minimum_tls_version: str | None = None
    https_traffic_only_enabled: bool | None = None
    is_hns_enabled: bool | None = None
    is_sftp_enabled: bool | None = None
    nfs_v3_enabled: bool | None = None
    dns_endpoint_type: str | None = None
    container_count: int | None = None
    file_share_count: int | None = None
    queue_count: int | None = None
    table_count: int | None = None


class SnapshotDiskAsset(BaseModel):
    id: str
    name: str
    asset_kind: str
    resource_group: str | None = None
    location: str | None = None
    disk_role: str | None = None
    attachment_state: str | None = None
    attached_to_id: str | None = None
    attached_to_name: str | None = None
    source_resource_id: str | None = None
    source_resource_name: str | None = None
    source_resource_kind: str | None = None
    os_type: str | None = None
    size_gb: int | None = None
    time_created: str | None = None
    incremental: bool | None = None
    network_access_policy: str | None = None
    public_network_access: str | None = None
    disk_access_id: str | None = None
    max_shares: int | None = None
    encryption_type: str | None = None
    disk_encryption_set_id: str | None = None
    summary: str
    related_ids: list[str] = Field(default_factory=list)


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


class VmssAsset(BaseModel):
    id: str
    name: str
    resource_group: str | None = None
    location: str | None = None
    sku_name: str | None = None
    instance_count: int | None = None
    orchestration_mode: str | None = None
    upgrade_mode: str | None = None
    overprovision: bool | None = None
    single_placement_group: bool | None = None
    zone_balance: bool | None = None
    zones: list[str] = Field(default_factory=list)
    identity_type: str | None = None
    principal_id: str | None = None
    client_id: str | None = None
    identity_ids: list[str] = Field(default_factory=list)
    subnet_ids: list[str] = Field(default_factory=list)
    nic_configuration_count: int = 0
    public_ip_configuration_count: int = 0
    load_balancer_backend_pool_count: int = 0
    application_gateway_backend_pool_count: int = 0
    inbound_nat_pool_count: int = 0
    summary: str
    related_ids: list[str] = Field(default_factory=list)


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


class ApplicationGatewayAsset(BaseModel):
    id: str
    name: str
    resource_group: str | None = None
    location: str | None = None
    state: str | None = None
    sku_name: str | None = None
    sku_tier: str | None = None
    public_frontend_count: int = 0
    private_frontend_count: int = 0
    public_ip_address_ids: list[str] = Field(default_factory=list)
    public_ip_addresses: list[str] = Field(default_factory=list)
    private_frontend_ips: list[str] = Field(default_factory=list)
    subnet_ids: list[str] = Field(default_factory=list)
    listener_count: int = 0
    request_routing_rule_count: int = 0
    backend_pool_count: int = 0
    backend_target_count: int = 0
    url_path_map_count: int = 0
    redirect_configuration_count: int = 0
    rewrite_rule_set_count: int = 0
    waf_enabled: bool | None = None
    waf_mode: str | None = None
    firewall_policy_id: str | None = None
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
    webhook_count: int | None = None
    enabled_webhook_count: int | None = None
    webhook_action_types: list[str] = Field(default_factory=list)
    broad_webhook_scope_count: int | None = None
    replication_count: int | None = None
    replication_regions: list[str] = Field(default_factory=list)
    quarantine_policy_status: str | None = None
    retention_policy_status: str | None = None
    retention_policy_days: int | None = None
    trust_policy_status: str | None = None
    trust_policy_type: str | None = None
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
    high_availability_mode: str | None = None
    delegated_subnet_resource_id: str | None = None
    private_dns_zone_resource_id: str | None = None
    database_count: int | None = None
    user_database_names: list[str] = Field(default_factory=list)
    workload_identity_type: str | None = None
    workload_principal_id: str | None = None
    workload_client_id: str | None = None
    workload_identity_ids: list[str] = Field(default_factory=list)
    summary: str
    related_ids: list[str] = Field(default_factory=list)


class DevopsTrustedInput(BaseModel):
    input_type: str
    ref: str
    visibility_state: str | None = None
    current_operator_access_state: str | None = None
    current_operator_can_poison: bool | None = None
    trusted_input_evidence_basis: str | None = None
    trusted_input_permission_source: str | None = None
    trusted_input_permission_detail: str | None = None
    surface_types: list[str] = Field(default_factory=list)
    join_ids: list[str] = Field(default_factory=list)


class DevopsPipelineAsset(BaseModel):

    id: str
    definition_id: str
    name: str
    project_id: str | None = None
    project_name: str
    path: str | None = None
    repository_id: str | None = None
    repository_name: str | None = None
    repository_type: str | None = None
    repository_url: str | None = None
    repository_host_type: str | None = None
    source_visibility_state: str | None = None
    default_branch: str | None = None
    trigger_types: list[str] = Field(default_factory=list)
    variable_group_names: list[str] = Field(default_factory=list)
    secret_variable_count: int = 0
    secret_variable_names: list[str] = Field(default_factory=list)
    key_vault_group_names: list[str] = Field(default_factory=list)
    key_vault_names: list[str] = Field(default_factory=list)
    azure_service_connection_names: list[str] = Field(default_factory=list)
    azure_service_connection_types: list[str] = Field(default_factory=list)
    azure_service_connection_auth_schemes: list[str] = Field(default_factory=list)
    azure_service_connection_ids: list[str] = Field(default_factory=list)
    azure_service_connection_principal_ids: list[str] = Field(default_factory=list)
    azure_service_connection_client_ids: list[str] = Field(default_factory=list)
    azure_service_connection_tenant_ids: list[str] = Field(default_factory=list)
    azure_service_connection_subscription_ids: list[str] = Field(default_factory=list)
    target_clues: list[str] = Field(default_factory=list)
    risk_cues: list[str] = Field(default_factory=list)
    execution_modes: list[str] = Field(default_factory=list)
    upstream_sources: list[str] = Field(default_factory=list)
    trusted_inputs: list[DevopsTrustedInput] = Field(default_factory=list)
    trusted_input_types: list[str] = Field(default_factory=list)
    trusted_input_refs: list[str] = Field(default_factory=list)
    trusted_input_join_ids: list[str] = Field(default_factory=list)
    primary_injection_surface: str | None = None
    primary_trusted_input_ref: str | None = None
    source_join_ids: list[str] = Field(default_factory=list)
    trigger_join_ids: list[str] = Field(default_factory=list)
    identity_join_ids: list[str] = Field(default_factory=list)
    secret_support_types: list[str] = Field(default_factory=list)
    secret_dependency_ids: list[str] = Field(default_factory=list)
    injection_surface_types: list[str] = Field(default_factory=list)
    current_operator_injection_surface_types: list[str] = Field(default_factory=list)
    edit_path_state: str | None = None
    queue_path_state: str | None = None
    rerun_path_state: str | None = None
    approval_path_state: str | None = None
    current_operator_can_view_definition: bool | None = None
    current_operator_can_queue: bool | None = None
    current_operator_can_edit: bool | None = None
    current_operator_can_view_source: bool | None = None
    current_operator_can_contribute_source: bool | None = None
    consequence_types: list[str] = Field(default_factory=list)
    missing_execution_path: bool = False
    missing_injection_point: bool = False
    missing_target_mapping: bool = False
    partial_read: bool = False
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
    private_endpoint_reference_count: int | None = None
    summary: str
    related_ids: list[str] = Field(default_factory=list)


class AutomationAccountAsset(BaseModel):
    id: str
    name: str
    resource_group: str | None = None
    location: str | None = None
    state: str | None = None
    sku_name: str | None = None
    identity_type: str | None = None
    principal_id: str | None = None
    client_id: str | None = None
    identity_ids: list[str] = Field(default_factory=list)
    runbook_count: int | None = None
    published_runbook_count: int | None = None
    published_runbook_names: list[str] = Field(default_factory=list)
    schedule_count: int | None = None
    job_schedule_count: int | None = None
    webhook_count: int | None = None
    hybrid_worker_group_count: int | None = None
    credential_count: int | None = None
    certificate_count: int | None = None
    connection_count: int | None = None
    variable_count: int | None = None
    encrypted_variable_count: int | None = None
    start_modes: list[str] = Field(default_factory=list)
    primary_start_mode: str | None = None
    primary_runbook_name: str | None = None
    schedule_runbook_names: list[str] = Field(default_factory=list)
    webhook_runbook_names: list[str] = Field(default_factory=list)
    hybrid_worker_group_ids: list[str] = Field(default_factory=list)
    trigger_join_ids: list[str] = Field(default_factory=list)
    identity_join_ids: list[str] = Field(default_factory=list)
    secret_support_types: list[str] = Field(default_factory=list)
    secret_dependency_ids: list[str] = Field(default_factory=list)
    consequence_types: list[str] = Field(default_factory=list)
    missing_execution_path: bool = False
    missing_target_mapping: bool = False
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
