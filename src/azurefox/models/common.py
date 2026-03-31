from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0.0"


class OutputMode(StrEnum):
    TABLE = "table"
    JSON = "json"
    CSV = "csv"


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
    container_count: int = 0
    file_share_count: int = 0
    queue_count: int = 0
    table_count: int = 0


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


class Finding(BaseModel):
    id: str
    severity: str
    title: str
    description: str
    related_ids: list[str] = Field(default_factory=list)
