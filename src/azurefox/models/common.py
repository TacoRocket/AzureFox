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
