from __future__ import annotations

from collections import Counter

from pydantic import BaseModel, Field

from azurefox.models.common import (
    ArmDeploymentSummary,
    AuthPolicySummary,
    CollectionIssue,
    CommandMetadata,
    Finding,
    KeyVaultAsset,
    ManagedIdentity,
    PermissionSummary,
    Principal,
    PrincipalSummary,
    PrivescPathSummary,
    ResourceTrustSummary,
    RoleAssignment,
    RoleTrustSummary,
    ScopeRef,
    StorageAsset,
    SubscriptionRef,
    VmAsset,
)


class WhoAmIOutput(BaseModel):
    metadata: CommandMetadata
    tenant_id: str | None = None
    subscription: SubscriptionRef | None = None
    principal: Principal | None = None
    effective_scopes: list[ScopeRef] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)


class InventoryOutput(BaseModel):
    metadata: CommandMetadata
    subscription: SubscriptionRef | None = None
    resource_group_count: int = 0
    resource_count: int = 0
    top_resource_types: dict[str, int] = Field(default_factory=dict)
    issues: list[CollectionIssue] = Field(default_factory=list)


class RbacOutput(BaseModel):
    metadata: CommandMetadata
    principals: list[Principal] = Field(default_factory=list)
    scopes: list[ScopeRef] = Field(default_factory=list)
    role_assignments: list[RoleAssignment] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)

    def role_distribution(self) -> dict[str, int]:
        dist = Counter()
        for assignment in self.role_assignments:
            dist[assignment.role_name or "Unknown"] += 1
        return dict(dist)


class PrincipalsOutput(BaseModel):
    metadata: CommandMetadata
    principals: list[PrincipalSummary] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)


class PermissionsOutput(BaseModel):
    metadata: CommandMetadata
    permissions: list[PermissionSummary] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)


class PrivescOutput(BaseModel):
    metadata: CommandMetadata
    paths: list[PrivescPathSummary] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)


class RoleTrustsOutput(BaseModel):
    metadata: CommandMetadata
    trusts: list[RoleTrustSummary] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)


class ResourceTrustsOutput(BaseModel):
    metadata: CommandMetadata
    resource_trusts: list[ResourceTrustSummary] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)


class ArmDeploymentsOutput(BaseModel):
    metadata: CommandMetadata
    deployments: list[ArmDeploymentSummary] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)


class AuthPoliciesOutput(BaseModel):
    metadata: CommandMetadata
    auth_policies: list[AuthPolicySummary] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)


class ManagedIdentitiesOutput(BaseModel):
    metadata: CommandMetadata
    identities: list[ManagedIdentity] = Field(default_factory=list)
    role_assignments: list[RoleAssignment] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)


class KeyVaultOutput(BaseModel):
    metadata: CommandMetadata
    key_vaults: list[KeyVaultAsset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)


class StorageOutput(BaseModel):
    metadata: CommandMetadata
    storage_assets: list[StorageAsset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)


class VmsOutput(BaseModel):
    metadata: CommandMetadata
    vm_assets: list[VmAsset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)
