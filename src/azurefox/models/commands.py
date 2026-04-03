from __future__ import annotations

from collections import Counter

from pydantic import BaseModel, Field

from azurefox.models.common import (
    AcrRegistryAsset,
    AksClusterAsset,
    ApiMgmtServiceAsset,
    AppServiceAsset,
    ArmDeploymentSummary,
    AuthPolicySummary,
    CollectionIssue,
    CommandMetadata,
    DatabaseServerAsset,
    DnsZoneAsset,
    EndpointSummary,
    EnvVarSummary,
    Finding,
    FunctionAppAsset,
    KeyVaultAsset,
    ManagedIdentity,
    NetworkPortSummary,
    NicAsset,
    PermissionSummary,
    Principal,
    PrincipalSummary,
    PrivescPathSummary,
    ResourceTrustSummary,
    RoleAssignment,
    RoleTrustsMode,
    RoleTrustSummary,
    ScopeRef,
    StorageAsset,
    SubscriptionRef,
    TokenCredentialSurfaceSummary,
    VmAsset,
    WorkloadSummary,
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


class AppServicesOutput(BaseModel):
    metadata: CommandMetadata
    app_services: list[AppServiceAsset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)


class AcrOutput(BaseModel):
    metadata: CommandMetadata
    registries: list[AcrRegistryAsset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)


class DatabasesOutput(BaseModel):
    metadata: CommandMetadata
    database_servers: list[DatabaseServerAsset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)


class DnsOutput(BaseModel):
    metadata: CommandMetadata
    dns_zones: list[DnsZoneAsset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)


class AksOutput(BaseModel):
    metadata: CommandMetadata
    aks_clusters: list[AksClusterAsset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)


class ApiMgmtOutput(BaseModel):
    metadata: CommandMetadata
    api_management_services: list[ApiMgmtServiceAsset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)


class FunctionsOutput(BaseModel):
    metadata: CommandMetadata
    function_apps: list[FunctionAppAsset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
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
    mode: RoleTrustsMode = RoleTrustsMode.FAST
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


class EnvVarsOutput(BaseModel):
    metadata: CommandMetadata
    env_vars: list[EnvVarSummary] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)


class EndpointsOutput(BaseModel):
    metadata: CommandMetadata
    endpoints: list[EndpointSummary] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)


class NetworkPortsOutput(BaseModel):
    metadata: CommandMetadata
    network_ports: list[NetworkPortSummary] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)


class TokensCredentialsOutput(BaseModel):
    metadata: CommandMetadata
    surfaces: list[TokenCredentialSurfaceSummary] = Field(default_factory=list)
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


class NicsOutput(BaseModel):
    metadata: CommandMetadata
    nic_assets: list[NicAsset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)


class VmsOutput(BaseModel):
    metadata: CommandMetadata
    vm_assets: list[VmAsset] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)


class WorkloadsOutput(BaseModel):
    metadata: CommandMetadata
    workloads: list[WorkloadSummary] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)
