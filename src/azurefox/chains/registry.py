from __future__ import annotations

from dataclasses import dataclass

GROUPED_COMMAND_NAME = "chains"
GROUPED_COMMAND_INPUT_MODES = ("live", "artifacts")
PREFERRED_ARTIFACT_ORDER = ("loot", "json")


@dataclass(frozen=True, slots=True)
class ChainSourceSpec:
    command: str
    minimum_fields: tuple[str, ...]
    rationale: str


@dataclass(frozen=True, slots=True)
class ChainFamilySpec:
    name: str
    meaning: str
    summary: str
    allowed_claim: str
    current_gap: str
    best_current_examples: tuple[str, ...]
    source_commands: tuple[ChainSourceSpec, ...]


CHAIN_FAMILIES: tuple[ChainFamilySpec, ...] = (
    ChainFamilySpec(
        name="credential-path",
        meaning=(
            "A workload, configuration surface, artifact, or nearby service exposes a usable or "
            "near-usable credential path toward a downstream target."
        ),
        summary=(
            "Follow credential clues from surfaced secret-bearing or token-bearing evidence toward "
            "the likely downstream service."
        ),
        allowed_claim=(
            "Can claim that the visible evidence suggests a likely credential path and name the "
            "most plausible downstream service. Cannot claim the credential works or that the path "
            "is confirmed without deeper source evidence."
        ),
        current_gap=(
            "Grouped extraction and cross-command joins still need to be wired so the user does "
            "not have to stitch the path together manually."
        ),
        best_current_examples=(
            "env-vars -> tokens-credentials -> databases",
            "env-vars -> tokens-credentials -> storage",
        ),
        source_commands=(
            ChainSourceSpec(
                command="env-vars",
                minimum_fields=(
                    "asset_id",
                    "asset_name",
                    "setting_name",
                    "value_type",
                    "reference_target",
                    "workload_identity_ids",
                ),
                rationale=(
                    "Provides the first credential-shaped or secret-dependency clue on the "
                    "workload."
                ),
            ),
            ChainSourceSpec(
                command="tokens-credentials",
                minimum_fields=(
                    "asset_id",
                    "asset_name",
                    "surface_type",
                    "access_path",
                    "priority",
                    "operator_signal",
                ),
                rationale=(
                    "Confirms whether the same workload already looks like a direct credential or "
                    "token path."
                ),
            ),
            ChainSourceSpec(
                command="databases",
                minimum_fields=(
                    "id",
                    "name",
                    "engine",
                    "fully_qualified_domain_name",
                    "user_database_names",
                ),
                rationale=(
                    "Provides likely relational target services when the credential clue points "
                    "toward a data path."
                ),
            ),
            ChainSourceSpec(
                command="storage",
                minimum_fields=(
                    "id",
                    "name",
                    "public_access",
                    "allow_shared_key_access",
                    "container_count",
                    "file_share_count",
                ),
                rationale=(
                    "Provides likely storage targets when the surfaced credential story points to "
                    "blob, file, or account access."
                ),
            ),
            ChainSourceSpec(
                command="keyvault",
                minimum_fields=(
                    "id",
                    "name",
                    "vault_uri",
                    "public_network_access",
                    "enable_rbac_authorization",
                    "access_policy_count",
                ),
                rationale=(
                    "Provides the upstream secret-store boundary when the workload depends on Key "
                    "Vault rather than exposing the secret directly."
                ),
            ),
        ),
    ),
    ChainFamilySpec(
        name="deployment-path",
        meaning=(
            "A service can already change Azure state, redeploy workloads, or reintroduce access "
            "through build and automation machinery."
        ),
        summary=(
            "Follow deployment and automation clues toward the Azure resources that can be changed "
            "or redeployed next."
        ),
        allowed_claim=(
            "Can claim that the visible evidence suggests a named Azure change path. Cannot claim "
            "the path can be executed successfully or that the exact downstream resource can "
            "already be changed without deeper source evidence."
        ),
        current_gap=(
            "The grouped runner still needs stronger joins between pipelines or automation hubs "
            "and the Azure resources they can influence."
        ),
        best_current_examples=(
            "devops -> permissions -> arm-deployments",
            "devops -> aks",
            "automation -> permissions",
        ),
        source_commands=(
            ChainSourceSpec(
                command="devops",
                minimum_fields=(
                    "id",
                    "name",
                    "project_name",
                    "azure_service_connection_names",
                    "target_clues",
                    "risk_cues",
                ),
                rationale=(
                    "Provides the strongest current named Azure change-path clues from build "
                    "definitions and service connections."
                ),
            ),
            ChainSourceSpec(
                command="automation",
                minimum_fields=(
                    "id",
                    "name",
                    "identity_type",
                    "published_runbook_count",
                    "schedule_count",
                    "webhook_count",
                ),
                rationale=(
                    "Provides Azure-native automation hubs that may already be able to execute or "
                    "reintroduce change."
                ),
            ),
            ChainSourceSpec(
                command="arm-deployments",
                minimum_fields=(
                    "id",
                    "name",
                    "scope",
                    "outputs_count",
                    "providers",
                    "summary",
                ),
                rationale=(
                    "Provides deployment history and target clues that help explain what Azure "
                    "state a pipeline or automation path may affect."
                ),
            ),
            ChainSourceSpec(
                command="aks",
                minimum_fields=(
                    "id",
                    "name",
                    "cluster_identity_ids",
                    "private_cluster_enabled",
                    "workload_identity_enabled",
                    "summary",
                ),
                rationale=(
                    "Provides high-value cluster targets when the deployment path looks Kubernetes "
                    "or workload-platform oriented."
                ),
            ),
            ChainSourceSpec(
                command="functions",
                minimum_fields=(
                    "id",
                    "name",
                    "default_hostname",
                    "workload_identity_ids",
                    "azure_webjobs_storage_value_type",
                    "summary",
                ),
                rationale=(
                    "Provides deployable workload targets with identity and runtime clues when the "
                    "path points toward serverless workloads."
                ),
            ),
            ChainSourceSpec(
                command="app-services",
                minimum_fields=(
                    "id",
                    "name",
                    "default_hostname",
                    "workload_identity_ids",
                    "public_network_access",
                    "summary",
                ),
                rationale=(
                    "Provides App Service targets when the deployment path points toward web "
                    "application change rather than infrastructure-only change."
                ),
            ),
        ),
    ),
    ChainFamilySpec(
        name="workload-identity-path",
        meaning=(
            "A workload identity, managed identity, service principal, or trusted application "
            "relationship can already act in Azure or obtain stronger access."
        ),
        summary=(
            "Follow workload-linked identities toward the permissions and trust relationships that "
            "make the next Azure control step plausible."
        ),
        allowed_claim=(
            "Can claim that the visible evidence suggests a likely workload-identity control path. "
            "Cannot claim token minting success or confirmed broader control without deeper source "
            "evidence."
        ),
        current_gap=(
            "The grouped runner still needs a shorter operator story that makes the next move feel "
            "obvious instead of spread across identity, permissions, and trust commands."
        ),
        best_current_examples=(
            "managed-identities -> permissions -> role-trusts",
            "functions -> managed-identities -> permissions",
            "app-services -> managed-identities -> permissions",
        ),
        source_commands=(
            ChainSourceSpec(
                command="managed-identities",
                minimum_fields=(
                    "id",
                    "name",
                    "identity_type",
                    "principal_id",
                    "attached_to",
                    "scope_ids",
                ),
                rationale=(
                    "Provides the workload-linked identity anchor and where that identity is "
                    "attached."
                ),
            ),
            ChainSourceSpec(
                command="permissions",
                minimum_fields=(
                    "principal_id",
                    "high_impact_roles",
                    "all_role_names",
                    "scope_ids",
                    "privileged",
                ),
                rationale=(
                    "Provides the Azure control power behind the attached identity."
                ),
            ),
            ChainSourceSpec(
                command="role-trusts",
                minimum_fields=(
                    "trust_type",
                    "source_object_id",
                    "target_object_id",
                    "confidence",
                    "summary",
                ),
                rationale=(
                    "Provides the trust-edge view that can widen the path beyond direct RBAC."
                ),
            ),
            ChainSourceSpec(
                command="tokens-credentials",
                minimum_fields=(
                    "asset_id",
                    "asset_name",
                    "surface_type",
                    "access_path",
                    "priority",
                    "operator_signal",
                ),
                rationale=(
                    "Provides the direct token-opportunity clue when the workload can already mint "
                    "or request tokens."
                ),
            ),
            ChainSourceSpec(
                command="workloads",
                minimum_fields=(
                    "asset_id",
                    "asset_name",
                    "identity_ids",
                    "ingress_paths",
                    "exposure_families",
                    "summary",
                ),
                rationale=(
                    "Provides the workload context that ties exposure and identity together before "
                    "the operator pivots deeper."
                ),
            ),
        ),
    ),
)


def get_chain_family_specs() -> tuple[ChainFamilySpec, ...]:
    return CHAIN_FAMILIES


def chain_family_names() -> tuple[str, ...]:
    return tuple(spec.name for spec in CHAIN_FAMILIES)


def get_chain_family_spec(name: str) -> ChainFamilySpec | None:
    for spec in CHAIN_FAMILIES:
        if spec.name == name:
            return spec
    return None
