from __future__ import annotations

from dataclasses import dataclass

from azurefox.config import GlobalOptions
from azurefox.models.commands import (
    AksOutput,
    AppServicesOutput,
    ArmDeploymentsOutput,
    AutomationOutput,
    DatabasesOutput,
    DevopsOutput,
    EnvVarsOutput,
    FunctionsOutput,
    KeyVaultOutput,
    ManagedIdentitiesOutput,
    PermissionsOutput,
    RbacOutput,
    RoleTrustsOutput,
    StorageOutput,
    TokensCredentialsOutput,
    WorkloadsOutput,
)

GROUPED_COMMAND_NAME = "chains"
GROUPED_COMMAND_INPUT_MODES = ("live", "artifacts", "mixed")
PREFERRED_ARTIFACT_ORDER = ("json",)
SEMANTIC_LOOT_CHAIN_FAMILIES = (
    "credential-path",
    "deployment-path",
    "escalation-path",
    "compute-control",
)


@dataclass(frozen=True, slots=True)
class ChainSourceSpec:
    command: str
    minimum_fields: tuple[str, ...]
    rationale: str


@dataclass(frozen=True, slots=True)
class ChainFamilySpec:
    name: str
    state: str
    meaning: str
    summary: str
    allowed_claim: str
    current_gap: str
    best_current_examples: tuple[str, ...]
    source_commands: tuple[ChainSourceSpec, ...]


_CHAIN_SOURCE_MODELS = {
    "devops": DevopsOutput,
    "automation": AutomationOutput,
    "permissions": PermissionsOutput,
    "rbac": RbacOutput,
    "role-trusts": RoleTrustsOutput,
    "keyvault": KeyVaultOutput,
    "arm-deployments": ArmDeploymentsOutput,
    "app-services": AppServicesOutput,
    "functions": FunctionsOutput,
    "aks": AksOutput,
    "env-vars": EnvVarsOutput,
    "tokens-credentials": TokensCredentialsOutput,
    "workloads": WorkloadsOutput,
    "managed-identities": ManagedIdentitiesOutput,
    "databases": DatabasesOutput,
    "storage": StorageOutput,
}


CHAIN_FAMILIES: tuple[ChainFamilySpec, ...] = (
    ChainFamilySpec(
        name="credential-path",
        state="implemented",
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
            "most plausible downstream service. Cannot claim the exact downstream target or that "
            "the setting is confirmed to reach it."
        ),
        current_gap=(
            "The live family now joins backing evidence in one run, but it still needs periodic "
            "review so rows that only restate a source clue do not survive as fake grouped value."
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
        state="implemented",
        meaning=(
            "A supply-chain or automation source already looks capable of changing Azure state, "
            "redeploying workloads, or reintroducing access."
        ),
        summary=(
            "Follow controllable deployment and automation paths toward the Azure footprint they "
            "are most likely to change next."
        ),
        allowed_claim=(
            "Can claim that the visible evidence suggests a controllable or nearly controllable "
            "Azure change path and can name or narrow the likely downstream footprint when the "
            "join is honest. Cannot claim successful execution or the exact downstream Azure "
            "change from current visible evidence alone."
        ),
        current_gap=(
            "The live family still needs stronger source-side actionability proof and tighter "
            "downstream target joins before every row reads like a defended change path instead of "
            "review-heavy deployment context."
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
                command="permissions",
                minimum_fields=(
                    "principal_id",
                    "principal_type",
                    "high_impact_roles",
                    "scope_count",
                    "privileged",
                ),
                rationale=(
                    "Provides direct RBAC proof for automation identities and service-connection-"
                    "backed principals."
                ),
            ),
            ChainSourceSpec(
                command="rbac",
                minimum_fields=(
                    "scope_id",
                    "principal_id",
                    "role_name",
                ),
                rationale=(
                    "Provides exact role-to-scope evidence for the current identity when the "
                    "family needs to prove start or edit control on an automation path."
                ),
            ),
            ChainSourceSpec(
                command="role-trusts",
                minimum_fields=(
                    "source_object_id",
                    "target_object_id",
                    "trust_type",
                    "confidence",
                    "summary",
                ),
                rationale=(
                    "Provides trust-expansion context when the deployment identity can also "
                    "control other app or service-principal boundaries."
                ),
            ),
            ChainSourceSpec(
                command="keyvault",
                minimum_fields=(
                    "name",
                    "vault_uri",
                    "public_network_access",
                    "enable_rbac_authorization",
                    "access_policy_count",
                ),
                rationale=(
                    "Provides the visible secret-store boundary when the deployment path relies "
                    "on Key Vault-backed variable or input support."
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
        name="escalation-path",
        state="implemented",
        meaning=(
            "A current foothold, trust edge, or bounded support clue already suggests a stronger "
            "identity or control path in Azure."
        ),
        summary=(
            "Follow the strongest current-foothold escalation stories toward the next defended "
            "identity or control step."
        ),
        allowed_claim=(
            "Can claim that visible evidence suggests a current-foothold escalation story and can "
            "name what stronger control or trust consequence is in view. Cannot claim exploit "
            "success or multi-hop control without deeper evidence."
        ),
        current_gap=(
            "The live family now joins current-foothold control, trust takeover, federated "
            "trust, and app-permission reach when the transform and stronger Azure control are "
            "explicit. Broader secret-bearing or support-only starts still sit outside this "
            "family, and ranking is still heuristic within the admitted current-foothold paths."
        ),
        best_current_examples=(
            "permissions",
            "permissions -> role-trusts",
        ),
        source_commands=(
            ChainSourceSpec(
                command="permissions",
                minimum_fields=(
                    "principal_id",
                    "display_name",
                    "priority",
                    "high_impact_roles",
                    "scope_count",
                    "scope_ids",
                    "privileged",
                    "is_current_identity",
                ),
                rationale=(
                    "Provides the direct current-identity and visible Azure-control evidence that "
                    "anchors the chain family's starting foothold."
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
                    "Provides trust edges that can widen a current-foothold path into stronger "
                    "identity control when that edge is actually connected."
                ),
            ),
        ),
    ),
    ChainFamilySpec(
        name="compute-control",
        state="implemented",
        meaning=(
            "A token-capable compute foothold can already act as an attached identity and that "
            "identity already maps to stronger Azure control."
        ),
        summary=(
            "Follow token-capable compute footholds toward the identity-backed Azure control they "
            "can reach next."
        ),
        allowed_claim=(
            "Can claim a direct token opportunity only when AzureFox can show the compute-side "
            "token path, the attached identity, and the stronger Azure control behind that "
            "identity. Cannot claim SSRF, runtime compromise, metadata abuse, token minting "
            "success, or broader credential, deployment, or trust stories without a clearer "
            "compute-side transform."
        ),
        current_gap=(
            "The live family is intentionally narrow in v1: direct token-opportunity rows only. "
            "Broader trust expansion and secret-bearing config starts still sit outside this "
            "family, mixed-identity workloads still need explicit corroboration before default "
            "admission, and AzureFox stays on the recon side of the boundary rather than trying "
            "to verify web-app exploitation or other runtime execution paths."
        ),
        best_current_examples=(
            "tokens-credentials -> managed-identities -> permissions",
            "tokens-credentials -> env-vars -> managed-identities -> permissions",
        ),
        source_commands=(
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
                    "Provides the token-capable compute foothold when a workload can already mint "
                    "or request tokens."
                ),
            ),
            ChainSourceSpec(
                command="env-vars",
                minimum_fields=(
                    "asset_id",
                    "asset_name",
                    "setting_name",
                    "value_type",
                    "key_vault_reference_identity",
                    "workload_identity_ids",
                ),
                rationale=(
                    "Provides workload configuration clues that can explicitly name which "
                    "attached identity a mixed-identity web workload is using."
                ),
            ),
            ChainSourceSpec(
                command="workloads",
                minimum_fields=(
                    "asset_id",
                    "asset_name",
                    "asset_kind",
                    "identity_ids",
                    "identity_principal_id",
                    "endpoints",
                ),
                rationale=(
                    "Provides the compute-anchor context that explains why the foothold should "
                    "interrupt broader collection."
                ),
            ),
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
                    "Provides the explicit attached-identity anchor when AzureFox can name it "
                    "cleanly from current scope."
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
                    "Provides the stronger Azure control visible behind the attached identity."
                ),
            ),
        ),
    ),
)


def get_chain_family_specs() -> tuple[ChainFamilySpec, ...]:
    return CHAIN_FAMILIES


def chain_family_names() -> tuple[str, ...]:
    return tuple(spec.name for spec in CHAIN_FAMILIES)


def implemented_chain_family_names() -> tuple[str, ...]:
    return tuple(spec.name for spec in CHAIN_FAMILIES if spec.state == "implemented")


def is_implemented_chain_family(name: str) -> bool:
    spec = get_chain_family_spec(name)
    return spec is not None and spec.state == "implemented"


def get_chain_family_spec(name: str) -> ChainFamilySpec | None:
    for spec in CHAIN_FAMILIES:
        if spec.name == name:
            return spec
    return None


def chain_source_model(command: str):
    try:
        return _CHAIN_SOURCE_MODELS[command]
    except KeyError as exc:
        raise ValueError(f"Missing empty grouped-source model for '{command}'") from exc


def empty_chain_source_fields(
    command: str,
    issue: dict[str, object],
    options: GlobalOptions,
) -> dict[str, object]:
    fields_by_command: dict[str, dict[str, object]] = {
        "devops": {"pipelines": [], "issues": [issue]},
        "automation": {"automation_accounts": [], "issues": [issue]},
        "permissions": {"permissions": [], "issues": [issue]},
        "rbac": {"principals": [], "scopes": [], "role_assignments": [], "issues": [issue]},
        "role-trusts": {"mode": options.role_trusts_mode, "trusts": [], "issues": [issue]},
        "keyvault": {"key_vaults": [], "issues": [issue]},
        "arm-deployments": {"deployments": [], "issues": [issue]},
        "app-services": {"app_services": [], "issues": [issue]},
        "functions": {"function_apps": [], "issues": [issue]},
        "aks": {"aks_clusters": [], "issues": [issue]},
        "env-vars": {"env_vars": [], "issues": [issue]},
        "tokens-credentials": {"surfaces": [], "issues": [issue]},
        "workloads": {"workloads": [], "issues": [issue]},
        "managed-identities": {"identities": [], "role_assignments": [], "issues": [issue]},
        "databases": {"database_servers": [], "issues": [issue]},
        "storage": {"storage_assets": [], "issues": [issue]},
    }
    try:
        return fields_by_command[command]
    except KeyError as exc:
        raise ValueError(f"Missing empty grouped-source shape for '{command}'") from exc
