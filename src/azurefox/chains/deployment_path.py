from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from azurefox.models.common import (
    ArmDeploymentSummary,
    AutomationAccountAsset,
    DevopsPipelineAsset,
)

DeploymentSourcePosture = Literal[
    "can already change Azure here",
    "stores secrets here",
    "insufficient evidence",
]
DeploymentPathConcept = Literal[
    "controllable-change-path",
    "execution-hub",
    "secret-escalation-support",
]
DeploymentRowState = Literal[
    "named match",
    "narrowed candidates",
    "visibility blocked",
    "blocked",
]
DeploymentConfirmationBasis = Literal[
    "asset-id-match",
    "resource-id-match",
    "principal-id-match",
    "managed-identity-id-match",
    "normalized-uri-match",
    "parsed-config-target",
    "same-workload-corroborated",
    "source-issue-present",
    "name-only-inference",
]

_CANONICAL_CONFIRMATION_BASES = {
    "asset-id-match",
    "resource-id-match",
    "principal-id-match",
    "managed-identity-id-match",
    "normalized-uri-match",
    "parsed-config-target",
    "same-workload-corroborated",
}
_DEVOPS_TARGET_HINTS = {
    "aks/kubernetes": ("aks",),
    "app service": ("app-services",),
    "azure functions": ("functions",),
    "function app": ("functions",),
    "functions": ("functions",),
    "arm/bicep/terraform": ("arm-deployments",),
}
_ARM_PROVIDER_TARGET_HINTS = {
    "microsoft.containerservice": ("aks",),
    "microsoft.web": ("app-services", "functions"),
}


@dataclass(frozen=True, slots=True)
class DeploymentSourceAssessment:
    source_command: str
    source_name: str
    posture: DeploymentSourcePosture
    path_concept: DeploymentPathConcept | None = None
    change_signals: tuple[str, ...] = ()
    secret_support_signals: tuple[str, ...] = ()
    consequence_types: tuple[str, ...] = ()
    missing_execution_path: bool = False
    missing_target_mapping: bool = False
    target_family_hints: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DeploymentRowAdmission:
    state: DeploymentRowState
    admitted: bool
    reason: str


def assess_deployment_source(
    source: DevopsPipelineAsset | AutomationAccountAsset,
) -> DeploymentSourceAssessment:
    if isinstance(source, DevopsPipelineAsset):
        return _assess_devops_source(source)
    if isinstance(source, AutomationAccountAsset):
        return _assess_automation_source(source)
    raise TypeError(f"Unsupported deployment-path source type: {type(source).__name__}")


def target_family_hints_from_arm_deployment(record: ArmDeploymentSummary) -> tuple[str, ...]:
    families: list[str] = []
    for provider in record.providers:
        families.extend(_ARM_PROVIDER_TARGET_HINTS.get(str(provider).strip().lower(), ()))
    return tuple(sorted(dict.fromkeys(families)))


def admit_deployment_path_row(
    source: DeploymentSourceAssessment,
    *,
    exact_target_count: int = 0,
    narrowed_candidate_count: int = 0,
    confirmation_basis: DeploymentConfirmationBasis | None = None,
    visibility_issue: str | None = None,
) -> DeploymentRowAdmission:
    if source.missing_execution_path:
        return DeploymentRowAdmission(
            state="blocked",
            admitted=False,
            reason=(
                "Default deployment-path rows need a visible execution foothold. This source "
                "does not yet show how the Azure change path is started, triggered, or modified."
            ),
        )

    if not source.consequence_types:
        return DeploymentRowAdmission(
            state="blocked",
            admitted=False,
            reason=(
                "Default deployment-path rows need a defended Azure impact point. This source "
                "still reads like deployment inventory rather than a path with a clear Azure "
                "change consequence."
            ),
        )

    candidate_count = max(exact_target_count, narrowed_candidate_count)

    if source.posture == "stores secrets here":
        return _resolved_deployment_row_admission(
            exact_target_count=exact_target_count,
            candidate_count=candidate_count,
            confirmation_basis=confirmation_basis,
            visibility_blocked=bool(visibility_issue or source.missing_target_mapping),
            named_match_reason=(
                "Secret-bearing deployment support is tied to a visible Azure change path, "
                "and the downstream target is joined by canonical evidence."
            ),
            visibility_reason=(
                "Secret-bearing deployment support is visible, but AzureFox still needs "
                "stronger target mapping before it can name the downstream Azure footprint."
            ),
            narrowed_reason=(
                "Secret-bearing deployment support is visible, and current evidence narrows "
                "the Azure footprint it could widen if another foothold controls execution."
            ),
            blocked_reason=(
                "Support-only deployment rows still need a named target, a narrowed candidate "
                "set, or an explicit missing target-mapping boundary."
            ),
        )

    if source.posture != "can already change Azure here":
        return DeploymentRowAdmission(
            state="blocked",
            admitted=False,
            reason=(
                "Default deployment-path rows start only from sources that can already change "
                "Azure here or from clearly bounded secret-backed support rows."
            ),
        )

    return _resolved_deployment_row_admission(
        exact_target_count=exact_target_count,
        candidate_count=candidate_count,
        confirmation_basis=confirmation_basis,
        visibility_blocked=bool(visibility_issue),
        named_match_reason=(
            "The source already looks change-capable and the downstream target is joined by "
            "canonical evidence rather than name-only inference."
        ),
        visibility_reason=(
            "The source already looks change-capable, but current scope does not confirm "
            "which downstream Azure targets are visible enough to name."
        ),
        narrowed_reason=(
            "The source already looks change-capable, but current evidence narrows the next "
            "review set without proving one exact downstream target."
        ),
        blocked_reason=(
            "Visible execution or service-connection posture alone is not enough; a default "
            "deployment-path row also needs a named target, a narrowed candidate set, or an "
            "explicit visibility block."
        ),
    )


def _resolved_deployment_row_admission(
    *,
    exact_target_count: int,
    candidate_count: int,
    confirmation_basis: DeploymentConfirmationBasis | None,
    visibility_blocked: bool,
    named_match_reason: str,
    visibility_reason: str,
    narrowed_reason: str,
    blocked_reason: str,
) -> DeploymentRowAdmission:
    if exact_target_count == 1 and confirmation_basis in _CANONICAL_CONFIRMATION_BASES:
        return DeploymentRowAdmission(
            state="named match",
            admitted=True,
            reason=named_match_reason,
        )
    if visibility_blocked:
        return DeploymentRowAdmission(
            state="visibility blocked",
            admitted=True,
            reason=visibility_reason,
        )
    if candidate_count > 0:
        return DeploymentRowAdmission(
            state="narrowed candidates",
            admitted=True,
            reason=narrowed_reason,
        )
    return DeploymentRowAdmission(
        state="blocked",
        admitted=False,
        reason=blocked_reason,
    )


def _assess_devops_source(source: DevopsPipelineAsset) -> DeploymentSourceAssessment:
    change_signals: list[str] = []
    secret_support_signals = list(source.secret_support_types)
    target_family_hints = _target_family_hints_from_devops(source.target_clues)
    trigger_types = {str(value).strip().lower() for value in source.trigger_types}

    if source.azure_service_connection_names:
        change_signals.append("azure-service-connection")
    if source.repository_name:
        change_signals.append("repo-backed-definition")
    if "continuousintegration" in trigger_types:
        change_signals.append("auto-trigger")
    if "pullrequest" in trigger_types:
        change_signals.append("pull-request-trigger")
    if "schedule" in trigger_types:
        change_signals.append("scheduled-trigger")
    if target_family_hints:
        change_signals.append("target-family-clue")
    if not secret_support_signals:
        if source.secret_variable_count > 0:
            secret_support_signals.append("secret-variables")
        if source.key_vault_names or source.key_vault_group_names:
            secret_support_signals.append("keyvault-backed-support")
        if source.variable_group_names:
            secret_support_signals.append("variable-groups")

    posture: DeploymentSourcePosture = "insufficient evidence"
    path_concept: DeploymentPathConcept | None = None
    if (
        source.azure_service_connection_names
        and not source.missing_execution_path
        and bool(source.consequence_types)
    ):
        posture = "can already change Azure here"
        path_concept = "controllable-change-path"
    elif secret_support_signals:
        posture = "stores secrets here"
        path_concept = "secret-escalation-support"

    return DeploymentSourceAssessment(
        source_command="devops",
        source_name=source.name,
        posture=posture,
        path_concept=path_concept,
        change_signals=tuple(change_signals),
        secret_support_signals=tuple(secret_support_signals),
        consequence_types=tuple(source.consequence_types),
        missing_execution_path=source.missing_execution_path,
        missing_target_mapping=source.missing_target_mapping,
        target_family_hints=target_family_hints,
    )


def _assess_automation_source(source: AutomationAccountAsset) -> DeploymentSourceAssessment:
    change_signals: list[str] = []
    secret_support_signals = list(source.secret_support_types)

    if source.identity_type:
        change_signals.append("managed-identity")
    if (source.published_runbook_count or 0) > 0:
        change_signals.append("published-runbooks")
    if (source.schedule_count or 0) > 0 or (source.job_schedule_count or 0) > 0:
        change_signals.append("scheduled-start")
    if (source.webhook_count or 0) > 0:
        change_signals.append("webhook-start")
    if (source.hybrid_worker_group_count or 0) > 0:
        change_signals.append("hybrid-worker-reach")
    if not secret_support_signals:
        if (source.credential_count or 0) > 0:
            secret_support_signals.append("credentials")
        if (source.certificate_count or 0) > 0:
            secret_support_signals.append("certificates")
        if (source.connection_count or 0) > 0:
            secret_support_signals.append("connections")
        if (source.encrypted_variable_count or 0) > 0:
            secret_support_signals.append("encrypted-variables")

    has_identity = bool(source.identity_type)
    has_execution_surface = not source.missing_execution_path and any(
        signal in change_signals
        for signal in (
            "published-runbooks",
            "scheduled-start",
            "webhook-start",
            "hybrid-worker-reach",
        )
    )

    posture: DeploymentSourcePosture = "insufficient evidence"
    path_concept: DeploymentPathConcept | None = None
    if has_identity and has_execution_surface and bool(source.consequence_types):
        posture = "can already change Azure here"
        path_concept = "execution-hub"
    elif secret_support_signals:
        posture = "stores secrets here"
        path_concept = "secret-escalation-support"

    return DeploymentSourceAssessment(
        source_command="automation",
        source_name=source.name,
        posture=posture,
        path_concept=path_concept,
        change_signals=tuple(change_signals),
        secret_support_signals=tuple(secret_support_signals),
        consequence_types=tuple(source.consequence_types),
        missing_execution_path=source.missing_execution_path,
        missing_target_mapping=source.missing_target_mapping,
        target_family_hints=(),
    )


def _target_family_hints_from_devops(target_clues: list[str]) -> tuple[str, ...]:
    families: list[str] = []
    for clue in target_clues:
        normalized = str(clue).strip().lower()
        families.extend(_DEVOPS_TARGET_HINTS.get(normalized, ()))
    return tuple(sorted(dict.fromkeys(families)))
