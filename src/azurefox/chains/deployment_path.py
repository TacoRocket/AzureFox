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
    change_signals: tuple[str, ...] = ()
    secret_support_signals: tuple[str, ...] = ()
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
    if source.posture != "can already change Azure here":
        return DeploymentRowAdmission(
            state="blocked",
            admitted=False,
            reason=(
                "Default deployment-path rows start only from sources that can already change "
                "Azure here; secret-bearing support alone does not earn a grouped row."
            ),
        )

    if exact_target_count == 1 and confirmation_basis in _CANONICAL_CONFIRMATION_BASES:
        return DeploymentRowAdmission(
            state="named match",
            admitted=True,
            reason=(
                "The source already looks change-capable and the downstream target is joined by "
                "canonical evidence rather than name-only inference."
            ),
        )

    if visibility_issue:
        return DeploymentRowAdmission(
            state="visibility blocked",
            admitted=True,
            reason=(
                "The source already looks change-capable, but current scope does not confirm "
                "which downstream Azure targets are visible enough to name."
            ),
        )

    candidate_count = max(exact_target_count, narrowed_candidate_count)
    if candidate_count > 0:
        return DeploymentRowAdmission(
            state="narrowed candidates",
            admitted=True,
            reason=(
                "The source already looks change-capable, but current evidence narrows the next "
                "review set without proving one exact downstream target."
            ),
        )

    return DeploymentRowAdmission(
        state="blocked",
        admitted=False,
        reason=(
            "Visible execution or service-connection posture alone is not enough; a default "
            "deployment-path row also needs a named target, a narrowed candidate set, or an "
            "explicit visibility block."
        ),
    )


def _assess_devops_source(source: DevopsPipelineAsset) -> DeploymentSourceAssessment:
    change_signals: list[str] = []
    secret_support_signals: list[str] = []
    target_family_hints = _target_family_hints_from_devops(source.target_clues)

    if source.azure_service_connection_names:
        change_signals.append("azure-service-connection")
    if target_family_hints:
        change_signals.append("target-family-clue")
    if source.secret_variable_count > 0:
        secret_support_signals.append("secret-variables")
    if source.key_vault_names or source.key_vault_group_names:
        secret_support_signals.append("keyvault-backed-support")
    if source.variable_group_names:
        secret_support_signals.append("variable-groups")

    posture: DeploymentSourcePosture = "insufficient evidence"
    if source.azure_service_connection_names:
        posture = "can already change Azure here"
    elif secret_support_signals:
        posture = "stores secrets here"

    return DeploymentSourceAssessment(
        source_command="devops",
        source_name=source.name,
        posture=posture,
        change_signals=tuple(change_signals),
        secret_support_signals=tuple(secret_support_signals),
        target_family_hints=target_family_hints,
    )


def _assess_automation_source(source: AutomationAccountAsset) -> DeploymentSourceAssessment:
    change_signals: list[str] = []
    secret_support_signals: list[str] = []

    if source.identity_type:
        change_signals.append("managed-identity")
    if (source.published_runbook_count or 0) > 0:
        change_signals.append("published-runbooks")
    if (source.schedule_count or 0) > 0 or (source.job_schedule_count or 0) > 0:
        change_signals.append("scheduled-execution")
    if (source.webhook_count or 0) > 0:
        change_signals.append("webhook-execution")
    if (source.hybrid_worker_group_count or 0) > 0:
        change_signals.append("hybrid-worker-reach")
    if (source.credential_count or 0) > 0:
        secret_support_signals.append("credentials")
    if (source.certificate_count or 0) > 0:
        secret_support_signals.append("certificates")
    if (source.connection_count or 0) > 0:
        secret_support_signals.append("connections")
    if (source.encrypted_variable_count or 0) > 0:
        secret_support_signals.append("encrypted-variables")

    has_identity = bool(source.identity_type)
    has_execution_surface = any(
        signal in change_signals
        for signal in (
            "published-runbooks",
            "scheduled-execution",
            "webhook-execution",
            "hybrid-worker-reach",
        )
    )

    posture: DeploymentSourcePosture = "insufficient evidence"
    if has_identity and has_execution_surface:
        posture = "can already change Azure here"
    elif secret_support_signals:
        posture = "stores secrets here"

    return DeploymentSourceAssessment(
        source_command="automation",
        source_name=source.name,
        posture=posture,
        change_signals=tuple(change_signals),
        secret_support_signals=tuple(secret_support_signals),
        target_family_hints=(),
    )


def _target_family_hints_from_devops(target_clues: list[str]) -> tuple[str, ...]:
    families: list[str] = []
    for clue in target_clues:
        normalized = str(clue).strip().lower()
        families.extend(_DEVOPS_TARGET_HINTS.get(normalized, ()))
    return tuple(sorted(dict.fromkeys(families)))
