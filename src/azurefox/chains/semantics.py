from __future__ import annotations

from dataclasses import dataclass

SEMANTIC_PRIORITY_ORDER = {
    "high": 0,
    "medium": 1,
    "low": 2,
}

SEMANTIC_URGENCY_ORDER = {
    "pivot-now": 0,
    "review-soon": 1,
    "bookmark": 2,
}


@dataclass(frozen=True, slots=True)
class ChainSemanticContext:
    family: str
    clue_type: str
    target_service: str
    target_resolution: str
    target_count: int
    source_command: str | None = None
    path_concept: str | None = None
    current_operator_can_drive: bool | None = None
    current_operator_can_inject: bool | None = None


@dataclass(frozen=True, slots=True)
class ChainSemanticDecision:
    priority: str
    urgency: str | None
    next_review: str


def evaluate_chain_semantics(context: ChainSemanticContext) -> ChainSemanticDecision:
    evaluator = _FAMILY_EVALUATORS.get(context.family, _default_chain_semantics)
    return evaluator(context)


def semantic_priority_sort_value(priority: str) -> int:
    return SEMANTIC_PRIORITY_ORDER.get(priority, 9)


def semantic_urgency_sort_value(urgency: str | None) -> int:
    return SEMANTIC_URGENCY_ORDER.get(str(urgency or ""), 9)


def _credential_path_semantics(context: ChainSemanticContext) -> ChainSemanticDecision:
    if context.target_resolution == "named match":
        if context.target_service == "keyvault":
            return ChainSemanticDecision(
                priority="high",
                urgency="review-soon",
                next_review="Check vault access path and referenced secret use.",
            )
        return ChainSemanticDecision(
            priority="high",
            urgency="review-soon",
            next_review="Validate the exact named target from workload config.",
        )

    if context.target_resolution == "visibility blocked":
        return ChainSemanticDecision(
            priority="low",
            urgency="bookmark",
            next_review=f"Restore {context.target_service} visibility before choosing a target.",
        )

    if (
        context.clue_type == "plain-text-secret"
        and context.target_resolution == "narrowed candidates"
        and context.target_count == 1
    ):
        if context.target_service == "database":
            return ChainSemanticDecision(
                priority="medium",
                urgency="review-soon",
                next_review=(
                    "Current env-vars and token surfaces do not name the exact database target."
                ),
            )
        if context.target_service == "storage":
            return ChainSemanticDecision(
                priority="medium",
                urgency="bookmark",
                next_review=(
                    "Current env-vars and token surfaces do not name the exact storage target."
                ),
            )
        return ChainSemanticDecision(
            priority="medium",
            urgency="bookmark",
            next_review="Confirm the exact target before deeper follow-up.",
        )

    if context.target_resolution == "narrowed candidates":
        if context.target_service == "database":
            return ChainSemanticDecision(
                priority="low",
                urgency="bookmark",
                next_review=(
                    "Current env-vars and token surfaces do not name the exact database target."
                ),
            )
        if context.target_service == "storage":
            return ChainSemanticDecision(
                priority="low",
                urgency="bookmark",
                next_review=(
                    "Current env-vars and token surfaces do not name the exact storage target."
                ),
            )
        return ChainSemanticDecision(
            priority="low",
            urgency="bookmark",
            next_review=(
                "Current evidence does not name the exact target yet; review the visible "
                "candidates next."
            ),
        )

    if context.target_resolution == "tenant-wide candidates":
        return ChainSemanticDecision(
            priority="low",
            urgency="bookmark",
            next_review=(
                "Current evidence only narrows this to a broad visible target set; review the "
                "visible candidates and look for stronger naming clues next."
            ),
        )

    if context.target_resolution == "service hint only":
        return ChainSemanticDecision(
            priority="low",
            urgency="bookmark",
            next_review=(
                "Current target-side inventory does not name any concrete target here; collect "
                "richer target visibility before follow-up."
            ),
        )

    if context.target_resolution == "named target not visible":
        return ChainSemanticDecision(
            priority="low",
            urgency="bookmark",
            next_review="Verify that the named target is visible in current inventory.",
        )

    return _default_chain_semantics(context)


def _default_chain_semantics(context: ChainSemanticContext) -> ChainSemanticDecision:
    if context.target_resolution == "named match":
        return ChainSemanticDecision(
            priority="high",
            urgency="review-soon",
            next_review="Validate the exact named target from chain evidence.",
        )

    if context.target_resolution == "visibility blocked":
        return ChainSemanticDecision(
            priority="low",
            urgency="bookmark",
            next_review=f"Restore {context.target_service} visibility before choosing a target.",
        )

    return ChainSemanticDecision(
        priority="low",
        urgency="bookmark",
        next_review="Confirm the next target before deeper follow-up.",
    )


def _deployment_path_semantics(context: ChainSemanticContext) -> ChainSemanticDecision:
    if context.path_concept == "secret-escalation-support":
        if context.target_resolution == "named match":
            return ChainSemanticDecision(
                priority="medium",
                urgency="bookmark",
                next_review=(
                    "Review the exact target and confirm what separate foothold could reuse "
                    "the secret-backed deployment support."
                ),
            )
        if context.target_resolution == "visibility blocked":
            return ChainSemanticDecision(
                priority="low",
                urgency="bookmark",
                next_review=(
                    "Review the secret-backed support boundary and restore consequence "
                    "grounding before treating it as a fuller path."
                ),
            )
        if context.target_resolution == "narrowed candidates":
            return ChainSemanticDecision(
                priority="low",
                urgency="bookmark",
                next_review=(
                    "Review the secret-backed support and the narrowed consequence set, then "
                    "confirm what separate foothold could drive execution."
                ),
            )

    if context.target_resolution == "named match":
        if context.source_command == "devops":
            if context.current_operator_can_inject:
                return ChainSemanticDecision(
                    priority="high",
                    urgency="pivot-now",
                    next_review=(
                        "Current credentials can poison a trusted input; review the exact named "
                        "Azure target next."
                    ),
                )
            return ChainSemanticDecision(
                priority="medium",
                urgency="review-soon",
                next_review=(
                    "Review the exact named target and the backing Azure service connection, "
                    "but keep source poisoning marked unproven until a trusted input is writable."
                ),
            )
        if context.source_command == "automation":
            return ChainSemanticDecision(
                priority="high",
                urgency="review-soon",
                next_review="Review the automation identity and the exact named Azure target path.",
            )
        return ChainSemanticDecision(
            priority="high",
            urgency="review-soon",
            next_review="Validate the exact named target from deployment evidence.",
        )

    if context.target_resolution == "visibility blocked":
        if context.path_concept == "execution-hub":
            return ChainSemanticDecision(
                priority="medium",
                urgency="review-soon",
                next_review=(
                    f"Check permissions or role-trusts for the automation identity and restore "
                    f"{context.target_service} visibility before naming downstream impact."
                ),
            )
        return ChainSemanticDecision(
            priority="medium",
            urgency="review-soon",
            next_review=(
                f"Check permissions or role-trusts for the backing Azure path and restore "
                f"{context.target_service} visibility before naming downstream impact."
            ),
        )

    if context.target_resolution == "narrowed candidates":
        if context.current_operator_can_inject:
            return ChainSemanticDecision(
                priority="high",
                urgency="pivot-now",
                next_review=(
                    "Current credentials can poison a trusted input; validate the narrowed Azure "
                    "change candidates next."
                ),
            )
        if (
            context.path_concept == "controllable-change-path"
            or context.clue_type == "azure-service-connection"
        ):
            return ChainSemanticDecision(
                priority="medium",
                urgency="review-soon",
                next_review=(
                    "Check permissions or role-trusts for the backing Azure path, then review "
                    "the narrowed Azure change candidates."
                ),
            )
        return ChainSemanticDecision(
            priority="low",
            urgency="bookmark",
            next_review="Review the narrowed deployment targets before deeper follow-up.",
        )

    return _default_chain_semantics(context)


def _escalation_path_semantics(context: ChainSemanticContext) -> ChainSemanticDecision:
    if context.path_concept == "current-foothold-direct-control":
        return ChainSemanticDecision(
            priority="high",
            urgency="pivot-now",
            next_review="Check rbac for the exact assignment evidence behind the current foothold.",
        )

    if context.path_concept == "trust-expansion":
        if context.target_resolution == "path-confirmed":
            return ChainSemanticDecision(
                priority="medium",
                urgency="review-soon",
                next_review="Check permissions for the stronger target behind this trust edge.",
            )
        return ChainSemanticDecision(
            priority="low",
            urgency="bookmark",
            next_review="Confirm whether the trust target also holds meaningful Azure control.",
        )

    return _default_chain_semantics(context)


def _compute_control_semantics(context: ChainSemanticContext) -> ChainSemanticDecision:
    if context.path_concept == "direct-token-opportunity":
        if context.target_resolution == "path-confirmed":
            return ChainSemanticDecision(
                priority="high",
                urgency="pivot-now",
                next_review=(
                    "Validate the compute foothold and attached identity path before deeper "
                    "Azure control follow-up."
                ),
            )
        if context.target_resolution == "visibility blocked":
            return ChainSemanticDecision(
                priority="medium",
                urgency="review-soon",
                next_review=(
                    "Restore workload or identity visibility before treating this compute path "
                    "like a defended Azure-control pivot."
                ),
            )

    return _default_chain_semantics(context)


_FAMILY_EVALUATORS = {
    "credential-path": _credential_path_semantics,
    "deployment-path": _deployment_path_semantics,
    "escalation-path": _escalation_path_semantics,
    "compute-control": _compute_control_semantics,
}
