from __future__ import annotations

from dataclasses import dataclass

SEMANTIC_PRIORITY_ORDER = {
    "high": 0,
    "medium": 1,
    "low": 2,
}


@dataclass(frozen=True, slots=True)
class ChainSemanticContext:
    family: str
    clue_type: str
    target_service: str
    target_resolution: str
    target_count: int


@dataclass(frozen=True, slots=True)
class ChainSemanticDecision:
    priority: str
    next_review: str


def evaluate_chain_semantics(context: ChainSemanticContext) -> ChainSemanticDecision:
    evaluator = _FAMILY_EVALUATORS.get(context.family, _default_chain_semantics)
    return evaluator(context)


def semantic_priority_sort_value(priority: str) -> int:
    return SEMANTIC_PRIORITY_ORDER.get(priority, 9)


def _credential_path_semantics(context: ChainSemanticContext) -> ChainSemanticDecision:
    if context.target_resolution == "named match":
        if context.target_service == "keyvault":
            return ChainSemanticDecision(
                priority="high",
                next_review="Check vault access path and referenced secret use.",
            )
        return ChainSemanticDecision(
            priority="high",
            next_review="Validate the exact named target from workload config.",
        )

    if context.target_resolution == "visibility blocked":
        return ChainSemanticDecision(
            priority="low",
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
                next_review="Confirm the database target from app config or connection clues.",
            )
        if context.target_service == "storage":
            return ChainSemanticDecision(
                priority="medium",
                next_review="Confirm the storage target from binding or connection clues.",
            )
        return ChainSemanticDecision(
            priority="medium",
            next_review="Confirm the exact target before deeper follow-up.",
        )

    if context.target_resolution == "narrowed candidates":
        if context.target_service == "database":
            return ChainSemanticDecision(
                priority="low",
                next_review="Confirm the database target from app config or connection clues.",
            )
        if context.target_service == "storage":
            return ChainSemanticDecision(
                priority="low",
                next_review="Confirm the storage target from binding or connection clues.",
            )
        return ChainSemanticDecision(
            priority="low",
            next_review="Confirm the exact target before deeper follow-up.",
        )

    if context.target_resolution == "tenant-wide candidates":
        return ChainSemanticDecision(
            priority="low",
            next_review="Narrow the target with stronger naming or deployment clues.",
        )

    if context.target_resolution == "service hint only":
        return ChainSemanticDecision(
            priority="low",
            next_review="Collect richer target-side inventory before follow-up.",
        )

    if context.target_resolution == "named target not visible":
        return ChainSemanticDecision(
            priority="low",
            next_review="Verify that the named target is visible in current inventory.",
        )

    return _default_chain_semantics(context)


def _default_chain_semantics(context: ChainSemanticContext) -> ChainSemanticDecision:
    if context.target_resolution == "named match":
        return ChainSemanticDecision(
            priority="high",
            next_review="Validate the exact named target from chain evidence.",
        )

    if context.target_resolution == "visibility blocked":
        return ChainSemanticDecision(
            priority="low",
            next_review=f"Restore {context.target_service} visibility before choosing a target.",
        )

    return ChainSemanticDecision(
        priority="low",
        next_review="Confirm the next target before deeper follow-up.",
    )


def _deployment_path_semantics(context: ChainSemanticContext) -> ChainSemanticDecision:
    if context.target_resolution == "named match":
        return ChainSemanticDecision(
            priority="high",
            next_review="Validate the exact named target from deployment evidence.",
        )

    if context.target_resolution == "visibility blocked":
        return ChainSemanticDecision(
            priority="low",
            next_review=f"Restore {context.target_service} visibility before trusting the path.",
        )

    if context.target_resolution == "narrowed candidates":
        if context.clue_type == "azure-service-connection":
            return ChainSemanticDecision(
                priority="medium",
                next_review="Review the narrowed deployment targets and the backing Azure path.",
            )
        return ChainSemanticDecision(
            priority="low",
            next_review="Review the narrowed deployment targets before deeper follow-up.",
        )

    return _default_chain_semantics(context)


_FAMILY_EVALUATORS = {
    "credential-path": _credential_path_semantics,
    "deployment-path": _deployment_path_semantics,
    "workload-identity-path": _default_chain_semantics,
}
