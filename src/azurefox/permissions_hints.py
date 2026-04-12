from __future__ import annotations


def permissions_operator_signal(
    *,
    privileged: bool,
    is_current_identity: bool,
    has_workload_pivot: bool,
    workload_visibility_blocked: bool,
    trust_expansion_follow_on: bool,
) -> str:
    if not privileged:
        return "Direct control not confirmed."
    if is_current_identity:
        return "Direct control visible; current foothold."
    if has_workload_pivot:
        return "Direct control visible; workload pivot visible."
    if workload_visibility_blocked:
        return "Direct control visible; visibility blocked."
    if trust_expansion_follow_on:
        return "Direct control visible; trust expansion follow-on."
    return "Direct control visible; exact assignment review next."


def permissions_next_review_hint(
    *,
    privileged: bool,
    is_current_identity: bool,
    has_workload_pivot: bool,
    workload_visibility_blocked: bool,
    trust_expansion_follow_on: bool,
) -> str:
    if not privileged:
        return "Check rbac for the exact assignment evidence behind this lower-signal row."
    if is_current_identity:
        return "Check privesc for the direct abuse or escalation path behind this current identity."
    if has_workload_pivot:
        return "Check managed-identities for the workload pivot behind this direct control row."
    if workload_visibility_blocked:
        return (
            "Check managed-identities; current scope does not yet show the workload pivot behind "
            "this direct-control row."
        )
    if trust_expansion_follow_on:
        return "Check role-trusts for trust expansion around who can influence this principal."
    return "Check rbac for the exact assignment scope behind this direct-control row."


def permissions_priority(
    *,
    privileged: bool,
    is_current_identity: bool,
    has_workload_pivot: bool,
    workload_visibility_blocked: bool,
    trust_expansion_follow_on: bool,
) -> str:
    if not privileged:
        return "low"
    if is_current_identity or has_workload_pivot:
        return "high"
    return "medium"


def permissions_summary(
    *,
    principal_name: str,
    principal_type: str,
    high_impact_roles: list[str],
    scope_count: int,
    privileged: bool,
    is_current_identity: bool,
    has_workload_pivot: bool,
    workload_visibility_blocked: bool,
    trust_expansion_follow_on: bool,
    next_review: str,
) -> str:
    if not privileged:
        return (
            f"Principal '{principal_name}' does not yet show direct control from visible RBAC. "
            f"{next_review}"
        )

    role_text = ", ".join(high_impact_roles) or "high-impact roles"
    scope_text = "subscription-wide" if scope_count <= 1 else f"{scope_count} visible scopes"

    if is_current_identity:
        return (
            f"Current identity '{principal_name}' already has direct control visible through "
            f"{role_text} across {scope_text}. {next_review}"
        )

    if has_workload_pivot:
        return (
            f"{principal_type} '{principal_name}' already has direct control visible through "
            f"{role_text} across {scope_text}, and current scope also shows a workload pivot. "
            f"{next_review}"
        )

    if workload_visibility_blocked:
        return (
            f"{principal_type} '{principal_name}' already has direct control visible through "
            f"{role_text} across {scope_text}, but the backing workload pivot stays visibility "
            f"blocked from current scope. {next_review}"
        )

    if trust_expansion_follow_on:
        return (
            f"{principal_type} '{principal_name}' already has direct control visible through "
            f"{role_text} across {scope_text}. The next useful question is trust expansion, not "
            f"more privilege ranking. {next_review}"
        )

    return (
        f"{principal_type} '{principal_name}' already has direct control visible through "
        f"{role_text} across {scope_text}. {next_review}"
    )
