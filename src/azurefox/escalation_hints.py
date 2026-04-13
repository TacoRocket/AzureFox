from __future__ import annotations


def current_foothold_proven_path(
    *,
    principal_name: str,
    impact_roles: list[str],
) -> str:
    role_text = ", ".join(impact_roles) or "high-impact roles"
    return (
        f"Current foothold '{principal_name}' already holds high-impact RBAC "
        f"({role_text}) on visible scope."
    )


def current_foothold_missing_proof() -> str:
    return (
        "AzureFox does not prove which exact abuse action is the best next step "
        "from this row alone."
    )


def current_foothold_next_review_hint() -> str:
    return (
        "Check rbac for the exact assignment evidence and scope behind this "
        "current-identity escalation lead."
    )
