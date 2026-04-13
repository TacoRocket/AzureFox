from __future__ import annotations

from azurefox.escalation_hints import (
    current_foothold_missing_proof,
    current_foothold_next_review_hint,
    current_foothold_proven_path,
)


def privesc_operator_signal(*, path_type: str, current_identity: bool) -> str:
    if path_type == "public-identity-pivot":
        if current_identity:
            return "Current foothold already reaches an ingress-backed workload identity path."
        return "Visible ingress-backed lead; not yet rooted in current foothold."

    if current_identity:
        return "Current foothold already has direct control."

    return "Visible privileged lead; not yet rooted in current foothold."


def privesc_proven_path(
    *,
    principal_name: str,
    path_type: str,
    asset_name: str | None,
    impact_roles: list[str],
    current_identity: bool,
) -> str:
    role_text = _role_text(impact_roles)

    if path_type == "public-identity-pivot":
        asset = asset_name or "visible workload"
        return (
            f"Public workload '{asset}' carries identity '{principal_name}' with "
            f"high-impact RBAC ({role_text})."
        )

    if current_identity:
        return current_foothold_proven_path(
            principal_name=principal_name,
            impact_roles=impact_roles,
        )

    return (
        f"Principal '{principal_name}' already holds high-impact RBAC "
        f"({role_text}) on visible scope."
    )


def privesc_missing_proof(*, path_type: str, current_identity: bool) -> str:
    if path_type == "public-identity-pivot":
        return "AzureFox does not prove control of the workload or successful token use from it."

    if current_identity:
        return current_foothold_missing_proof()

    return "AzureFox does not prove the current identity can act as or control this principal."


def privesc_next_review_hint(*, path_type: str, current_identity: bool) -> str:
    if path_type == "public-identity-pivot":
        return (
            "Check managed-identities for the workload-to-identity anchor behind "
            "this ingress-backed lead."
        )

    if current_identity:
        return current_foothold_next_review_hint()

    return (
        "Check role-trusts for paths that could let the current identity influence "
        "this privileged principal."
    )


def privesc_summary(*, proven_path: str, missing_proof: str, next_review: str) -> str:
    return f"{proven_path} {missing_proof} {next_review}"


def _role_text(impact_roles: list[str]) -> str:
    return ", ".join(impact_roles) or "high-impact roles"
