from __future__ import annotations


def role_trust_operator_signal(
    *,
    trust_type: str,
    source_name: str | None,
    target_name: str | None,
    summary: str,
) -> str:
    if _outside_tenant_follow_on(
        trust_type=trust_type,
        source_name=source_name,
        target_name=target_name,
        summary=summary,
    ):
        return "Trust expansion visible; outside-tenant follow-on."
    if trust_type in {"app-owner", "service-principal-owner"}:
        return "Indirect control visible; ownership review next."
    if trust_type == "federated-credential":
        return "Trust expansion visible; privilege confirmation next."
    if trust_type == "app-to-service-principal":
        return "Indirect control visible; privilege confirmation next."
    return "Indirect control visible; privilege confirmation next."


def role_trust_next_review_hint(
    *,
    trust_type: str,
    source_name: str | None,
    source_object_id: str,
    target_name: str | None,
    target_object_id: str,
    target_type: str,
    summary: str,
) -> str:
    if _outside_tenant_follow_on(
        trust_type=trust_type,
        source_name=source_name,
        target_name=target_name,
        summary=summary,
    ):
        return (
            "Check cross-tenant for related outside-tenant control or delegated-management "
            f"paths around {_identity_ref(target_name, target_object_id, target_type)}."
        )

    if trust_type == "app-owner":
        return (
            f"Review ownership around {_identity_ref(target_name, target_object_id, target_type)}; "
            "if it backs an Azure-facing identity, confirm that identity in permissions."
        )

    if trust_type == "service-principal-owner":
        return (
            f"Review ownership around {_identity_ref(target_name, target_object_id, target_type)}, "
            "then confirm Azure control in permissions."
        )

    if trust_type == "federated-credential":
        if target_type == "ServicePrincipal":
            return (
                "Check permissions for Azure control on "
                f"{_identity_ref(target_name, target_object_id, target_type)}."
            )
        return (
            "Check permissions for the backing identity behind "
            f"{_identity_ref(target_name, target_object_id, target_type)}."
        )

    if trust_type == "app-to-service-principal":
        return (
            "Check permissions for Azure control on "
            f"{_identity_ref(source_name, source_object_id, 'ServicePrincipal')}."
        )

    return (
        "Check permissions or rbac to confirm whether this trust edge reaches meaningful "
        "Azure control."
    )


def role_trust_summary(
    *,
    trust_type: str,
    source_name: str | None,
    target_name: str | None,
    summary: str,
    next_review: str,
) -> str:
    if _outside_tenant_follow_on(
        trust_type=trust_type,
        source_name=source_name,
        target_name=target_name,
        summary=summary,
    ):
        return (
            f"{summary} This row points to outside-tenant follow-up, not direct Azure role "
            f"confirmation first. {next_review}"
        )

    if trust_type in {"app-owner", "service-principal-owner"}:
        return (
            f"{summary} This is an indirect-control row: ownership is the visible trust path, "
            f"not direct Azure privilege by itself. {next_review}"
        )

    if trust_type == "federated-credential":
        return (
            f"{summary} This row shows trust expansion into the target identity rather than "
            f"direct Azure privilege by itself. {next_review}"
        )

    if trust_type == "app-to-service-principal":
        return (
            f"{summary} This row is a trust-edge and application-permission cue; confirm whether "
            f"the same identity also holds Azure control. {next_review}"
        )

    return f"{summary} {next_review}"


def _outside_tenant_follow_on(
    *,
    trust_type: str,
    source_name: str | None,
    target_name: str | None,
    summary: str,
) -> bool:
    if trust_type not in {"app-owner", "service-principal-owner", "federated-credential"}:
        return False
    text = " ".join(
        value for value in (summary, source_name or "", target_name or "") if value
    ).lower()
    return any(
        marker in text
        for marker in (
            "outside-tenant",
            "cross-tenant",
            "external tenant",
            "externally owned",
            "#ext#",
        )
    )


def _identity_ref(name: str | None, object_id: str, identity_type: str) -> str:
    label = identity_type.replace("ServicePrincipal", "service principal").replace(
        "Application", "application"
    )
    if name:
        return f"{label} '{name}'"
    return f"{label} '{object_id}'"
