from __future__ import annotations


def role_trust_control_primitive(
    *,
    trust_type: str,
    target_type: str,
) -> str | None:
    if trust_type == "app-owner":
        return "change-auth-material"
    if trust_type == "service-principal-owner":
        return "owner-control"
    if trust_type == "federated-credential":
        return "existing-federated-credential"
    if trust_type == "app-to-service-principal":
        return "existing-app-role-assignment"
    return None


def role_trust_controlled_object(
    *,
    trust_type: str,
    source_name: str | None,
    source_type: str,
    target_name: str | None,
    target_type: str,
) -> tuple[str | None, str | None]:
    if trust_type == "federated-credential":
        return source_type or "Application", source_name
    return target_type, target_name


def role_trust_escalation_mechanism(
    *,
    trust_type: str,
    source_name: str | None,
    target_name: str | None,
    target_type: str,
    backing_service_principal_name: str | None = None,
) -> str | None:
    if trust_type == "app-owner":
        app_name = target_name or "unknown application"
        if backing_service_principal_name:
            return (
                f"Control of application '{app_name}' could change authentication material "
                f"that makes service principal '{backing_service_principal_name}' usable."
            )
        return (
            f"Control of application '{app_name}' could change authentication material Azure "
            "accepts for identities backed by that application."
        )

    if trust_type == "service-principal-owner":
        principal = _identity_ref(target_name, "unknown", target_type)
        return (
            f"Owner-level control over {principal} is visible, but the exact "
            "authentication-control transform is not yet explicit."
        )

    if trust_type == "federated-credential":
        app_name = source_name or "unknown application"
        if target_type == "ServicePrincipal" and target_name:
            return (
                f"Application '{app_name}' already has federated trust that can yield "
                f"service principal '{target_name}' access."
            )
        return f"Application '{app_name}' already has a federated trust path."

    if trust_type == "app-to-service-principal":
        source = source_name or "unknown service principal"
        target = target_name or "unknown service principal"
        return (
            f"Service principal '{source}' already holds an application-permission path into "
            f"service principal '{target}'."
        )

    return None


def role_trust_usable_identity_result(
    *,
    trust_type: str,
    source_name: str | None,
    target_name: str | None,
    target_type: str,
    backing_service_principal_name: str | None = None,
) -> str | None:
    if trust_type == "app-owner" and target_name and backing_service_principal_name:
        return (
            f"Control of application '{target_name}' could make service principal "
            f"'{backing_service_principal_name}' usable."
        )

    if trust_type == "federated-credential" and target_type == "ServicePrincipal" and target_name:
        return f"Federated sign-in can yield service principal '{target_name}' access."

    if trust_type == "app-to-service-principal" and source_name and target_name:
        return (
            f"Service principal '{source_name}' already has application-permission reach to "
            f"'{target_name}'."
        )

    return None


def role_trust_defender_cut_point(
    *,
    trust_type: str,
    source_name: str | None,
    target_name: str | None,
    target_type: str,
) -> str | None:
    if trust_type == "app-owner" and target_name:
        return (
            "Remove the ownership path that lets the source control application "
            f"'{target_name}'."
        )

    if trust_type == "service-principal-owner":
        return (
            "Remove the owner-level control path over "
            f"{_identity_ref(target_name, 'unknown', target_type)}."
        )

    if trust_type == "federated-credential" and source_name:
        return f"Remove or tighten the federated credential on application '{source_name}'."

    if trust_type == "app-to-service-principal" and source_name and target_name:
        return (
            f"Remove the app-role assignment path from service principal '{source_name}' "
            f"to '{target_name}'."
        )

    return None


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
