from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class _RoleTrustHintContext:
    source_name: str | None = None
    source_type: str = "ServicePrincipal"
    source_object_id: str = "unknown"
    target_name: str | None = None
    target_type: str = "ServicePrincipal"
    target_object_id: str = "unknown"
    backing_service_principal_name: str | None = None
    summary: str = ""
    next_review: str = ""


ControlledObjectResolver = Callable[
    [_RoleTrustHintContext], tuple[str | None, str | None]
]
TextResolver = Callable[[_RoleTrustHintContext], str | None]
RequiredTextResolver = Callable[[_RoleTrustHintContext], str]


@dataclass(frozen=True)
class _RoleTrustStrategy:
    control_primitive: str | None
    controlled_object: ControlledObjectResolver
    escalation_mechanism: TextResolver
    usable_identity_result: TextResolver
    defender_cut_point: TextResolver
    operator_signal: str
    next_review_hint: RequiredTextResolver
    summary_suffix: RequiredTextResolver


def role_trust_control_primitive(
    *,
    trust_type: str,
    target_type: str,
) -> str | None:
    del target_type
    strategy = _role_trust_strategy(trust_type)
    if strategy is None:
        return None
    return strategy.control_primitive


def role_trust_controlled_object(
    *,
    trust_type: str,
    source_name: str | None,
    source_type: str,
    target_name: str | None,
    target_type: str,
) -> tuple[str | None, str | None]:
    strategy = _role_trust_strategy(trust_type)
    if strategy is None:
        return target_type, target_name
    context = _RoleTrustHintContext(
        source_name=source_name,
        source_type=source_type,
        target_name=target_name,
        target_type=target_type,
    )
    return strategy.controlled_object(context)


def role_trust_escalation_mechanism(
    *,
    trust_type: str,
    source_name: str | None,
    target_name: str | None,
    target_type: str,
    backing_service_principal_name: str | None = None,
) -> str | None:
    strategy = _role_trust_strategy(trust_type)
    if strategy is None:
        return None
    context = _RoleTrustHintContext(
        source_name=source_name,
        target_name=target_name,
        target_type=target_type,
        backing_service_principal_name=backing_service_principal_name,
    )
    return strategy.escalation_mechanism(context)


def role_trust_usable_identity_result(
    *,
    trust_type: str,
    source_name: str | None,
    target_name: str | None,
    target_type: str,
    backing_service_principal_name: str | None = None,
) -> str | None:
    strategy = _role_trust_strategy(trust_type)
    if strategy is None:
        return None
    context = _RoleTrustHintContext(
        source_name=source_name,
        target_name=target_name,
        target_type=target_type,
        backing_service_principal_name=backing_service_principal_name,
    )
    return strategy.usable_identity_result(context)


def role_trust_defender_cut_point(
    *,
    trust_type: str,
    source_name: str | None,
    target_name: str | None,
    target_type: str,
) -> str | None:
    strategy = _role_trust_strategy(trust_type)
    if strategy is None:
        return None
    context = _RoleTrustHintContext(
        source_name=source_name,
        target_name=target_name,
        target_type=target_type,
    )
    return strategy.defender_cut_point(context)


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
    strategy = _role_trust_strategy(trust_type)
    if strategy is None:
        return "Indirect control visible; privilege confirmation next."
    return strategy.operator_signal


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

    strategy = _role_trust_strategy(trust_type)
    if strategy is None:
        return (
            "Check permissions or rbac to confirm whether this trust edge reaches meaningful "
            "Azure control."
        )
    context = _RoleTrustHintContext(
        source_name=source_name,
        source_object_id=source_object_id,
        target_name=target_name,
        target_object_id=target_object_id,
        target_type=target_type,
        summary=summary,
    )
    return strategy.next_review_hint(context)


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

    strategy = _role_trust_strategy(trust_type)
    if strategy is None:
        return f"{summary} {next_review}"
    context = _RoleTrustHintContext(summary=summary, next_review=next_review)
    return strategy.summary_suffix(context)


def _role_trust_strategy(trust_type: str) -> _RoleTrustStrategy | None:
    return _ROLE_TRUST_STRATEGIES.get(trust_type)


def _default_controlled_object(
    context: _RoleTrustHintContext,
) -> tuple[str | None, str | None]:
    return context.target_type, context.target_name


def _federated_controlled_object(
    context: _RoleTrustHintContext,
) -> tuple[str | None, str | None]:
    return context.source_type or "Application", context.source_name


def _app_owner_escalation_mechanism(context: _RoleTrustHintContext) -> str:
    app_name = context.target_name or "unknown application"
    if context.backing_service_principal_name:
        return (
            f"Control of application '{app_name}' could change authentication material "
            f"that makes service principal '{context.backing_service_principal_name}' usable."
        )
    return (
        f"Control of application '{app_name}' could change authentication material Azure "
        "accepts for identities backed by that application."
    )


def _service_principal_owner_escalation_mechanism(
    context: _RoleTrustHintContext,
) -> str:
    principal = _identity_ref(context.target_name, "unknown", context.target_type)
    return (
        f"Owner-level control over {principal} could add or replace authentication material "
        f"Azure accepts for {principal}."
    )


def _federated_credential_escalation_mechanism(
    context: _RoleTrustHintContext,
) -> str:
    app_name = context.source_name or "unknown application"
    if context.target_type == "ServicePrincipal" and context.target_name:
        return (
            f"Application '{app_name}' already has federated trust that can yield "
            f"service principal '{context.target_name}' access."
        )
    return f"Application '{app_name}' already has a federated trust path."


def _app_to_service_principal_escalation_mechanism(
    context: _RoleTrustHintContext,
) -> str:
    source = context.source_name or "unknown service principal"
    target = context.target_name or "unknown service principal"
    return (
        f"Service principal '{source}' already holds an application-permission path into "
        f"service principal '{target}'."
    )


def _app_owner_usable_identity_result(
    context: _RoleTrustHintContext,
) -> str | None:
    if context.target_name and context.backing_service_principal_name:
        return (
            f"Control of application '{context.target_name}' could make service principal "
            f"'{context.backing_service_principal_name}' usable."
        )
    return None


def _service_principal_owner_usable_identity_result(
    context: _RoleTrustHintContext,
) -> str:
    principal = _identity_ref(context.target_name, "unknown", context.target_type)
    return f"That could make {principal} usable."


def _federated_credential_usable_identity_result(
    context: _RoleTrustHintContext,
) -> str | None:
    if context.target_type == "ServicePrincipal" and context.target_name:
        return (
            f"Federated sign-in can yield service principal '{context.target_name}' access."
        )
    return None


def _app_to_service_principal_usable_identity_result(
    context: _RoleTrustHintContext,
) -> str | None:
    if context.source_name and context.target_name:
        return (
            f"Service principal '{context.source_name}' already has application-permission "
            f"reach to '{context.target_name}'."
        )
    return None


def _app_owner_defender_cut_point(context: _RoleTrustHintContext) -> str | None:
    if not context.target_name:
        return None
    return (
        "Remove the ownership path that lets the source control application "
        f"'{context.target_name}'."
    )


def _service_principal_owner_defender_cut_point(
    context: _RoleTrustHintContext,
) -> str:
    return (
        "Remove the owner-level control path over "
        f"{_identity_ref(context.target_name, 'unknown', context.target_type)}."
    )


def _federated_credential_defender_cut_point(
    context: _RoleTrustHintContext,
) -> str | None:
    if not context.source_name:
        return None
    return (
        f"Remove or tighten the federated credential on application "
        f"'{context.source_name}'."
    )


def _app_to_service_principal_defender_cut_point(
    context: _RoleTrustHintContext,
) -> str | None:
    if not context.source_name or not context.target_name:
        return None
    return (
        f"Remove the app-role assignment path from service principal "
        f"'{context.source_name}' to '{context.target_name}'."
    )


def _app_owner_next_review_hint(context: _RoleTrustHintContext) -> str:
    return (
        f"Review ownership around "
        f"{_identity_ref(context.target_name, context.target_object_id, context.target_type)}; "
        "if it backs an Azure-facing identity, confirm that identity in permissions."
    )


def _identity_permissions_next_review_hint(context: _RoleTrustHintContext) -> str:
    return (
        "Check permissions for Azure control on "
        f"{_identity_ref(context.target_name, context.target_object_id, context.target_type)}."
    )


def _federated_credential_next_review_hint(context: _RoleTrustHintContext) -> str:
    if context.target_type == "ServicePrincipal":
        return _identity_permissions_next_review_hint(context)
    return (
        "Check permissions for the backing identity behind "
        f"{_identity_ref(context.target_name, context.target_object_id, context.target_type)}."
    )


def _app_to_service_principal_next_review_hint(
    context: _RoleTrustHintContext,
) -> str:
    return (
        "Check permissions for Azure control on "
        f"{_identity_ref(context.source_name, context.source_object_id, 'ServicePrincipal')}."
    )


def _app_owner_summary(context: _RoleTrustHintContext) -> str:
    return (
        f"{context.summary} This is an indirect-control row: ownership is the visible trust "
        f"path, not direct Azure privilege by itself. {context.next_review}"
    )


def _service_principal_owner_summary(context: _RoleTrustHintContext) -> str:
    return (
        f"{context.summary} This row shows a service-principal takeover path rather than "
        f"direct Azure privilege by itself. {context.next_review}"
    )


def _federated_credential_summary(context: _RoleTrustHintContext) -> str:
    return (
        f"{context.summary} This row shows trust expansion into the target identity rather "
        f"than direct Azure privilege by itself. {context.next_review}"
    )


def _app_to_service_principal_summary(context: _RoleTrustHintContext) -> str:
    return (
        f"{context.summary} This row is a trust-edge and application-permission cue; confirm "
        f"whether the same identity also holds Azure control. {context.next_review}"
    )


_ROLE_TRUST_STRATEGIES: dict[str, _RoleTrustStrategy] = {
    "app-owner": _RoleTrustStrategy(
        control_primitive="change-auth-material",
        controlled_object=_default_controlled_object,
        escalation_mechanism=_app_owner_escalation_mechanism,
        usable_identity_result=_app_owner_usable_identity_result,
        defender_cut_point=_app_owner_defender_cut_point,
        operator_signal="Indirect control visible; ownership review next.",
        next_review_hint=_app_owner_next_review_hint,
        summary_suffix=_app_owner_summary,
    ),
    "service-principal-owner": _RoleTrustStrategy(
        control_primitive="owner-control",
        controlled_object=_default_controlled_object,
        escalation_mechanism=_service_principal_owner_escalation_mechanism,
        usable_identity_result=_service_principal_owner_usable_identity_result,
        defender_cut_point=_service_principal_owner_defender_cut_point,
        operator_signal="Trust expansion visible; privilege confirmation next.",
        next_review_hint=_identity_permissions_next_review_hint,
        summary_suffix=_service_principal_owner_summary,
    ),
    "federated-credential": _RoleTrustStrategy(
        control_primitive="existing-federated-credential",
        controlled_object=_federated_controlled_object,
        escalation_mechanism=_federated_credential_escalation_mechanism,
        usable_identity_result=_federated_credential_usable_identity_result,
        defender_cut_point=_federated_credential_defender_cut_point,
        operator_signal="Trust expansion visible; privilege confirmation next.",
        next_review_hint=_federated_credential_next_review_hint,
        summary_suffix=_federated_credential_summary,
    ),
    "app-to-service-principal": _RoleTrustStrategy(
        control_primitive="existing-app-role-assignment",
        controlled_object=_default_controlled_object,
        escalation_mechanism=_app_to_service_principal_escalation_mechanism,
        usable_identity_result=_app_to_service_principal_usable_identity_result,
        defender_cut_point=_app_to_service_principal_defender_cut_point,
        operator_signal="Trust expansion visible; privilege confirmation next.",
        next_review_hint=_app_to_service_principal_next_review_hint,
        summary_suffix=_app_to_service_principal_summary,
    ),
}


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
