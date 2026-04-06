from __future__ import annotations


def managed_identity_operator_signal(
    *,
    attachment_kind: str | None,
    exposed: bool,
    privileged: bool,
    visibility_blocked: bool,
    attachment_count: int,
) -> str:
    pivot = _pivot_label(attachment_kind, exposed)
    if visibility_blocked:
        control = "visibility blocked"
    elif privileged:
        control = "direct control visible"
    else:
        control = "direct control not confirmed"

    if attachment_count > 1:
        return f"{pivot}; {control}; reused across {attachment_count} workloads."
    return f"{pivot}; {control}."


def managed_identity_next_review_hint(
    *,
    attachment_kind: str | None,
    privileged: bool,
    visibility_blocked: bool,
) -> str:
    if attachment_kind in {"AppService", "FunctionApp", "WebWorkload"}:
        if visibility_blocked:
            return (
                "Check env-vars for the backing workload context; current scope does not yet "
                "show direct control on this identity."
            )
        if privileged:
            return (
                "Check permissions for direct control on this identity, then env-vars for "
                "secret-bearing config on the same workload."
            )
        return (
            "Check env-vars for secret-bearing config on this workload, then permissions to "
            "confirm direct control."
        )

    if attachment_kind == "VM":
        if visibility_blocked:
            return (
                "Check vms for the host context behind this workload pivot; current scope does "
                "not yet show direct control on this identity."
            )
        if privileged:
            return (
                "Check permissions for direct control on this identity, then vms for the host "
                "context behind the workload pivot."
            )
        return (
            "Check vms for the host context behind this workload pivot, then permissions to "
            "confirm direct control."
        )

    if attachment_kind == "VMSS":
        if visibility_blocked:
            return (
                "Check vmss for the fleet context behind this workload pivot; current scope does "
                "not yet show direct control on this identity."
            )
        if privileged:
            return (
                "Check permissions for direct control on this identity, then vmss for the fleet "
                "context behind the workload pivot."
            )
        return (
            "Check vmss for the fleet context behind this workload pivot, then permissions to "
            "confirm direct control."
        )

    if visibility_blocked:
        return (
            "Review the attached workload context first; current scope does not yet show direct "
            "control on this identity."
        )
    if privileged:
        return "Check permissions for direct control on this identity."
    return "Check permissions to confirm whether this workload pivot becomes direct control."


def managed_identity_summary(
    *,
    identity_name: str,
    attachment_name: str | None,
    attachment_kind: str | None,
    exposed: bool,
    privileged_roles: list[str],
    visibility_blocked: bool,
    next_review: str,
    attachment_count: int,
) -> str:
    subject = _attachment_subject(attachment_kind, attachment_name)
    exposure = "public " if exposed else ""
    repeated = (
        f" Identity reuse across {attachment_count} workloads broadens the pivot surface."
        if attachment_count > 1
        else ""
    )

    if visibility_blocked:
        return (
            f"{subject} gives a {exposure}workload pivot into managed identity "
            f"'{identity_name}', but current scope does not show the backing principal cleanly."
            f"{repeated} {next_review}"
        )

    if privileged_roles:
        role_text = ", ".join(privileged_roles)
        return (
            f"{subject} gives a {exposure}workload pivot into managed identity "
            f"'{identity_name}'. Current scope already shows direct control through high-impact "
            f"roles ({role_text}).{repeated} {next_review}"
        )

    return (
        f"{subject} gives a {exposure}workload pivot into managed identity '{identity_name}'. "
        f"Current scope does not confirm direct control.{repeated} {next_review}"
    )


def _pivot_label(attachment_kind: str | None, exposed: bool) -> str:
    labels = {
        "AppService": "App Service workload pivot",
        "FunctionApp": "Function App workload pivot",
        "WebWorkload": "Web workload pivot",
        "VM": "VM workload pivot",
        "VMSS": "VMSS workload pivot",
    }
    base = labels.get(attachment_kind, "Workload pivot")
    if not exposed:
        return base
    if base.startswith("App Service"):
        return "Public App Service workload pivot"
    if base.startswith("Function App"):
        return "Public Function App workload pivot"
    if base.startswith("Web workload"):
        return "Public web workload pivot"
    if base.startswith("VM workload"):
        return "Public VM workload pivot"
    if base.startswith("VMSS workload"):
        return "Exposed VMSS workload pivot"
    return f"Exposed {base[0].lower() + base[1:]}"


def _attachment_subject(attachment_kind: str | None, attachment_name: str | None) -> str:
    kind_labels = {
        "AppService": "App Service",
        "FunctionApp": "Function App",
        "WebWorkload": "Web workload",
        "VM": "VM",
        "VMSS": "VMSS",
    }
    label = kind_labels.get(attachment_kind, "Attached workload")
    if attachment_name:
        return f"{label} '{attachment_name}'"
    return label
