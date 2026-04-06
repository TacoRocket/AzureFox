from __future__ import annotations


def tokens_credential_next_review_hint(
    *,
    surface_type: str,
    access_path: str,
    operator_signal: str,
) -> str:
    if surface_type == "plain-text-secret":
        return "Check env-vars for the exact setting context behind this credential clue."

    if surface_type == "managed-identity-token":
        public_ip = _signal_value(operator_signal, "public-ip")
        if access_path == "imds" and public_ip and public_ip != "none":
            return (
                "Check endpoints for the ingress path, then managed-identities and permissions "
                "for Azure control."
            )
        return "Check managed-identities for the identity path, then permissions for Azure control."

    if surface_type == "keyvault-reference":
        identity = _signal_value(operator_signal, "identity")
        if identity:
            return (
                "Check keyvault for the referenced secret boundary, then managed-identities for "
                "the backing workload identity."
            )
        return "Check keyvault for the referenced secret boundary."

    if surface_type == "deployment-output":
        return "Check arm-deployments for the exact output context behind this credential clue."

    if surface_type == "linked-deployment-content":
        return (
            "Check arm-deployments for the linked template or parameter path behind this "
            "credential clue."
        )

    return "Review the surfaced workload context before deeper follow-up."


def _signal_value(signal: str, key: str) -> str | None:
    prefix = f"{key}="
    for part in signal.split(";"):
        value = part.strip()
        if value.startswith(prefix):
            candidate = value[len(prefix) :].strip()
            return candidate or None
    return None
