from __future__ import annotations


def env_var_next_review_hint(
    *,
    setting_name: str,
    value_type: str,
    looks_sensitive: bool,
    reference_target: str | None,
    workload_identity_type: str | None,
) -> str:
    target_service = env_var_target_service(setting_name)
    has_identity = bool(workload_identity_type)

    if value_type == "keyvault-ref":
        if has_identity:
            return (
                "Check keyvault for the referenced secret path; review managed-identities for "
                "the workload token path."
            )
        return "Check keyvault for the referenced secret path."

    if looks_sensitive and value_type == "plain-text":
        if target_service == "storage":
            return (
                "Check tokens-credentials first; this likely feeds a storage credential path."
            )
        if target_service == "database":
            return (
                "Check tokens-credentials first; this likely feeds a database credential path."
            )
        return "Check tokens-credentials for the workload credential surface."

    if target_service == "storage":
        if has_identity:
            return (
                "Check tokens-credentials for the config-backed access path, then "
                "managed-identities for the workload token path."
            )
        return "Check tokens-credentials for the config-backed storage access path."

    if target_service == "database":
        return "Check tokens-credentials for the config-backed database access path."

    if reference_target and "vault" in reference_target.lower():
        return "Check keyvault for the referenced secret path."

    if has_identity:
        return "Check managed-identities for the workload token path behind this setting."

    return "Review the workload config directly before deeper follow-up."


def env_var_target_service(setting_name: str) -> str | None:
    services = env_var_target_services(setting_name)
    return services[0] if services else None


def env_var_target_services(setting_name: str) -> tuple[str, ...]:
    lowered = setting_name.lower()
    matches: list[str] = []

    if lowered == "azurewebjobsstorage":
        matches.append("storage")
    if any(
        token in lowered
        for token in ("storage", "blob", "queue", "table", "share", "file", "container")
    ):
        matches.append("storage")
    if any(token in lowered for token in ("db", "database", "sql", "mysql", "postgres")):
        matches.append("database")
    return tuple(dict.fromkeys(matches))
