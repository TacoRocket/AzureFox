from __future__ import annotations


def devops_next_review_hint(
    *,
    target_clues: list[str],
    key_vault_names: list[str],
    key_vault_group_names: list[str],
    azure_service_connection_names: list[str],
    partial_read: bool,
) -> str:
    if partial_read:
        return (
            "Restore service-connection or variable-group visibility before choosing the next "
            "Azure follow-up."
        )

    primary_target = _primary_target_command(target_clues)
    has_key_vault_support = bool(key_vault_names or key_vault_group_names)
    has_azure_control_path = bool(azure_service_connection_names)

    if primary_target and has_key_vault_support and has_azure_control_path:
        return (
            f"Check {primary_target} for the named deployment target; review permissions and "
            "role-trusts for Azure control; review keyvault for the vault-backed support."
        )
    if primary_target and has_azure_control_path:
        return (
            f"Check {primary_target} for the named deployment target; review permissions and "
            "role-trusts for Azure control."
        )
    if primary_target:
        return f"Check {primary_target} for the named deployment target."
    if has_key_vault_support and has_azure_control_path:
        return (
            "Check keyvault for the vault-backed support behind this deployment path; review "
            "permissions and role-trusts for Azure control."
        )
    if has_key_vault_support:
        return "Check keyvault for the vault-backed support behind this deployment path."
    if has_azure_control_path:
        return (
            "Check permissions and role-trusts for the Azure control path behind this "
            "service connection."
        )
    return "Review the definition directly to confirm the next Azure target."


def _primary_target_command(target_clues: list[str]) -> str | None:
    clue_to_command = {
        "AKS/Kubernetes": "aks",
        "App Service": "app-services",
        "Functions": "functions",
        "ARM/Bicep/Terraform": "arm-deployments",
        "ACR/Containers": "acr",
    }
    for clue in target_clues:
        command = clue_to_command.get(clue)
        if command:
            return command
    return None
