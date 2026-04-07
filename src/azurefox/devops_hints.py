from __future__ import annotations


def devops_next_review_hint(
    *,
    target_clues: list[str],
    key_vault_names: list[str],
    key_vault_group_names: list[str],
    azure_service_connection_names: list[str],
    partial_read: bool,
    current_operator_can_queue: bool | None = None,
    current_operator_can_edit: bool | None = None,
    current_operator_can_contribute_source: bool | None = None,
    current_operator_injection_surface_types: list[str] | None = None,
    primary_trusted_input_type: str | None = None,
    primary_trusted_input_ref: str | None = None,
    primary_injection_surface: str | None = None,
    primary_trusted_input_access_state: str | None = None,
    repository_host_type: str | None = None,
    source_visibility_state: str | None = None,
) -> str:
    if partial_read:
        return (
            "Restore service-connection or variable-group visibility before choosing the next "
            "Azure follow-up."
        )

    primary_target = _primary_target_command(target_clues)
    has_key_vault_support = bool(key_vault_names or key_vault_group_names)
    has_azure_control_path = bool(azure_service_connection_names)
    prefix = _current_operator_prefix(
        current_operator_can_queue=current_operator_can_queue,
        current_operator_can_edit=current_operator_can_edit,
        current_operator_can_contribute_source=current_operator_can_contribute_source,
        current_operator_injection_surface_types=current_operator_injection_surface_types or [],
        primary_trusted_input_type=primary_trusted_input_type,
        primary_trusted_input_ref=primary_trusted_input_ref,
        primary_injection_surface=primary_injection_surface,
        primary_trusted_input_access_state=primary_trusted_input_access_state,
    )
    repo_prefix = _source_visibility_prefix(
        repository_host_type=repository_host_type,
        source_visibility_state=source_visibility_state,
    )

    if primary_target and has_key_vault_support and has_azure_control_path:
        hint = (
            f"Check {primary_target} for the named deployment target; review permissions and "
            "role-trusts for Azure control; review keyvault for the vault-backed support."
        )
        return _join_hint_prefixes(prefix, repo_prefix, hint)
    if primary_target and has_azure_control_path:
        hint = (
            f"Check {primary_target} for the named deployment target; review permissions and "
            "role-trusts for Azure control."
        )
        return _join_hint_prefixes(prefix, repo_prefix, hint)
    if primary_target:
        return _join_hint_prefixes(
            prefix,
            repo_prefix,
            f"Check {primary_target} for the named deployment target.",
        )
    if has_key_vault_support and has_azure_control_path:
        hint = (
            "Check keyvault for the vault-backed support behind this deployment path; review "
            "permissions and role-trusts for Azure control."
        )
        return _join_hint_prefixes(prefix, repo_prefix, hint)
    if has_key_vault_support:
        return _join_hint_prefixes(
            prefix,
            repo_prefix,
            "Check keyvault for the vault-backed support behind this deployment path.",
        )
    if has_azure_control_path:
        hint = (
            "Check permissions and role-trusts for the Azure control path behind this "
            "service connection."
        )
        return _join_hint_prefixes(prefix, repo_prefix, hint)
    return _join_hint_prefixes(
        prefix,
        repo_prefix,
        "Review the definition directly to confirm the next Azure target.",
    )


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


def _current_operator_prefix(
    *,
    current_operator_can_queue: bool | None,
    current_operator_can_edit: bool | None,
    current_operator_can_contribute_source: bool | None,
    current_operator_injection_surface_types: list[str],
    primary_trusted_input_type: str | None,
    primary_trusted_input_ref: str | None,
    primary_injection_surface: str | None,
    primary_trusted_input_access_state: str | None,
) -> str:
    trusted_input = describe_trusted_input(
        input_type=primary_trusted_input_type,
        ref=primary_trusted_input_ref,
    )
    if primary_trusted_input_access_state == "write" and primary_injection_surface:
        return (
            f"Current credentials can poison {primary_injection_surface} through "
            f"{trusted_input}."
        )
    if current_operator_injection_surface_types:
        surfaces = ", ".join(current_operator_injection_surface_types)
        return f"Current credentials can inject through {surfaces}."
    if primary_trusted_input_access_state == "read":
        if primary_trusted_input_type == "pipeline-artifact":
            return (
                f"This path trusts {trusted_input}, and current credentials can inspect the "
                "upstream producer path but Azure DevOps evidence here does not prove "
                "producer-side control."
            )
        return (
            f"This path trusts {trusted_input}, and current credentials can read it but not "
            "write it from Azure DevOps evidence here."
        )
    if primary_trusted_input_access_state == "exists-only":
        missing_proof = _trusted_input_missing_proof(primary_trusted_input_type)
        if missing_proof:
            return (
                f"This path trusts {trusted_input}, but current evidence only shows that it "
                f"exists; AzureFox has not yet proven {missing_proof}."
            )
        return f"This path trusts {trusted_input}, but current evidence only shows that it exists."
    if current_operator_can_queue:
        return (
            "Current credentials can queue this pipeline, but AzureFox has not yet proven a "
            "poisonable trusted input."
        )
    if current_operator_can_edit or current_operator_can_contribute_source:
        return (
            "Current credentials can change part of this path, but AzureFox has not yet proven "
            "which trusted input becomes attacker-controlled."
        )
    return ""


def _source_visibility_prefix(
    *,
    repository_host_type: str | None,
    source_visibility_state: str | None,
) -> str:
    if repository_host_type == "azure-repos" and source_visibility_state == "inferred-only":
        return "Azure Repos source is only inferred from the pipeline definition right now."
    if source_visibility_state == "external-reference":
        return "Source appears external to Azure DevOps, so current repo access is not proven here."
    return ""


def _join_hint_prefixes(*parts: str) -> str:
    return " ".join(part.strip() for part in parts if part.strip())


def _trusted_input_missing_proof(input_type: str | None) -> str | None:
    return {
        "package-feed": "the current operator's Azure Artifacts feed role",
        "pipeline-artifact": (
            "control of the upstream producer definition, run path, or producer-side trusted "
            "inputs"
        ),
        "template-repository": "read or contribute rights on the referenced template repo",
        "repository": "read or contribute rights on the referenced repo",
        "secure-file": (
            "whether current credentials only see the file, can use it, or can administer it"
        ),
    }.get(str(input_type or ""))


def describe_trusted_input(*, input_type: str | None, ref: str | None) -> str:
    if not ref:
        return "a trusted input"
    inferred_type = input_type
    if inferred_type is None and ":" in ref:
        prefix = ref.split(":", 1)[0]
        if prefix in {
            "repository",
            "package-feed",
            "pipeline-artifact",
            "template-repository",
            "external-url",
            "registry-image",
            "secure-file",
        }:
            inferred_type = prefix
            ref = ref.split(":", 1)[1]
    elif inferred_type and ref.startswith(f"{inferred_type}:"):
        ref = ref.split(":", 1)[1]

    labels = {
        "repository": "repository",
        "package-feed": "package feed",
        "pipeline-artifact": "pipeline artifact",
        "template-repository": "template repository",
        "external-url": "external download",
        "registry-image": "registry image",
        "secure-file": "secure file",
    }
    label = labels.get(inferred_type or "", "trusted input")
    return f"{label} {ref}".strip()
