from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from azurefox.chains.deployment_path import (
    DeploymentSourceAssessment,
    admit_deployment_path_row,
    assess_deployment_source,
    target_family_hints_from_arm_deployment,
)
from azurefox.chains.registry import (
    GROUPED_COMMAND_NAME,
    PREFERRED_ARTIFACT_ORDER,
    get_chain_family_spec,
)
from azurefox.chains.semantics import (
    ChainSemanticContext,
    evaluate_chain_semantics,
    semantic_priority_sort_value,
)
from azurefox.collectors.provider import BaseProvider
from azurefox.config import GlobalOptions
from azurefox.devops_hints import describe_trusted_input
from azurefox.env_var_hints import env_var_target_service
from azurefox.models.chains import (
    ChainPathRecord,
    ChainSourceArtifact,
    ChainsOutput,
)
from azurefox.models.commands import (
    AksOutput,
    AppServicesOutput,
    ArmDeploymentsOutput,
    AutomationOutput,
    ChainsCommandOutput,
    DatabasesOutput,
    DevopsOutput,
    EnvVarsOutput,
    FunctionsOutput,
    KeyVaultOutput,
    StorageOutput,
    TokensCredentialsOutput,
)
from azurefox.models.common import ArmDeploymentSummary, CollectionIssue, CommandMetadata
from azurefox.output.writer import emit_output
from azurefox.registry import get_command_specs

_SUPPORTED_IMPLEMENTED_FAMILIES = {"credential-path", "deployment-path"}
_SOURCE_MODEL_MAP = {
    "aks": AksOutput,
    "app-services": AppServicesOutput,
    "arm-deployments": ArmDeploymentsOutput,
    "automation": AutomationOutput,
    "devops": DevopsOutput,
    "env-vars": EnvVarsOutput,
    "functions": FunctionsOutput,
    "tokens-credentials": TokensCredentialsOutput,
    "databases": DatabasesOutput,
    "storage": StorageOutput,
    "keyvault": KeyVaultOutput,
}
_CANDIDATE_LIMIT = 3
_JOIN_QUALITY_ORDER = {
    "named match": 0,
    "narrowed candidates": 1,
    "tenant-wide candidates": 2,
    "visibility blocked": 3,
    "service hint only": 4,
    "named target not visible": 5,
}
_DEPLOYMENT_TARGET_SPECS = {
    "aks": {
        "command": "aks",
        "label": "AKS cluster",
        "service": "aks",
        "collection_key": "aks_clusters",
    },
    "app-services": {
        "command": "app-services",
        "label": "App Service",
        "service": "app-service",
        "collection_key": "app_services",
    },
    "functions": {
        "command": "functions",
        "label": "Function App",
        "service": "function-app",
        "collection_key": "function_apps",
    },
    "arm-deployments": {
        "command": "arm-deployments",
        "label": "ARM deployment",
        "service": "arm-deployment",
        "collection_key": "deployments",
    },
}


def implemented_chain_families() -> tuple[str, ...]:
    return tuple(sorted(_SUPPORTED_IMPLEMENTED_FAMILIES))


def run_chain_family(
    provider: BaseProvider,
    options: GlobalOptions,
    family_name: str,
) -> ChainsOutput:
    if family_name not in _SUPPORTED_IMPLEMENTED_FAMILIES:
        raise ValueError(f"Chain family '{family_name}' is not implemented yet")

    family = get_chain_family_spec(family_name)
    if family is None:
        raise ValueError(f"Unknown chain family '{family_name}'")

    source_artifacts = _collect_family_artifacts(provider, options, family_name)
    if family_name == "credential-path":
        return _build_credential_path_output(options, family_name, source_artifacts)
    if family_name == "deployment-path":
        return _build_deployment_path_output(options, family_name, source_artifacts)

    raise ValueError(f"Unsupported chain family '{family_name}'")


def _collect_family_artifacts(
    provider: BaseProvider,
    options: GlobalOptions,
    family_name: str,
) -> list[ChainSourceArtifact]:
    family = get_chain_family_spec(family_name)
    if family is None:
        raise ValueError(f"Unknown chain family '{family_name}'")

    collector_by_name = {spec.name: spec.collector for spec in get_command_specs()}
    source_artifacts: list[ChainSourceArtifact] = []

    for source in family.source_commands:
        collector = collector_by_name[source.command]
        model = collector(provider, options)
        artifact_paths = emit_output(source.command, model, options, emit_stdout=False)
        artifact_type, artifact_path = _preferred_artifact_for_command(artifact_paths)
        source_artifacts.append(
            ChainSourceArtifact(
                command=source.command,
                artifact_type=artifact_type,
                path=str(artifact_path),
            )
        )

    return source_artifacts


def _preferred_artifact_for_command(artifact_paths: dict[str, Path]) -> tuple[str, Path]:
    for artifact_type in PREFERRED_ARTIFACT_ORDER:
        path = artifact_paths.get(artifact_type)
        if path is not None:
            return artifact_type, path
    if artifact_paths:
        artifact_type, path = next(iter(artifact_paths.items()))
        return artifact_type, path
    raise ValueError("No artifacts were emitted for chain source command")


def _build_credential_path_output(
    options: GlobalOptions,
    family_name: str,
    source_artifacts: list[ChainSourceArtifact],
) -> ChainsCommandOutput:
    family = get_chain_family_spec(family_name)
    assert family is not None  # pragma: no cover - guarded above

    loaded = {source.command: _load_source_output(source) for source in source_artifacts}
    env_output = loaded["env-vars"]
    token_output = loaded["tokens-credentials"]
    database_output = loaded["databases"]
    storage_output = loaded["storage"]
    keyvault_output = loaded["keyvault"]
    target_visibility_notes = {
        "database": _target_visibility_note("database", getattr(database_output, "issues", [])),
        "storage": _target_visibility_note("storage", getattr(storage_output, "issues", [])),
        "keyvault": _target_visibility_note("Key Vault", getattr(keyvault_output, "issues", [])),
    }
    target_visibility_issues = {
        "database": _target_visibility_issue(getattr(database_output, "issues", [])),
        "storage": _target_visibility_issue(getattr(storage_output, "issues", [])),
        "keyvault": _target_visibility_issue(getattr(keyvault_output, "issues", [])),
    }

    token_setting_index: dict[tuple[str, str], list[dict]] = defaultdict(list)
    keyvault_surface_index: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for surface in token_output.surfaces:
        signal = _parse_operator_signal(surface.operator_signal)
        setting_name = signal.get("setting")
        if setting_name:
            token_setting_index[(surface.asset_id, setting_name.lower())].append(
                surface.model_dump(mode="json")
            )
        target = signal.get("target")
        if target:
            keyvault_surface_index[(surface.asset_id, _normalize_reference_target(target))].append(
                surface.model_dump(mode="json")
            )

    database_candidates = [
        item.model_dump(mode="json") for item in database_output.database_servers
    ]
    storage_candidates = [item.model_dump(mode="json") for item in storage_output.storage_assets]
    keyvaults = [item.model_dump(mode="json") for item in keyvault_output.key_vaults]

    paths: list[ChainPathRecord] = []
    issues: list[CollectionIssue] = []

    for env_var in env_output.env_vars:
        env = env_var.model_dump(mode="json")
        setting_key = (env["asset_id"], env["setting_name"].lower())
        joined_surfaces = list(token_setting_index.get(setting_key, []))

        if env.get("value_type") == "keyvault-ref":
            if env.get("reference_target"):
                joined_surfaces.extend(
                    keyvault_surface_index.get(
                        (env["asset_id"], _normalize_reference_target(env["reference_target"])),
                        [],
                    )
                )
            record = _build_keyvault_record(
                family_name,
                env,
                joined_surfaces,
                keyvaults,
                visibility_note=target_visibility_notes["keyvault"],
            )
            if record is not None:
                paths.append(record)
            continue

        if not _is_credential_like_env_var(env, joined_surfaces):
            continue

        target_service = _target_service_for_env_var(env)
        if target_service == "database":
            paths.append(
                _build_candidate_record(
                    family_name,
                    env,
                    joined_surfaces,
                    target_service,
                    database_candidates,
                    visibility_note=target_visibility_notes["database"],
                    visibility_issue=target_visibility_issues["database"],
                )
            )
        elif target_service == "storage":
            paths.append(
                _build_candidate_record(
                    family_name,
                    env,
                    joined_surfaces,
                    target_service,
                    storage_candidates,
                    visibility_note=target_visibility_notes["storage"],
                    visibility_issue=target_visibility_issues["storage"],
                )
            )

    paths.sort(
        key=lambda item: (
            semantic_priority_sort_value(item.priority),
            _JOIN_QUALITY_ORDER.get(item.target_resolution, 9),
            item.asset_name,
            item.setting_name,
            item.target_service,
        )
    )

    for source_name in ("env-vars", "tokens-credentials", "databases", "storage", "keyvault"):
        issues.extend(getattr(loaded[source_name], "issues", []))

    return ChainsCommandOutput(
        metadata=CommandMetadata(
            command=GROUPED_COMMAND_NAME,
            tenant_id=options.tenant,
            subscription_id=options.subscription,
            devops_organization=options.devops_organization,
            token_source=None,
        ),
        grouped_command_name=GROUPED_COMMAND_NAME,
        family=family_name,
        input_mode="live",
        command_state="extraction-only",
        summary=family.summary,
        claim_boundary=family.allowed_claim,
        artifact_preference_order=list(PREFERRED_ARTIFACT_ORDER),
        backing_commands=[source.command for source in family.source_commands],
        source_artifacts=source_artifacts,
        paths=paths,
        issues=issues,
    )


def _build_deployment_path_output(
    options: GlobalOptions,
    family_name: str,
    source_artifacts: list[ChainSourceArtifact],
) -> ChainsCommandOutput:
    family = get_chain_family_spec(family_name)
    assert family is not None  # pragma: no cover - guarded above

    loaded = {source.command: _load_source_output(source) for source in source_artifacts}
    devops_output = loaded["devops"]
    automation_output = loaded["automation"]
    arm_output = loaded["arm-deployments"]
    app_services_output = loaded["app-services"]
    functions_output = loaded["functions"]
    aks_output = loaded["aks"]

    target_candidates = {
        command_name: [
            item.model_dump(mode="json")
            for item in getattr(output, _DEPLOYMENT_TARGET_SPECS[command_name]["collection_key"])
        ]
        for command_name, output in (
            ("aks", aks_output),
            ("app-services", app_services_output),
            ("functions", functions_output),
            ("arm-deployments", arm_output),
        )
    }
    target_visibility_notes = {
        "aks": _target_visibility_note("AKS", getattr(aks_output, "issues", [])),
        "app-services": _target_visibility_note(
            "App Service", getattr(app_services_output, "issues", [])
        ),
        "functions": _target_visibility_note(
            "Function App", getattr(functions_output, "issues", [])
        ),
        "arm-deployments": _target_visibility_note(
            "ARM deployment", getattr(arm_output, "issues", [])
        ),
    }
    target_visibility_issues = {
        "aks": _target_visibility_issue(getattr(aks_output, "issues", [])),
        "app-services": _target_visibility_issue(getattr(app_services_output, "issues", [])),
        "functions": _target_visibility_issue(getattr(functions_output, "issues", [])),
        "arm-deployments": _target_visibility_issue(getattr(arm_output, "issues", [])),
    }
    arm_correlations = _arm_correlations_by_target_family(
        [item.model_dump(mode="json") for item in arm_output.deployments]
    )

    paths: list[ChainPathRecord] = []
    for pipeline in devops_output.pipelines:
        pipeline_dict = pipeline.model_dump(mode="json")
        assessment = assess_deployment_source(pipeline)
        for target_family in assessment.target_family_hints:
            target_spec = _DEPLOYMENT_TARGET_SPECS.get(target_family)
            if target_spec is None:
                continue
            exact_targets, confirmation_basis = _structured_deployment_target_matches(
                pipeline_dict,
                target_family,
                target_candidates[target_family],
            )
            record = _build_deployment_source_record(
                family_name,
                source=pipeline_dict,
                source_command="devops",
                source_context=pipeline.project_name,
                asset_kind="DevOpsPipeline",
                assessment=assessment,
                target_family=target_family,
                target_candidates=target_candidates[target_family],
                exact_targets=exact_targets,
                confirmation_basis=confirmation_basis,
                target_visibility_note=target_visibility_notes[target_family],
                target_visibility_issue=target_visibility_issues[target_family],
                supporting_deployments=arm_correlations.get(target_family, []),
            )
            if record is not None:
                paths.append(record)

    for account in automation_output.automation_accounts:
        account_dict = account.model_dump(mode="json")
        assessment = assess_deployment_source(account)
        if assessment.posture == "insufficient evidence":
            continue
        record = _build_deployment_source_record(
            family_name,
            source=account_dict,
            source_command="automation",
            source_context=account.identity_type,
            asset_kind="AutomationAccount",
            assessment=assessment,
            target_family="arm-deployments",
            target_candidates=[],
            exact_targets=[],
            confirmation_basis=None,
            target_visibility_note=target_visibility_notes["arm-deployments"],
            target_visibility_issue=(
                target_visibility_issues["arm-deployments"]
                or "current automation surface does not name downstream Azure targets"
            ),
            supporting_deployments=[],
        )
        if record is not None:
            paths.append(record)

    paths.sort(
        key=lambda item: (
            semantic_priority_sort_value(item.priority),
            _JOIN_QUALITY_ORDER.get(item.target_resolution, 9),
            item.asset_name,
            item.target_service,
            item.source_command or "",
        )
    )

    issues: list[CollectionIssue] = []
    for source_name in (
        "devops",
        "automation",
        "arm-deployments",
        "app-services",
        "functions",
        "aks",
    ):
        issues.extend(getattr(loaded[source_name], "issues", []))

    return ChainsCommandOutput(
        metadata=CommandMetadata(
            command=GROUPED_COMMAND_NAME,
            tenant_id=options.tenant,
            subscription_id=options.subscription,
            devops_organization=options.devops_organization,
            token_source=None,
        ),
        grouped_command_name=GROUPED_COMMAND_NAME,
        family=family_name,
        input_mode="live",
        command_state="extraction-only",
        summary=family.summary,
        claim_boundary=family.allowed_claim,
        artifact_preference_order=list(PREFERRED_ARTIFACT_ORDER),
        backing_commands=[source.command for source in family.source_commands],
        source_artifacts=source_artifacts,
        paths=paths,
        issues=issues,
    )


def _load_source_output(source: ChainSourceArtifact):
    model = _SOURCE_MODEL_MAP[source.command]
    payload = json.loads(Path(source.path).read_text(encoding="utf-8"))
    return model.model_validate(payload)


def _build_keyvault_record(
    family_name: str,
    env: dict,
    joined_surfaces: list[dict],
    keyvaults: list[dict],
    *,
    visibility_note: str | None = None,
) -> ChainPathRecord | None:
    reference_target = env.get("reference_target")
    if not reference_target:
        return None

    reference_host = _reference_host(reference_target)
    matched_vaults = [
        vault for vault in keyvaults if _reference_host(vault.get("vault_uri")) == reference_host
    ]
    target_names = [vault.get("name") for vault in matched_vaults if vault.get("name")]
    target_ids = [vault.get("id") for vault in matched_vaults if vault.get("id")]
    target_resolution = "named match" if matched_vaults else "named target not visible"
    visible_path = "Key Vault-backed setting -> named vault"
    summary = (
        f"{env['asset_kind']} '{env['asset_name']}' maps setting '{env['setting_name']}' to the "
        f"named Key Vault reference '{reference_host}'."
    )
    if matched_vaults:
        summary = (
            f"{summary} AzureFox can join that reference to visible Key Vault inventory: "
            f"{', '.join(target_names[:_CANDIDATE_LIMIT])}."
        )
    else:
        summary = (
            f"{summary} The current Key Vault inventory does not name a matching vault in the "
            "current artifacts."
        )
    if visibility_note:
        summary = f"{summary} {visibility_note}"

    related_ids = _merge_related_ids(
        env.get("related_ids", []),
        *[surface.get("related_ids", []) for surface in joined_surfaces],
        target_ids,
    )
    semantic = evaluate_chain_semantics(
        ChainSemanticContext(
            family=family_name,
            clue_type="keyvault-reference",
            target_service="keyvault",
            target_resolution=target_resolution,
            target_count=len(target_ids),
        )
    )

    return ChainPathRecord(
        chain_id=_chain_id(env["asset_id"], env["setting_name"], "keyvault"),
        asset_id=env["asset_id"],
        asset_name=env["asset_name"],
        asset_kind=env["asset_kind"],
        location=env.get("location"),
        setting_name=env["setting_name"],
        clue_type="keyvault-reference",
        confirmation_basis="normalized-uri-match" if matched_vaults else None,
        priority=semantic.priority,
        visible_path=visible_path,
        target_service="keyvault",
        target_resolution=target_resolution,
        evidence_commands=["env-vars", "tokens-credentials", "keyvault"],
        joined_surface_types=_joined_surface_types(joined_surfaces, fallback="keyvault-reference"),
        target_count=len(target_ids),
        target_ids=target_ids,
        target_names=target_names,
        target_visibility_issue=None,
        next_review=semantic.next_review,
        summary=summary,
        missing_confirmation=(
            "The named Key Vault dependency is visible, but current artifacts do not confirm "
            "secret read access, secret values, or successful downstream use."
        ),
        related_ids=related_ids,
    )


def _build_candidate_record(
    family_name: str,
    env: dict,
    joined_surfaces: list[dict],
    target_service: str,
    candidates: list[dict],
    *,
    visibility_note: str | None = None,
    visibility_issue: str | None = None,
) -> ChainPathRecord:
    scoped_candidates, target_resolution = _select_candidates_for_location(
        candidates,
        env.get("location"),
    )
    target_names = [item.get("name") for item in scoped_candidates if item.get("name")]
    target_ids = [item.get("id") for item in scoped_candidates if item.get("id")]
    if visibility_issue:
        target_names = []
        target_ids = []
        target_resolution = "visibility blocked"
    visible_path = f"Credential-like setting -> likely {target_service} path"
    summary = _candidate_summary(
        env=env,
        target_service=target_service,
        target_names=target_names,
        target_resolution=target_resolution,
        visibility_note=visibility_note,
    )
    semantic = evaluate_chain_semantics(
        ChainSemanticContext(
            family=family_name,
            clue_type="plain-text-secret",
            target_service=target_service,
            target_resolution=target_resolution,
            target_count=len(target_ids),
        )
    )

    return ChainPathRecord(
        chain_id=_chain_id(env["asset_id"], env["setting_name"], target_service),
        asset_id=env["asset_id"],
        asset_name=env["asset_name"],
        asset_kind=env["asset_kind"],
        location=env.get("location"),
        setting_name=env["setting_name"],
        clue_type="plain-text-secret",
        confirmation_basis="name-only-inference",
        priority=semantic.priority,
        visible_path=visible_path,
        target_service=target_service,
        target_resolution=target_resolution,
        evidence_commands=[
            "env-vars",
            "tokens-credentials",
            target_service + "s" if target_service == "database" else target_service,
        ],
        joined_surface_types=_joined_surface_types(joined_surfaces, fallback="plain-text-secret"),
        target_count=len(target_ids),
        target_ids=target_ids,
        target_names=target_names,
        target_visibility_issue=visibility_issue,
        next_review=semantic.next_review,
        summary=summary,
        missing_confirmation=(
            f"The current artifacts do not show a direct {target_service} hostname, connection "
            "string value, or confirmed successful credential use from this workload."
        ),
        related_ids=_merge_related_ids(
            env.get("related_ids", []),
            *[surface.get("related_ids", []) for surface in joined_surfaces],
            target_ids,
        ),
    )


def _select_candidates_for_location(
    candidates: list[dict],
    location: str | None,
) -> tuple[list[dict], str]:
    if location:
        location_matches = [item for item in candidates if item.get("location") == location]
        if location_matches:
            return location_matches, "narrowed candidates"
    if candidates:
        return candidates, "tenant-wide candidates"
    return [], "service hint only"


def _is_credential_like_env_var(env: dict, joined_surfaces: list[dict]) -> bool:
    if env.get("looks_sensitive") and env.get("value_type") == "plain-text":
        return True
    return any(surface.get("surface_type") == "plain-text-secret" for surface in joined_surfaces)


def _target_service_for_env_var(env: dict) -> str | None:
    return env_var_target_service(str(env.get("setting_name") or ""))


def _candidate_summary(
    *,
    env: dict,
    target_service: str,
    target_names: list[str],
    target_resolution: str,
    visibility_note: str | None = None,
) -> str:
    prefix = (
        f"{env['asset_kind']} '{env['asset_name']}' exposes credential-like setting "
        f"'{env['setting_name']}', and the visible naming suggests a {target_service} path. "
    )

    if target_resolution == "visibility blocked":
        summary = (
            f"{prefix}AzureFox cannot name candidate {target_service} targets because current "
            "credentials do not show enough target-side visibility."
        )
        if visibility_note:
            summary = f"{summary} {visibility_note}"
        return summary

    if target_resolution == "narrowed candidates":
        summary = (
            f"{prefix}AzureFox cannot name the exact {target_service} from the setting alone, "
            f"but it can narrow the next review set to {len(target_names)} visible "
            f"{target_service} candidate(s) in the same Azure location: "
            f"{', '.join(target_names[:_CANDIDATE_LIMIT])}."
        )
        if visibility_note:
            summary = f"{summary} {visibility_note}"
        return summary

    if target_resolution == "tenant-wide candidates":
        summary = (
            f"{prefix}AzureFox cannot narrow that beyond tenant-visible {target_service} "
            f"candidate(s) yet: {', '.join(target_names[:_CANDIDATE_LIMIT])}."
        )
        if visibility_note:
            summary = f"{summary} {visibility_note}"
        return summary

    summary = (
        f"{prefix}The current artifacts do not narrow that to a specific {target_service} "
        "asset yet."
    )
    if visibility_note:
        summary = f"{summary} {visibility_note}"
    return summary


def _build_deployment_source_record(
    family_name: str,
    *,
    source: dict,
    source_command: str,
    source_context: str | None,
    asset_kind: str,
    assessment: DeploymentSourceAssessment,
    target_family: str,
    target_candidates: list[dict],
    exact_targets: list[dict],
    confirmation_basis: str | None,
    target_visibility_note: str | None,
    target_visibility_issue: str | None,
    supporting_deployments: list[dict],
) -> ChainPathRecord | None:
    target_spec = _DEPLOYMENT_TARGET_SPECS[target_family]
    admission = admit_deployment_path_row(
        assessment,
        exact_target_count=len(exact_targets),
        narrowed_candidate_count=len(target_candidates),
        confirmation_basis=confirmation_basis,
        visibility_issue=target_visibility_issue,
    )
    if not admission.admitted:
        return None

    selected_targets = exact_targets if admission.state == "named match" else target_candidates
    target_names = [item.get("name") for item in selected_targets if item.get("name")]
    target_ids = [item.get("id") for item in selected_targets if item.get("id")]
    if target_visibility_issue and admission.state == "visibility blocked":
        target_names = []
        target_ids = []

    record_confirmation_basis = confirmation_basis
    if record_confirmation_basis is None and admission.state == "narrowed candidates":
        record_confirmation_basis = "name-only-inference"
    elif (
        record_confirmation_basis is None
        and target_visibility_issue
        and (
            target_visibility_issue.startswith("permission_denied:")
            or target_visibility_issue.startswith("partial_collection:")
        )
    ):
        record_confirmation_basis = "source-issue-present"

    semantic = evaluate_chain_semantics(
        ChainSemanticContext(
            family=family_name,
            clue_type=assessment.path_concept or source_command,
            target_service=target_spec["service"],
            target_resolution=admission.state,
            target_count=len(target_ids),
            source_command=source_command,
            path_concept=assessment.path_concept,
            current_operator_can_drive=_source_current_operator_can_drive(source_command, source),
            current_operator_can_inject=_source_current_operator_can_inject(source_command, source),
        )
    )

    return ChainPathRecord(
        chain_id=_source_chain_id(
            family_name,
            str(source.get("id") or source.get("name") or source_command),
            target_spec["service"],
        ),
        asset_id=str(source.get("id") or source.get("name") or ""),
        asset_name=str(source.get("name") or source.get("id") or source_command),
        asset_kind=asset_kind,
        location=source.get("location"),
        source_command=source_command,
        source_context=source_context,
        clue_type=assessment.path_concept or source_command,
        confirmation_basis=record_confirmation_basis,
        priority=semantic.priority,
        visible_path=_deployment_visible_path(
            source_command,
            assessment.path_concept,
            target_spec["label"],
        ),
        path_concept=assessment.path_concept,
        primary_injection_surface=(
            str(source.get("primary_injection_surface"))
            if source.get("primary_injection_surface")
            else None
        ),
        primary_trusted_input_ref=(
            str(source.get("primary_trusted_input_ref"))
            if source.get("primary_trusted_input_ref")
            else None
        ),
        why_care=_deployment_why_care(
            source_command,
            source,
            assessment=assessment,
        ),
        likely_impact=_deployment_likely_impact(
            target_label=target_spec["label"],
            target_names=target_names,
            target_resolution=admission.state,
            missing_target_mapping=assessment.missing_target_mapping,
        ),
        confidence_boundary=_deployment_confidence_boundary(
            target_label=target_spec["label"],
            target_resolution=admission.state,
            confirmation_basis=record_confirmation_basis,
            current_operator_can_drive=_source_current_operator_can_drive(source_command, source),
            current_operator_can_inject=_source_current_operator_can_inject(source_command, source),
            missing_target_mapping=assessment.missing_target_mapping,
        ),
        target_service=target_spec["service"],
        target_resolution=admission.state,
        evidence_commands=_deployment_evidence_commands(
            source_command,
            source,
            target_family,
            supporting_deployments=supporting_deployments,
        ),
        joined_surface_types=_deployment_joined_surfaces(
            source_command,
            assessment.change_signals,
            supporting_deployments=supporting_deployments,
        ),
        target_count=len(target_ids),
        target_ids=target_ids,
        target_names=target_names,
        target_visibility_issue=target_visibility_issue,
        next_review=_deployment_next_review(
            source_command=source_command,
            source=source,
            path_concept=assessment.path_concept,
            target_family=target_family,
            target_resolution=admission.state,
        ),
        summary=_deployment_summary(
            source=source,
            source_command=source_command,
            assessment=assessment,
            target_label=target_spec["label"],
            target_names=target_names,
            target_resolution=admission.state,
            confirmation_basis=record_confirmation_basis,
            target_visibility_note=target_visibility_note,
            supporting_deployments=supporting_deployments,
        ),
        missing_confirmation=_deployment_missing_confirmation(
            source_command=source_command,
            path_concept=assessment.path_concept,
            target_label=target_spec["label"],
            target_resolution=admission.state,
            missing_target_mapping=assessment.missing_target_mapping,
        ),
        related_ids=_merge_related_ids(
            source.get("related_ids", []),
            target_ids,
            *[item.get("related_ids", []) for item in supporting_deployments],
        ),
    )


def _deployment_visible_path(
    source_command: str,
    path_concept: str | None,
    target_label: str,
) -> str:
    if path_concept == "controllable-change-path":
        return f"Controllable Azure pipeline -> likely {target_label}"
    if path_concept == "execution-hub":
        return f"Managed-identity execution hub -> likely {target_label}"
    if path_concept == "secret-escalation-support":
        if source_command == "devops":
            return f"Secret-backed deployment support -> likely {target_label}"
        if source_command == "automation":
            return f"Secret-backed automation support -> likely {target_label}"
    if source_command == "devops":
        return f"Azure-facing pipeline -> likely {target_label}"
    if source_command == "automation":
        return f"Automation execution hub -> likely {target_label}"
    return f"Deployment source -> likely {target_label}"


def _deployment_why_care(
    source_command: str,
    source: dict,
    *,
    assessment: DeploymentSourceAssessment,
) -> str:
    source_name = str(source.get("name") or source.get("id") or source_command)
    consequence_phrase = _deployment_consequence_phrase(source)
    support_parts = _deployment_support_phrase_parts(source)
    support_phrase = (
        " and ".join(support_parts) if support_parts else "secret-backed deployment support"
    )

    if assessment.path_concept == "secret-escalation-support":
        if source_command == "devops":
            sentence = (
                f"This path is not yet a proven attacker-usable Azure change path, but it "
                f"concentrates {support_phrase} around an Azure-facing deployment route. "
                f"Another foothold that can start or control execution could "
                f"{consequence_phrase}."
            )
        elif source_command == "automation":
            sentence = (
                f"Automation account '{source_name}' is not yet a proven attacker-usable Azure "
                f"change path on its own, but it concentrates {support_phrase} around reusable "
                f"automation. Another foothold that can start or control execution could "
                f"{consequence_phrase}."
            )
        else:
            sentence = (
                "Secret-backed deployment support is visible, but another foothold is still "
                "needed before it becomes an attacker-usable Azure change path."
            )
        current_operator_suffix = _deployment_current_operator_suffix(source_command, source)
        if current_operator_suffix:
            sentence = f"{sentence} {current_operator_suffix}"
        if source.get("missing_target_mapping"):
            sentence = (
                f"{sentence} AzureFox has not yet mapped the downstream Azure footprint cleanly."
            )
        return sentence

    if source_command == "devops":
        trusted_input = _devops_primary_trusted_input(source)
        sentence = (
            f"This path trusts {_devops_trusted_input_text(trusted_input)}; poisoning it would "
            f"execute under {_deployment_execution_context(source_command, source)} and could "
            f"{consequence_phrase}."
        )
        current_operator_suffix = _deployment_current_operator_suffix(source_command, source)
        if current_operator_suffix:
            sentence = f"{sentence} {current_operator_suffix}"

        if support_parts:
            sentence = (
                f"{sentence} The surrounding deployment support also includes "
                + " and ".join(support_parts)
                + ", which could widen blast radius once execution is controlled."
            )
        if source.get("missing_target_mapping"):
            sentence = (
                f"{sentence} AzureFox has not yet mapped the downstream Azure footprint cleanly."
            )
        return sentence

    if source_command == "automation":
        surface_parts: list[str] = []
        if source.get("identity_type"):
            surface_parts.append("managed identity")
        published = int(source.get("published_runbook_count") or 0)
        if published > 0:
            surface_parts.append(f"{published} published runbook(s)")
        if "webhook-start" in assessment.change_signals:
            webhooks = int(source.get("webhook_count") or 0)
            surface_parts.append(f"{webhooks} webhook start path(s)")
        if "scheduled-start" in assessment.change_signals:
            schedules = int(source.get("schedule_count") or 0)
            surface_parts.append(f"{schedules} schedule-backed run path(s)")
        if "hybrid-worker-reach" in assessment.change_signals:
            workers = int(source.get("hybrid_worker_group_count") or 0)
            surface_parts.append(f"{workers} Hybrid Worker reach point(s)")
        sentence = (
            f"Automation account '{source_name}' combines "
            + ", ".join(surface_parts)
            + f", so control of this execution hub could {consequence_phrase} rather than stay "
            "at passive automation visibility."
        )
        if _deployment_support_phrase_parts(source):
            sentence = (
                f"{sentence} Secure assets around the account could widen blast radius once a "
                "run path is started or modified."
            )
        if source.get("missing_target_mapping"):
            sentence = (
                f"{sentence} AzureFox has not yet mapped the downstream Azure footprint cleanly."
            )
        return sentence

    return "Visible source evidence suggests Azure change capability"


def _deployment_consequence_phrase(source: dict) -> str:
    labels = {
        "consume-secret-backed-deployment-material": "consume secret-backed deployment material",
        "modify-infra": "modify Azure infrastructure",
        "redeploy-workload": "redeploy Azure workloads",
        "reintroduce-config": "reintroduce Azure configuration changes",
        "run-recurring-execution": "run recurring Azure-facing execution",
    }
    consequence_order = {
        "modify-infra": 0,
        "redeploy-workload": 1,
        "consume-secret-backed-deployment-material": 2,
        "reintroduce-config": 3,
        "run-recurring-execution": 4,
    }
    phrases = [
        labels.get(value, value.replace("-", " "))
        for value in sorted(
            [str(value) for value in source.get("consequence_types", []) or []],
            key=lambda value: consequence_order.get(value, 9),
        )
    ]
    if not phrases:
        return "change Azure state"
    if len(phrases) == 1:
        return phrases[0]
    if len(phrases) == 2:
        return f"{phrases[0]} and {phrases[1]}"
    return ", ".join(phrases[:-1]) + f", and {phrases[-1]}"


def _deployment_support_phrase_parts(source: dict) -> list[str]:
    support_labels = {
        "credentials": "credentials",
        "deployment-creds": "deployment credentials",
        "encrypted-variables": "encrypted variables",
        "keyvault-backed-inputs": "Key Vault-backed inputs",
        "publish-profiles": "publish profiles",
        "registry-creds": "registry credentials",
        "secret-variables": "secret variables",
        "signing-keys": "signing keys",
    }
    return [
        support_labels.get(str(value), str(value).replace("-", " "))
        for value in source.get("secret_support_types", []) or []
        if value != "variable-groups"
    ]


def _deployment_current_operator_suffix(source_command: str, source: dict) -> str:
    if source_command == "devops":
        injection_surfaces = [
            str(value) for value in (source.get("current_operator_injection_surface_types") or [])
        ]
        primary_input = _devops_primary_trusted_input(source)
        queue = source.get("current_operator_can_queue")
        edit = source.get("current_operator_can_edit")
        if any(value != "definition-edit" for value in injection_surfaces):
            return (
                "Current credentials can already poison that trusted input through "
                + ", ".join(value for value in injection_surfaces if value != "definition-edit")
                + "."
            )
        if "definition-edit" in injection_surfaces or edit:
            return "Current credentials can already edit the pipeline definition directly."
        if queue:
            return (
                "Current credentials can already queue this pipeline, but AzureFox has not yet "
                "proven that they can poison the trusted input."
            )
        access_state = (
            str(primary_input.get("current_operator_access_state"))
            if primary_input and primary_input.get("current_operator_access_state")
            else None
        )
        if access_state == "read":
            return (
                "Current credentials can read that trusted input, but Azure DevOps evidence here "
                "does not prove a write path."
            )
        if access_state == "exists-only":
            return "Current evidence only shows that the trusted input exists."
        if source.get("missing_injection_point"):
            return "AzureFox has not yet proven a poisonable trusted input for current credentials."
    return ""


def _source_current_operator_can_drive(source_command: str, source: dict) -> bool | None:
    if source_command == "devops":
        queue = source.get("current_operator_can_queue")
        edit = source.get("current_operator_can_edit")
        if isinstance(queue, bool) or isinstance(edit, bool):
            return bool(queue or edit)
    return None


def _source_current_operator_can_inject(source_command: str, source: dict) -> bool | None:
    if source_command == "devops":
        injection_surfaces = source.get("current_operator_injection_surface_types") or []
        queue = source.get("current_operator_can_queue")
        edit = source.get("current_operator_can_edit")
        if injection_surfaces or isinstance(queue, bool) or isinstance(edit, bool):
            return bool(injection_surfaces)
    return None


def _deployment_execution_context(source_command: str, source: dict) -> str:
    if source_command == "devops":
        names = [
            str(value) for value in (source.get("azure_service_connection_names") or []) if value
        ]
        if names:
            return "Azure service connection " + ", ".join(names)
        return "the authenticated Azure deployment path behind this pipeline"
    if source_command == "automation":
        identity_type = str(source.get("identity_type") or "").strip()
        if identity_type:
            return f"automation identity {identity_type}"
        return "the automation execution context"
    return "the visible execution context"


def _devops_primary_trusted_input(source: dict) -> dict | None:
    trusted_inputs = [
        value for value in source.get("trusted_inputs") or [] if isinstance(value, dict)
    ]
    primary_ref = str(source.get("primary_trusted_input_ref") or "") or None
    if primary_ref:
        for trusted_input in trusted_inputs:
            if str(trusted_input.get("ref") or "") == primary_ref:
                return trusted_input
    return trusted_inputs[0] if trusted_inputs else None


def _devops_trusted_input_text(trusted_input: dict | None) -> str:
    if trusted_input is None:
        return "the visible deployment input"
    return describe_trusted_input(
        input_type=str(trusted_input.get("input_type") or "") or None,
        ref=str(trusted_input.get("ref") or "") or None,
    )


def _deployment_likely_impact(
    *,
    target_label: str,
    target_names: list[str],
    target_resolution: str,
    missing_target_mapping: bool,
) -> str:
    lowered_label = target_label.lower()
    if missing_target_mapping:
        return f"Azure footprint not yet mapped; {lowered_label} evidence is consequence grounding"
    if target_resolution == "named match":
        return f"exact {lowered_label}: {', '.join(target_names[:_CANDIDATE_LIMIT])}"
    if target_resolution == "narrowed candidates":
        return f"{len(target_names)} visible {lowered_label} candidate(s)"
    if target_resolution == "visibility blocked":
        return f"likely {lowered_label}; target-side visibility blocked"
    return f"likely {lowered_label}; exact target unconfirmed"


def _deployment_confidence_boundary(
    *,
    target_label: str,
    target_resolution: str,
    confirmation_basis: str | None,
    current_operator_can_drive: bool | None,
    current_operator_can_inject: bool | None,
    missing_target_mapping: bool,
) -> str:
    if missing_target_mapping:
        if current_operator_can_inject:
            return (
                "Current credentials can control the source side, but AzureFox has not yet "
                f"mapped the downstream Azure footprint beyond {target_label} consequence "
                "grounding."
            )
        if current_operator_can_drive:
            return (
                "Current credentials can start or edit the source path, but AzureFox has not yet "
                f"mapped the downstream Azure footprint beyond {target_label} consequence "
                "grounding."
            )
        return (
            "Current artifacts show meaningful deployment support, but AzureFox has not yet "
            f"mapped the downstream Azure footprint beyond {target_label} consequence grounding."
        )

    if current_operator_can_inject:
        if target_resolution == "named match":
            return (
                f"Impact is visible, the current credentials can poison a trusted input, and "
                f"the {target_label} target is joined strongly enough to "
                "validate next."
            )
        if target_resolution == "narrowed candidates":
            return (
                f"Impact is visible and the current credentials can poison a trusted input, but "
                f"the exact {target_label} target is still unconfirmed."
            )
        if target_resolution == "visibility blocked":
            return (
                f"Current credentials can poison a trusted input, but current scope cannot name "
                f"the downstream {target_label} target yet."
            )

    if current_operator_can_drive:
        if target_resolution == "named match":
            return (
                "Impact is visible and current credentials can start or edit this path, but "
                "AzureFox has not yet proven a poisonable trusted input."
            )
        if target_resolution == "narrowed candidates":
            return (
                f"Impact is visible and current credentials can start this path, but AzureFox "
                f"has not yet proven a poisonable trusted input or the exact {target_label} "
                "target."
            )
        if target_resolution == "visibility blocked":
            return (
                f"Current credentials can start this path, but AzureFox has not yet proven a "
                f"poisonable trusted input and current scope cannot name the downstream "
                f"{target_label} target."
            )

    if target_resolution == "named match":
        if confirmation_basis == "parsed-config-target":
            return (
                f"Impact is visible and the {target_label} target is joined from parsed source "
                "clues, but AzureFox has not yet proven that the current credentials can invoke "
                "this path."
            )
        return (
            f"Impact is visible and the {target_label} target is backed by a stronger visible "
            "join, but AzureFox has not yet proven that the current credentials can invoke this "
            "path."
        )
    if target_resolution == "narrowed candidates":
        return (
            f"Impact is visible, but AzureFox has not yet proven current-credential invocation "
            f"or the exact {target_label} target."
        )
    if target_resolution == "visibility blocked":
        return (
            f"Impact is partially visible, but AzureFox has not yet proven current-credential "
            f"invocation and current scope cannot name the downstream {target_label} target."
        )
    return (
        f"Current evidence does not yet hold a defensible {target_label} target story or prove "
        "that the current credentials can drive the source path."
    )


def _deployment_evidence_commands(
    source_command: str,
    source: dict,
    target_family: str,
    *,
    supporting_deployments: list[dict],
) -> list[str]:
    commands = [source_command, "permissions"]
    if source.get("azure_service_connection_client_ids") or source.get(
        "azure_service_connection_principal_ids"
    ):
        commands.append("role-trusts")
    if "keyvault-backed-inputs" in (source.get("secret_support_types") or []):
        commands.append("keyvault")
    commands.append(_DEPLOYMENT_TARGET_SPECS[target_family]["command"])
    if supporting_deployments and "arm-deployments" not in commands:
        commands.append("arm-deployments")
    return commands


def _deployment_next_review(
    *,
    source_command: str,
    source: dict,
    path_concept: str | None,
    target_family: str,
    target_resolution: str,
) -> str:
    if path_concept == "secret-escalation-support":
        steps: list[str] = ["Confirm what separate foothold could reuse this secret-backed support"]
    elif _source_current_operator_can_inject(source_command, source):
        steps: list[str] = ["Current credentials can already poison a trusted input"]
    elif _source_current_operator_can_drive(source_command, source):
        steps = [
            "Current credentials can already start this path, but trusted-input poisoning is "
            "not yet proven"
        ]
    else:
        steps = ["Check permissions for the backing identity or service connection"]
    if source_command == "devops" and source.get("missing_injection_point"):
        steps.append(
            "confirm which trusted input can actually be poisoned from current credentials"
        )
    if source.get("azure_service_connection_client_ids") or source.get(
        "azure_service_connection_principal_ids"
    ):
        steps.append("review role-trusts for controllable identity links")
    if "keyvault-backed-inputs" in (source.get("secret_support_types") or []):
        steps.append("review keyvault for secret-backed deployment support")

    target_command = _DEPLOYMENT_TARGET_SPECS[target_family]["command"]
    if source.get("missing_target_mapping"):
        steps.append(
            f"use {target_command} as consequence grounding because target mapping is still missing"
        )
    elif target_resolution == "visibility blocked":
        steps.append(f"restore {target_command} visibility for consequence grounding")
    else:
        steps.append(f"open {target_command} to validate the likely Azure impact")
    return "; ".join(steps) + "."


def _deployment_joined_surfaces(
    source_command: str,
    change_signals: tuple[str, ...],
    *,
    supporting_deployments: list[dict],
) -> list[str]:
    joined = [source_command, *change_signals]
    if supporting_deployments:
        joined.append("provider-family-match")
    return sorted(dict.fromkeys(joined))


def _deployment_summary(
    *,
    source: dict,
    source_command: str,
    assessment: DeploymentSourceAssessment,
    target_label: str,
    target_names: list[str],
    target_resolution: str,
    confirmation_basis: str | None,
    target_visibility_note: str | None,
    supporting_deployments: list[dict],
) -> str:
    summary = _deployment_why_care(source_command, source, assessment=assessment)
    if assessment.missing_target_mapping:
        impact_sentence = (
            f"AzureFox has not yet mapped the downstream Azure footprint cleanly, so "
            f"{target_label} evidence is only consequence grounding right now."
        )
    elif target_resolution == "visibility blocked":
        impact_sentence = (
            f"The most likely downstream Azure footprint is still unresolved because current "
            f"scope cannot name visible {target_label} targets."
        )
    elif target_resolution == "named match":
        impact_sentence = (
            f"The likeliest downstream Azure footprint is the exact visible {target_label} target "
            f"{', '.join(target_names[:_CANDIDATE_LIMIT])}."
        )
    else:
        impact_sentence = (
            f"The likeliest downstream Azure footprint is narrowed to {len(target_names)} visible "
            f"{target_label} candidate(s): {', '.join(target_names[:_CANDIDATE_LIMIT])}."
        )
    summary = (
        f"{summary} {impact_sentence} "
        f"{
            _deployment_confidence_boundary(
                target_label=target_label,
                target_resolution=target_resolution,
                confirmation_basis=confirmation_basis,
                current_operator_can_drive=_source_current_operator_can_drive(
                    source_command, source
                ),
                current_operator_can_inject=_source_current_operator_can_inject(
                    source_command, source
                ),
                missing_target_mapping=assessment.missing_target_mapping,
            )
        }"
    )

    if supporting_deployments:
        deployment_names = ", ".join(
            item.get("name")
            for item in supporting_deployments[:_CANDIDATE_LIMIT]
            if item.get("name")
        )
        if deployment_names:
            summary = (
                f"{summary} Supporting ARM deployment history for the same target family includes "
                f"{deployment_names}, which supports the likely Azure footprint without proving "
                "the exact target."
            )

    if target_visibility_note:
        summary = f"{summary} {target_visibility_note}"
    return summary


def _structured_deployment_target_matches(
    source: dict,
    target_family: str,
    candidates: list[dict],
) -> tuple[list[dict], str | None]:
    structured_names = _structured_target_names(source, target_family)
    if not structured_names:
        return [], None
    matched = [
        item
        for item in candidates
        if _normalize_target_name(str(item.get("name") or "")) in structured_names
    ]
    if matched:
        return matched, "parsed-config-target"
    return [], "parsed-config-target"


def _structured_target_names(source: dict, target_family: str) -> set[str]:
    family_tokens = {
        "aks": {"aks", "kubernetes"},
        "app-services": {"appservice", "app-service"},
        "functions": {"function", "functions", "functionapp", "function-app"},
        "arm-deployments": {"deployment", "arm", "bicep", "terraform"},
    }[target_family]
    normalized_names: set[str] = set()
    for clue in source.get("target_clues", []) or []:
        text = str(clue).strip()
        lowered = text.lower()
        if ":" in text:
            prefix, raw_name = text.split(":", 1)
            prefix_tokens = {
                token.strip().lower().replace(" ", "").replace("/", "")
                for token in prefix.split("/")
                if token.strip()
            }
            if prefix_tokens & family_tokens and raw_name.strip():
                normalized_names.add(_normalize_target_name(raw_name))
        elif lowered.startswith("target="):
            normalized_names.add(_normalize_target_name(text.split("=", 1)[1]))
    return normalized_names


def _normalize_target_name(value: str) -> str:
    return (
        value.strip().lower().replace(" ", "").replace("_", "").replace("/", "").replace("\\", "")
    )


def _deployment_missing_confirmation(
    *,
    source_command: str,
    path_concept: str | None,
    target_label: str,
    target_resolution: str,
    missing_target_mapping: bool,
) -> str:
    if path_concept == "secret-escalation-support":
        if missing_target_mapping:
            return (
                "Missing exact target mapping and a separate execution foothold; current "
                "artifacts only show secret-backed support around a live Azure change path."
            )
        if target_resolution == "visibility blocked":
            return (
                f"Missing target-side visibility for the downstream {target_label} footprint, "
                "and current artifacts only show secret-backed support rather than a directly "
                "attacker-usable execution path."
            )
        return (
            f"Current artifacts narrow the likely {target_label} footprint, but another foothold "
            "is still needed before the secret-backed support becomes attacker-usable."
        )

    if target_resolution == "visibility blocked":
        if source_command == "devops":
            return (
                f"Missing target-side visibility for the downstream {target_label} footprint, "
                "and current artifacts still do not prove a poisonable trusted input or a "
                "definition-edit path for current credentials."
            )
        return (
            f"Missing target-side visibility for the downstream {target_label} footprint, and "
            "current artifacts do not show that the current credentials can start the runbook "
            "path that performs the Azure change."
        )
    if target_resolution == "named match":
        if source_command == "devops":
            return (
                f"Current artifacts name the likely {target_label} target, but do not confirm a "
                "poisonable trusted input or a current-credential definition-edit path on the "
                "source side."
            )
        return (
            f"Current artifacts name the likely {target_label} target, but do not confirm which "
            "specific runbook or current-credential start path performs that Azure change."
        )
    if source_command == "devops":
        return (
            f"Missing exact {target_label} mapping and source-side poisoning proof; current "
            "artifacts do not confirm a poisonable trusted input or a current-credential "
            "definition-edit path."
        )
    return (
        f"Missing exact {target_label} mapping and runbook-level execution proof; current "
        "artifacts do not show that the current credentials can start the published runbook path "
        "that performs the Azure change."
    )


def _arm_correlations_by_target_family(deployments: list[dict]) -> dict[str, list[dict]]:
    correlated: dict[str, list[dict]] = defaultdict(list)
    for deployment in deployments:
        deployment_summary = ArmDeploymentSummary.model_validate(deployment)
        for family in target_family_hints_from_arm_deployment(deployment_summary):
            correlated[family].append(deployment)
    return correlated


def _target_visibility_note(target_label: str, issues: list[CollectionIssue]) -> str | None:
    if not issues:
        return None
    if any(issue.kind in {"permission_denied", "partial_collection"} for issue in issues):
        return (
            f"Current scope may not show full {target_label} visibility, so this target "
            "picture may be incomplete."
        )
    return None


def _target_visibility_issue(issues: list[CollectionIssue]) -> str | None:
    for issue in issues:
        if issue.kind in {"permission_denied", "partial_collection"}:
            return f"{issue.kind}: {issue.message}"
    return None


def _joined_surface_types(joined_surfaces: list[dict], *, fallback: str) -> list[str]:
    surface_types = sorted(
        {
            str(surface.get("surface_type"))
            for surface in joined_surfaces
            if surface.get("surface_type")
        }
    )
    return surface_types or [fallback]


def _parse_operator_signal(value: str | None) -> dict[str, str]:
    signal: dict[str, str] = {}
    for part in str(value or "").split(";"):
        key, sep, raw = part.strip().partition("=")
        if not sep:
            continue
        signal[key.strip().lower()] = raw.strip()
    return signal


def _normalize_reference_target(value: str) -> str:
    return str(value).strip().removeprefix("https://").strip("/").lower()


def _reference_host(value: str | None) -> str:
    normalized = _normalize_reference_target(value or "")
    if "/" in normalized:
        return normalized.split("/", 1)[0]
    return normalized


def _merge_related_ids(*groups: list[str]) -> list[str]:
    seen: set[str] = set()
    merged: list[str] = []
    for group in groups:
        for value in group:
            if value and value not in seen:
                seen.add(value)
                merged.append(value)
    return merged


def _chain_id(asset_id: str, setting_name: str, target_service: str) -> str:
    normalized_setting = setting_name.lower().replace("_", "-")
    return f"credential-path::{asset_id}::{normalized_setting}::{target_service}"


def _source_chain_id(family_name: str, asset_id: str, target_service: str) -> str:
    return f"{family_name}::{asset_id}::{target_service}"
