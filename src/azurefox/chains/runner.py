from __future__ import annotations

from collections import defaultdict

from azurefox.chains.credential_path import collect_credential_path_records
from azurefox.chains.deployment_path import (
    DeploymentSourceAssessment,
    admit_deployment_path_row,
    assess_deployment_source,
    target_family_hints_from_arm_deployment,
)
from azurefox.chains.registry import (
    GROUPED_COMMAND_NAME,
    ChainFamilySpec,
    get_chain_family_spec,
    implemented_chain_family_names,
    is_implemented_chain_family,
)
from azurefox.chains.semantics import (
    ChainSemanticContext,
    evaluate_chain_semantics,
    semantic_priority_sort_value,
)
from azurefox.collectors.provider import BaseProvider
from azurefox.config import GlobalOptions
from azurefox.devops_hints import describe_trusted_input
from azurefox.models.chains import (
    ChainPathRecord,
    ChainsOutput,
)
from azurefox.models.commands import ChainsCommandOutput
from azurefox.models.common import ArmDeploymentSummary, CollectionIssue, CommandMetadata
from azurefox.registry import get_command_specs

_CANDIDATE_LIMIT = 3
_JOIN_QUALITY_ORDER = {
    "path-confirmed": 0,
    "target-confirmed": 1,
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
_AUTOMATION_EDIT_ROLE_NAMES = {
    "owner",
    "contributor",
    "automation contributor",
}
_AUTOMATION_START_ROLE_NAMES = {
    "owner",
    "contributor",
    "automation contributor",
    "automation operator",
}
_AUTOMATION_EDIT_ROLE_DEFINITION_IDS = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",  # Owner
    "b24988ac-6180-42a0-ab88-20f7382dd24c",  # Contributor
}


def implemented_chain_families() -> tuple[str, ...]:
    return implemented_chain_family_names()


def run_chain_family(
    provider: BaseProvider,
    options: GlobalOptions,
    family_name: str,
) -> ChainsOutput:
    family = get_chain_family_spec(family_name)
    if family is None:
        raise ValueError(f"Unknown chain family '{family_name}'")
    if not is_implemented_chain_family(family_name):
        raise ValueError(f"Chain family '{family_name}' is not implemented yet")

    loaded = _collect_family_outputs(provider, options, family_name)
    if family_name == "credential-path":
        return _build_credential_path_output(provider, options, family_name, loaded)
    if family_name == "deployment-path":
        return _build_deployment_path_output(options, family_name, loaded)
    if family_name == "escalation-path":
        return _build_escalation_path_output(options, family_name, loaded)

    raise ValueError(f"Unsupported chain family '{family_name}'")


def _collect_family_outputs(
    provider: BaseProvider,
    options: GlobalOptions,
    family_name: str,
) -> dict[str, object]:
    family = get_chain_family_spec(family_name)
    if family is None:
        raise ValueError(f"Unknown chain family '{family_name}'")

    collector_by_name = {spec.name: spec.collector for spec in get_command_specs()}
    loaded: dict[str, object] = {}

    for source in family.source_commands:
        collector = collector_by_name[source.command]
        loaded[source.command] = collector(provider, options)

    return loaded


def _build_credential_path_output(
    provider: BaseProvider,
    options: GlobalOptions,
    family_name: str,
    loaded: dict[str, object],
) -> ChainsCommandOutput:
    family = get_chain_family_spec(family_name)
    assert family is not None  # pragma: no cover - guarded above

    paths, issues = collect_credential_path_records(provider, family_name, loaded)

    paths.sort(
        key=lambda item: (
            semantic_priority_sort_value(item.priority),
            _JOIN_QUALITY_ORDER.get(item.target_resolution, 9),
            item.asset_name,
            item.setting_name,
            item.target_service,
        )
    )

    return _build_chains_command_output(
        options=options,
        family=family,
        family_name=family_name,
        paths=paths,
        issues=issues,
    )


def _build_deployment_path_output(
    options: GlobalOptions,
    family_name: str,
    loaded: dict[str, object],
) -> ChainsCommandOutput:
    family = get_chain_family_spec(family_name)
    assert family is not None  # pragma: no cover - guarded above

    devops_output = loaded["devops"]
    automation_output = loaded["automation"]
    permissions_output = loaded["permissions"]
    rbac_output = loaded["rbac"]
    role_trusts_output = loaded["role-trusts"]
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
    permissions_by_principal = {
        item.principal_id: item.model_dump(mode="json")
        for item in permissions_output.permissions
        if item.principal_id
    }
    current_identity_principal_ids = {
        str(item.principal_id)
        for item in permissions_output.permissions
        if item.is_current_identity and item.principal_id
    }
    current_identity_role_assignments = [
        item.model_dump(mode="json")
        for item in rbac_output.role_assignments
        if str(item.principal_id or "") in current_identity_principal_ids
    ]
    trusts_by_source_id: dict[str, list[dict]] = defaultdict(list)
    trusts_by_object_id: dict[str, list[dict]] = defaultdict(list)
    for trust in role_trusts_output.trusts:
        trust_row = trust.model_dump(mode="json")
        source_object_id = str(trust_row.get("source_object_id") or "")
        if source_object_id:
            trusts_by_source_id[source_object_id].append(trust_row)
            trusts_by_object_id[source_object_id].append(trust_row)
        target_object_id = str(trust_row.get("target_object_id") or "")
        if target_object_id and target_object_id != source_object_id:
            trusts_by_object_id[target_object_id].append(trust_row)

    paths: list[ChainPathRecord] = []
    for pipeline in devops_output.pipelines:
        pipeline_dict = pipeline.model_dump(mode="json")
        pipeline_dict["joined_permission"] = _devops_joined_permission(
            pipeline_dict,
            permissions_by_principal,
        )
        pipeline_dict["joined_role_trusts"] = _devops_joined_role_trusts(
            pipeline_dict,
            trusts_by_object_id,
        )
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
        account_dict["current_operator_access"] = _automation_current_operator_access(
            account_dict,
            current_identity_role_assignments,
        )
        account_dict["joined_permission"] = _automation_joined_permission(
            account_dict,
            permissions_by_principal,
        )
        account_dict["joined_role_trusts"] = _automation_joined_role_trusts(
            account_dict,
            trusts_by_source_id,
        )
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
        "permissions",
        "rbac",
        "role-trusts",
        "arm-deployments",
        "app-services",
        "functions",
        "aks",
    ):
        issues.extend(getattr(loaded[source_name], "issues", []))

    return _build_chains_command_output(
        options=options,
        family=family,
        family_name=family_name,
        paths=paths,
        issues=issues,
    )


def _build_escalation_path_output(
    options: GlobalOptions,
    family_name: str,
    loaded: dict[str, object],
) -> ChainsCommandOutput:
    family = get_chain_family_spec(family_name)
    assert family is not None  # pragma: no cover - guarded above

    privesc_output = loaded["privesc"]
    permissions_output = loaded["permissions"]
    role_trusts_output = loaded["role-trusts"]

    permissions_by_principal = {
        item.principal_id: item.model_dump(mode="json")
        for item in permissions_output.permissions
        if item.principal_id
    }
    current_foothold_row = next(
        (
            item.model_dump(mode="json")
            for item in privesc_output.paths
            if item.current_identity and item.principal_id
        ),
        None,
    )
    current_foothold_id = (
        str(current_foothold_row.get("principal_id")) if current_foothold_row else None
    )

    paths: list[ChainPathRecord] = []
    if current_foothold_row:
        permission = permissions_by_principal.get(current_foothold_id or "")
        if current_foothold_row.get("path_type") == "direct-role-abuse" and permission:
            paths.append(
                _build_escalation_direct_control_record(
                    family_name,
                    current_foothold_row,
                    permission,
                )
            )
        trust_row = _build_escalation_trust_record(
            family_name,
            current_foothold_row,
            role_trusts_output.trusts,
            permissions_by_principal,
            current_foothold_id=current_foothold_id,
        )
        if trust_row is not None:
            paths.append(trust_row)

    paths.sort(
        key=lambda item: (
            semantic_priority_sort_value(item.priority),
            _JOIN_QUALITY_ORDER.get(item.target_resolution, 9),
            item.asset_name,
            item.path_concept or "",
        )
    )

    issues: list[CollectionIssue] = []
    for source_name in ("privesc", "permissions", "role-trusts"):
        issues.extend(getattr(loaded[source_name], "issues", []))

    return _build_chains_command_output(
        options=options,
        family=family,
        family_name=family_name,
        paths=paths,
        issues=issues,
    )


def _build_chains_command_output(
    *,
    options: GlobalOptions,
    family: ChainFamilySpec,
    family_name: str,
    paths: list[ChainPathRecord],
    issues: list[CollectionIssue],
) -> ChainsCommandOutput:
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
        current_gap=family.current_gap,
        artifact_preference_order=[],
        backing_commands=[source.command for source in family.source_commands],
        source_artifacts=[],
        paths=paths,
        issues=issues,
    )


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
    semantic_priority = _deployment_priority_override(
        source_command=source_command,
        source=source,
        path_concept=assessment.path_concept,
        semantic_priority=semantic.priority,
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
        priority=semantic_priority,
        urgency=semantic.urgency,
        actionability_state=_deployment_actionability_state(
            source_command=source_command,
            source=source,
            path_concept=assessment.path_concept,
            target_resolution=admission.state,
            missing_target_mapping=assessment.missing_target_mapping,
        ),
        visible_path=_deployment_visible_path(
            source_command,
            assessment.path_concept,
            target_spec["label"],
        ),
        insertion_point=_deployment_insertion_point(
            source_command=source_command,
            source=source,
            path_concept=assessment.path_concept,
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
            source_command=source_command,
            source=source,
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
            source=source,
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
            target_names=target_names,
            target_label=target_spec["label"],
            supporting_deployments=supporting_deployments,
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
            source=source,
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


def _deployment_actionability_state(
    *,
    source_command: str,
    source: dict,
    path_concept: str | None,
    target_resolution: str,
    missing_target_mapping: bool,
) -> str:
    if path_concept == "secret-escalation-support":
        return "support-only"
    if _source_current_operator_can_inject(source_command, source):
        return "currently actionable"
    if _source_current_operator_can_drive(source_command, source):
        return "conditionally actionable"
    if target_resolution == "visibility blocked" and not missing_target_mapping:
        return "visibility-bounded"
    return "consequence-grounded but insertion point unproven"


def _deployment_insertion_point(
    *,
    source_command: str,
    source: dict,
    path_concept: str | None,
) -> str:
    if source_command == "devops":
        return _deployment_devops_insertion_point(source)
    if source_command == "automation":
        return _deployment_automation_insertion_point(source, path_concept=path_concept)
    return "Visible deployment path, but the insertion point is not yet described."


def _deployment_devops_insertion_point(source: dict) -> str:
    primary_input = _devops_primary_trusted_input(source)
    trusted_input_text = _devops_trusted_input_text(primary_input)
    control_mode = _devops_current_operator_control_mode(source, primary_input=primary_input)
    non_definition_surfaces = _devops_non_definition_injection_surfaces(source)
    if control_mode == "trusted-input-poison":
        surface_list = ", ".join(non_definition_surfaces)
        return f"Poison {trusted_input_text} through {surface_list}."
    if control_mode == "definition-edit":
        return "Edit the pipeline definition directly."
    if control_mode == "queue-only":
        if primary_input:
            access_state = str(primary_input.get("current_operator_access_state") or "")
            if access_state == "use" and primary_input.get("input_type") == "secure-file":
                return (
                    f"Queue this pipeline now; {trusted_input_text} is usable in pipeline "
                    "context, but secure-file administration is still unproven."
                )
            if access_state == "read" and primary_input.get("input_type") == "pipeline-artifact":
                return (
                    "Queue this pipeline now; the upstream producer behind "
                    f"{trusted_input_text} is inspectable, but producer control is still "
                    "unproven."
                )
            if access_state == "read":
                return f"Queue this pipeline now; {trusted_input_text} is only readable."
            if access_state == "exists-only":
                return (
                    f"Queue this pipeline now; {trusted_input_text} is visible, but source control "
                    "is still unproven."
                )
        return "Queue this pipeline now, but source poisoning is still unproven."
    if primary_input:
        input_type = str(primary_input.get("input_type") or "")
        access_state = str(primary_input.get("current_operator_access_state") or "")
        if access_state == "use" and primary_input.get("input_type") == "secure-file":
            return (
                f"{trusted_input_text} is usable in pipeline context, but secure-file "
                "administration is unproven."
            )
        if access_state == "read" and primary_input.get("input_type") == "pipeline-artifact":
            return (
                f"The upstream producer behind {trusted_input_text} is inspectable, but "
                "producer control is unproven."
            )
        if input_type == "pipeline-artifact":
            return (
                f"Artifact trust is visible at {trusted_input_text}, but upstream producer control "
                "is unproven."
            )
        if access_state == "read":
            return (
                f"{trusted_input_text} is visible and readable, but not writable from "
                "current evidence."
            )
        if access_state == "exists-only":
            return f"{trusted_input_text} is visible, but current control is unproven."
        return f"Source depends on {trusted_input_text}."
    return (
        "Azure-facing pipeline is visible, but the source-side insertion point is "
        "still unproven."
    )


def _deployment_automation_insertion_point(source: dict, *, path_concept: str | None) -> str:
    primary_mode = str(source.get("primary_start_mode") or "") or None
    primary_runbook = str(source.get("primary_runbook_name") or "") or None
    identity_type = str(source.get("identity_type") or "").strip() or None
    primary_clause = _automation_primary_run_path_clause(
        primary_mode=primary_mode,
        primary_runbook=primary_runbook,
        identity_type=identity_type,
    )
    webhook_runbooks = [
        str(value) for value in (source.get("webhook_runbook_names") or []) if value
    ]
    schedule_runbooks = [
        str(value) for value in (source.get("schedule_runbook_names") or []) if value
    ]
    hybrid_count = int(source.get("hybrid_worker_group_count") or 0)

    surfaces: list[str] = []
    if primary_clause:
        surfaces.append(primary_clause)
    elif webhook_runbooks:
        surfaces.append("webhook-triggerable runbooks " + ", ".join(webhook_runbooks[:2]))
    elif schedule_runbooks:
        surfaces.append("schedule-backed runbooks " + ", ".join(schedule_runbooks[:2]))
    if hybrid_count > 0:
        surfaces.append(f"{hybrid_count} Hybrid Worker reach point(s)")
    operator_clause = _automation_current_operator_control_clause(source)
    if operator_clause:
        surfaces.append(operator_clause)

    if surfaces and path_concept == "secret-escalation-support":
        return "; ".join(surfaces) + "."
    if surfaces:
        if operator_clause:
            return "; ".join(surfaces) + "."
        return "; ".join(surfaces) + ", but current operator control is still unproven."
    if path_concept == "secret-escalation-support":
        return (
            "Reusable automation support is visible, but no operator-controlled run "
            "path is proven."
        )
    return (
        "Automation consequences are grounded, but the operator-controlled start "
        "or edit path is still unproven."
    )


def _automation_joined_permission(
    source: dict,
    permissions_by_principal: dict[str, dict],
) -> dict | None:
    identity_refs = _automation_identity_refs(source)
    for ref in identity_refs:
        if ref in permissions_by_principal:
            return dict(permissions_by_principal[ref])
    return None


def _automation_joined_role_trusts(
    source: dict,
    trusts_by_source_id: dict[str, list[dict]],
) -> list[dict]:
    identity_refs = _automation_identity_refs(source)
    seen: set[tuple[str, str, str]] = set()
    joined: list[dict] = []
    for ref in identity_refs:
        for trust in trusts_by_source_id.get(ref, []):
            key = (
                str(trust.get("source_object_id") or ""),
                str(trust.get("trust_type") or ""),
                str(trust.get("target_object_id") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            joined.append(dict(trust))
    return joined


def _automation_identity_refs(source: dict) -> list[str]:
    refs: list[str] = []
    for value in (
        source.get("principal_id"),
        *list(source.get("identity_join_ids") or []),
        *list(source.get("identity_ids") or []),
    ):
        text = str(value or "").strip()
        if text and text not in refs:
            refs.append(text)
    return refs


def _automation_primary_run_path_clause(
    *,
    primary_mode: str | None,
    primary_runbook: str | None,
    identity_type: str | None,
) -> str | None:
    identity_clause = f" under automation identity {identity_type}" if identity_type else ""
    if primary_mode == "webhook" and primary_runbook:
        return f"webhook path can start runbook {primary_runbook}{identity_clause}"
    if primary_mode == "schedule" and primary_runbook:
        return f"schedule path can start runbook {primary_runbook}{identity_clause}"
    if primary_mode == "manual-only" and primary_runbook:
        return f"published runbook {primary_runbook}{identity_clause} is visible"
    if primary_mode == "published-runbook" and primary_runbook:
        return f"published runbook {primary_runbook}{identity_clause} is visible"
    if primary_mode == "hybrid-worker":
        return "hybrid-worker-backed execution is visible"
    return None


def _automation_primary_run_path_evidence_sentence(source: dict) -> str | None:
    primary_mode = str(source.get("primary_start_mode") or "") or None
    primary_runbook = str(source.get("primary_runbook_name") or "") or None
    identity_type = str(source.get("identity_type") or "").strip() or None
    identity_clause = f" under automation identity {identity_type}" if identity_type else ""
    if primary_mode == "webhook" and primary_runbook:
        return (
            f"AzureFox can identify a webhook path into runbook {primary_runbook}"
            f"{identity_clause}."
        )
    if primary_mode == "schedule" and primary_runbook:
        return (
            f"AzureFox can identify a schedule-backed path into runbook "
            f"{primary_runbook}{identity_clause}."
        )
    if primary_mode in {"manual-only", "published-runbook"} and primary_runbook:
        return f"AzureFox can identify published runbook {primary_runbook}{identity_clause}."
    if primary_mode == "hybrid-worker":
        return "AzureFox can identify hybrid-worker-backed execution."
    return None


def _automation_current_operator_access(
    source: dict,
    role_assignments: list[dict],
) -> dict | None:
    resource_id = str(source.get("id") or "").strip()
    if not resource_id:
        return None

    best_access: dict | None = None
    best_sort_key: tuple[int, int] | None = None
    for assignment in role_assignments:
        scope_id = str(assignment.get("scope_id") or "").strip()
        role_name = str(assignment.get("role_name") or "").strip()
        if not scope_id or not _scope_applies_to_resource(scope_id, resource_id):
            continue

        capability = _automation_role_capability(
            role_name=role_name,
            role_definition_id=str(assignment.get("role_definition_id") or "").strip() or None,
        )
        if capability is None:
            continue

        sort_key = (1 if capability == "edit" else 0, len(scope_id))
        if best_sort_key is not None and sort_key <= best_sort_key:
            continue
        best_sort_key = sort_key
        best_access = {
            "capability": capability,
            "role_name": role_name,
            "scope_id": scope_id,
        }
    return best_access


def _devops_joined_permission(
    source: dict,
    permissions_by_principal: dict[str, dict],
) -> dict | None:
    for ref in _devops_service_principal_refs(source):
        if ref in permissions_by_principal:
            return dict(permissions_by_principal[ref])
    return None


def _devops_joined_role_trusts(
    source: dict,
    trusts_by_object_id: dict[str, list[dict]],
) -> list[dict]:
    known_refs = {ref for ref, _, _ in _devops_identity_ref_candidates(source)}
    best_scores: dict[tuple[str, str, str], tuple[int, int, int, str, str]] = {}
    best_rows: dict[tuple[str, str, str], dict] = {}
    for ref, ref_kind, ref_rank in _devops_identity_ref_candidates(source):
        for trust in trusts_by_object_id.get(ref, []):
            key = (
                str(trust.get("source_object_id") or ""),
                str(trust.get("trust_type") or ""),
                str(trust.get("target_object_id") or ""),
            )
            score = _devops_role_trust_sort_key(
                trust,
                matched_ref=ref,
                matched_kind=ref_kind,
                ref_rank=ref_rank,
                known_refs=known_refs,
            )
            if key not in best_scores or score < best_scores[key]:
                best_scores[key] = score
                best_rows[key] = dict(trust)
    return [best_rows[key] for key in sorted(best_rows, key=lambda item: best_scores[item])]


def _devops_service_principal_refs(source: dict) -> list[str]:
    refs: list[str] = []
    for value in source.get("azure_service_connection_principal_ids") or []:
        text = str(value or "").strip()
        if text and text not in refs:
            refs.append(text)
    return refs


def _devops_application_refs(source: dict) -> list[str]:
    refs: list[str] = []
    for value in source.get("azure_service_connection_client_ids") or []:
        text = str(value or "").strip()
        if text and text not in refs:
            refs.append(text)
    return refs


def _devops_identity_ref_candidates(source: dict) -> list[tuple[str, str, int]]:
    candidates: list[tuple[str, str, int]] = []
    for ref in _devops_service_principal_refs(source):
        candidates.append((ref, "service-principal", 0))
    for ref in _devops_application_refs(source):
        candidates.append((ref, "application", 1))
    return candidates


def _devops_identity_refs(source: dict) -> list[str]:
    return [ref for ref, _, _ in _devops_identity_ref_candidates(source)]


def _devops_role_trust_sort_key(
    trust: dict,
    *,
    matched_ref: str,
    matched_kind: str,
    ref_rank: int,
    known_refs: set[str],
) -> tuple[int, int, int, str, str]:
    source_object_id = str(trust.get("source_object_id") or "").strip()
    target_object_id = str(trust.get("target_object_id") or "").strip()
    both_known = int(not (source_object_id in known_refs and target_object_id in known_refs))
    matched_side_rank = 2
    if target_object_id == matched_ref:
        matched_side_rank = 0
    elif source_object_id == matched_ref:
        matched_side_rank = 1
    trust_type_rank = {
        "federated-credential": 0,
        "app-to-service-principal": 1,
        "service-principal-owner": 2,
        "app-owner": 3,
    }.get(str(trust.get("trust_type") or ""), 9)
    kind_rank = 0 if matched_kind == "service-principal" else 1
    return (
        both_known,
        matched_side_rank,
        min(ref_rank, kind_rank, 1),
        trust_type_rank,
        source_object_id,
        target_object_id,
    )


def _automation_current_operator_control_clause(source: dict) -> str | None:
    access = source.get("current_operator_access")
    if not isinstance(access, dict):
        return None

    capability = str(access.get("capability") or "").strip()
    role_name = str(access.get("role_name") or "").strip()
    scope_id = str(access.get("scope_id") or "").strip()
    if not capability or not role_name or not scope_id:
        return None

    scope_text = _automation_scope_label(scope_id, resource_id=str(source.get("id") or ""))
    primary_mode = str(source.get("primary_start_mode") or "").strip() or None
    primary_runbook = str(source.get("primary_runbook_name") or "").strip() or None

    if capability == "edit":
        if primary_runbook and primary_mode == "webhook":
            return (
                f"current role assignment {role_name} at {scope_text} can edit runbook "
                f"{primary_runbook} or its webhook-backed execution boundary; AzureFox does not "
                "prove possession of the current webhook URI"
            )
        if primary_runbook and primary_mode == "schedule":
            return (
                f"current role assignment {role_name} at {scope_text} can edit runbook "
                f"{primary_runbook} or its schedule-backed execution boundary"
            )
        if primary_runbook:
            return (
                f"current role assignment {role_name} at {scope_text} can edit published "
                f"runbook {primary_runbook}"
            )
        return (
            f"current role assignment {role_name} at {scope_text} can edit this "
            "automation execution boundary"
        )

    if primary_runbook:
        return (
            f"current role assignment {role_name} at {scope_text} can start runbook "
            f"{primary_runbook}, but edit control is still unproven"
        )
    return (
        f"current role assignment {role_name} at {scope_text} can start visible runbook jobs, "
        "but edit control is still unproven"
    )


def _automation_scope_label(scope_id: str, *, resource_id: str) -> str:
    normalized_scope = _normalized_arm_segments(scope_id)
    normalized_resource = _normalized_arm_segments(resource_id)
    if normalized_scope == normalized_resource:
        return "this automation account"
    if _arm_scope_kind(scope_id) == "resource_group":
        return f"resource group {_arm_scope_name(scope_id)}"
    if _arm_scope_kind(scope_id) == "subscription":
        return "subscription scope"
    if _arm_scope_kind(scope_id) == "resource":
        resource_name = _arm_scope_name(scope_id)
        if resource_name:
            return f"resource scope {resource_name}"
    return "a parent scope of this automation account"


def _scope_applies_to_resource(scope_id: str | None, resource_id: str | None) -> bool:
    if not scope_id or not resource_id:
        return False
    scope_segments = _normalized_arm_segments(scope_id)
    resource_segments = _normalized_arm_segments(resource_id)
    if not scope_segments or len(scope_segments) > len(resource_segments):
        return False
    return resource_segments[: len(scope_segments)] == scope_segments


def _normalized_arm_segments(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    return tuple(part.strip().lower() for part in str(value).split("/") if part.strip())


def _arm_scope_kind(scope_id: str | None) -> str | None:
    segments = _normalized_arm_segments(scope_id)
    if len(segments) == 2 and segments[0] == "subscriptions":
        return "subscription"
    if len(segments) == 4 and segments[0] == "subscriptions" and segments[2] == "resourcegroups":
        return "resource_group"
    if len(segments) >= 8 and segments[0] == "subscriptions" and segments[2] == "resourcegroups":
        return "resource"
    return None


def _arm_scope_name(scope_id: str | None) -> str | None:
    parts = [part for part in str(scope_id or "").split("/") if part]
    if not parts:
        return None
    kind = _arm_scope_kind(scope_id)
    if kind == "resource_group" and len(parts) >= 4:
        return parts[3]
    if kind == "resource":
        return parts[-1]
    return None


def _normalize_role_name(value: str | None) -> str:
    return " ".join(str(value or "").split()).strip().lower()


def _role_definition_key(role_definition_id: str | None) -> str | None:
    text = str(role_definition_id or "").strip()
    if not text:
        return None
    return text.rstrip("/").split("/")[-1].lower()


def _automation_role_capability(
    *,
    role_name: str | None,
    role_definition_id: str | None,
) -> str | None:
    role_key = _role_definition_key(role_definition_id)
    if role_key in _AUTOMATION_EDIT_ROLE_DEFINITION_IDS:
        return "edit"

    normalized_role = _normalize_role_name(role_name)
    if normalized_role in _AUTOMATION_EDIT_ROLE_NAMES:
        return "edit"
    if normalized_role in _AUTOMATION_START_ROLE_NAMES:
        return "start"
    return None


def _deployment_priority_override(
    *,
    source_command: str,
    source: dict,
    path_concept: str | None,
    semantic_priority: str,
) -> str:
    if path_concept == "secret-escalation-support":
        return "low"
    if source_command == "automation" and _source_current_operator_can_inject(
        source_command, source
    ):
        return "high"
    return semantic_priority


def _automation_permission_clause(source: dict) -> str | None:
    permission = source.get("joined_permission")
    if not isinstance(permission, dict):
        return None
    if not bool(permission.get("privileged")):
        return None
    roles = [str(role) for role in permission.get("high_impact_roles") or [] if role]
    role_text = ", ".join(roles) or "high-impact RBAC"
    scope_count = int(permission.get("scope_count") or 0)
    scope_text = "subscription-wide scope" if scope_count <= 1 else f"{scope_count} visible scopes"
    principal_name = str(
        permission.get("display_name")
        or source.get("name")
        or permission.get("principal_id")
        or "automation identity"
    )
    return f"Azure identity '{principal_name}' already has {role_text} across {scope_text}"


def _automation_role_trust_clause(source: dict) -> str | None:
    trusts = source.get("joined_role_trusts")
    if not isinstance(trusts, list) or not trusts:
        return None
    trust = trusts[0] if isinstance(trusts[0], dict) else None
    if not trust:
        return None
    trust_type = str(trust.get("trust_type") or "")
    target_name = str(trust.get("target_name") or trust.get("target_object_id") or "unknown target")
    source_name = str(trust.get("source_name") or trust.get("source_object_id") or "unknown source")
    if trust_type == "service-principal-owner":
        return (
            f"AzureFox also sees a separate identity-control path into Azure identity "
            f"'{target_name}' through service principal '{source_name}'"
        )
    if trust_type == "app-owner":
        return (
            f"AzureFox also sees a separate app control path into app '{target_name}' "
            f"through '{source_name}'"
        )
    if trust_type == "federated-credential":
        return (
            f"AzureFox also sees a separate app trust path into Azure identity "
            f"'{target_name}' through app '{source_name}'"
        )
    if trust_type == "app-to-service-principal":
        return (
            f"AzureFox also sees a separate app-permission path into Azure identity "
            f"'{target_name}'"
        )
    summary = str(trust.get("summary") or "").strip()
    return summary or None


def _devops_permission_clause(source: dict) -> str | None:
    permission = source.get("joined_permission")
    if not isinstance(permission, dict):
        return None
    if not bool(permission.get("privileged")):
        return None
    roles = [str(role) for role in permission.get("high_impact_roles") or [] if role]
    role_text = ", ".join(roles) or "high-impact RBAC"
    scope_count = int(permission.get("scope_count") or 0)
    scope_text = "subscription-wide scope" if scope_count <= 1 else f"{scope_count} visible scopes"
    principal_name = str(
        permission.get("display_name")
        or permission.get("principal_id")
        or "the Azure identity tied to this pipeline"
    )
    return (
        f"This pipeline runs as Azure identity '{principal_name}', which already has "
        f"{role_text} across {scope_text}"
    )


def _devops_role_trust_clause(source: dict) -> str | None:
    trusts = source.get("joined_role_trusts")
    if not isinstance(trusts, list) or not trusts:
        return None
    trust = trusts[0] if isinstance(trusts[0], dict) else None
    if not trust:
        return None
    trust_type = str(trust.get("trust_type") or "")
    target_name = str(trust.get("target_name") or trust.get("target_object_id") or "unknown target")
    source_name = str(trust.get("source_name") or trust.get("source_object_id") or "unknown source")
    same_identity = _devops_execution_identity_name(source) == target_name
    target_identity_text = (
        "that same Azure identity"
        if same_identity
        else f"Azure identity '{target_name}'"
    )
    if trust_type == "service-principal-owner":
        return (
            f"AzureFox also sees a separate identity-control path into {target_identity_text} "
            f"through service principal '{source_name}'"
        )
    if trust_type == "app-owner":
        return (
            f"AzureFox also sees a separate app control path through '{source_name}' "
            f"into app '{target_name}'"
        )
    if trust_type == "federated-credential":
        return (
            f"AzureFox also sees a separate app trust path into {target_identity_text} "
            f"through app '{source_name}'"
        )
    if trust_type == "app-to-service-principal":
        return f"AzureFox also sees a separate app-permission path into {target_identity_text}"
    summary = str(trust.get("summary") or "").strip()
    return summary or None


def _devops_execution_identity_name(source: dict) -> str | None:
    permission = source.get("joined_permission")
    if isinstance(permission, dict):
        text = str(permission.get("display_name") or permission.get("principal_id") or "").strip()
        if text:
            return text

    identity_refs = set(_devops_identity_refs(source))
    trusts = source.get("joined_role_trusts")
    if isinstance(trusts, list):
        for trust in trusts:
            if not isinstance(trust, dict):
                continue
            target_object_id = str(trust.get("target_object_id") or "").strip()
            target_name = str(trust.get("target_name") or "").strip()
            if target_object_id and target_object_id in identity_refs and target_name:
                return target_name
            source_object_id = str(trust.get("source_object_id") or "").strip()
            source_name = str(trust.get("source_name") or "").strip()
            if source_object_id and source_object_id in identity_refs and source_name:
                return source_name
    return None


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
        return sentence

    if source_command == "devops":
        trusted_input = _devops_primary_trusted_input(source)
        sentence = _devops_why_care_intro(source, trusted_input=trusted_input)
        grounded_reach = _devops_grounded_reach_clause(source)
        if grounded_reach:
            sentence = f"{sentence} {grounded_reach}"

        if support_parts:
            sentence = (
                f"{sentence} Visible deployment support around this path also includes "
                + " and ".join(support_parts)
                + "."
            )
        permission_clause = _devops_permission_clause(source)
        if permission_clause:
            sentence = f"{sentence} {permission_clause}."
        trust_clause = _devops_role_trust_clause(source)
        if trust_clause:
            sentence = f"{sentence} {trust_clause}."
        if source.get("missing_target_mapping"):
            sentence = (
                f"{sentence} AzureFox has not yet mapped the downstream Azure footprint cleanly."
            )
        return sentence

    if source_command == "automation":
        primary_mode = str(source.get("primary_start_mode") or "") or None
        primary_runbook = str(source.get("primary_runbook_name") or "") or None
        identity_type = str(source.get("identity_type") or "").strip() or None
        primary_clause = _automation_primary_run_path_clause(
            primary_mode=primary_mode,
            primary_runbook=primary_runbook,
            identity_type=identity_type,
        )
        surface_parts: list[str] = []
        if primary_clause:
            surface_parts.append(primary_clause)
        elif source.get("identity_type"):
            surface_parts.append("managed identity")
        published = int(source.get("published_runbook_count") or 0)
        if published > 0:
            surface_parts.append(f"{published} published runbook(s)")
        if "webhook-start" in assessment.change_signals and primary_mode != "webhook":
            webhooks = int(source.get("webhook_count") or 0)
            surface_parts.append(f"{webhooks} webhook start path(s)")
        if "scheduled-start" in assessment.change_signals and primary_mode != "schedule":
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
        current_operator_suffix = _deployment_current_operator_suffix(source_command, source)
        if current_operator_suffix:
            sentence = f"{sentence} {current_operator_suffix}"
        permission_clause = _automation_permission_clause(source)
        if permission_clause:
            sentence = f"{sentence} {permission_clause}."
        trust_clause = _automation_role_trust_clause(source)
        if trust_clause:
            sentence = f"{sentence} {trust_clause}."
        return sentence

    return "Visible source evidence suggests Azure change capability"


def _devops_why_care_intro(source: dict, *, trusted_input: dict | None) -> str:
    trusted_input_text = _devops_trusted_input_text(trusted_input)
    execution_context = _deployment_execution_context("devops", source)
    control_mode = _devops_current_operator_control_mode(source, primary_input=trusted_input)
    if control_mode == "definition-edit":
        return (
            f"This path trusts {trusted_input_text}. Current credentials can already edit this "
            f"pipeline definition directly. An edited run would use {execution_context} when it "
            "makes changes in Azure."
        )
    if _source_current_operator_can_inject("devops", source):
        return (
            f"This path trusts {trusted_input_text}. Current credentials can already poison "
            f"that source. A poisoned run would use {execution_context} when it makes changes "
            "in Azure."
        )
    return (
        f"This path trusts {trusted_input_text}. If that trusted input becomes "
        f"attacker-controlled, a poisoned run would use {execution_context} when it makes "
        "changes in Azure."
    )


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
        primary_input = _devops_primary_trusted_input(source)
        control_mode = _devops_current_operator_control_mode(source, primary_input=primary_input)
        non_definition_surfaces = _devops_non_definition_injection_surfaces(source)
        if control_mode == "trusted-input-poison":
            return (
                "Current credentials can already poison that trusted input through "
                + ", ".join(non_definition_surfaces)
                + "."
            )
        if control_mode == "definition-edit":
            return "Current credentials can already edit the pipeline definition directly."
        if control_mode == "queue-only":
            return (
                "Current credentials can already queue this pipeline, but AzureFox has not yet "
                "proven that they can poison the trusted input."
            )
        access_state = (
            str(primary_input.get("current_operator_access_state"))
            if primary_input and primary_input.get("current_operator_access_state")
            else None
        )
        if (
            access_state == "use"
            and primary_input
            and primary_input.get("input_type") == "secure-file"
        ):
            return (
                "Current credentials can use that secure file in pipeline context, but "
                "Azure DevOps evidence here does not prove secure-file administration."
            )
        if access_state == "read":
            if primary_input and primary_input.get("input_type") == "pipeline-artifact":
                return (
                    "Current credentials can inspect the upstream producer path, but Azure DevOps "
                    "evidence here does not prove producer-side control."
                )
            if primary_input and primary_input.get("input_type") == "secure-file":
                return (
                    "Current credentials can use that secure file in pipeline context, but "
                    "Azure DevOps evidence here does not prove secure-file administration."
                )
            return (
                "Current credentials can read that trusted input, but Azure DevOps evidence here "
                "does not prove a write path."
            )
        if access_state == "exists-only":
            missing_proof = _devops_missing_trusted_input_proof(
                str(primary_input.get("input_type") or "") if primary_input else None
            )
            if missing_proof:
                return (
                    "Current evidence only shows that the trusted input exists; "
                    + missing_proof
                    + " remains unproven."
                )
            return "Current evidence only shows that the trusted input exists."
        if source.get("missing_injection_point"):
            return (
                "AzureFox has not yet proven "
                + _devops_missing_source_control_text(definite=False)
                + " for current credentials."
            )
    if source_command == "automation":
        clause = _automation_current_operator_control_clause(source)
        if clause:
            return clause[:1].upper() + clause[1:] + "."
    return ""


def _source_current_operator_can_drive(source_command: str, source: dict) -> bool | None:
    if source_command == "devops":
        queue = source.get("current_operator_can_queue")
        edit = source.get("current_operator_can_edit")
        if isinstance(queue, bool) or isinstance(edit, bool):
            return bool(queue or edit)
    if source_command == "automation":
        access = source.get("current_operator_access")
        if isinstance(access, dict):
            return str(access.get("capability") or "") in {"start", "edit"}
    return None


def _source_current_operator_can_inject(source_command: str, source: dict) -> bool | None:
    if source_command == "devops":
        injection_surfaces = source.get("current_operator_injection_surface_types") or []
        queue = source.get("current_operator_can_queue")
        edit = source.get("current_operator_can_edit")
        if injection_surfaces or isinstance(queue, bool) or isinstance(edit, bool):
            return bool(injection_surfaces)
    if source_command == "automation":
        access = source.get("current_operator_access")
        if isinstance(access, dict):
            return str(access.get("capability") or "") == "edit"
    return None


def _devops_non_definition_injection_surfaces(source: dict) -> list[str]:
    return [
        str(value)
        for value in (source.get("current_operator_injection_surface_types") or [])
        if value and str(value) != "definition-edit"
    ]


def _devops_current_operator_control_mode(
    source: dict,
    *,
    primary_input: dict | None = None,
) -> str | None:
    if _devops_non_definition_injection_surfaces(source):
        return "trusted-input-poison"
    injection_surfaces = [
        str(value)
        for value in (source.get("current_operator_injection_surface_types") or [])
        if value
    ]
    if "definition-edit" in injection_surfaces or source.get("current_operator_can_edit"):
        return "definition-edit"
    if source.get("current_operator_can_queue"):
        return "queue-only"
    primary_input = primary_input or _devops_primary_trusted_input(source)
    if primary_input:
        access_state = str(primary_input.get("current_operator_access_state") or "")
        if access_state == "use" and primary_input.get("input_type") == "secure-file":
            return "secure-file-use"
        if access_state == "read" and primary_input.get("input_type") == "pipeline-artifact":
            return "artifact-read"
        if access_state == "read":
            return "trusted-input-read"
        if access_state == "exists-only":
            return "trusted-input-exists"
    if source.get("missing_injection_point"):
        return "unproven"
    return None


def _deployment_execution_context(source_command: str, source: dict) -> str:
    if source_command == "devops":
        identity_name = _devops_execution_identity_name(source)
        if identity_name:
            return f"Azure identity '{identity_name}'"
        return "the Azure identity tied to this pipeline"
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


def _devops_missing_trusted_input_proof(input_type: str | None) -> str | None:
    return {
        "package-feed": "the current operator's feed role",
        "pipeline-artifact": "upstream producer control",
        "template-repository": "referenced repo read/write proof",
        "repository": "repo read/write proof",
        "secure-file": "secure-file use or admin proof",
    }.get(str(input_type or ""))


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
        shown = ", ".join(target_names[:_CANDIDATE_LIMIT])
        if shown:
            return f"{len(target_names)} visible {lowered_label} candidate(s): {shown}"
        return f"{len(target_names)} visible {lowered_label} candidate(s)"
    if target_resolution == "visibility blocked":
        return f"likely {lowered_label}; target-side visibility blocked"
    return f"likely {lowered_label}; exact target unconfirmed"


def _deployment_confidence_boundary(
    *,
    source_command: str | None = None,
    source: dict | None = None,
    target_label: str,
    target_resolution: str,
    confirmation_basis: str | None,
    current_operator_can_drive: bool | None,
    current_operator_can_inject: bool | None,
    missing_target_mapping: bool,
) -> str:
    source_control_label = _deployment_source_control_label(source_command, source)
    if missing_target_mapping:
        if current_operator_can_inject:
            return (
                "This row proves source-side control, but AzureFox has not yet mapped the "
                f"downstream Azure footprint beyond {target_label} evidence."
            )
        if current_operator_can_drive:
            return (
                "This row proves current-credential run-path control, but AzureFox has not yet "
                f"mapped the downstream Azure footprint beyond {target_label} evidence."
            )
        return (
            "AzureFox can ground downstream consequence here, but it has not yet mapped the real "
            f"Azure footprint beyond {target_label} evidence."
        )

    if current_operator_can_inject:
        if target_resolution == "named match":
            return (
                f"{_deployment_operator_control_boundary(source_command, source, target_label)}, "
                f"but not {_deployment_remaining_identity_boundary(source_command, source)}."
            )
        if target_resolution == "narrowed candidates":
            return (
                f"This row proves {source_control_label}, but not the exact {target_label} target."
            )
        if target_resolution == "visibility blocked":
            return (
                f"This row proves {source_control_label}, but current scope still hides the "
                f"downstream {target_label} target."
            )

    if current_operator_can_drive:
        if target_resolution == "named match":
            return (
                f"This row proves current-credential run-path control and the exact "
                f"{target_label} target, but not a writable source."
            )
        if target_resolution == "narrowed candidates":
            return (
                f"This row proves current-credential run-path control, but not a writable "
                f"source or the exact {target_label} target."
            )
        if target_resolution == "visibility blocked":
            return (
                f"This row proves current-credential run-path control, but not a writable source "
                f"or visible downstream {target_label} target."
            )

    if target_resolution == "named match":
        if confirmation_basis == "parsed-config-target":
            return (
                f"This row proves the exact {target_label} target from parsed source clues, but "
                "not current-credential invocation."
            )
        return (
            f"This row proves the exact {target_label} target, but not current-credential "
            "invocation."
        )
    if target_resolution == "narrowed candidates":
        return (
            f"This row narrows the likely {target_label} targets, but not current-credential "
            "invocation."
        )
    if target_resolution == "visibility blocked":
        return (
            f"Current scope still hides the downstream {target_label} target, so AzureFox cannot "
            "complete the target-side judgment yet."
        )
    return (
        f"AzureFox still cannot prove either a defensible {target_label} target story or a "
        "current-credential path into this source."
    )


def _deployment_remaining_identity_boundary(
    source_command: str | None,
    source: dict | None,
) -> str:
    if source_command == "devops" and source is not None:
        identity_name = _devops_execution_identity_name(source)
        if identity_name:
            return f"a separate direct sign-in as Azure identity '{identity_name}'"
    if source_command == "automation" and source is not None:
        identity_type = str(source.get("identity_type") or "").strip()
        if identity_type:
            return f"a separate direct sign-in as the automation Azure identity ({identity_type})"
    return "a separate direct sign-in from this row alone"


def _deployment_operator_control_boundary(
    source_command: str | None,
    source: dict | None,
    target_label: str,
) -> str:
    if source_command == "devops" and source is not None:
        identity_name = _devops_execution_identity_name(source)
        if _devops_current_operator_control_mode(source) == "definition-edit":
            if identity_name:
                return (
                    "Current evidence shows you can edit this pipeline definition so it runs as "
                    f"Azure identity '{identity_name}' against the exact {target_label} target"
                )
            return (
                "Current evidence shows you can edit this pipeline definition so it runs "
                f"against the exact {target_label} target"
            )
        if identity_name:
            return (
                "Current evidence shows you can poison this trusted input so it runs as Azure "
                f"identity '{identity_name}' against the exact {target_label} target"
            )
        return (
            "Current evidence shows you can poison this trusted input against the exact "
            f"{target_label} target"
        )
    if source_command == "automation":
        return (
            "Current evidence shows you can control this source-side path against the exact "
            f"{target_label} target"
        )
    return f"Current evidence shows source poisoning and the exact {target_label} target"


def _deployment_source_control_label(
    source_command: str | None,
    source: dict | None,
) -> str:
    if source_command == "devops" and source is not None:
        if _devops_current_operator_control_mode(source) == "definition-edit":
            return "source-side definition control"
        return "source poisoning"
    if source_command == "automation":
        return "source-side control"
    return "source poisoning"


def _devops_missing_source_control_text(*, definite: bool = True) -> str:
    phrase = "writable trusted input or current-credential definition-edit path"
    return f"the {phrase}" if definite else phrase


def _deployment_evidence_commands(
    source_command: str,
    source: dict,
    target_family: str,
    *,
    supporting_deployments: list[dict],
) -> list[str]:
    commands = [source_command, "permissions"]
    if source_command == "automation" and source.get("current_operator_access"):
        commands.append("rbac")
    if source_command == "automation" and (
        source.get("principal_id") or source.get("client_id") or source.get("identity_ids")
    ):
        commands.append("role-trusts")
    if source.get("azure_service_connection_client_ids") or source.get(
        "azure_service_connection_principal_ids"
    ):
        commands.append("role-trusts")
    if "keyvault-backed-inputs" in (source.get("secret_support_types") or []):
        commands.append("keyvault")
    commands.append(_DEPLOYMENT_TARGET_SPECS[target_family]["command"])
    if supporting_deployments and "arm-deployments" not in commands:
        commands.append("arm-deployments")
    return list(dict.fromkeys(commands))


def _deployment_next_review(
    *,
    source_command: str,
    source: dict,
    path_concept: str | None,
    target_family: str,
    target_resolution: str,
    target_names: list[str],
    target_label: str,
    supporting_deployments: list[dict],
) -> str:
    if source_command == "automation":
        primary_mode = str(source.get("primary_start_mode") or "") or None
        primary_runbook = str(source.get("primary_runbook_name") or "") or None
        permission_clause = _automation_permission_clause(source)
        trust_clause = _automation_role_trust_clause(source)
        current_operator_can_edit = bool(
            _source_current_operator_can_inject(source_command, source)
        )
        current_operator_can_start = bool(
            _source_current_operator_can_drive(source_command, source)
        )
        if path_concept == "secret-escalation-support":
            steps = ["Confirm what separate foothold could reuse this secret-backed support"]
        elif current_operator_can_edit:
            steps = ["Current RBAC evidence already shows edit-capable automation control here"]
        elif current_operator_can_start:
            steps = ["Current RBAC evidence already shows runbook-start control here"]
        elif permission_clause:
            steps = ["Validate what Azure scope the automation identity can already change"]
        else:
            steps = ["Check permissions for the automation identity behind this execution path"]
        if current_operator_can_edit and primary_runbook and primary_mode == "webhook":
            steps.append(
                f"map what runbook {primary_runbook} changes because current "
                "control does not depend on the webhook URI"
            )
        elif current_operator_can_edit and primary_runbook:
            steps.append(f"map what runbook {primary_runbook} changes on the Azure side")
        elif current_operator_can_start and primary_runbook:
            steps.append(
                f"confirm whether runbook {primary_runbook} also has an editable "
                "trigger or definition path"
            )
        elif primary_runbook and primary_mode == "webhook":
            steps.append(
                "confirm whether current credentials can trigger webhook runbook "
                f"{primary_runbook}"
            )
        elif primary_runbook and primary_mode == "schedule":
            steps.append(
                "confirm whether current credentials can influence scheduled "
                f"runbook {primary_runbook}"
            )
        elif primary_runbook:
            steps.append(
                f"confirm how runbook {primary_runbook} is started from current "
                "credentials"
            )
        else:
            steps.append("confirm which runbook and trigger path performs the Azure change")
        if trust_clause:
            steps.append("review other identity trust paths around that same Azure identity")
        elif source.get("principal_id") or source.get("client_id") or source.get("identity_ids"):
            steps.append("review other identity trust paths around the automation identity")
        if source.get("missing_target_mapping"):
            steps.append(
                "use already-loaded ARM deployment evidence as consequence grounding "
                "because runbook target mapping is still missing"
            )
        elif target_resolution == "visibility blocked":
            steps.append(
                f"restore {target_label} visibility so AzureFox can finish the target-side join"
            )
        else:
            steps.append(
                _deployment_target_review_step(
                    target_resolution=target_resolution,
                    target_label=target_label,
                    target_names=target_names,
                    supporting_deployments=supporting_deployments,
                )
            )
        return "; ".join(steps) + "."

    if path_concept == "secret-escalation-support":
        steps: list[str] = ["Confirm what separate foothold could reuse this secret-backed support"]
    elif _source_current_operator_can_inject(source_command, source):
        if (
            source_command == "devops"
            and _devops_current_operator_control_mode(source) == "definition-edit"
        ):
            steps = ["Current credentials can already edit this pipeline definition directly"]
        else:
            steps = ["Current credentials can already poison a trusted input"]
    elif _source_current_operator_can_drive(source_command, source):
        steps = [
            "Current credentials can already start this path, but trusted-input poisoning is "
            "not yet proven"
        ]
    else:
        steps = ["Check permissions for the backing identity or service connection"]
    if source_command == "devops" and source.get("missing_injection_point"):
        primary_input = _devops_primary_trusted_input(source)
        missing_proof = _devops_missing_trusted_input_proof(
            str(primary_input.get("input_type") or "") if primary_input else None
        )
        if missing_proof:
            steps.append(f"confirm {missing_proof}")
        else:
            steps.append(
                "confirm which trusted input can actually be poisoned from current credentials"
            )
    if source.get("azure_service_connection_client_ids") or source.get(
        "azure_service_connection_principal_ids"
    ):
        if source.get("joined_role_trusts"):
            steps.append(
                "use the already-joined app and identity trust evidence to validate "
                "other sign-in paths into that same Azure identity"
            )
        else:
            steps.append("review other trust paths into the Azure identity tied to this pipeline")
    permission_clause = _devops_permission_clause(source)
    if permission_clause:
        steps.append(
            "use the already-joined Azure control on the Azure identity tied to this pipeline"
        )
    if "keyvault-backed-inputs" in (source.get("secret_support_types") or []):
        steps.append(
            "use the already-loaded Key Vault support evidence to keep blast "
            "radius in view"
        )
    if source.get("missing_target_mapping"):
        steps.append(
            "use already-loaded ARM deployment evidence as consequence grounding "
            "because target mapping is still missing"
        )
    elif target_resolution == "visibility blocked":
        steps.append(
            f"restore {target_label} visibility so AzureFox can finish the target-side join"
        )
    else:
        steps.append(
            _deployment_target_review_step(
                target_resolution=target_resolution,
                target_label=target_label,
                target_names=target_names,
                supporting_deployments=supporting_deployments,
            )
        )
    return "; ".join(steps) + "."


def _deployment_target_review_step(
    *,
    target_resolution: str,
    target_label: str,
    target_names: list[str],
    supporting_deployments: list[dict],
) -> str:
    shown_targets = ", ".join(target_names[:_CANDIDATE_LIMIT])
    if target_resolution == "named match" and shown_targets:
        step = (
            f"AzureFox already named the exact {target_label} target {shown_targets}; "
            "validate that target directly"
        )
    elif shown_targets:
        step = (
            f"AzureFox already narrowed the likely {target_label} candidates to {shown_targets}; "
            "confirm which one this path actually changes"
        )
    else:
        step = f"confirm which {target_label} this path actually changes"
    supporting_names = ", ".join(
        str(item.get("name") or "")
        for item in supporting_deployments[:_CANDIDATE_LIMIT]
        if item.get("name")
    )
    if supporting_names:
        step += f" while keeping supporting ARM deployment history {supporting_names} in view"
    return step


def _devops_grounded_reach_clause(source: dict) -> str:
    consequence_types = {str(value) for value in (source.get("consequence_types") or []) if value}
    phrases: list[str] = []
    if "redeploy-workload" in consequence_types:
        phrases.append("AzureFox already ties this path to visible workload deployment reach")
    if "modify-infra" in consequence_types:
        phrases.append("visible infrastructure deployment reach")
    if "reintroduce-config" in consequence_types:
        phrases.append("configuration change reach")
    if "run-recurring-execution" in consequence_types:
        phrases.append("recurring execution")
    if "consume-secret-backed-deployment-material" in consequence_types:
        phrases.append("secret-backed deployment material")
    if not phrases:
        return ""
    if len(phrases) == 1:
        return phrases[0] + "."
    if len(phrases) == 2:
        return f"{phrases[0]} and {phrases[1]}."
    return ", ".join(phrases[:-1]) + f", and {phrases[-1]}."


def _deployment_joined_surfaces(
    source_command: str,
    change_signals: tuple[str, ...],
    *,
    supporting_deployments: list[dict],
    source: dict | None = None,
) -> list[str]:
    joined = [source_command, *change_signals]
    if supporting_deployments:
        joined.append("provider-family-match")
    if source_command == "devops" and source is not None:
        if source.get("joined_permission"):
            joined.append("permission-summary")
        if source.get("joined_role_trusts"):
            joined.append("trust-edge")
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
    confidence_boundary = _deployment_confidence_boundary(
        source_command=source_command,
        source=source,
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
    summary = f"{summary} {impact_sentence} {confidence_boundary}"

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
    source: dict,
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
                "evidence only shows secret-backed support around a live Azure change path."
            )
        if target_resolution == "visibility blocked":
            return (
                f"Missing target-side visibility for the downstream {target_label} footprint, "
                "and current evidence only shows secret-backed support rather than a directly "
                "attacker-usable execution path."
            )
        return (
            f"Current evidence narrows the likely {target_label} footprint, but another foothold "
            "is still needed before the secret-backed support becomes attacker-usable."
        )

    if target_resolution == "visibility blocked":
        if source_command == "devops":
            return (
                f"Missing target-side visibility for the downstream {target_label} footprint, "
                "and current evidence still does not prove "
                + _devops_missing_source_control_text(definite=False)
                + "."
            )
        if _source_current_operator_can_inject(source_command, source):
            return (
                f"Missing target-side visibility for the downstream {target_label} footprint; "
                "current RBAC evidence already shows edit-capable automation control, but AzureFox "
                "still cannot name which Azure target that control reaches."
            )
        if _source_current_operator_can_drive(source_command, source):
            return (
                f"Missing target-side visibility for the downstream {target_label} footprint; "
                "current RBAC evidence already shows runbook-start control, but AzureFox still "
                "cannot name which Azure target that execution reaches."
            )
        primary_mode = str(source.get("primary_start_mode") or "") or None
        primary_runbook = str(source.get("primary_runbook_name") or "") or None
        permission_clause = _automation_permission_clause(source)
        if primary_runbook and primary_mode:
            return (
                f"Missing target-side visibility for the downstream {target_label} footprint, and "
                f"current evidence does not show that the current credentials can control the "
                f"{primary_mode} path into runbook {primary_runbook}"
                + (
                    f" even though the {permission_clause}."
                    if permission_clause
                    else "."
                )
            )
        return (
            f"Missing target-side visibility for the downstream {target_label} footprint, and "
            "current evidence does not show that the current credentials can start the runbook "
            "path that performs the Azure change."
        )
    if target_resolution == "named match":
        if source_command == "devops":
            return (
                f"Current evidence names the likely {target_label} target, but does not confirm a "
                + _devops_missing_source_control_text(definite=False)
                + " on the source side."
            )
        return (
            f"Current evidence names the likely {target_label} target, but does not confirm which "
            "specific runbook or current-credential start path performs that Azure change."
        )
    if source_command == "devops":
        return (
            f"Missing exact {target_label} mapping and source-side poisoning proof; current "
            "evidence does not confirm "
            + _devops_missing_source_control_text(definite=False)
            + "."
        )
    if _source_current_operator_can_inject(source_command, source):
        return (
            f"Missing exact {target_label} mapping; current RBAC evidence already shows "
            "edit-capable automation control, but AzureFox has not yet mapped which Azure target "
            "that control reaches."
        )
    if _source_current_operator_can_drive(source_command, source):
        return (
            f"Missing exact {target_label} mapping; current RBAC evidence already shows "
            "runbook-start control, but AzureFox has not yet mapped which Azure target that "
            "execution reaches."
        )
    primary_mode = str(source.get("primary_start_mode") or "") or None
    primary_runbook = str(source.get("primary_runbook_name") or "") or None
    permission_clause = _automation_permission_clause(source)
    if primary_runbook and primary_mode:
        return (
            f"Missing exact {target_label} mapping and runbook-level execution proof; current "
            f"evidence does not show that the current credentials can control the {primary_mode} "
            f"path into runbook {primary_runbook}"
            + (
                f" even though the {permission_clause}."
                if permission_clause
                else "."
            )
        )
    return (
        f"Missing exact {target_label} mapping and runbook-level execution proof; current "
        "evidence does not show that the current credentials can start the published runbook path "
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


def _build_escalation_direct_control_record(
    family_name: str,
    privesc_row: dict,
    permission_row: dict,
) -> ChainPathRecord:
    scope_text = _permission_scope_text(permission_row)
    stronger_outcome = _permission_control_summary(permission_row)
    semantic = evaluate_chain_semantics(
        ChainSemanticContext(
            family=family_name,
            clue_type=str(privesc_row.get("path_type") or "direct-role-abuse"),
            target_service="azure-control",
            target_resolution="path-confirmed",
            target_count=max(1, len(permission_row.get("scope_ids") or [])),
            source_command="privesc",
            path_concept="current-foothold-direct-control",
        )
    )
    confidence_boundary = " ".join(
        part
        for part in (
            str(privesc_row.get("proven_path") or "").strip(),
            str(privesc_row.get("missing_proof") or "").strip(),
        )
        if part
    )
    next_review = str(privesc_row.get("next_review") or semantic.next_review)

    return ChainPathRecord(
        chain_id=f"escalation-path::{privesc_row.get('principal_id')}::current-foothold-direct-control",
        asset_id=str(privesc_row.get("principal_id") or "unknown"),
        asset_name=str(
            privesc_row.get("starting_foothold")
            or privesc_row.get("principal")
            or "unknown current foothold"
        ),
        asset_kind=str(privesc_row.get("principal_type") or "Principal"),
        source_command="privesc",
        source_context=str(privesc_row.get("principal") or ""),
        clue_type=str(privesc_row.get("path_type") or "direct-role-abuse"),
        confirmation_basis="current-identity-rooted",
        priority=semantic.priority,
        urgency=semantic.urgency,
        visible_path="Current foothold -> high-impact RBAC already visible",
        insertion_point="Current foothold already holds high-impact RBAC on visible scope.",
        path_concept="current-foothold-direct-control",
        stronger_outcome=stronger_outcome,
        why_care=(
            f"The current foothold already sits on {scope_text} high-impact Azure control, so this "
            "is not a speculative lead or a separate pivot hunt. The next move is to confirm the "
            "exact assignment boundary and pick the strongest direct abuse route from that control."
        ),
        likely_impact=stronger_outcome,
        confidence_boundary=confidence_boundary,
        target_service="azure-control",
        target_resolution="path-confirmed",
        evidence_commands=["privesc", "permissions"],
        joined_surface_types=["current-foothold", "permission-summary"],
        target_count=max(1, len(permission_row.get("scope_ids") or [])),
        target_ids=[str(value) for value in permission_row.get("scope_ids") or [] if value],
        target_names=[scope_text],
        next_review=next_review,
        summary=f"{confidence_boundary} {next_review}".strip(),
        missing_confirmation=str(privesc_row.get("missing_proof") or ""),
        related_ids=[str(value) for value in privesc_row.get("related_ids") or [] if value],
    )


def _build_escalation_trust_record(
    family_name: str,
    privesc_row: dict,
    trusts: list,
    permissions_by_principal: dict[str, dict],
    *,
    current_foothold_id: str | None,
) -> ChainPathRecord | None:
    if not current_foothold_id:
        return None

    for trust in trusts:
        trust_row = trust.model_dump(mode="json")
        if trust_row.get("source_object_id") != current_foothold_id:
            continue

        target_permission = permissions_by_principal.get(
            str(trust_row.get("target_object_id") or "")
        )
        escalation_mechanism = str(trust_row.get("escalation_mechanism") or "").strip()
        usable_identity_result = str(trust_row.get("usable_identity_result") or "").strip()
        defender_cut_point = str(trust_row.get("defender_cut_point") or "").strip()

        if not target_permission or not escalation_mechanism or not usable_identity_result:
            continue

        target_resolution = "path-confirmed"
        stronger_outcome = _permission_control_summary(target_permission)
        semantic = evaluate_chain_semantics(
            ChainSemanticContext(
                family=family_name,
                clue_type=str(trust_row.get("trust_type") or "trust-expansion"),
                target_service="identity-trust",
                target_resolution=target_resolution,
                target_count=1,
                source_command="role-trusts",
                path_concept="trust-expansion",
            )
        )
        confidence_boundary = (
            f"{escalation_mechanism} {usable_identity_result} "
            "AzureFox can also confirm the stronger target's Azure control. "
            "AzureFox does not prove successful conversion of that control path into usable "
            "downstream identity access from this row alone."
        ).strip()
        next_review = str(trust_row.get("next_review") or semantic.next_review)
        why_care = (
            "This row names a real control transform from the current foothold into a stronger "
            "identity path, not just a nearby trust relationship."
        )
        if defender_cut_point:
            why_care = f"{why_care} {defender_cut_point}"

        return ChainPathRecord(
            chain_id=f"escalation-path::{current_foothold_id}::trust-expansion::{trust_row.get('target_object_id')}",
            asset_id=str(current_foothold_id),
            asset_name=str(
                privesc_row.get("starting_foothold")
                or privesc_row.get("principal")
                or "unknown current foothold"
            ),
            asset_kind=str(privesc_row.get("principal_type") or "Principal"),
            source_command="role-trusts",
            source_context=str(
                trust_row.get("source_name") or trust_row.get("source_object_id") or ""
            ),
            clue_type=str(trust_row.get("trust_type") or "trust-expansion"),
            confirmation_basis=str(trust_row.get("confidence") or "confirmed"),
            priority=semantic.priority,
            urgency=semantic.urgency,
            visible_path="Current foothold -> trust edge -> higher-value identity",
            insertion_point=escalation_mechanism,
            path_concept="trust-expansion",
            stronger_outcome=stronger_outcome,
            why_care=why_care,
            likely_impact=stronger_outcome,
            confidence_boundary=confidence_boundary,
            target_service="identity-trust",
            target_resolution=target_resolution,
            evidence_commands=["privesc", "role-trusts", "permissions"],
            joined_surface_types=["current-foothold", "trust-edge"],
            target_count=1,
            target_ids=[str(trust_row.get("target_object_id") or "")],
            target_names=[
                str(trust_row.get("target_name") or trust_row.get("target_object_id") or "")
            ],
            next_review=next_review,
            summary=f"{confidence_boundary} {next_review}".strip(),
            missing_confirmation=(
                "AzureFox does not prove successful conversion of the visible trust-control path "
                "into usable downstream identity access."
            ),
            related_ids=[str(value) for value in trust_row.get("related_ids") or [] if value],
        )

    return None


def _merge_related_ids(*groups: list[str]) -> list[str]:
    seen: set[str] = set()
    merged: list[str] = []
    for group in groups:
        for value in group:
            if value and value not in seen:
                seen.add(value)
                merged.append(value)
    return merged


def _permission_scope_text(permission_row: dict | None) -> str:
    if not permission_row:
        return "visible scope"
    scope_count = int(
        permission_row.get("scope_count") or len(permission_row.get("scope_ids") or []) or 0
    )
    if scope_count <= 1:
        return "subscription-wide scope"
    return f"{scope_count} visible scopes"


def _permission_control_summary(permission_row: dict | None) -> str:
    if not permission_row:
        return "Potential stronger Azure control; exact privilege not yet confirmed"
    roles = [str(role) for role in permission_row.get("high_impact_roles") or [] if role]
    role_text = ", ".join(roles) or "high-impact roles"
    scope_text = _permission_scope_text(permission_row)
    return f"{role_text} across {scope_text}"
def _source_chain_id(family_name: str, asset_id: str, target_service: str) -> str:
    return f"{family_name}::{asset_id}::{target_service}"
