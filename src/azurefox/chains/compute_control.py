from __future__ import annotations

import re
from collections import defaultdict

from azurefox.chains.semantics import semantic_priority_sort_value, semantic_urgency_sort_value
from azurefox.models.chains import ChainPathRecord
from azurefox.models.common import CollectionIssue
from azurefox.scope_hints import permission_scope_phrase

_HIGH_IMPACT_ROLE_NAMES = {
    "owner",
    "contributor",
    "user access administrator",
}
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def collect_compute_control_records(
    family_name: str,
    loaded: dict[str, object],
) -> tuple[list[ChainPathRecord], list[CollectionIssue]]:
    tokens_output = loaded["tokens-credentials"]
    env_output = loaded.get("env-vars")
    managed_output = loaded["managed-identities"]
    permissions_output = loaded["permissions"]
    workloads_output = loaded["workloads"]

    workloads_by_asset = {
        item.asset_id: item.model_dump(mode="json")
        for item in workloads_output.workloads
        if item.asset_id
    }
    managed_by_id = {
        item.id: item.model_dump(mode="json") for item in managed_output.identities if item.id
    }
    managed_by_principal: dict[str, list[dict]] = defaultdict(list)
    for item in managed_output.identities:
        row = item.model_dump(mode="json")
        principal_id = str(row.get("principal_id") or "").strip()
        if principal_id:
            managed_by_principal[principal_id].append(row)
    permissions_by_principal = {
        item.principal_id: item.model_dump(mode="json")
        for item in permissions_output.permissions
        if item.principal_id and item.privileged
    }
    env_rows_by_asset: dict[str, list[dict]] = defaultdict(list)
    if env_output is not None:
        for item in env_output.env_vars:
            if item.asset_id:
                env_rows_by_asset[item.asset_id].append(item.model_dump(mode="json"))
    role_assignments_by_principal: dict[str, list[dict]] = defaultdict(list)
    for assignment in managed_output.role_assignments:
        row = assignment.model_dump(mode="json")
        principal_id = str(row.get("principal_id") or "").strip()
        if principal_id:
            role_assignments_by_principal[principal_id].append(row)

    paths: list[ChainPathRecord] = []
    for surface in tokens_output.surfaces:
        row = surface.model_dump(mode="json")
        if str(row.get("surface_type") or "") != "managed-identity-token":
            continue

        workload = workloads_by_asset.get(str(row.get("asset_id") or ""))
        if workload is None:
            continue

        env_rows = env_rows_by_asset.get(str(row.get("asset_id") or ""), [])
        if _is_mixed_identity_workload(workload):
            identity_binding = _resolve_mixed_identity_binding(
                surface_row=row,
                workload_row=workload,
                env_rows=env_rows,
                managed_by_id=managed_by_id,
                managed_by_principal=managed_by_principal,
            )
            if identity_binding is not None:
                permission_row = permissions_by_principal.get(str(identity_binding["principal_id"]))
                assignment_summary = _assignment_control_summary(
                    str(identity_binding["principal_id"]),
                    role_assignments_by_principal,
                )
                if permission_row is not None or assignment_summary is not None:
                    paths.append(
                        _build_compute_control_record(
                            family_name=family_name,
                            surface_row=row,
                            workload_row=workload,
                            identity_binding=identity_binding,
                            permission_row=permission_row,
                            assignment_summary=assignment_summary,
                        )
                    )
                    continue

            candidate_bindings = _mixed_identity_candidates(
                surface_row=row,
                workload_row=workload,
                managed_by_id=managed_by_id,
                managed_by_principal=managed_by_principal,
                permissions_by_principal=permissions_by_principal,
                role_assignments_by_principal=role_assignments_by_principal,
            )
            if candidate_bindings:
                paths.append(
                    _build_mixed_identity_candidate_record(
                        family_name=family_name,
                        surface_row=row,
                        workload_row=workload,
                        candidate_bindings=candidate_bindings,
                    )
                )
            continue

        identity_binding = _resolve_identity_binding(
            surface_row=row,
            workload_row=workload,
            managed_by_id=managed_by_id,
            managed_by_principal=managed_by_principal,
        )
        if identity_binding is None:
            continue

        permission_row = permissions_by_principal.get(str(identity_binding["principal_id"]))
        assignment_summary = _assignment_control_summary(
            str(identity_binding["principal_id"]),
            role_assignments_by_principal,
        )
        if permission_row is None and assignment_summary is None:
            continue

        paths.append(
            _build_compute_control_record(
                family_name=family_name,
                surface_row=row,
                workload_row=workload,
                identity_binding=identity_binding,
                permission_row=permission_row,
                assignment_summary=assignment_summary,
            )
        )

    paths.sort(
        key=lambda item: (
            semantic_priority_sort_value(item.priority),
            semantic_urgency_sort_value(item.urgency),
            item.asset_name,
            item.insertion_point or "",
        )
    )

    issues = [
        *getattr(tokens_output, "issues", []),
        *(getattr(env_output, "issues", []) if env_output is not None else []),
        *getattr(managed_output, "issues", []),
        *getattr(permissions_output, "issues", []),
        *getattr(workloads_output, "issues", []),
    ]
    return paths, issues


def _resolve_identity_binding(
    *,
    surface_row: dict,
    workload_row: dict,
    managed_by_id: dict[str, dict],
    managed_by_principal: dict[str, list[dict]],
) -> dict[str, object] | None:
    related_ids = [str(value) for value in surface_row.get("related_ids") or [] if value]
    workload_identity_ids = [
        str(value) for value in workload_row.get("identity_ids") or [] if value
    ]

    managed_matches = []
    seen_ids: set[str] = set()
    for value in [*related_ids, *workload_identity_ids]:
        if value in managed_by_id and value not in seen_ids:
            seen_ids.add(value)
            managed_matches.append(managed_by_id[value])

    if len(managed_matches) == 1:
        return _binding_from_managed_identity_row(managed_matches[0])

    if len(managed_matches) > 1:
        return None

    principal_id = str(workload_row.get("identity_principal_id") or "").strip()
    if not principal_id:
        principal_ids = {value for value in related_ids if _UUID_RE.match(value)}
        if len(principal_ids) == 1:
            principal_id = next(iter(principal_ids))

    if not principal_id:
        return None

    attached_binding = _attached_identity_binding_for_principal(
        principal_id=principal_id,
        asset_id=str(surface_row.get("asset_id") or ""),
        managed_by_principal=managed_by_principal,
    )
    if attached_binding is not None:
        return attached_binding

    return _workload_principal_binding(
        principal_id=principal_id,
        surface_row=surface_row,
        workload_row=workload_row,
    )


def _is_mixed_identity_workload(workload_row: dict) -> bool:
    return bool(workload_row.get("identity_principal_id")) and bool(
        workload_row.get("identity_ids")
    )


def _binding_from_managed_identity_row(managed_row: dict) -> dict[str, object] | None:
    principal_id = str(managed_row.get("principal_id") or "").strip()
    if not principal_id:
        return None
    return {
        "principal_id": principal_id,
        "identity_name": str(managed_row.get("name") or principal_id),
        "identity_id": str(managed_row.get("id") or principal_id),
        "binding_source": "managed-identity",
    }


def _attached_identity_binding_for_principal(
    *,
    principal_id: str,
    asset_id: str,
    managed_by_principal: dict[str, list[dict]],
) -> dict[str, object] | None:
    principal_matches = [
        item
        for item in managed_by_principal.get(principal_id, [])
        if asset_id in {str(value) for value in item.get("attached_to") or []}
    ]
    if len(principal_matches) != 1:
        return None
    return _binding_from_managed_identity_row(principal_matches[0])


def _workload_principal_binding(
    *,
    principal_id: str,
    surface_row: dict,
    workload_row: dict,
) -> dict[str, object]:
    return {
        "principal_id": principal_id,
        "identity_name": (
            f"{workload_row.get('asset_name') or surface_row.get('asset_name')} system identity"
        ),
        "identity_id": principal_id,
        "binding_source": "workload-principal",
    }


def _resolve_mixed_identity_binding(
    *,
    surface_row: dict,
    workload_row: dict,
    env_rows: list[dict],
    managed_by_id: dict[str, dict],
    managed_by_principal: dict[str, list[dict]],
) -> dict[str, object] | None:
    corroboration = _identity_choice_corroboration(workload_row, env_rows)
    if corroboration is None:
        return None

    if corroboration["identity_choice"] == "systemAssigned":
        principal_id = str(workload_row.get("identity_principal_id") or "").strip()
        if not principal_id:
            return None
        binding = _attached_identity_binding_for_principal(
            principal_id=principal_id,
            asset_id=str(surface_row.get("asset_id") or ""),
            managed_by_principal=managed_by_principal,
        ) or _workload_principal_binding(
            principal_id=principal_id,
            surface_row=surface_row,
            workload_row=workload_row,
        )
        binding["identity_choice_basis"] = corroboration["basis"]
        binding["identity_choice_detail"] = corroboration["detail"]
        return binding

    if corroboration["identity_choice"] == "userAssigned":
        identity_id = str(corroboration.get("identity_id") or "")
        if identity_id and identity_id in managed_by_id:
            binding = _binding_from_managed_identity_row(managed_by_id[identity_id])
            if binding is None:
                return None
            binding["identity_choice_basis"] = corroboration["basis"]
            binding["identity_choice_detail"] = corroboration["detail"]
            return binding
    return None


def _identity_choice_corroboration(
    workload_row: dict, env_rows: list[dict]
) -> dict[str, str] | None:
    identity_ids = [str(value) for value in workload_row.get("identity_ids") or [] if value]
    identity_names: dict[str, set[str]] = defaultdict(set)
    for identity_id in identity_ids:
        normalized = _normalized_identity_selector(identity_id)
        if normalized:
            identity_names[normalized].add(identity_id)
    identity_ids_set = set(identity_ids)
    corroborations: dict[tuple[str, str], dict[str, str]] = {}
    for row in env_rows:
        explicit_identity = str(row.get("key_vault_reference_identity") or "").strip()
        if not explicit_identity:
            continue
        basis = f"env-vars:{row.get('setting_name') or 'unknown-setting'}"
        if explicit_identity.lower() == "systemassigned":
            corroborations[("systemAssigned", "")] = {
                "identity_choice": "systemAssigned",
                "basis": basis,
                "detail": (
                    "current app configuration explicitly names SystemAssigned for a "
                    "collected workload behavior."
                ),
            }
            continue
        if explicit_identity in identity_ids_set:
            corroborations[("userAssigned", explicit_identity)] = {
                "identity_choice": "userAssigned",
                "identity_id": explicit_identity,
                "basis": basis,
                "detail": (
                    "current app configuration explicitly names the attached "
                    "user-assigned identity "
                    f"'{_display_identity_selector(explicit_identity)}' for a "
                    "collected workload behavior."
                ),
            }
            continue
        normalized_identity = _normalized_identity_selector(explicit_identity)
        matched_ids = identity_names.get(normalized_identity or "", set())
        if len(matched_ids) == 1:
            matched_identity_id = next(iter(matched_ids))
            corroborations[("userAssigned", matched_identity_id)] = {
                "identity_choice": "userAssigned",
                "identity_id": matched_identity_id,
                "basis": basis,
                "detail": (
                    "current app configuration explicitly names the attached "
                    "user-assigned identity "
                    f"'{_display_identity_selector(explicit_identity)}' for a "
                    "collected workload behavior."
                ),
            }

    if len(corroborations) != 1:
        return None
    return next(iter(corroborations.values()))


def _mixed_identity_candidates(
    *,
    surface_row: dict,
    workload_row: dict,
    managed_by_id: dict[str, dict],
    managed_by_principal: dict[str, list[dict]],
    permissions_by_principal: dict[str, dict],
    role_assignments_by_principal: dict[str, list[dict]],
) -> list[dict[str, str]]:
    asset_id = str(surface_row.get("asset_id") or "")
    candidates: list[dict[str, str]] = []
    seen_keys: set[tuple[str, str]] = set()

    system_principal_id = str(workload_row.get("identity_principal_id") or "").strip()
    if system_principal_id:
        system_match = _attached_identity_binding_for_principal(
            principal_id=system_principal_id,
            asset_id=asset_id,
            managed_by_principal=managed_by_principal,
        )
        if system_match is not None:
            candidates.append(system_match)
        else:
            candidates.append(
                _workload_principal_binding(
                    principal_id=system_principal_id,
                    surface_row=surface_row,
                    workload_row=workload_row,
                )
            )

    for identity_id in [str(value) for value in workload_row.get("identity_ids") or [] if value]:
        managed_row = managed_by_id.get(identity_id)
        if managed_row is None:
            candidates.append(
                {
                    "principal_id": "",
                    "identity_name": _display_identity_selector(identity_id),
                    "identity_id": identity_id,
                }
            )
            continue
        binding = _binding_from_managed_identity_row(managed_row)
        if binding is not None:
            candidates.append(binding)

    visible_candidates: list[dict[str, str]] = []
    for candidate in candidates:
        dedupe_key = (
            str(candidate.get("principal_id") or ""),
            str(candidate.get("identity_id") or ""),
        )
        if dedupe_key in seen_keys:
            continue
        seen_keys.add(dedupe_key)
        stronger_outcome, control_basis = _candidate_control_summary(
            candidate=candidate,
            permissions_by_principal=permissions_by_principal,
            role_assignments_by_principal=role_assignments_by_principal,
        )
        if stronger_outcome:
            candidate["stronger_outcome"] = stronger_outcome
            candidate["control_basis"] = control_basis or ""
        visible_candidates.append(candidate)

    if not any(item.get("stronger_outcome") for item in visible_candidates):
        return []
    return visible_candidates


def _candidate_control_summary(
    *,
    candidate: dict[str, str],
    permissions_by_principal: dict[str, dict],
    role_assignments_by_principal: dict[str, list[dict]],
) -> tuple[str | None, str | None]:
    principal_id = str(candidate.get("principal_id") or "").strip()
    if not principal_id:
        return None, None
    permission_summary = _permission_control_summary(permissions_by_principal.get(principal_id))
    if permission_summary:
        return permission_summary, "permissions"
    assignment_summary = _assignment_control_summary(
        principal_id,
        role_assignments_by_principal,
    )
    if assignment_summary:
        return assignment_summary, "role-assignment"
    return None, None


def _normalized_identity_selector(value: str) -> str:
    return value.rstrip("/").split("/")[-1].strip().lower()


def _display_identity_selector(value: str) -> str:
    if "/" not in value:
        return value
    return value.rstrip("/").split("/")[-1]


def _assignment_control_summary(
    principal_id: str,
    role_assignments_by_principal: dict[str, list[dict]],
) -> str | None:
    assignments = role_assignments_by_principal.get(principal_id, [])
    high_impact_roles = sorted(
        {
            str(item.get("role_name"))
            for item in assignments
            if str(item.get("role_name") or "").lower() in _HIGH_IMPACT_ROLE_NAMES
        }
    )
    if not high_impact_roles:
        return None

    scopes = sorted(
        {str(item.get("scope_id") or "") for item in assignments if item.get("scope_id")}
    )
    return (
        f"{', '.join(high_impact_roles)} "
        f"{permission_scope_phrase(scopes, scope_count=len(scopes))}"
    )


def _build_compute_control_record(
    *,
    family_name: str,
    surface_row: dict,
    workload_row: dict,
    identity_binding: dict[str, object],
    permission_row: dict | None,
    assignment_summary: str | None,
) -> ChainPathRecord:
    stronger_outcome = _permission_control_summary(permission_row) or assignment_summary or "-"
    public_foothold = _has_public_compute_signal(workload_row)
    binding_source = str(identity_binding.get("binding_source") or "managed-identity")
    identity_choice_basis = str(identity_binding.get("identity_choice_basis") or "")
    identity_choice_detail = str(identity_binding.get("identity_choice_detail") or "")
    mixed_identity_corroborated = bool(identity_choice_basis)

    if public_foothold:
        priority = "high"
        urgency = "pivot-now"
    else:
        priority = "medium"
        urgency = "review-soon"

    if mixed_identity_corroborated and permission_row is not None:
        confidence_boundary = (
            "Due to mixed identities and the current foothold, AzureFox cannot directly verify "
            "which attached identity the raw token path will choose on every request. Another "
            "collected workload surface currently points to this identity as the best current "
            f"lead, and the stronger Azure control behind it is visible. Specifically, "
            f"{identity_choice_detail}"
        )
    elif mixed_identity_corroborated:
        confidence_boundary = (
            "Due to mixed identities and the current foothold, AzureFox cannot directly verify "
            "which attached identity the raw token path will choose on every request. Another "
            "collected workload surface currently points to this identity as the best current "
            "lead. "
            f"Specifically, {identity_choice_detail}"
        )
    elif permission_row is not None and binding_source == "managed-identity":
        confidence_boundary = (
            "AzureFox can name the token-capable compute foothold, the attached identity, and "
            "the stronger Azure control behind it from current scope."
        )
    elif permission_row is not None:
        confidence_boundary = (
            "AzureFox can name the token-capable compute foothold and the workload principal "
            "that maps to stronger Azure control from current scope. The explicit managed "
            "identity anchor is inferred from workload metadata rather than a separate "
            "managed-identities row."
        )
    elif binding_source == "managed-identity":
        confidence_boundary = (
            "AzureFox can name the token-capable compute foothold and the attached identity, "
            "and can see a high-impact role signal on that identity. The fuller permission story "
            "still needs confirmation."
        )
    else:
        confidence_boundary = (
            "AzureFox can name the token-capable compute foothold and a high-impact role signal "
            "on the workload principal that identity uses, but the explicit managed identity "
            "anchor and fuller permission story still need confirmation."
        )

    next_review = _compute_control_next_review(
        workload_row,
        identity_choice_basis=identity_choice_basis,
    )
    identity_name = identity_binding["identity_name"]
    path_type = "direct-token-opportunity"
    if mixed_identity_corroborated:
        why_care = (
            f"{workload_row.get('asset_kind')} '{workload_row.get('asset_name')}' carries mixed "
            f"identities. Current collected workload behavior points to {identity_name} as the "
            f"best current lead, and that identity already maps to {stronger_outcome}."
        )
    else:
        why_care = (
            f"{workload_row.get('asset_kind')} '{workload_row.get('asset_name')}' can request "
            "tokens "
            f"as {identity_name}; that identity already maps to {stronger_outcome}."
        )
    why_care = _compute_control_why_care(
        why_care,
        surface_row=surface_row,
        workload_row=workload_row,
    )
    evidence_commands = ["tokens-credentials", "workloads"]
    joined_surface_types = ["managed-identity-token", "workload"]
    if mixed_identity_corroborated:
        evidence_commands.append("env-vars")
        joined_surface_types.append("identity-choice-corroboration")
    if binding_source == "managed-identity":
        evidence_commands.append("managed-identities")
        joined_surface_types.append("identity-anchor")
    else:
        joined_surface_types.append("workload-principal")
    if permission_row is not None:
        evidence_commands.append("permissions")
        joined_surface_types.append("permissions")
    else:
        joined_surface_types.append("role-assignment")

    return ChainPathRecord(
        **_base_compute_control_payload(
            surface_row=surface_row,
            workload_row=workload_row,
            chain_id=f"{family_name}::{surface_row.get('asset_id')}::{identity_binding['principal_id']}",
            path_type=path_type,
            confirmation_basis=(
                "mixed-identity-corroborated-permission-join"
                if mixed_identity_corroborated and permission_row is not None
                else "mixed-identity-corroborated-role-assignment-join"
                if mixed_identity_corroborated
                else "permission-join"
                if permission_row is not None
                else "role-assignment-join"
            ),
            priority=priority,
            urgency=urgency,
            stronger_outcome=stronger_outcome,
            why_care=why_care,
            likely_impact=stronger_outcome,
            confidence_boundary=confidence_boundary,
            target_resolution=(
                "identity-choice-corroborated" if mixed_identity_corroborated else "path-confirmed"
            ),
            evidence_commands=evidence_commands,
            joined_surface_types=joined_surface_types,
            target_ids=[str(identity_binding["identity_id"])],
            target_names=[str(identity_name)],
            next_review=next_review,
            missing_confirmation=(
                "Current foothold does not directly verify which attached identity the raw "
                "token path will choose on every request."
                if mixed_identity_corroborated
                else ""
            ),
            related_ids=_merge_related_ids(
                [str(value) for value in surface_row.get("related_ids") or [] if value],
                [str(value) for value in workload_row.get("related_ids") or [] if value],
                [str(identity_binding["identity_id"])],
            ),
        )
    )


def _base_compute_control_payload(
    *,
    surface_row: dict,
    workload_row: dict,
    chain_id: str,
    path_type: str,
    confirmation_basis: str,
    priority: str,
    urgency: str,
    stronger_outcome: str,
    why_care: str,
    likely_impact: str,
    confidence_boundary: str,
    target_resolution: str,
    evidence_commands: list[str],
    joined_surface_types: list[str],
    target_ids: list[str],
    target_names: list[str],
    next_review: str,
    missing_confirmation: str,
    related_ids: list[str],
) -> dict[str, object]:
    return {
        "chain_id": chain_id,
        "asset_id": str(surface_row.get("asset_id") or ""),
        "asset_name": str(surface_row.get("asset_name") or surface_row.get("asset_id") or ""),
        "asset_kind": str(surface_row.get("asset_kind") or workload_row.get("asset_kind") or ""),
        "location": surface_row.get("location") or workload_row.get("location"),
        "source_command": "tokens-credentials",
        "source_context": str(surface_row.get("access_path") or ""),
        "clue_type": str(surface_row.get("surface_type") or ""),
        "priority": priority,
        "urgency": urgency,
        "visible_path": str(surface_row.get("summary") or ""),
        "insertion_point": _compute_control_insertion_point(surface_row, workload_row),
        "path_concept": path_type,
        "confirmation_basis": confirmation_basis,
        "stronger_outcome": stronger_outcome,
        "why_care": why_care,
        "likely_impact": likely_impact,
        "confidence_boundary": confidence_boundary,
        "target_service": "azure-control",
        "target_resolution": target_resolution,
        "evidence_commands": evidence_commands,
        "joined_surface_types": joined_surface_types,
        "target_count": len(target_ids),
        "target_ids": target_ids,
        "target_names": target_names,
        "next_review": next_review,
        "summary": f"{confidence_boundary} {next_review}",
        "missing_confirmation": missing_confirmation,
        "related_ids": related_ids,
    }


def _build_mixed_identity_candidate_record(
    *,
    family_name: str,
    surface_row: dict,
    workload_row: dict,
    candidate_bindings: list[dict[str, str]],
) -> ChainPathRecord:
    control_candidates = [
        item for item in candidate_bindings if str(item.get("stronger_outcome") or "").strip()
    ]
    stronger_outcome = "; ".join(
        f"{item['identity_name']}={item['stronger_outcome']}" for item in control_candidates
    )
    control_bases = {str(item.get("control_basis") or "") for item in control_candidates}
    binding_sources = {str(item.get("binding_source") or "") for item in candidate_bindings}
    confidence_boundary = (
        "Based on the current evidence, this workload can request tokens through mixed attached "
        "identities, but AzureFox cannot directly verify which attached identity the raw token "
        "path will choose on every request. The attached identities currently in play are listed "
        "here instead of a single chosen lead."
    )
    next_review = (
        "The current foothold bounds this path to the attached identities shown here; exact "
        "per-request identity choice remains unconfirmed."
    )
    why_care = (
        f"{workload_row.get('asset_kind')} '{workload_row.get('asset_name')}' carries mixed "
        "identities. AzureFox cannot yet defend one chosen identity, but visible Azure control "
        f"currently maps to {stronger_outcome}."
    )
    why_care = _compute_control_why_care(
        why_care,
        surface_row=surface_row,
        workload_row=workload_row,
    )

    evidence_commands = ["tokens-credentials", "workloads"]
    joined_surface_types = ["managed-identity-token", "workload"]
    if "managed-identity" in binding_sources:
        evidence_commands.append("managed-identities")
        joined_surface_types.append("identity-anchor")
    if "workload-principal" in binding_sources:
        joined_surface_types.append("workload-principal")
    if "permissions" in control_bases:
        evidence_commands.append("permissions")
        joined_surface_types.append("permissions")
    if "role-assignment" in control_bases:
        joined_surface_types.append("role-assignment")

    target_ids = [
        str(item.get("identity_id") or "") for item in candidate_bindings if item.get("identity_id")
    ]
    target_names = [
        str(item.get("identity_name") or "")
        for item in candidate_bindings
        if item.get("identity_name")
    ]

    return ChainPathRecord(
        **_base_compute_control_payload(
            surface_row=surface_row,
            workload_row=workload_row,
            chain_id=f"{family_name}::{surface_row.get('asset_id')}::mixed-identities",
            path_type="direct-token-opportunity",
            confirmation_basis="mixed-identity-attached-candidates",
            priority="high" if _has_public_compute_signal(workload_row) else "medium",
            urgency="pivot-now" if _has_public_compute_signal(workload_row) else "review-soon",
            stronger_outcome=stronger_outcome,
            why_care=why_care,
            likely_impact=stronger_outcome,
            confidence_boundary=confidence_boundary,
            target_resolution="narrowed candidates",
            evidence_commands=evidence_commands,
            joined_surface_types=joined_surface_types,
            target_ids=target_ids,
            target_names=target_names,
            next_review=next_review,
            missing_confirmation=(
                "Current foothold does not directly verify which attached identity the raw "
                "token path will choose on every request."
            ),
            related_ids=_merge_related_ids(
                [str(value) for value in surface_row.get("related_ids") or [] if value],
                [str(value) for value in workload_row.get("related_ids") or [] if value],
                target_ids,
            ),
        )
    )


def _compute_control_insertion_point(surface_row: dict, workload_row: dict) -> str:
    access_path = str(surface_row.get("access_path") or "")
    if access_path == "imds":
        if _has_public_compute_signal(workload_row):
            return "public IMDS token path"
        return "IMDS token path"
    if access_path == "workload-identity":
        if _has_public_compute_signal(workload_row):
            return "reachable service token request path"
        return "service token request path"
    return access_path or "token-capable compute path"


def _compute_control_next_review(workload_row: dict, *, identity_choice_basis: str = "") -> str:
    asset_kind = str(workload_row.get("asset_kind") or "")
    if asset_kind == "VM":
        return (
            "Check vms for the host foothold, then permissions for exact scope on the attached "
            "identity."
        )
    if asset_kind == "VMSS":
        return (
            "Check vmss for the fleet foothold, then permissions for exact scope on the attached "
            "identity."
        )
    if asset_kind == "AppService":
        return (
            "Check app-services for the running service foothold, then permissions for exact "
            "scope on the attached identity."
        )
    if asset_kind == "FunctionApp":
        if identity_choice_basis:
            return (
                "Current collected workload configuration already narrows this path to the "
                "identity shown here; exact per-request token choice remains bounded by the "
                "current foothold."
            )
        return (
            "Check functions for the running service foothold, then permissions for exact scope "
            "on the attached identity."
        )
    return (
        "Check workloads for the compute foothold, then permissions for exact scope on the "
        "attached identity."
    )


def _compute_control_why_care(
    base_text: str,
    *,
    surface_row: dict,
    workload_row: dict,
) -> str:
    return f"{base_text} {_compute_control_required_foothold(surface_row, workload_row)}"


def _compute_control_required_foothold(surface_row: dict, workload_row: dict) -> str:
    access_path = str(surface_row.get("access_path") or "")
    asset_kind = str(workload_row.get("asset_kind") or "workload")
    public_signal = _has_public_compute_signal(workload_row)
    public_compute_label = (
        "this public-facing container group"
        if asset_kind == "ContainerInstance"
        else "this public-facing service"
    )
    public_token_request_label = (
        "make this public-facing container group ask Azure for its own token"
        if asset_kind == "ContainerInstance"
        else "make this public-facing service ask Azure for its own token"
    )
    internal_compute_label = (
        "this container group" if asset_kind == "ContainerInstance" else "this workload"
    )

    if access_path == "workload-identity":
        if public_signal:
            return (
                "To turn this into downstream Azure access, an operator would need "
                f"a way to {public_token_request_label}. AzureFox shows that "
                f"{public_compute_label} is public and token-capable, but public reachability "
                "alone does not prove that path."
            )
        return (
            "To turn this into downstream Azure access, an operator would need a service-side "
            f"foothold that can run inside {internal_compute_label} and invoke its token request "
            "path. "
            "AzureFox does not yet show that start from the current foothold."
        )

    if access_path == "imds":
        if public_signal:
            return (
                "To turn this into downstream Azure access, an operator would need a "
                "way to make this public-facing workload reach the Azure VM metadata service. "
                "AzureFox shows that the workload is public and IMDS-backed, but public "
                "reachability alone does not prove that path."
            )
        return (
            f"To turn this into downstream Azure access, an operator would need host-level "
            f"execution or admin access on this {asset_kind} so the Azure VM metadata token "
            "path is reachable. AzureFox does not yet show that start from the current foothold."
        )

    return (
        "To turn this into downstream Azure access, an operator would need a foothold that "
        "can reach the workload-side token path. AzureFox does not yet show that start from "
        "the current foothold."
    )


def _permission_control_summary(permission_row: dict | None) -> str | None:
    if not permission_row:
        return None

    roles = [str(role) for role in permission_row.get("high_impact_roles") or [] if role]
    role_text = ", ".join(roles) or "high-impact roles"
    return (
        f"{role_text} "
        f"{permission_scope_phrase(
            list(permission_row.get('scope_ids') or []),
            scope_count=int(
                permission_row.get('scope_count')
                or len(permission_row.get('scope_ids') or [])
                or 0
            ),
        )}"
    )


def _has_public_compute_signal(workload_row: dict) -> bool:
    return bool(workload_row.get("endpoints")) or any(
        str(value).lower() == "public-ip" for value in workload_row.get("exposure_families") or []
    )


def _merge_related_ids(*groups: list[str]) -> list[str]:
    seen: set[str] = set()
    merged: list[str] = []
    for group in groups:
        for value in group:
            if value and value not in seen:
                seen.add(value)
                merged.append(value)
    return merged
