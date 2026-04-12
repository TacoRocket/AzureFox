from __future__ import annotations

import re
from collections import defaultdict

from azurefox.chains.semantics import semantic_priority_sort_value, semantic_urgency_sort_value
from azurefox.models.chains import ChainPathRecord
from azurefox.models.common import CollectionIssue

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
    managed_output = loaded["managed-identities"]
    permissions_output = loaded["permissions"]
    workloads_output = loaded["workloads"]

    workloads_by_asset = {
        item.asset_id: item.model_dump(mode="json")
        for item in workloads_output.workloads
        if item.asset_id
    }
    managed_by_id = {
        item.id: item.model_dump(mode="json")
        for item in managed_output.identities
        if item.id
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

        identity_binding = _resolve_identity_binding(
            surface_row=row,
            workload_row=workload,
            managed_by_id=managed_by_id,
            managed_by_principal=managed_by_principal,
        )
        if identity_binding is None:
            continue

        permission_row = permissions_by_principal.get(identity_binding["principal_id"])
        assignment_summary = _assignment_control_summary(
            identity_binding["principal_id"],
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
) -> dict[str, str] | None:
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

    # Mixed system-assigned and user-assigned identities stay out of the narrow v1
    # until the actor is explicit enough to defend one default row.
    if workload_row.get("identity_principal_id") and workload_identity_ids:
        return None

    if len(managed_matches) == 1:
        principal_id = str(managed_matches[0].get("principal_id") or "").strip()
        if not principal_id:
            return None
        return {
            "principal_id": principal_id,
            "identity_name": str(managed_matches[0].get("name") or principal_id),
            "identity_id": str(managed_matches[0].get("id") or ""),
            "binding_source": "managed-identity",
        }

    if len(managed_matches) > 1:
        return None

    principal_id = str(workload_row.get("identity_principal_id") or "").strip()
    if not principal_id:
        principal_ids = {
            value for value in related_ids if _UUID_RE.match(value)
        }
        if len(principal_ids) == 1:
            principal_id = next(iter(principal_ids))

    if not principal_id:
        return None

    principal_matches = [
        item
        for item in managed_by_principal.get(principal_id, [])
        if str(surface_row.get("asset_id") or "")
        in {str(value) for value in item.get("attached_to") or []}
    ]
    if len(principal_matches) == 1:
        return {
            "principal_id": principal_id,
            "identity_name": str(principal_matches[0].get("name") or principal_id),
            "identity_id": str(principal_matches[0].get("id") or principal_id),
            "binding_source": "managed-identity",
        }
    if len(principal_matches) > 1:
        return None

    return {
        "principal_id": principal_id,
        "identity_name": (
            f"{workload_row.get('asset_name') or surface_row.get('asset_name')} system identity"
        ),
        "identity_id": principal_id,
        "binding_source": "workload-principal",
    }


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

    scopes = {str(item.get("scope_id") or "") for item in assignments if item.get("scope_id")}
    scope_count = len(scopes)
    scope_text = "subscription-wide scope" if scope_count <= 1 else f"{scope_count} visible scopes"
    return f"{', '.join(high_impact_roles)} across {scope_text}"


def _build_compute_control_record(
    *,
    family_name: str,
    surface_row: dict,
    workload_row: dict,
    identity_binding: dict[str, str],
    permission_row: dict | None,
    assignment_summary: str | None,
) -> ChainPathRecord:
    stronger_outcome = _permission_control_summary(permission_row) or assignment_summary or "-"
    public_foothold = _has_public_compute_signal(workload_row)
    binding_source = str(identity_binding.get("binding_source") or "managed-identity")

    if public_foothold:
        priority = "high"
        urgency = "pivot-now"
    else:
        priority = "medium"
        urgency = "review-soon"

    if permission_row is not None and binding_source == "managed-identity":
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

    next_review = _compute_control_next_review(workload_row)
    identity_name = identity_binding["identity_name"]
    path_type = "direct-token-opportunity"
    why_care = (
        f"{workload_row.get('asset_kind')} '{workload_row.get('asset_name')}' can request tokens "
        f"as {identity_name}; that identity already maps to {stronger_outcome}."
    )
    evidence_commands = ["tokens-credentials", "workloads"]
    joined_surface_types = ["managed-identity-token", "workload"]
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
        chain_id=(
            f"{family_name}::{surface_row.get('asset_id')}::{identity_binding['principal_id']}"
        ),
        asset_id=str(surface_row.get("asset_id") or ""),
        asset_name=str(surface_row.get("asset_name") or surface_row.get("asset_id") or ""),
        asset_kind=str(surface_row.get("asset_kind") or workload_row.get("asset_kind") or ""),
        location=surface_row.get("location") or workload_row.get("location"),
        source_command="tokens-credentials",
        source_context=str(surface_row.get("access_path") or ""),
        clue_type=str(surface_row.get("surface_type") or ""),
        confirmation_basis=(
            "permission-join" if permission_row is not None else "role-assignment-join"
        ),
        priority=priority,
        urgency=urgency,
        visible_path=str(surface_row.get("summary") or ""),
        insertion_point=_compute_control_insertion_point(surface_row, workload_row),
        path_concept=path_type,
        stronger_outcome=stronger_outcome,
        why_care=why_care,
        likely_impact=stronger_outcome,
        confidence_boundary=confidence_boundary,
        target_service="azure-control",
        target_resolution="path-confirmed",
        evidence_commands=evidence_commands,
        joined_surface_types=joined_surface_types,
        target_count=1,
        target_ids=[identity_binding["identity_id"]],
        target_names=[identity_name],
        next_review=next_review,
        summary=f"{confidence_boundary} {next_review}",
        missing_confirmation="",
        related_ids=_merge_related_ids(
            [str(value) for value in surface_row.get("related_ids") or [] if value],
            [str(value) for value in workload_row.get("related_ids") or [] if value],
            [identity_binding["identity_id"]],
        ),
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


def _compute_control_next_review(workload_row: dict) -> str:
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
        return (
            "Check functions for the running service foothold, then permissions for exact scope "
            "on the attached identity."
        )
    return (
        "Check workloads for the compute foothold, then permissions for exact scope on the "
        "attached identity."
    )


def _permission_control_summary(permission_row: dict | None) -> str | None:
    if not permission_row:
        return None

    roles = [str(role) for role in permission_row.get("high_impact_roles") or [] if role]
    role_text = ", ".join(roles) or "high-impact roles"
    scope_count = int(
        permission_row.get("scope_count") or len(permission_row.get("scope_ids") or []) or 0
    )
    scope_text = "subscription-wide scope" if scope_count <= 1 else f"{scope_count} visible scopes"
    return f"{role_text} across {scope_text}"


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
