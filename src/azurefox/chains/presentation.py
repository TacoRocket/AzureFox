from __future__ import annotations


def compute_control_when_label(urgency: str) -> str:
    labels = {
        "pivot-now": "act now",
        "review-soon": "review soon",
        "bookmark": "keep in view",
    }
    return labels.get(urgency, urgency or "-")


def compute_control_token_path_label(insertion_point: str) -> str:
    labels = {
        "reachable service token request path": "service token request",
        "public IMDS token path": "public VM metadata token",
        "IMDS token path": "VM metadata token",
    }
    return labels.get(insertion_point, insertion_point or "-")


def compute_control_reach_from_here_label(insertion_point: str) -> str:
    if insertion_point in {"reachable service token request path", "public IMDS token path"}:
        return "public exposure visible; exploitation not proved"
    return "current access does not show the start"


def compute_control_identity_label(target_names: list[object]) -> str:
    names = [str(value) for value in target_names if str(value).strip()]
    if not names:
        return "not visible"
    if len(names) == 1:
        return names[0]
    return "multiple possible: " + ", ".join(names)


def compute_control_proof_status_label(target_resolution: str) -> str:
    labels = {
        "path-confirmed": "confirmed",
        "identity-choice-corroborated": "best current match",
        "narrowed candidates": "multiple identities possible",
        "visibility blocked": "limited visibility",
        "tenant-wide candidates": "broad match only",
        "service hint only": "early signal only",
        "named target not visible": "named identity not visible",
    }
    return labels.get(target_resolution, "bounded")


def escalation_path_type_label(path_concept: str) -> str:
    labels = {
        "current-foothold-direct-control": "current foothold direct control",
        "trust-expansion": "trust expansion",
    }
    return labels.get(path_concept, path_concept or "-")


def normalize_chain_payload_for_output(command: str, payload: dict) -> dict:
    if command != "chains":
        return payload
    family = str(payload.get("family") or "")
    if family not in {"compute-control", "escalation-path"}:
        return payload
    paths = payload.get("paths")
    if not isinstance(paths, list):
        return payload

    normalized_payload = dict(payload)
    normalized_payload["paths"] = [
        normalize_chain_path_row(family, row) if isinstance(row, dict) else row for row in paths
    ]
    return normalized_payload


def normalize_chain_path_row(family: str, row: dict) -> dict:
    normalized_row = dict(row)
    if family == "escalation-path":
        normalized_row["starting_foothold"] = str(
            row.get("starting_foothold") or row.get("asset_name") or ""
        )
        normalized_row["path_type"] = str(
            row.get("path_type")
            or escalation_path_type_label(str(row.get("path_concept") or ""))
        )
        normalized_row["note"] = str(row.get("why_care") or row.get("note") or "")
        return normalized_row

    insertion_point = str(row.get("insertion_point") or "")
    urgency = str(row.get("urgency") or "")
    target_resolution = str(row.get("target_resolution") or "")
    target_names = row.get("target_names") or []

    normalized_row["when"] = str(row.get("when") or compute_control_when_label(urgency))
    normalized_row["reach_from_here"] = str(
        row.get("reach_from_here")
        or compute_control_reach_from_here_label(insertion_point)
    )
    normalized_row["compute_foothold"] = str(
        row.get("compute_foothold") or row.get("asset_name") or ""
    )
    normalized_row["token_path"] = str(
        row.get("token_path") or compute_control_token_path_label(insertion_point)
    )
    normalized_row["identity"] = str(
        row.get("identity") or compute_control_identity_label(target_names)
    )
    normalized_row["azure_access"] = str(
        row.get("azure_access") or row.get("stronger_outcome") or row.get("likely_impact") or ""
    )
    normalized_row["proof_status"] = str(
        row.get("proof_status")
        or compute_control_proof_status_label(target_resolution)
    )
    normalized_row["note"] = str(row.get("why_care") or row.get("note") or "")
    return normalized_row
