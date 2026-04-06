from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

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
from azurefox.env_var_hints import env_var_target_service
from azurefox.models.chains import (
    ChainSourceArtifact,
    ChainsOutput,
    CredentialPathRecord,
)
from azurefox.models.commands import (
    ChainsCommandOutput,
    DatabasesOutput,
    EnvVarsOutput,
    KeyVaultOutput,
    StorageOutput,
    TokensCredentialsOutput,
)
from azurefox.models.common import CollectionIssue, CommandMetadata
from azurefox.output.writer import emit_output
from azurefox.registry import get_command_specs

_SUPPORTED_IMPLEMENTED_FAMILIES = {"credential-path"}
_SOURCE_MODEL_MAP = {
    "env-vars": EnvVarsOutput,
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

    loaded = {
        source.command: _load_source_output(source)
        for source in source_artifacts
    }
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

    paths: list[CredentialPathRecord] = []
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
) -> CredentialPathRecord | None:
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

    return CredentialPathRecord(
        chain_id=_chain_id(env["asset_id"], env["setting_name"], "keyvault"),
        asset_id=env["asset_id"],
        asset_name=env["asset_name"],
        asset_kind=env["asset_kind"],
        location=env.get("location"),
        setting_name=env["setting_name"],
        clue_type="keyvault-reference",
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
) -> CredentialPathRecord:
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

    return CredentialPathRecord(
        chain_id=_chain_id(env["asset_id"], env["setting_name"], target_service),
        asset_id=env["asset_id"],
        asset_name=env["asset_name"],
        asset_kind=env["asset_kind"],
        location=env.get("location"),
        setting_name=env["setting_name"],
        clue_type="plain-text-secret",
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


def _target_visibility_note(target_label: str, issues: list[CollectionIssue]) -> str | None:
    if not issues:
        return None
    if any(issue.kind in {"permission_denied", "partial_collection"} for issue in issues):
        return (
            f"Current credentials may not show full {target_label} visibility, so this target "
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
