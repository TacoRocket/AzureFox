from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from azurefox.chains.handler_registry import ChainFamilyHandler, run_chain_handlers
from azurefox.chains.semantics import ChainSemanticContext, evaluate_chain_semantics
from azurefox.collectors.provider import BaseProvider
from azurefox.env_var_hints import env_var_target_services
from azurefox.models.chains import ChainPathRecord
from azurefox.models.common import CollectionIssue

_CANDIDATE_LIMIT = 3
_CREDENTIAL_PATH_SOURCE_NAMES = (
    "env-vars",
    "tokens-credentials",
    "databases",
    "storage",
    "keyvault",
)


@dataclass(frozen=True, slots=True)
class CredentialPathTargetView:
    service: str
    label: str
    candidates: list[dict]
    visibility_note: str | None
    visibility_issue: str | None


@dataclass(frozen=True, slots=True)
class CredentialPathSource:
    env: dict
    joined_surfaces: list[dict]


@dataclass(frozen=True, slots=True)
class CredentialPathState:
    provider: BaseProvider
    family_name: str
    target_views: dict[str, CredentialPathTargetView]

    def target_view(self, service: str) -> CredentialPathTargetView:
        return self.target_views[service]


@dataclass(frozen=True, slots=True)
class KeyVaultCredentialPathHandler:
    name: str = "keyvault"

    def build_records(
        self,
        state: CredentialPathState,
        source: CredentialPathSource,
    ) -> list[ChainPathRecord]:
        if source.env.get("value_type") != "keyvault-ref":
            return []

        target_view = state.target_view("keyvault")
        record = _build_keyvault_record(
            state.provider,
            state.family_name,
            source.env,
            source.joined_surfaces,
            target_view.candidates,
            visibility_note=target_view.visibility_note,
        )
        return [record] if record is not None else []


@dataclass(frozen=True, slots=True)
class CandidateCredentialPathHandler:
    name: str
    target_service: str

    def build_records(
        self,
        state: CredentialPathState,
        source: CredentialPathSource,
    ) -> list[ChainPathRecord]:
        if not _is_credential_like_env_var(source.env, source.joined_surfaces):
            return []
        if self.target_service not in env_var_target_services(
            str(source.env.get("setting_name") or "")
        ):
            return []

        target_view = state.target_view(self.target_service)
        return [
            _build_candidate_record(
                state.family_name,
                source.env,
                source.joined_surfaces,
                self.target_service,
                target_view.candidates,
                visibility_note=target_view.visibility_note,
                visibility_issue=target_view.visibility_issue,
            )
        ]


CREDENTIAL_PATH_HANDLERS: tuple[
    ChainFamilyHandler[CredentialPathState, CredentialPathSource], ...
] = (
    KeyVaultCredentialPathHandler(),
    CandidateCredentialPathHandler(name="database", target_service="database"),
    CandidateCredentialPathHandler(name="storage", target_service="storage"),
)


def collect_credential_path_records(
    provider: BaseProvider,
    family_name: str,
    loaded: dict[str, object],
) -> tuple[list[ChainPathRecord], list[CollectionIssue]]:
    state = CredentialPathState(
        provider=provider,
        family_name=family_name,
        target_views=_build_target_views(loaded),
    )
    sources = _build_credential_path_sources(loaded)
    paths = run_chain_handlers(CREDENTIAL_PATH_HANDLERS, state=state, sources=sources)

    issues: list[CollectionIssue] = []
    for source_name in _CREDENTIAL_PATH_SOURCE_NAMES:
        issues.extend(getattr(loaded[source_name], "issues", []))

    return paths, issues


def _build_target_views(loaded: dict[str, object]) -> dict[str, CredentialPathTargetView]:
    database_output = loaded["databases"]
    storage_output = loaded["storage"]
    keyvault_output = loaded["keyvault"]

    return {
        "database": CredentialPathTargetView(
            service="database",
            label="database",
            candidates=[
                item.model_dump(mode="json") for item in database_output.database_servers
            ],
            visibility_note=_target_visibility_note(
                "database", getattr(database_output, "issues", [])
            ),
            visibility_issue=_target_visibility_issue(getattr(database_output, "issues", [])),
        ),
        "storage": CredentialPathTargetView(
            service="storage",
            label="storage",
            candidates=[item.model_dump(mode="json") for item in storage_output.storage_assets],
            visibility_note=_target_visibility_note(
                "storage", getattr(storage_output, "issues", [])
            ),
            visibility_issue=_target_visibility_issue(getattr(storage_output, "issues", [])),
        ),
        "keyvault": CredentialPathTargetView(
            service="keyvault",
            label="Key Vault",
            candidates=[item.model_dump(mode="json") for item in keyvault_output.key_vaults],
            visibility_note=_target_visibility_note(
                "Key Vault", getattr(keyvault_output, "issues", [])
            ),
            visibility_issue=_target_visibility_issue(getattr(keyvault_output, "issues", [])),
        ),
    }


def _build_credential_path_sources(loaded: dict[str, object]) -> list[CredentialPathSource]:
    env_output = loaded["env-vars"]
    token_output = loaded["tokens-credentials"]

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

    sources: list[CredentialPathSource] = []
    for env_var in env_output.env_vars:
        env = env_var.model_dump(mode="json")
        setting_key = (env["asset_id"], env["setting_name"].lower())
        joined_surfaces = list(token_setting_index.get(setting_key, []))
        if env.get("value_type") == "keyvault-ref" and env.get("reference_target"):
            joined_surfaces.extend(
                keyvault_surface_index.get(
                    (env["asset_id"], _normalize_reference_target(env["reference_target"])),
                    [],
                )
            )
        sources.append(CredentialPathSource(env=env, joined_surfaces=joined_surfaces))

    return sources


def _build_keyvault_record(
    provider: BaseProvider,
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
    vault_name = target_names[0] if target_names else reference_host.split(".", 1)[0]
    secret_name, secret_version = _reference_secret_parts(reference_target)
    access_verdict = provider.keyvault_secret_access(
        vault_name=vault_name,
        vault_resource_id=target_ids[0] if target_ids else None,
        secret_name=secret_name or "",
        secret_version=secret_version,
    )
    current_identity_access = str(access_verdict.get("state") or "unknown")
    target_resolution = "named match" if matched_vaults else "named target not visible"
    visible_path = "Workload setting -> named Key Vault dependency"
    access_sentence = _keyvault_access_summary_sentence(current_identity_access)
    if matched_vaults:
        summary = (
            f"{env['asset_kind']} '{env['asset_name']}' pulls '{env['setting_name']}' from Key "
            f"Vault '{target_names[0]}'."
        )
        if len(target_names) > 1:
            summary = (
                f"{summary[:-1]} Matching visible vaults: "
                f"{', '.join(target_names[:_CANDIDATE_LIMIT])}."
            )
    else:
        summary = (
            f"{env['asset_kind']} '{env['asset_name']}' pulls '{env['setting_name']}' from Key "
            f"Vault '{reference_host}', but AzureFox cannot see that vault in current inventory."
        )
    if access_sentence:
        summary = f"{summary} {access_sentence}"
    if visibility_note:
        summary = f"{summary} {visibility_note}"

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
        urgency=semantic.urgency,
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
        confidence_boundary=_keyvault_access_note(current_identity_access),
        summary=summary,
        missing_confirmation=_keyvault_missing_confirmation(current_identity_access),
        related_ids=_merge_related_ids(
            env.get("related_ids", []),
            *[surface.get("related_ids", []) for surface in joined_surfaces],
            target_ids,
        ),
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
        urgency=semantic.urgency,
        visible_path=f"Credential-like setting -> likely {target_service} path",
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
        confidence_boundary=_candidate_confidence_boundary(
            target_service=target_service,
            target_resolution=target_resolution,
            target_names=target_names,
        ),
        summary=_candidate_summary(
            env=env,
            target_service=target_service,
            target_names=target_names,
            target_resolution=target_resolution,
            visibility_note=visibility_note,
        ),
        missing_confirmation=_candidate_missing_confirmation(
            target_service=target_service,
            target_resolution=target_resolution,
            target_count=len(target_ids),
            visibility_issue=visibility_issue,
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


def _candidate_summary(
    *,
    env: dict,
    target_service: str,
    target_names: list[str],
    target_resolution: str,
    visibility_note: str | None = None,
) -> str:
    prefix = (
        f"{env['asset_kind']} '{env['asset_name']}' exposes '{env['setting_name']}' as a "
        "plain-text secret-shaped setting. "
    )

    if target_resolution == "visibility blocked":
        summary = (
            f"{prefix}AzureFox cannot tell which {target_service} it reaches because current "
            "credentials do not show enough target-side visibility."
        )
        if visibility_note:
            summary = f"{summary} {visibility_note}"
        return summary

    if target_resolution == "narrowed candidates":
        summary = (
            f"{prefix}That likely feeds a {target_service} path. AzureFox cannot name the exact "
            f"{target_service} yet, but it can narrow the next review set to "
            f"{len(target_names)} visible {target_service} candidate(s) in the same Azure "
            f"location: {', '.join(target_names[:_CANDIDATE_LIMIT])}."
        )
        if visibility_note:
            summary = f"{summary} {visibility_note}"
        return summary

    if target_resolution == "tenant-wide candidates":
        summary = (
            f"{prefix}That likely feeds a {target_service} path, but AzureFox cannot narrow it "
            f"beyond tenant-visible {target_service} candidate(s) yet: "
            f"{', '.join(target_names[:_CANDIDATE_LIMIT])}."
        )
        if visibility_note:
            summary = f"{summary} {visibility_note}"
        return summary

    summary = f"{prefix}AzureFox has not yet narrowed it to a specific {target_service} asset."
    if visibility_note:
        summary = f"{summary} {visibility_note}"
    return summary


def _candidate_confidence_boundary(
    *,
    target_service: str,
    target_resolution: str,
    target_names: list[str],
) -> str:
    if target_resolution == "visibility blocked":
        return (
            f"Current scope does not confirm which downstream {target_service} target this "
            "setting reaches."
        )

    if target_resolution == "narrowed candidates":
        candidate_count = max(len(target_names), 1)
        candidate_text = "candidate" if candidate_count == 1 else "candidates"
        return (
            f"AzureFox narrowed this to {candidate_count} visible {target_service} "
            f"{candidate_text}, but the loaded evidence does not name the exact target, so this "
            "setting is not confirmed to reach it."
        )

    if target_resolution == "tenant-wide candidates":
        return (
            f"AzureFox can only narrow this to a broad visible {target_service} set so far; "
            "the loaded evidence does not name the exact target, so this setting is not "
            "confirmed to reach a specific downstream target."
        )

    if target_resolution == "service hint only":
        return (
            f"AzureFox only has a service hint for this {target_service} path so far; no "
            "concrete downstream target is visible, so this setting is not confirmed to reach a "
            "specific downstream target."
        )

    return (
        f"AzureFox has not yet proved the exact downstream {target_service} target, so this "
        "setting is not confirmed to reach a specific downstream target."
    )


def _candidate_missing_confirmation(
    *,
    target_service: str,
    target_resolution: str,
    target_count: int,
    visibility_issue: str | None,
) -> str:
    if target_resolution == "visibility blocked" or visibility_issue:
        return (
            f"Current scope does not confirm which {target_service} target this setting reaches. "
            "AzureFox also has not proved a working credential there."
        )
    if target_resolution == "narrowed candidates":
        if target_count == 1:
            return (
                f"Current env-vars and token surfaces narrow this to one visible "
                f"{target_service} candidate, but they do not name the exact downstream target. "
                "AzureFox also has not proved a working credential there."
            )
        return (
            f"Current env-vars and token surfaces narrow this to {target_count} visible "
            f"{target_service} candidates, but they do not show which one this setting reaches. "
            "AzureFox also has not proved a working credential against any listed target."
        )
    if target_resolution == "tenant-wide candidates":
        return (
            f"Current evidence only narrows this to a broad visible {target_service} set and "
            "does not name the exact downstream target. AzureFox also has not proved a working "
            "credential there."
        )
    if target_resolution == "service hint only":
        return (
            f"Current evidence suggests a {target_service} path, but no concrete downstream "
            "target is visible from current inventory and AzureFox has not proved a working "
            "credential."
        )
    return (
        f"AzureFox has not yet proved the exact downstream {target_service} target or a working "
        "credential."
    )


def _target_visibility_note(target_label: str, issues: list[CollectionIssue]) -> str | None:
    if not issues:
        return None
    if any(issue.kind in {"permission_denied", "partial_collection"} for issue in issues):
        return (
            f"Current scope may not show full {target_label} visibility, so this target picture "
            "may be incomplete."
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


def _reference_secret_parts(value: str | None) -> tuple[str | None, str | None]:
    normalized = _normalize_reference_target(value or "")
    parts = [part for part in normalized.split("/") if part]
    if len(parts) < 3 or parts[1] != "secrets":
        return None, None
    secret_name = parts[2] or None
    secret_version = parts[3] if len(parts) > 3 else None
    return secret_name, secret_version


def _keyvault_access_summary_sentence(access_state: str) -> str | None:
    if access_state == "can-read":
        return "Your current identity can read that secret."
    if access_state == "cannot-read":
        return "Your current identity cannot read that secret."
    if access_state == "appears-able":
        return "Your current identity appears able to read secrets there."
    return None


def _keyvault_access_note(access_state: str) -> str:
    if access_state == "can-read":
        return "Your current identity can read this secret."
    if access_state == "cannot-read":
        return "Your current identity cannot read this secret."
    if access_state == "appears-able":
        return "Your current identity appears able to read secrets there."
    return (
        "AzureFox can name the vault, but cannot yet tell whether your current identity can read "
        "the secret."
    )


def _keyvault_missing_confirmation(access_state: str) -> str:
    if access_state == "appears-able":
        return "AzureFox has not yet proved a live secret read with your current identity."
    if access_state in {"can-read", "cannot-read"}:
        return ""
    return (
        "AzureFox has not yet shown whether your current identity or the workload identity can "
        "read that secret."
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


def _chain_id(asset_id: str, setting_name: str, target_service: str) -> str:
    normalized_setting = setting_name.lower().replace("_", "-")
    return f"credential-path::{asset_id}::{normalized_setting}::{target_service}"
