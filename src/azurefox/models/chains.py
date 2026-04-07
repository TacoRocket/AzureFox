from __future__ import annotations

from pydantic import BaseModel, Field

from azurefox.models.common import CollectionIssue, CommandMetadata


class ChainSourceDescriptor(BaseModel):
    command: str
    minimum_fields: list[str] = Field(default_factory=list)
    rationale: str


class ChainFamilyDescriptor(BaseModel):
    family: str
    meaning: str
    summary: str
    allowed_claim: str
    current_gap: str
    best_current_examples: list[str] = Field(default_factory=list)
    source_commands: list[ChainSourceDescriptor] = Field(default_factory=list)


class ChainsScaffoldOutput(BaseModel):
    metadata: CommandMetadata
    grouped_command_name: str
    command_state: str
    current_behavior: str
    planned_input_modes: list[str] = Field(default_factory=list)
    preferred_artifact_order: list[str] = Field(default_factory=list)
    selected_family: str | None = None
    families: list[ChainFamilyDescriptor] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)


class ChainSourceArtifact(BaseModel):
    command: str
    artifact_type: str
    path: str


class ChainPathRecord(BaseModel):
    chain_id: str
    asset_id: str
    asset_name: str
    asset_kind: str
    location: str | None = None
    source_command: str | None = None
    source_context: str | None = None
    setting_name: str | None = None
    clue_type: str
    confirmation_basis: str | None = None
    priority: str
    visible_path: str
    path_concept: str | None = None
    primary_injection_surface: str | None = None
    primary_trusted_input_ref: str | None = None
    why_care: str | None = None
    likely_impact: str | None = None
    confidence_boundary: str | None = None
    target_service: str
    target_resolution: str
    evidence_commands: list[str] = Field(default_factory=list)
    joined_surface_types: list[str] = Field(default_factory=list)
    target_count: int = 0
    target_ids: list[str] = Field(default_factory=list)
    target_names: list[str] = Field(default_factory=list)
    target_visibility_issue: str | None = None
    next_review: str
    summary: str
    missing_confirmation: str
    related_ids: list[str] = Field(default_factory=list)


CredentialPathRecord = ChainPathRecord


class ChainsOutput(BaseModel):
    metadata: CommandMetadata
    grouped_command_name: str
    family: str
    input_mode: str
    command_state: str
    summary: str
    claim_boundary: str
    artifact_preference_order: list[str] = Field(default_factory=list)
    backing_commands: list[str] = Field(default_factory=list)
    source_artifacts: list[ChainSourceArtifact] = Field(default_factory=list)
    paths: list[ChainPathRecord] = Field(default_factory=list)
    issues: list[CollectionIssue] = Field(default_factory=list)
