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
