from __future__ import annotations

from pydantic import BaseModel, Field

from azurefox.models.common import CommandMetadata


class RunCommandResult(BaseModel):
    command: str
    section: str
    status: str
    artifact_paths: dict[str, str] = Field(default_factory=dict)
    error: str | None = None


class AllChecksSummary(BaseModel):
    metadata: CommandMetadata
    section: str | None = None
    results: list[RunCommandResult] = Field(default_factory=list)
