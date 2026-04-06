from __future__ import annotations

from azurefox.chains.registry import (
    GROUPED_COMMAND_INPUT_MODES,
    GROUPED_COMMAND_NAME,
    PREFERRED_ARTIFACT_ORDER,
    get_chain_family_spec,
    get_chain_family_specs,
)
from azurefox.models.chains import (
    ChainFamilyDescriptor,
    ChainSourceDescriptor,
    ChainsScaffoldOutput,
)
from azurefox.models.common import CommandMetadata

CURRENT_BEHAVIOR = (
    "Internal scaffold only. The grouped runner shape, family registry, and minimum extraction "
    "points are recorded here, but full-family execution and joins are not implemented yet."
)


def build_chains_scaffold_output(selected_family: str | None = None) -> ChainsScaffoldOutput:
    specs = get_chain_family_specs()
    if selected_family is not None:
        spec = get_chain_family_spec(selected_family)
        if spec is None:
            raise ValueError(f"Unknown chain family '{selected_family}'")
        specs = (spec,)

    return ChainsScaffoldOutput(
        metadata=CommandMetadata(command=GROUPED_COMMAND_NAME),
        grouped_command_name=GROUPED_COMMAND_NAME,
        command_state="scaffold",
        current_behavior=CURRENT_BEHAVIOR,
        planned_input_modes=list(GROUPED_COMMAND_INPUT_MODES),
        preferred_artifact_order=list(PREFERRED_ARTIFACT_ORDER),
        selected_family=selected_family,
        families=[_descriptor_from_spec(spec) for spec in specs],
        issues=[],
    )


def _descriptor_from_spec(spec) -> ChainFamilyDescriptor:
    return ChainFamilyDescriptor(
        family=spec.name,
        meaning=spec.meaning,
        summary=spec.summary,
        allowed_claim=spec.allowed_claim,
        current_gap=spec.current_gap,
        best_current_examples=list(spec.best_current_examples),
        source_commands=[
            ChainSourceDescriptor(
                command=source.command,
                minimum_fields=list(source.minimum_fields),
                rationale=source.rationale,
            )
            for source in spec.source_commands
        ],
    )
