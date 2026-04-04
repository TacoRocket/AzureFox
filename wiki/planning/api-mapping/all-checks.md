# all-checks API Mapping

## Slice Goal

Provide a stable operator-first orchestration path across implemented commands and sections.

This first version answers:
"What is the cleanest grouped sweep I can run right now for this tenant or one section, and where
did each command write its artifacts?"

## Initial Scope

- Stable command ordering across implemented slices
- Optional section filtering
- Per-command status and artifact-path reporting in `run-summary.json`
- Reuse of each command's existing output contract rather than inventing a second format

## Explicit Non-Goals For V1

- Runtime optimization or deduplication across commands
- Special broad-graph modes beyond the normal implemented command set
- Replacement of the flat standalone command workflow

## Primary Inputs

- AzureFox command registry and section mappings
- The existing standalone command collectors and output writers

## Correlation / Joins

- Run the implemented commands in a stable operator-first sequence and summarize their outcomes
- Keep orchestration metadata explicit so operators can inspect per-command artifacts directly

## Blind Spots

- `all-checks` is an orchestration layer, not a separate evidence source
- A slower grouped run does not imply broader proof than the underlying command outputs provide

