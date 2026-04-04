# Understanding Output

AzureFox writes table, JSON, CSV, and loot artifacts from the same underlying model output.
That means the formats are different views of the same collected result, not separate collectors.

## Output Modes

- `--output table` for quick operator reading in the terminal
- `--output json` for structured review and automation
- `--output csv` for spreadsheet-style inspection

Example:

```bash
azurefox --outdir ./azurefox-demo whoami --output json
```

## Artifact Layout

All commands write under `<outdir>/`:

- `loot/<command>.json`
- `json/<command>.json`
- `table/<command>.txt`
- `csv/<command>.csv`

`all-checks` also writes:

- `run-summary.json`

## What `run-summary.json` Means

`run-summary.json` is orchestration metadata for `all-checks`.
It tells you which commands ran and where their artifacts were written.
It is not a separate evidence source.

## Practical Reading Pattern

1. Start with terminal table output for quick triage.
2. Open the JSON artifact when you want the exact structured result.
3. Use the table or CSV files later if you want saved views outside the terminal.
4. For `all-checks`, use `run-summary.json` to jump into the per-command artifacts.

## Contract Expectations

- JSON output is deterministic.
- Table output should not invent fields that are absent from the JSON contract.
- Schema files under `schemas/` and snapshots under `tests/golden/` are the regression baseline.

If you need deeper reference or planning material outside a live operator run, use:

- `docs/output-contracts.md`
- `wiki/planning/api-mapping/`
