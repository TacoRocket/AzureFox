# Command Output Source

This folder holds generated, trimmed AzureFox example output for downstream wiki work.

It is intentionally neutral source material:

- not `wiki/seed`
- not product docs
- not a regression baseline

Current structure:

- `command-output/<command>/output.json`
- `command-output/<command>/table.txt`
- `command-output/chains/<family>/output.json`
- `command-output/chains/<family>/table.txt`

Generation rules:

- examples come from `tests/fixtures/lab_tenant`
- `metadata.generated_at` is normalized to `<generated_at>`
- top-level lists are trimmed to the first `3` entries to keep examples readable
- grouped chain families stay under `command-output/chains/` so they are separate from flat commands

To refresh the examples from current behavior:

```bash
python3 scripts/generate_command_output_examples.py
```
