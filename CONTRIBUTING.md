# Contributing

## Local Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev,azure]
bash scripts/setup_local_guardrails.sh
```

## Test Matrix

- Unit tests: models, correlation, collector transformations
- Contract tests: schema snapshots under `schemas/`
- Smoke tests: CLI command execution using fixtures
- Integration tests: real Azure lab tenant (manual/opt-in)

Run default suite:

```bash
ruff check .
pytest -m "not integration"
```

Run integration suite:

```bash
export AZUREFOX_RUN_INTEGRATION=1
export AZURE_SUBSCRIPTION_ID=<subscription-id>
pytest -m integration
```

## Semantics + Contracts

- Keep command boundaries stable.
- Use normalized models under `src/azurefox/models/`.
- Keep JSON output deterministic and schema-compatible.
- Update schemas with `python scripts/generate_schemas.py`.

## Lightweight Guardrails (Solo)

- Create a short-lived branch per change (`feat/...`, `fix/...`, `docs/...`).
- Open a PR into `main` even when working solo.
- Keep PRs small and single-purpose.
- Merge only after CI is green.
- If command output contracts change, update schema snapshots and golden fixtures in the same PR.
- Local pre-push hook blocks direct pushes to `main` and runs lint/tests.
- Temporary bypass for emergency push: `AZUREFOX_ALLOW_MAIN_PUSH=1 git push`.
