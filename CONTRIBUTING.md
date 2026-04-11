# Contributing

## Local Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
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

- Before changing output wording, proof language, help text, or artifact behavior that could apply
  across the HarrierOps family, read:
  - the shared family style guide
  - the shared family style guide applicability register
- Keep command boundaries stable.
- Use normalized models under `src/azurefox/models/`.
- Keep JSON output deterministic and schema-compatible.
- Keep family-wide truthfulness rules, claim-strength rules, and partial-read rules aligned with
  the shared family documents instead of re-inventing them in repo-local prose.
- Update schemas with `python scripts/generate_schemas.py`.
- If AzureFox needs a documented wording or contract exception, update the applicability register in
  the same change instead of leaving the exception implied only by local docs, help text, or tests.

## Documentation Boundaries

- Keep live operator guidance in `azurefox help`, `azurefox help <command>`, `README.md`, and curated `docs/` content.
- Keep non-operator documentation out of the repo unless the file is directly needed for build,
  validation, release, install, or packaging flow.
- Treat maintainer-only planning, drift-control, and family-governance notes as external reference
  material rather than repo content.
- If a temporary note or governance reminder lands locally during implementation, remove it before
  merge unless it is truly required for the repo to build, validate, release, install, or package.
- If planning material becomes durable user-facing documentation, promote it into maintained
  operator documentation instead of leaving internal notes in the repo.

## Lightweight Guardrails (Solo)

- Create a short-lived branch per change (`feat/...`, `fix/...`, `docs/...`).
- Open a PR into `main` even when working solo.
- Keep PRs small and single-purpose.
- Merge only after CI is green.
- If command output contracts change, update schema snapshots and golden fixtures in the same PR.
- Local pre-push hook blocks `codex` branch names, blocks direct pushes to `main`, and runs lint/tests.
- CI blocks Codex-branded PR titles.
- Temporary bypass for emergency push: `AZUREFOX_ALLOW_MAIN_PUSH=1 git push`.
- Before merge, remove any non-operator doc that is not required for build, validation, release,
  install, or packaging.
