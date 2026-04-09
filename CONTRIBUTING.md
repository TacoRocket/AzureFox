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

- Keep command boundaries stable.
- Use normalized models under `src/azurefox/models/`.
- Keep JSON output deterministic and schema-compatible.
- Update schemas with `python scripts/generate_schemas.py`.

## Documentation Boundaries

- Keep live operator guidance in `azurefox help`, `azurefox help <command>`, `README.md`, and curated `docs/` content.
- Treat `wiki/` as source material for intentional long-form wiki pages, not as a catch-all for internal planning notes.
- Do not add new command-by-command planning trees under `wiki/` unless they are actively maintained and have a clear published destination.
- If a note is temporary design scratch work, keep it out of the main repo or remove it once the implementation lands.
- If planning material becomes durable user-facing documentation, promote it into a maintained docs/wiki page instead of leaving README links pointed at planning notes.

## Lightweight Guardrails (Solo)

- Create a short-lived branch per change (`feat/...`, `fix/...`, `docs/...`).
- Open a PR into `main` even when working solo.
- Keep PRs small and single-purpose.
- Merge only after CI is green.
- If command output contracts change, update schema snapshots and golden fixtures in the same PR.
- Local pre-push hook blocks `codex` branch names, blocks direct pushes to `main`, and runs lint/tests.
- CI blocks Codex-branded PR titles.
- Temporary bypass for emergency push: `AZUREFOX_ALLOW_MAIN_PUSH=1 git push`.
