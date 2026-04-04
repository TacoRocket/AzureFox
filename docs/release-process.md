# Release Process

Maintainer note:
These steps currently use Unix-style shell examples because the release workflow has been authored
and exercised that way so far. That is a maintainer workflow detail, not an operator-facing AzureFox
platform support statement.

## Versioning

Use semantic versioning (`MAJOR.MINOR.PATCH`).

Current project release-boundary rule:

- `PATCH` for fixes, packaging improvements, docs-only release-worthy corrections, and other
  backward-compatible cleanup to existing shipped behavior
- `MINOR` for a meaningful new AzureFox capability tranche that stays backward-compatible
- `MAJOR` only when operator-facing compatibility or output-contract expectations break in a
  meaningful way

Current tranche decision:

- `v1.0.0` represents the initial Phase 1 through Phase 3 command surface
- the grounded post-Phase-3 follow-on tranche should roll up into `v1.1.0`
- that tranche currently means:
  - `api-mgmt-depth`
  - `aks-depth`
  - `acr-depth`
  - `databases-relational-depth`
  - `dns-depth`
  - `storage-depth`
- do not bump to `v1.1.0` one slice at a time unless maintainers explicitly decide to change that
  release boundary

## Steps

1. Update `pyproject.toml` version.
2. Add release notes in `CHANGELOG.md`.
3. Run validation:
   ```bash
   python3 -m ruff check src tests scripts
   PYTHONPATH=src python3 scripts/generate_schemas.py
   PYTHONPATH=src python3 -m pytest -m "not integration"
   ```
4. Build release artifacts:
   ```bash
   python3 -m build
   ```
5. Smoke-test the built artifact from a fresh virtual environment:
   ```bash
   python3 -m venv /tmp/azurefox-release-venv
   /tmp/azurefox-release-venv/bin/pip install dist/azurefox-<version>-py3-none-any.whl
   /tmp/azurefox-release-venv/bin/azurefox help
   AZUREFOX_FIXTURE_DIR=tests/fixtures/lab_tenant \
     /tmp/azurefox-release-venv/bin/azurefox --outdir /tmp/azurefox-release-smoke --output json whoami
   ```
6. Optionally smoke-test the live Azure dependency profile from source:
   ```bash
   python3 -m venv /tmp/azurefox-release-live-venv
   /tmp/azurefox-release-live-venv/bin/pip install -e .
   /tmp/azurefox-release-live-venv/bin/azurefox help
   ```
7. Tag release:
   ```bash
   git tag v<version>
   git push origin v<version>
   ```
8. Let `.github/workflows/release.yml` publish the built artifacts:
   - to GitHub Releases with the tag name as the release title
   - to PyPI via Trusted Publishing from the `pypi` GitHub Actions environment
9. Keep PyPI publishing tokenless:
   - configure the PyPI trusted publisher for owner `TacoRocket`, repo `AzureFox`,
     workflow `release.yml`, and environment `pypi`
   - add protection rules to the `pypi` GitHub environment so publish approval stays explicit
