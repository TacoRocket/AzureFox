# Release Process

## Versioning

Use semantic versioning (`MAJOR.MINOR.PATCH`).

## Steps

1. Update `pyproject.toml` version.
2. Add release notes in `CHANGELOG.md`.
3. Run `ruff check .` and `pytest -m "not integration"`.
4. Tag release:
   ```bash
   git tag v<version>
   git push origin v<version>
   ```
5. Publish package artifact (future step once packaging registry target is selected).

