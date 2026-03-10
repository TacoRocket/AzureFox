# AzureFox

AzureFox is a Python CLI for offensive-focused Azure situational awareness.

## Milestone 1 Commands

- `whoami`
- `inventory`
- `rbac`
- `managed-identities`
- `storage`
- `vms`

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev,azure]
azurefox whoami --output table
```

## Auth Precedence

1. Azure CLI credential
2. Environment/service principal credential

Azure CLI example:

```bash
az login
az account set --subscription <subscription-id>
azurefox inventory --subscription <subscription-id>
```

Environment credential example:

```bash
export AZURE_TENANT_ID=<tenant-id>
export AZURE_CLIENT_ID=<client-id>
export AZURE_CLIENT_SECRET=<client-secret>
azurefox whoami --tenant <tenant-id> --subscription <subscription-id>
```

## Output Modes

- `--output table` (default)
- `--output json`
- `--output csv`

All commands also write a loot artifact to `<outdir>/loot/<command>.json`.

## Fixture Mode

Set `AZUREFOX_FIXTURE_DIR` to run against local fixture files rather than Azure APIs.

```bash
AZUREFOX_FIXTURE_DIR=tests/fixtures/lab_tenant azurefox rbac --output json
```

## Development

```bash
pip install -e .[dev,azure]
ruff check .
pytest
```

CI enforces lint + unit/contract/smoke tests. Integration tests are opt-in.

