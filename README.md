# AzureFox

AzureFox is a Python CLI for offensive-focused Azure situational awareness.

## Attribution

AzureFox is inspired by [CloudFox](https://github.com/BishopFox/cloudfox), created by Bishop Fox.
The command model and operator workflow goals in this project are heavily informed by CloudFox's
approach to cloud situational awareness and attack-path-focused enumeration.

This project is an independent implementation and is not affiliated with or endorsed by Bishop
Fox.

## Currently Supported Azure Commands

- `whoami`
- `inventory`
- `rbac`
- `principals`
- `permissions`
- `privesc`
- `role-trusts`
- `auth-policies`
- `managed-identities`
- `keyvault`
- `storage`
- `vms`
- `all-checks`

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev,azure]
azurefox --outdir /tmp/azurefox-demo whoami --output table
azurefox --outdir /tmp/azurefox-demo all-checks --output table
```

## Auth Precedence

1. Azure CLI credential
2. Environment/service principal credential

### Web auth (browser-based) via Azure CLI

If you want web-based authentication, run `az login` first (outside AzureFox), then run AzureFox.
AzureFox does not currently launch its own browser auth flow.

Azure CLI example:

```bash
az login
az account set --subscription <subscription-id>
azurefox inventory --subscription <subscription-id>
```

### Non-web auth (no `az login` required)

If you do not want to use web auth, set service principal environment variables and pass CLI flags
for tenant/subscription targeting.

Environment credential + CLI options example:

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

All commands write artifacts under `<outdir>/`:

- `loot/<command>.json`
- `json/<command>.json`
- `table/<command>.txt`
- `csv/<command>.csv`
- `run-summary.json` for `all-checks`

## Sections And All-Checks

AzureFox keeps flat standalone commands and also supports grouped execution:

```bash
azurefox all-checks
azurefox all-checks --section identity
azurefox all-checks --section secrets
azurefox all-checks --section storage
azurefox all-checks --section compute
```

Current section mappings:

- `identity`: `whoami`, `rbac`, `principals`, `permissions`, `privesc`, `role-trusts`, `auth-policies`, `managed-identities`
- `secrets`: `keyvault`
- `storage`: `storage`
- `compute`: `vms`
- `core`: `inventory`

## Help

AzureFox supports generic and scoped help:

```bash
azurefox help
azurefox help identity
azurefox help permissions
azurefox -h identity
azurefox -h permissions
```

Command help includes ATT&CK cloud leads as investigative context so users can map the output to likely tactics and techniques without treating the help text as proof that a technique occurred.

For ad hoc demos or local exploration, prefer `--outdir /tmp/<name>` so generated artifacts do not accumulate in the repo root.

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

## License

AzureFox is licensed under the MIT License to match CloudFox's licensing model.
See [LICENSE](LICENSE).
