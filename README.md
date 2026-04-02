# AzureFox

<p align="center">
  <img src="docs/branding/azurefox-logo-concept.svg" alt="AzureFox logo concept" width="220" />
</p>

AzureFox is a Python CLI for offensive-focused Azure situational awareness.
It is designed to help operators and testers quickly build a truthful picture of Azure identity,
resource, network, secrets, and workload attack surface from management-plane read paths.

## Attribution

AzureFox is inspired by [CloudFox](https://github.com/BishopFox/cloudfox), created by Bishop Fox.
The command model and operator workflow goals in this project are heavily informed by CloudFox's
approach to cloud situational awareness and attack-path-focused enumeration.

This project is an independent implementation and is not affiliated with or endorsed by Bishop
Fox.

## Currently Supported Azure Commands

- `whoami`
- `inventory`
- `nics`
- `dns`
- `endpoints`
- `network-ports`
- `workloads`
- `app-services`
- `functions`
- `aks`
- `api-mgmt`
- `acr`
- `databases`
- `arm-deployments`
- `env-vars`
- `tokens-credentials`
- `rbac`
- `principals`
- `permissions`
- `privesc`
- `role-trusts`
- `auth-policies`
- `managed-identities`
- `keyvault`
- `resource-trusts`
- `storage`
- `vms`
- `all-checks`

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate
pip install 'azurefox[azure]'
azurefox --outdir /tmp/azurefox-demo whoami --output table
azurefox --outdir /tmp/azurefox-demo all-checks --output table
```

For local source-based development, use `pip install -e '.[dev,azure]'`.

## Install Profiles

AzureFox keeps a small core package and uses extras for live Azure collection and contributor
tooling.

- `pip install azurefox`
  installs the core CLI from PyPI without live Azure SDK dependencies; this is mostly useful for
  help output, packaging work, or fixture-based local development
- `pip install -e .`
  installs the core CLI only; this is mostly useful for help output, packaging work, or
  fixture-based local development
- `pip install 'azurefox[azure]'`
  installs the published AzureFox package plus the Azure SDK dependencies required for live Azure
  command execution; most operators should use this profile
- `pip install -e '.[azure]'`
  installs the Azure SDK dependencies required for live Azure command execution; most operators
  should use this profile when working from a local checkout
- `pip install -e '.[dev]'`
  installs lint, test, and type-check tooling for contributors working without live Azure SDK
  dependencies
- `pip install -e '.[dev,azure]'`
  installs both contributor tooling and the live Azure SDK bundle; this is the normal repo
  development profile

The current `azure` extra intentionally installs the full SDK bundle used by the implemented live
commands rather than splitting dependencies per-command.

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
azurefox all-checks --section config
azurefox all-checks --section secrets
azurefox all-checks --section resource
azurefox all-checks --section network
azurefox all-checks --section storage
azurefox all-checks --section compute
```

Treat `all-checks` as a broader validation pass rather than a quick spot check. It can take
materially longer than a single command, especially when a full section is producing grouped
artifacts across multiple commands.

Current section mappings:

- `identity`: `whoami`, `rbac`, `principals`, `permissions`, `privesc`, `role-trusts`, `auth-policies`, `managed-identities`
- `config`: `arm-deployments`, `env-vars`
- `secrets`: `keyvault`, `tokens-credentials`
- `resource`: `acr`, `api-mgmt`, `databases`, `resource-trusts`
- `storage`: `storage`
- `network`: `nics`, `dns`, `endpoints`, `network-ports`
- `compute`: `workloads`, `app-services`, `functions`, `aks`, `vms`
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
