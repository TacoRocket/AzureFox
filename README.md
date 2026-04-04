# AzureFox

<p align="center">
  <img src="docs/branding/azurefox-logo.png" alt="AzureFox logo" width="180" />
</p>

AzureFox is a Python CLI for offensive-focused Azure situational awareness.
It helps operators and testers figure out what Azure identity, network, secrets, and workload
exposure they can actually see from management-plane read paths.

## Quickstart

```bash
pip install azurefox
```

By default, AzureFox writes artifacts into your current directory. If you want them somewhere
else, pass `--outdir`:

```bash
azurefox --outdir ./azurefox-demo whoami --output table
azurefox --outdir ./azurefox-demo all-checks --output table
```

If you prefer an isolated virtual environment:

```bash
python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows PowerShell
# .venv\Scripts\Activate.ps1
pip install azurefox
```

For local source-based development, use `pip install -e '.[dev]'`.

AzureFox is intended to work on macOS, Linux, and Windows. The command examples below use
portable relative paths like `./azurefox-demo`; shell syntax mainly differs for virtualenv
activation and environment-variable export.

For a quick operator-focused summary of what changes across shells and what does not, see
[`docs/wiki-seed/Platform-Notes.md`](docs/wiki-seed/Platform-Notes.md).

## Need A Test Lab?

Don't have an Azure environment handy? The companion repo
[AzureFox OpenTofu Proof Lab](https://github.com/TacoRocket/terraform-labs-for-azurefox) spins up
a deliberately insecure Azure lab for demos, validation, and practice.

Use a disposable subscription you control. It is risky on purpose.

## Currently Supported Azure Commands

- `whoami`
- `inventory`
- `nics`
- `dns`
- `endpoints`
- `network-effective`
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

## CLI Invocation

Shared flags like `--tenant`, `--subscription`, `--output`, `--outdir`, and `--debug` work before
or after the command.

These forms are equivalent:

```bash
azurefox dns --output json --outdir ./azurefox-demo
azurefox --output json --outdir ./azurefox-demo dns
```

Use `azurefox <command> --help` or `azurefox help <command>` for command-specific help.

## Install Profiles

AzureFox installs the live Azure runtime dependencies by default so `pip install azurefox` is ready
for real Azure command execution.

- `pip install azurefox`
  installs the normal operator profile from PyPI, including the Azure SDK dependencies used by the
  implemented live commands
- `pip install -e .`
  installs the same live Azure command profile from a local checkout
- `pip install -e '.[dev]'`
  installs contributor tooling on top of the default live Azure dependencies; this is the normal
  repo development profile

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
# macOS/Linux
export AZURE_TENANT_ID=<tenant-id>
export AZURE_CLIENT_ID=<client-id>
export AZURE_CLIENT_SECRET=<client-secret>
azurefox whoami --tenant <tenant-id> --subscription <subscription-id>
```

```powershell
# Windows PowerShell
$env:AZURE_TENANT_ID="<tenant-id>"
$env:AZURE_CLIENT_ID="<client-id>"
$env:AZURE_CLIENT_SECRET="<client-secret>"
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

Treat `all-checks` as a broader validation pass, not a quick spot check. It can take much longer
than a single command, especially when a full section is writing grouped artifacts.

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
azurefox dns --help
azurefox -h identity
azurefox -h permissions
```

Command help includes ATT&CK cloud leads as investigation prompts, not proof that a technique
occurred.

For ad hoc demos or local testing, use a dedicated path like `--outdir ./azurefox-demo` so
artifacts do not pile up in the repo root.

## Fixture Mode

Set `AZUREFOX_FIXTURE_DIR` to run against local fixture files rather than Azure APIs.

```bash
# macOS/Linux
AZUREFOX_FIXTURE_DIR=tests/fixtures/lab_tenant azurefox rbac --output json
```

```powershell
# Windows PowerShell
$env:AZUREFOX_FIXTURE_DIR="tests/fixtures/lab_tenant"
azurefox rbac --output json
```

## Development

```bash
pip install -e '.[dev]'
ruff check .
pytest
```

CI runs lint plus unit, contract, and smoke tests. Integration tests are opt-in.

## Attribution

AzureFox is inspired by [CloudFox](https://github.com/BishopFox/cloudfox), created by Bishop Fox.
The command model and operator workflow goals in this project are heavily shaped by CloudFox's
approach to cloud situational awareness and attack-path-focused enumeration.

This project is an independent implementation and is not affiliated with or endorsed by Bishop
Fox.

## License

AzureFox is licensed under the MIT License to match CloudFox's licensing model.
See [LICENSE](LICENSE).
