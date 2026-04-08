# AzureFox

<p align="center">
  <img src="docs/branding/azurefox-logo.png" alt="AzureFox logo" width="180" />
</p>

Azure attack path reconnaissance for identifying privilege escalation paths, over-permissioned
identities, and exploitable cloud misconfigurations.

## Why Run AzureFox

Most Azure tools focus on inventory, configuration review, or compliance reporting.

AzureFox is built for offensive security and operator-first cloud triage:
- What can this identity actually do?
- Where can it pivot next?
- Which Azure path matters first?

## Install

```bash
pipx install azurefox
```

## Run It

Start with the current Azure identity and the strongest visible control paths:

```bash
azurefox whoami
azurefox permissions
```

## Example Output

`azurefox permissions`

| principal | type | high-impact roles | scopes | operator signal | next review |
| --- | --- | --- | --- | --- | --- |
| `azurefox-lab-sp` | `ServicePrincipal` | `Owner` | `1` | Direct control visible; current foothold. | Check `privesc` for the direct abuse or escalation path. |
| `operator@lab.local` | `User` |  | `1` | Direct control not confirmed. | Check `rbac` for the exact assignment evidence. |

AzureFox is not just listing Azure objects. It ranks the identities that matter, explains why
they matter, and points to the next command to run.

## What Makes This Different

- Identity-first, not just resource-first
- Focused on attack paths, not raw Azure data
- Output designed for operators who need to decide what matters next

## Currently Supported Azure Commands

| Section | Commands |
| --- | --- |
| `core` | [`inventory`](wiki/planning/api-mapping/inventory.md) |
| `identity` | [`whoami`](wiki/planning/api-mapping/whoami.md), [`rbac`](wiki/planning/api-mapping/rbac.md), [`principals`](wiki/planning/api-mapping/principals.md), [`permissions`](wiki/planning/api-mapping/permissions.md), [`privesc`](wiki/planning/api-mapping/privesc.md), [`role-trusts`](wiki/planning/api-mapping/role-trusts.md), `lighthouse`, [`auth-policies`](wiki/planning/api-mapping/auth-policies.md), [`managed-identities`](wiki/planning/api-mapping/managed-identities.md) |
| `config` | [`arm-deployments`](wiki/planning/api-mapping/arm-deployments.md), [`env-vars`](wiki/planning/api-mapping/env-vars.md) |
| `secrets` | [`keyvault`](wiki/planning/api-mapping/keyvault.md), [`tokens-credentials`](wiki/planning/api-mapping/tokens-credentials.md) |
| `resource` | `automation`, `devops`, [`acr`](wiki/planning/api-mapping/acr.md), [`api-mgmt`](wiki/planning/api-mapping/api-mgmt.md), [`databases`](wiki/planning/api-mapping/databases.md), [`resource-trusts`](wiki/planning/api-mapping/resource-trusts.md) |
| `storage` | [`storage`](wiki/planning/api-mapping/storage.md) |
| `network` | [`nics`](wiki/planning/api-mapping/nics.md), [`dns`](wiki/planning/api-mapping/dns.md), [`endpoints`](wiki/planning/api-mapping/endpoints.md), `network-effective`, [`network-ports`](wiki/planning/api-mapping/network-ports.md) |
| `compute` | [`workloads`](wiki/planning/api-mapping/workloads.md), [`app-services`](wiki/planning/api-mapping/app-services.md), [`functions`](wiki/planning/api-mapping/functions.md), [`aks`](wiki/planning/api-mapping/aks.md), [`vms`](wiki/planning/api-mapping/vms.md), `vmss`, `snapshots-disks` |
| orchestration | [`all-checks`](wiki/planning/api-mapping/all-checks.md) (deprecated) |

Commands without links do not have a dedicated wiki source page in the repo yet.

## Need A Test Lab?

Don't have an Azure environment handy? The companion repo
[AzureFox OpenTofu Proof Lab](https://github.com/TacoRocket/terraform-labs-for-azurefox) spins up
a deliberately insecure Azure lab for demos, validation, and practice.

Use a disposable subscription you control. It is risky on purpose.

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

Live operator guidance is built into `azurefox help` and `azurefox help <command>`.
Longer-form planning and wiki-source material lives under
[`wiki/`](https://github.com/TacoRocket/AzureFox/tree/main/wiki).

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
export AZUREFOX_DEVOPS_ORG=<org-name> # only needed for the devops command
azurefox whoami --tenant <tenant-id> --subscription <subscription-id>
```

```powershell
# Windows PowerShell
$env:AZURE_TENANT_ID="<tenant-id>"
$env:AZURE_CLIENT_ID="<client-id>"
$env:AZURE_CLIENT_SECRET="<client-secret>"
$env:AZUREFOX_DEVOPS_ORG="<org-name>" # only needed for the devops command
azurefox whoami --tenant <tenant-id> --subscription <subscription-id>
```

`AZUREFOX_DEVOPS_ORG` is only needed when running the `devops` command. The identity used for
`devops` still needs access to the Azure DevOps organization, not just ARM access to the tenant or
subscription.

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

Artifact intent:

- `json/` is the full structured command record.
- `loot/` is the smaller high-value handoff, focused on the top-ranked targets for quick operator
  follow-up and later chain-oriented workflows.
- `table/` and `csv/` are convenience views rendered from the same underlying command result.

## Sections And All-Checks

AzureFox keeps flat standalone commands and also supports grouped execution:

`all-checks` is deprecated.
It remains available while grouped chain families are being implemented, but the long-term
direction is narrower `chains` surfaces plus direct flat-command execution.

```bash
# deprecated broad sweep
azurefox all-checks
# deprecated section sweep
azurefox all-checks --section identity
azurefox all-checks --section config
azurefox all-checks --section secrets
azurefox all-checks --section resource
azurefox all-checks --section network
azurefox all-checks --section storage
azurefox all-checks --section compute
```

Treat `all-checks` as a temporary broad recon pass, not a quick spot check. It can take much
longer than a single command, especially when a full section is writing grouped artifacts.

For narrower current work:

- run the flat commands directly when you already know the lane you want
- use `all-checks` only when you still want the deprecated broad grouped sweep

Current section mappings:

- `identity`: `whoami`, `rbac`, `principals`, `permissions`, `privesc`, `role-trusts`, `lighthouse`, `auth-policies`, `managed-identities`
- `config`: `arm-deployments`, `env-vars`
- `secrets`: `keyvault`, `tokens-credentials`
- `resource`: `automation`, `devops`, `acr`, `api-mgmt`, `databases`, `resource-trusts`
- `storage`: `storage`
- `network`: `nics`, `dns`, `endpoints`, `network-effective`, `network-ports`
- `compute`: `workloads`, `app-services`, `functions`, `aks`, `vms`, `vmss`, `snapshots-disks`
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

Help also marks deprecated surfaces such as `all-checks` and broad section sweeps explicitly.

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
