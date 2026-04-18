# Changelog

## [1.5.0] - 2026-04-18

### Added
- Added strict grouped `chains` artifact reuse for compatible local source JSON so repeated family
  reruns can reuse already-produced evidence truthfully instead of recollecting every backing
  command.
- Added YAML-backed Azure DevOps pipeline evidence so `devops` and `chains deployment-path` can
  admit repo-backed Azure service connections and variable groups from real Azure Repos pipeline
  definitions and same-repo local templates.

### Changed
- Batched the expensive Graph fanout behind `role-trusts`, which keeps live grouped `chains`
  families responsive on fresh runs instead of stalling on serial trust-edge collection.
- Tightened reduced-view and maintenance-mode truthfulness across `permissions`,
  `tokens-credentials`, `credential-path`, `deployment-path`, `functions`, `arm-deployments`, and
  `resource-trusts` so reduced or partial visibility reads as exactly that instead of broader proof.
- Bumped the published package and output schema version to `1.5.0` for the completed minor
  release boundary.

## [1.4.0] - 2026-04-12

### Added
- Shipped the new `compute-control` chain family so AzureFox can join compute footholds to
  defended Azure-control follow-on paths in one operator-facing view.
- Added first-class `container-apps` and `container-instances` flat commands so those runtime
  surfaces are visible directly instead of only through shared compute follow-on logic.

### Changed
- Tightened `compute-control` admission, mixed-identity handling, terminal wording, and fixture
  coverage so live output stays truthful while still surfacing the strongest defended control path.
- Refreshed help text, README chain guidance, fixtures, and golden outputs to match the shipped
  chain and container-runtime surface.
- Bumped the published package and output schema version to `1.4.0` for the completed minor
  release boundary.

## [1.3.0] - 2026-04-08

### Added
- Added live-proof-aware `credential-path` handling for Key Vault-backed app settings so the
  grouped chain output can distinguish named vault dependency, policy-suggested access, successful
  secret read, and denied secret read without printing secret material.

### Changed
- Refactored `credential-path` onto a reusable handler registry so target-family-specific chain
  logic can expand beyond hardcoded runner branches and be reused by future chain families.
- Tightened operator-facing credential-path wording so rows separate target resolution from proof
  of current-identity access more clearly.
- Bumped the published package and output schema version to `1.3.0` for the next minor release.

## [1.2.0] - 2026-04-05

### Added
- Completed the Phase 4 Azure-native service lane with shipped `cross-tenant`, `lighthouse`,
  `automation`, `devops`, and `snapshots-disks` coverage now treated as the closed minor-release
  boundary.

### Changed
- Retired the remaining tracked command-intent drift for `nics`, `databases`, `acr`, and `aks` by
  pushing more operator-relevant assets to the top of each command's output.
- Tightened Phase 4 closeout truthfulness across `devops`, `snapshots-disks`, `storage`, `vms`,
  and `app-services` so CLI behavior, help text, and takeaway wording match the shipped evidence
  boundary more closely.
- Bumped the published package and output schema version to `1.2.0` for the completed end-of-
  Phase-4 minor release boundary.

## [1.1.0] - 2026-04-04

### Added
- Expanded `api-mgmt` with subscription, named-value, backend, and Key Vault-linked posture cues
  so APIM services are easier to rank for follow-up.
- Expanded `aks` with OIDC issuer, workload identity, and addon posture cues from the Azure
  management plane.
- Expanded `acr` with webhook, replication, and registry policy posture signals.
- Expanded `databases` from Azure SQL-only coverage to include PostgreSQL Flexible Server and MySQL
  Flexible Server in the same operator-first relational view.
- Expanded `dns` with private-zone private-endpoint reference context to highlight more active
  private-service namespaces.
- Expanded `storage` with public-network, auth, transport, and protocol posture signals.

### Changed
- Updated help text, API-mapping notes, fixtures, goldens, and terminal table presentation to match
  the deeper command posture now shipped in the grounded follow-on tranche.
- Bumped the published package and output schema version to `1.1.0` for the completed
  post-Phase-3 minor release boundary.

## [1.0.0] - 2026-04-02

### Added
- AzureFox Phase 1 through Phase 3 command surface, including identity, privilege, secrets,
  config, storage, compute, app, API, DNS, and network-oriented recon commands.
- Operator-first grouped orchestration with `all-checks` plus per-section execution.
- API-mapping and feature-complete reference docs that define the current evidence boundary.
- Release workflow for GitHub Releases plus PyPI Trusted Publishing.

### Changed
- Hardened truthfulness across trust, workload, endpoint, and storage outputs so commands do not
  imply stronger proof than the current read path supports.
- Improved `all-checks` help and README guidance to set longer-runtime expectations clearly.
- Tightened release packaging metadata and install guidance for the public Azure runtime
  dependencies.

### Fixed
- Normalized ARM ID joins used by `network-ports`, `workloads`, and related endpoint correlation
  so live joins stay stable across casing differences.
- Corrected the Azure runtime packaging constraint for `azure-mgmt-sql` so fresh installs succeed
  on the stable package index.
- Added CI gitleaks scanning and tokenless Trusted Publishing workflow support.
