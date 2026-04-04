# Changelog

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
