# Changelog

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
- Tightened release packaging metadata and install guidance for the public `azure` dependency
  profile.

### Fixed
- Normalized ARM ID joins used by `network-ports`, `workloads`, and related endpoint correlation
  so live joins stay stable across casing differences.
- Corrected the Azure extras packaging constraint for `azure-mgmt-sql` so fresh
  `pip install -e '.[azure]'` installs succeed on the stable package index.
- Added CI gitleaks scanning and tokenless Trusted Publishing workflow support.
