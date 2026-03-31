# CloudFox Compatibility Ledger

This file is the AzureFox repo source for CloudFox parity tracking.

## Status Categories

- `Implemented in AzureFox`
- `Planned Azure equivalent`
- `Azure-incompatible`
- `Covered differently`
- `Deferred`

## Command Ledger

| CloudFox Command | Provider | AzureFox Status | AzureFox Mapping | Category | Reasoning | ATT&CK / Offensive Question | Lab Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `whoami` | AWS, GCP, Azure | Implemented in AzureFox | `whoami` | `1:1 equivalent` | Caller context and subscription identity are direct Azure needs. | Valid account context and caller identity | Lab implemented |
| `inventory` | AWS, GCP, Azure | Implemented in AzureFox | `inventory` | `1:1 equivalent` | Resource inventory is a direct Azure equivalent. | Cloud infrastructure discovery | Lab implemented |
| `rbac` | Azure | Implemented in AzureFox | `rbac` | `1:1 equivalent` | Azure RBAC is already first-class in AzureFox. | Permission groups discovery | Lab implemented |
| `storage` | AWS, GCP, Azure | Implemented in AzureFox | `storage` | `Azure analogue` | Storage posture maps directly, though Azure data-plane trust is different enough to require Azure-specific findings. | Cloud storage discovery and exposure | Lab implemented |
| `vms` | Azure | Implemented in AzureFox | `vms` | `1:1 equivalent` | Azure VM and VMSS visibility is already present. | Compute discovery and exposure | Lab implemented |
| `principals` | AWS | Implemented in AzureFox | `principals` | `Azure analogue` | AzureFox now provides subscription-visible principal inventory from RBAC, caller context, and managed-identity attachment data; broader tenant graph depth can iterate later. | Identity graph and trust discovery | Lab planned |
| `permissions` | AWS, GCP | Planned Azure equivalent | `permissions` | `Azure analogue` | Azure effective permissions need RBAC expansion and Graph context. | Privilege analysis | Lab planned |
| `cape` / `privesc` | AWS, GCP | Planned Azure equivalent | `privesc` | `Covered differently` | Azure escalation paths are driven by RBAC, app trust, identities, and tenant controls rather than AWS role assumption semantics. | Privilege escalation pathing | Lab planned |
| `role-trusts` / `identity-federation` | AWS, GCP | Planned Azure equivalent | `role-trusts` | `Covered differently` | Azure trust edges center on app registrations, service principals, federated credentials, and consent. | Trusted relationship abuse | Lab planned |
| `all-checks` | AWS, GCP | Implemented in AzureFox | `all-checks` | `Azure analogue` | AzureFox uses flat commands plus a grouped runner for operator convenience. | Broad situational awareness sweep | Lab planned |

## Review Rules

- No AWS or GCP command should remain unclassified.
- If a 1:1 mapping is unclear, ask for clarification before finalizing the ledger entry.
- Azure-only commands should be tracked in the external handoff file even when there is no CloudFox source command.
