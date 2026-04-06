# keyvault API Mapping

## Primary APIs

- `azure.mgmt.keyvault.KeyVaultManagementClient.vaults.list_by_subscription`

## Correlation / Joins

- Public network access, firewall default action, and private endpoint presence are mapped into
  exposure findings.
- Purge protection state is surfaced as a destructive-leverage finding candidate.

## Assumptions

- Management-plane metadata is the Phase 2 starting point for Key Vault coverage.
- Data-plane enumeration of secrets, keys, and certificates is deferred until a later slice with
  explicit permission handling.

## Blind Spots

- Secret/key/certificate contents and access behavior are not inspected in this version.
- Per-principal data-plane authorization is not modeled yet.
