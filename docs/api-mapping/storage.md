# storage API Mapping

## Primary APIs

- `azure.mgmt.storage.StorageManagementClient.storage_accounts.list`
- Optional child enumeration where available:
  - `blob_containers.list`
  - `file_shares.list`
  - `queue.list`
  - `table.list`

## Correlation / Joins

- Public/anonymous indicators and firewall defaults are mapped into storage exposure findings.

## Assumptions

- Storage account management-plane metadata is primary in Milestone 1.

## Blind Spots

- Data-plane ACL and SAS token introspection is deferred.
