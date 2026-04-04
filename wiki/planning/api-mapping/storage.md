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
- Account-level management-plane posture is rolled up into operator-first depth cues for:
  - public network access
  - shared-key auth posture
  - minimum TLS and HTTPS-only transport posture
  - HNS, SFTP, NFS, and DNS endpoint style
  - coarse blob/file/queue/table inventory counts

## Assumptions

- Storage account management-plane metadata is primary in Milestone 1.
- Optional child counts should stay explicit when unreadable instead of silently collapsing to
  zero.
- The first depth pass stays at storage-account posture and does not enumerate data-plane names.

## Blind Spots

- Data-plane ACL and SAS token introspection is deferred.
- Blob, container, file-share, queue, and table names remain out of scope.
