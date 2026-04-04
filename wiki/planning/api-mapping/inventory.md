# inventory API Mapping

## Primary APIs

- `azure.mgmt.resource.ResourceManagementClient.resource_groups.list`
- `azure.mgmt.resource.ResourceManagementClient.resources.list`

## Correlation / Joins

- Resource type counts are aggregated from the full resource list.

## Assumptions

- Inventory is subscription-scoped in Milestone 1.

## Blind Spots

- No Resource Graph integration yet.
- No per-region summary breakdown in Milestone 1.
