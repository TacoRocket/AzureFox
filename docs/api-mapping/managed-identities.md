# managed-identities API Mapping

## Primary APIs

- `azure.mgmt.compute.ComputeManagementClient.virtual_machines.list_all`
- `azure.mgmt.compute.ComputeManagementClient.virtual_machine_scale_sets.list_all` (identity fallback coverage)
- RBAC feed from `rbac` command data path

## Correlation / Joins

- VM and VMSS identity attachments are normalized into managed identity nodes.
- Identity principal IDs are joined with role assignments to surface elevated-role findings.

## Assumptions

- Milestone 1 identity discovery is compute-centric.

## Blind Spots

- No direct managed identity resource provider enumeration yet.
- No Graph-backed service principal relationship expansion yet.
