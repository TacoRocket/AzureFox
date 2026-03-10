# rbac API Mapping

## Primary APIs

- `azure.mgmt.authorization.AuthorizationManagementClient.role_assignments.list_for_scope`
- `azure.mgmt.authorization.AuthorizationManagementClient.role_definitions.get`

## Correlation / Joins

- Role assignment `role_definition_id` is resolved to role name.
- Principal IDs are normalized into deduplicated principal nodes.

## Assumptions

- Collection starts at subscription scope and includes nested scopes returned by assignments.

## Blind Spots

- No Entra/Graph enrichment for principal display names in Milestone 1.
