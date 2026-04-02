# acr API Mapping

## Slice Goal

Surface Azure Container Registry posture before deeper repository or token analysis exists.

This first version answers:
"Which registries expose interesting login, auth, and network posture worth operator follow-up?"

## Initial Scope

- Registry enumeration
- Login server visibility
- Public network access and network-rule default-action visibility
- Admin-user and anonymous-pull posture
- Managed identity and basic service-shape cues

## Explicit Non-Goals For V1

- Repository or artifact inventory
- Token, scope-map, or webhook depth
- Content-trust or retention-policy deepening

## Primary APIs

- `azure.mgmt.containerregistry.ContainerRegistryManagementClient.registries.list`

## Correlation / Joins

- Normalize registry posture into operator-first rows that emphasize exposure and auth switches
- Keep data-plane content analysis out of the first slice

## Blind Spots

- Registry posture does not prove repository contents are readable
- Auth switches alone do not model every possible registry abuse path

