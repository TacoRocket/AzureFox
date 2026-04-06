# acr API Mapping

## Slice Goal

Surface Azure Container Registry posture with a narrow management-plane depth pass.

This version answers:
"Which registries expose the strongest login, auth, network, automation, and trust cues worth
operator follow-up?"

## Initial Scope

- Registry enumeration
- Login server visibility
- Public network access and network-rule default-action visibility
- Admin-user and anonymous-pull posture
- Managed identity and basic service-shape cues
- Webhook counts, action types, and broad scope cues
- Replication counts and replicated region names
- Quarantine, retention, and content-trust cues

## Explicit Non-Goals For V1

- Repository or artifact inventory
- Token, scope-map, or task depth
- Webhook callback URI retrieval
- Any repository-content or data-plane access path

## Primary APIs

- `azure.mgmt.containerregistry.ContainerRegistryManagementClient.registries.list`
- `azure.mgmt.containerregistry.ContainerRegistryManagementClient.webhooks.list`
- `azure.mgmt.containerregistry.ContainerRegistryManagementClient.replications.list`

## Correlation / Joins

- Normalize registry posture into operator-first rows that emphasize exposure, auth, automation,
  replication, and trust cues
- Keep nested read gaps explicit when webhook or replication visibility is denied
- Keep data-plane content analysis out of the first slice

## Blind Spots

- Registry posture does not prove repository contents are readable
- Webhook and replication cues do not prove downstream trust or exploitability
- Trust cues do not prove content-governance enforcement is operating as intended
