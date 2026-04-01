# Future Phase Candidates

Date: 2026-03-31

This note is not a roadmap change. It is a parking lot for later commands or phase ideas that are
already adjacent to AzureFox's current mapped surfaces and client plumbing.

## Inclusion Rule

Only include candidates that already have a meaningful foothold in the repo today through:

- existing Graph methods
- existing Azure management clients
- existing collector joins

## Candidates

### `entra-graph`

Why it is grounded now:

- AzureFox already uses Microsoft Graph for `role-trusts` and `auth-policies`
- the Graph client already includes methods such as:
  - application lookups
  - service-principal lookups
  - `oauth2PermissionGrants`
  - app-role assignments
  - ownership and federated credentials

Why it should be separate:

- broader consent and directory graph coverage would blur the boundary of `role-trusts`
- it is the cleanest future home for delegated/admin consent evidence and wider Entra teardown

### `public-ips`

Why it is grounded now:

- AzureFox already resolves public IP resources while building `vms`
- the network client is already in use for NIC and public IP lookups

Why it could matter later:

- a dedicated public-IP surface could support endpoint triage, ingress review, and later joins to
  load balancers or public-facing workloads

### `load-balancers`

Why it is grounded now:

- the repo already uses the network management client
- upcoming `nics` and `endpoints` work will likely make backend pool and ingress relationships more
  visible and easier to model cleanly

Why it should wait:

- it needs the shared network vocabulary from `nics` and `endpoints` first

### `network-effective`

Why it is grounded now:

- AzureFox already has the network management client in place
- `nics` and `endpoints` now establish shared attachment and ingress vocabulary
- upcoming `network-ports` work will likely expose where operator summaries stop short of full
  effective-rule evaluation

Why it should be separate:

- effective reachability and Azure NSG edge cases can easily overwhelm the operator-first
  `network-ports` boundary
- this is the cleaner future home for augmented-rule handling, layered ingress analysis, and
  stronger effective-exposure claims once the simpler network slices settle

### `vmss`

Why it is grounded now:

- VMSS inventory already appears in the current `vms` and `managed-identities` collection path

Why it might become its own command:

- scale sets often deserve operator treatment different from single VMs once networking,
  identities, and workload context get deeper

### `deployment-content`

Why it is grounded now:

- `arm-deployments` and `tokens-credentials` already surface linked template/parameter URIs and
  deployment output clues

Why it is not a near-term priority:

- current evidence is still operator-signal metadata, not content analysis
- broadening this too early risks duplicating or overcomplicating the Phase 2 deployment slices

## Candidates To Leave Out For Now

Do not promote these yet from the current repo state:

- service-specific data-plane commands without existing management-plane footholds
- services with no current client, fixture, or collector adjacency
- AI, Lighthouse, DevOps, or automation sub-slices beyond the roadmap until the core compute and
  network tranche is further along

## Recommendation

The strongest later candidate outside the current roadmap command list is `entra-graph`.

Reason:

- it already has real Graph adjacency
- it cleanly absorbs broader consent and directory teardown work
- it prevents `role-trusts` from becoming an overloaded catch-all
