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

### `api-mgmt-depth`

Why it is grounded now:

- the roadmap already includes `api-mgmt` as a Phase 3 service slice
- once AzureFox lands a first API Management foothold, the repo can reuse that client and
  service-level inventory path for narrower follow-on depth

Why it should be separate:

- API Management subscriptions, named-value secret handling, and policy-body inspection can easily
  overwhelm a first operator-first service census
- those areas deserve a later evidence-based follow-on once the initial gateway, hostname,
  identity, and inventory posture command settles

What this future follow-on could absorb:

- subscription inventory and operator risk cues
- named-value secret posture beyond simple counts
- Key Vault-backed named-value depth
- policy-body collection or policy-shape summaries
- backend URL and trust-path deepening where the first `api-mgmt` slice stays intentionally narrow

### `aks-depth`

Why it is grounded now:

- the roadmap already includes `aks` as a Phase 3 service slice
- once AzureFox lands a first AKS foothold, the repo can reuse that client and cluster-level
  posture path for narrower follow-on depth

Why it should be separate:

- Kubernetes-specific, node-pool-specific, and ingress-specific follow-on work can easily
  overwhelm a first operator-first AKS census
- those areas deserve a later evidence-based follow-on once the initial control-plane endpoint,
  identity, auth, and network shape command settles

What this future follow-on could absorb:

- node-pool posture and system-versus-user pool distinctions
- OIDC issuer and workload identity depth beyond simple cluster posture
- ingress, internal load balancer, and private DNS path deepening
- kubelet identity, addon profile, or maintenance configuration review
- cluster credential and Kubernetes-object follow-up once scope is explicitly chosen

### `acr-depth`

Why it is grounded now:

- the roadmap already includes `acr` as a Phase 3 service slice
- once AzureFox lands a first ACR foothold, the repo can reuse that client and registry-level
  posture path for narrower follow-on depth

Why it should be separate:

- repository enumeration, webhook review, task analysis, and connected-registry follow-on work can
  easily overwhelm a first operator-first ACR census
- those areas deserve a later evidence-based follow-on once the initial login-server, auth, and
  network-posture command settles

What this future follow-on could absorb:

- repository and artifact inventory with management-plane-safe scope
- webhook, task, and connected-registry relationships
- retention, quarantine, trust, export, and content-trust policy depth
- scope-map, token, and other registry-auth surface review once boundaries are explicit

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

## Broader Roadmap Gaps To Revisit Once Grounded

The external roadmap reference also calls out broader domain gaps that should stay visible even
though they do not yet meet this document's repo-foothold rule.

Keep these as watch items, not near-term candidates, until AzureFox gains client, fixture, or
collector adjacency for them:

- messaging and eventing
  Azure Service Bus, Event Grid, Event Hubs, and queue-oriented trust or data-path review
- filesystems and mounted storage
  Azure Files, Azure NetApp Files, and mount-oriented loot or trust paths
- data, analytics, and search platforms
  Synapse, Data Explorer, Log Analytics, and search-oriented operator surfaces that do not fit
  cleanly under broad `databases`
- governance metadata
  tags, labels, and other governance-oriented enumeration surfaces
- directory-services-specific coverage
  Azure AD DS or managed domain-service style visibility beyond current Entra and RBAC coverage

Note on edge and delivery surfaces:

- the external roadmap reference calls out Front Door, CDN, Application Gateway, and
  load-balancer-style discovery
- the current future candidates already partially cover this family through `public-ips` and
  `load-balancers`
- revisit a broader edge-delivery command later if those footholds land and we need a more unified
  operator surface

## Recommendation

The strongest later candidate outside the current roadmap command list is `entra-graph`.

Reason:

- it already has real Graph adjacency
- it cleanly absorbs broader consent and directory teardown work
- it prevents `role-trusts` from becoming an overloaded catch-all
