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

### `role-trusts` scale modes

Why it is grounded now:

- `role-trusts` now enumerates readable Graph trust edges directly instead of depending only on
  principal-seeded inputs
- that broader trust-edge pass is more truthful for Phase 1, but it will naturally do more Graph
  work in larger tenants

Why it should be separate:

- this is not a new trust family; it is an operator control and scale-hardening follow-on for an
  existing command
- AzureFox should not silently downgrade trust coverage based on tenant size because that would
  make results harder to explain

What this future follow-on could absorb:

- an explicit `role-trusts` collection mode split such as seeded/fast by default versus
  broad/explicit for slower full trust-edge enumeration
- alignment between single-command and orchestration behavior so `azurefox role-trusts` and
  `azurefox all-checks --section identity` can both stay on the quicker seeded sweep unless the
  operator explicitly asks for the broader pass
- clearer large-tenant handling for Graph pagination, throttling, and wait behavior
- more explicit issue surfacing when broad trust enumeration is only partially readable
- operator-facing wording that makes the coverage tradeoff obvious when a narrower mode is chosen

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

### `databases-relational-depth`

Why it is grounded now:

- the public roadmap already lists `databases`, while the current sequencing note keeps it as a
  later Phase 3 service slice after the shared network and compute foundation
- once AzureFox lands a first Azure SQL foothold, the repo can reuse that command shape for
  adjacent relational services that expose similar management-plane posture

Why it should be separate:

- PostgreSQL and MySQL flexible-server inventory adds more service-specific posture, SKU, HA, and
  network differences than a first narrow Azure SQL pass should absorb
- those engines deserve a later evidence-based expansion once the initial SQL server and visible
  database census settles

What this future follow-on could absorb:

- PostgreSQL flexible server posture and visible database inventory
- MySQL flexible server posture and visible database inventory
- cross-engine normalization of endpoint, public-network, and TLS posture where the first
  `databases` slice stays intentionally Azure SQL-first

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

### `dns-depth`

Why it is grounded now:

- the new `dns` command establishes a public-versus-private zone inventory surface using ARM
  metadata already available through the existing resource client
- visible record-set totals, public delegation cues, and private VNet-link counts now create a
  clean DNS vocabulary to deepen later

Why it should be separate:

- record contents, alias targets, resolution behavior, and takeover-style heuristics can easily
  overwhelm a first operator-first zone census
- private DNS link graph depth and per-zone target analysis deserve a later evidence-based follow-on
  once the initial namespace inventory command settles

What this future follow-on could absorb:

- record-type and record-target visibility beyond simple zone totals
- alias, CNAME, wildcard, and TXT review once boundaries are explicit
- private DNS VNet-link inventory beyond link counts
- takeover-style namespace checks or other DNS misconfiguration heuristics

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

### `cross-platform-ux`

Why it is grounded now:

- AzureFox itself is Python-first and mostly uses portable path handling and file I/O already
- the current product can be run from non-Mac environments even though most authoring and examples
  have been Mac/Linux oriented so far

Why it should be separate:

- this is mostly a packaging, docs, and operator-expectation follow-on rather than a new command
  surface
- the immediate value is clearer platform compatibility signaling, not expanding Azure coverage

What this future follow-on could absorb:

- clearer operator-facing wording about what AzureFox supports across macOS, Linux, and Windows
- documentation examples for Windows shell and temp-path equivalents where helpful
- a lightweight compatibility note that separates repo-maintainer workflows from end-user CLI
  portability
- targeted cleanup of any accidental machine-specific assumptions that show up during live usage

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
- non-relational and cache-backed database platforms
  Cosmos DB, Redis, and other multi-model data services that should wait until AzureFox has a
  clearer management-plane foothold and command boundary for them
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
