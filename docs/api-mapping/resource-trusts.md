# resource-trusts API Mapping

## Slice Goal

Surface high-signal resource trust surfaces that matter to operators before deeper service-specific
enumeration exists.

This first version answers:
"Which Storage and Key Vault resources still trust public network paths, and which ones are
constrained to private-link style access?"

## Initial Scope

- Storage account anonymous/public access signals
- Storage account public network default action
- Storage private endpoint presence
- Key Vault public network accessibility
- Key Vault private endpoint presence

## Explicit Non-Goals For V1

- Full Azure service-to-service graph coverage
- Data-plane ACL or secret enumeration
- NSG, route, or private DNS path simulation
- Principal authorization modeling that belongs in identity slices

## Primary APIs

- Existing AzureFox storage asset collection
- Existing AzureFox Key Vault asset collection

## Correlation / Joins

- Normalize public-network and private-endpoint posture into trust rows
- Reuse Storage findings and only the trust-relevant Key Vault exposure findings so evidence stays
  consistent with the underlying collectors without pulling in non-trust recovery posture

## Blind Spots

- Resource trust coverage is intentionally narrow in V1 and does not yet include App Service,
  Functions, AKS, ACR, or deployment-linked trust paths
- Private endpoint presence is not the same as end-to-end private-only reachability proof
