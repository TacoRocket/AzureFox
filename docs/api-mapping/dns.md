# dns API Mapping

## Slice Goal

Surface operator-first DNS zone posture before deeper DNS analysis exists.

This first version answers:
"Which public or private DNS zones expose namespace, delegation, or VNet-link context worth
operator follow-up?"

## Initial Scope

- Public DNS zone enumeration
- Private DNS zone enumeration
- Visible record-set totals from management-plane zone metadata
- Public-zone name-server delegation visibility
- Private-zone virtual-network link counts, including registration-enabled links when visible

## Explicit Non-Goals For V1

- Record-value inspection for `A`, `AAAA`, `CNAME`, `TXT`, `MX`, or other set contents
- Live DNS resolution, resolver-path behavior, or reachability proof
- Subdomain takeover heuristics, alias-target validation, or wildcard-depth analysis
- Per-link private-DNS graph depth beyond simple link-count visibility

## Primary APIs

- `azure.mgmt.resource.ResourceManagementClient.resources.list`

## Correlation / Joins

- Normalize public and private DNS zone ARM metadata into one operator-first zone summary shape
- Keep the slice at zone-level inventory so public delegation and private-link context stay easy to
  scan

## Blind Spots

- V1 does not show record contents, target hostnames, or record-type-specific risk cues
- V1 does not prove whether a public zone resolves to reachable services from the current network
- Private-zone link counts do not show which VNet identities, subnets, or resources actually
  depend on that namespace
