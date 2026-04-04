# network-ports API Mapping

## Slice Goal

Surface likely inbound port exposure for NIC-backed public endpoints without overstating what
Azure management metadata can prove.

This first version answers:
"Which visible public endpoints also have readable NSG allow evidence, and where does that allow
appear to come from?"

## Initial Scope

- Public-IP-backed endpoint filtering
- NIC-level NSG inbound allow rule visibility
- Subnet-level NSG inbound allow rule visibility
- Per-row protocol, port, source-summary, and confidence labeling

## Explicit Non-Goals For V1

- Full effective reachability analysis
- Guest firewall, application listener, or service-bind validation
- Load balancer, application gateway, or other layered ingress modeling

## Primary APIs

- Reuses AzureFox `endpoints` and `nics` collection output
- `azure.mgmt.network.NetworkManagementClient.security_groups.get`
- `azure.mgmt.network.NetworkManagementClient.subnets.get`

## Correlation / Joins

- Join public endpoint rows to NIC attachment context using normalized ARM IDs
- Merge visible NIC and subnet NSG allow rules into one operator-first exposure view
- Keep output evidence-based when no NSG is visible rather than implying openness or closure

## Blind Spots

- NSG allow evidence is not the same as proof that a remote operator can connect successfully
- Layered controls outside visible NSGs can still block traffic

