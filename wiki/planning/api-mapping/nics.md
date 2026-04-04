# nics API Mapping

## Slice Goal

Surface operator-first NIC attachment and network-placement context before deeper effective-network
analysis exists.

This first version answers:
"Which NICs anchor workload placement, public IP references, subnet membership, and visible NSG
context worth operator follow-up?"

## Initial Scope

- NIC enumeration across the subscription
- Attached workload visibility when Azure exposes the VM reference
- Private IP, public IP, subnet, and VNet reference collection
- NIC-level NSG reference visibility

## Explicit Non-Goals For V1

- Effective route or effective NSG evaluation
- Load balancer backend-pool modeling
- Per-IP-configuration risk scoring beyond simple placement visibility

## Primary APIs

- `azure.mgmt.network.NetworkManagementClient.network_interfaces.list_all`

## Correlation / Joins

- Normalize NIC metadata into operator-first rows that preserve attachment and placement context
- Reuse NIC references as shared join inputs for `network-ports`, `workloads`, and related slices

## Blind Spots

- NIC visibility alone does not prove effective ingress or egress behavior
- A missing attached asset can reflect read-path limits or Azure shape differences, not absence

