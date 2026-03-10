# vms API Mapping

## Primary APIs

- `azure.mgmt.compute.ComputeManagementClient.virtual_machines.list_all`
- `azure.mgmt.compute.ComputeManagementClient.virtual_machine_scale_sets.list_all`
- `azure.mgmt.network.NetworkManagementClient.network_interfaces.get`
- `azure.mgmt.network.NetworkManagementClient.public_ip_addresses.get`

## Correlation / Joins

- VM NIC references are resolved to private/public IPs.
- Identity attachments are joined with exposure indicators for correlation findings.

## Assumptions

- VM and VMSS visibility is subscription-scoped in Milestone 1.

## Blind Spots

- No deep NSG rule path simulation in Milestone 1.
