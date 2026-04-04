# workloads API Mapping

## Slice Goal

Build a joined workload census across compute, web workloads, identities, and visible endpoint
paths.

This first version answers:
"Which workloads are worth follow-up first once identity-bearing assets and visible endpoint paths
are viewed together?"

## Initial Scope

- VM, VMSS, App Service, and Function App workload census
- Managed identity context for compute and web workloads
- Visible endpoint-path joins from `endpoints`
- Operator-first summary text that stays narrower than exploitability proof

## Explicit Non-Goals For V1

- Deep per-service runtime or deployment analysis
- Port-level or effective-network exposure claims
- Kubernetes-object, App Service setting, or Function package depth

## Primary APIs

- Reuses AzureFox `vms`, web workload collection, and `endpoints` output

## Correlation / Joins

- Normalize compute and web workload metadata into one joined workload row shape
- Use normalized ARM ID joins so endpoint-path visibility stays stable across casing differences

## Blind Spots

- Visible endpoint paths do not prove internet reachability
- Workload census is intentionally broad and should hand off to deeper service-specific commands

