# endpoints API Mapping

## Slice Goal

Correlate public IPs and Azure-managed hostnames into a simple ingress triage surface.

This first version answers:
"Which visible IPs or hostnames belong to which assets, and what kind of ingress path does each
surface represent?"

## Initial Scope

- VM public IP endpoint visibility
- App Service and Function App default hostname visibility
- Exposure-family labeling for public IPs versus Azure-managed web hostnames
- Ingress-path labeling that stays narrower than full reachability proof

## Explicit Non-Goals For V1

- Port-level exposure analysis
- Effective reachability proof
- DNS-resolution behavior or custom-domain validation
- Load balancer or application gateway path modeling

## Primary APIs

- Reuses AzureFox `vms` output for public IP-backed compute endpoints
- Reuses AzureFox web workload collection for App Service and Function App hostnames

## Correlation / Joins

- Join workload identity and hostname context into one endpoint inventory shape
- Keep hostname visibility distinct from proven public reachability

## Blind Spots

- A visible hostname does not prove the application is reachable from the internet
- Endpoint visibility stays limited to the current public IP and Azure-managed hostname paths

