# app-services API Mapping

## Slice Goal

Deepen App Service posture beyond workload census while staying inside management-plane evidence.

This first version answers:
"Which App Service apps expose the most interesting runtime, identity, hostname, and basic
hardening posture for operator follow-up?"

## Initial Scope

- App Service enumeration
- Default hostname visibility
- Runtime stack visibility
- Managed identity attachment context
- Public network access, HTTPS-only, FTPS, and TLS posture where readable

## Explicit Non-Goals For V1

- App-setting or secret review
- Custom-domain validation or live reachability proof
- Deployment-slot or code-package analysis

## Primary APIs

- `azure.mgmt.web.WebSiteManagementClient.web_apps.list`
- `azure.mgmt.web.WebSiteManagementClient.web_apps.get_configuration`

## Correlation / Joins

- Join App Service app metadata with readable configuration posture into one service summary row
- Leave app-setting analysis to `env-vars`

## Blind Spots

- Hostname visibility does not prove a public route is actually reachable
- Missing runtime or posture fields can reflect partial-read limits rather than a negative state

