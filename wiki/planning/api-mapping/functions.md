# functions API Mapping

## Slice Goal

Deepen Function App posture beyond workload census while staying inside management-plane evidence.

This first version answers:
"Which Function Apps expose the most interesting runtime, storage-binding, identity, and basic
deployment posture for operator follow-up?"

## Initial Scope

- Function App enumeration
- Default hostname visibility
- Runtime stack and Functions runtime version visibility
- Managed identity attachment context
- AzureWebJobsStorage binding classification, run-from-package signals, and Key Vault reference count

## Explicit Non-Goals For V1

- Function code inspection
- Trigger inventory or execution proof
- Secret-value extraction from app settings or Key Vault

## Primary APIs

- `azure.mgmt.web.WebSiteManagementClient.web_apps.list`
- `azure.mgmt.web.WebSiteManagementClient.web_apps.get_configuration`
- `azure.mgmt.web.WebSiteManagementClient.web_apps.list_application_settings`

## Correlation / Joins

- Join Function App metadata, readable configuration, and app-setting posture into one service row
- Keep raw app-setting detail in `env-vars` while surfacing deployment-oriented operator cues here

## Blind Spots

- Deployment signals do not prove code content or runtime execution behavior
- Visible hostnames do not prove a reachable public path from the current network

