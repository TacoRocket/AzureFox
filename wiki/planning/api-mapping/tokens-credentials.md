# tokens-credentials API Mapping

## Slice Goal

Correlate readable Azure metadata that points to likely token-minting or credential-bearing
surfaces.

This first version answers:
"Which workloads can mint tokens, and which readable config or deployment artifacts may expose
credential material worth operator follow-up?"

## Initial Scope

- App Service and Function App settings that are plain-text credential-like values
- App Service and Function App settings that reference Key Vault-backed secrets
- Workloads with attached managed identities that can mint tokens
- ARM deployment history entries with output values or linked template/parameter content
- VM and VMSS managed-identity token paths surfaced through management-plane workload metadata

## Explicit Non-Goals For V1

- Reading actual secret values from Key Vault or workload runtimes
- Executing live token exchange, IMDS requests, or managed-identity proof
- Service principal secret, certificate, or federated token collection from Entra objects
- Data-plane secret discovery beyond what existing management-plane metadata already reveals

## Primary APIs

- `azure.mgmt.web.WebSiteManagementClient.web_apps.list`
- `azure.mgmt.web.WebSiteManagementClient.web_apps.list_application_settings`
- `azure.mgmt.resource.ResourceManagementClient.deployments.list_at_subscription_scope`
- `azure.mgmt.resource.ResourceManagementClient.deployments.list_by_resource_group`
- `azure.mgmt.compute.ComputeManagementClient.virtual_machines.list_all`
- `azure.mgmt.compute.ComputeManagementClient.virtual_machine_scale_sets.list_all`

## Correlation / Joins

- Reuse workload identity context from `env-vars` and `vms`
- Enumerate App Service and Function workload identity posture independently of whether any app
  settings are present or readable
- Reuse deployment metadata from `arm-deployments`
- Normalize those sources into operator-first token/credential surfaces
- Generate findings for plain-text credential-like settings, managed-identity token paths,
  Key Vault-backed settings, deployment outputs, and linked deployment content

## Blind Spots

- V1 surfaces likely credential paths but does not prove secret value readability
- Managed-identity rows show token-minting opportunity, not proven token scope or downstream
  permissions
- Deployment outputs and linked content are clues, not proof that sensitive values were exposed
