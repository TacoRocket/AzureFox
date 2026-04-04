# api-mgmt API Mapping

## Slice Goal

Surface operator-first API Management service posture with a narrow first depth pass.

This version answers:
"Which API Management services expose interesting gateway hostnames, identity context, basic
service inventory, and a few internal triage clues for operator follow-up?"

## Initial Scope

- API Management service enumeration
- Gateway, management, and portal hostname visibility
- Public network access and virtual network mode
- Managed identity attachment context
- Basic per-service inventory counts for APIs, backends, and named values
- Visible subscription counts and active-subscription cues
- API subscription-required rollups when readable
- Named-value secret counts and Key Vault-backed counts
- Backend host visibility from configured backend URLs

## Explicit Non-Goals For V1

- Full policy-body collection or policy-content export
- Named-value secret value retrieval
- Full backend trust modeling or reachability claims
- Content-heavy output that turns the command into a raw APIM dump

## Primary APIs

- `azure.mgmt.apimanagement.ApiManagementClient.api_management_service.list`
- `azure.mgmt.apimanagement.ApiManagementClient.api.list_by_service`
- `azure.mgmt.apimanagement.ApiManagementClient.subscription.list`
- `azure.mgmt.apimanagement.ApiManagementClient.backend.list_by_service`
- `azure.mgmt.apimanagement.ApiManagementClient.named_value.list_by_service`

## Correlation / Joins

- Normalize service-level APIM metadata into operator-first rows
- Join hostname, public exposure, identity, and service inventory into a single service summary
- Roll up visible subscription posture, named-value secret posture, and backend destination hosts
- Keep partial-read gaps explicit when API, backend, or named-value reads are denied

## Blind Spots

- The command still does not export policy bodies or dump raw APIM configuration
- Secret-marked and Key Vault-backed named values are posture clues, not secret retrieval
- Backend host visibility does not prove backend reachability or exploitability
