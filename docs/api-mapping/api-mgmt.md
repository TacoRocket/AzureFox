# api-mgmt API Mapping

## Slice Goal

Surface operator-first API Management service posture before deeper APIM analysis exists.

This first version answers:
"Which API Management services expose interesting gateway hostnames, identity context, and basic
service inventory for operator follow-up?"

## Initial Scope

- API Management service enumeration
- Gateway, management, and portal hostname visibility
- Public network access and virtual network mode
- Managed identity attachment context
- Basic per-service inventory counts for APIs, backends, and named values

## Explicit Non-Goals For V1

- APIM subscription inventory or subscription-required risk depth
- Named-value secret classification or Key Vault-backed named-value depth
- Policy body collection or policy-content inspection
- Backend URL trust modeling beyond simple backend count visibility

## Primary APIs

- `azure.mgmt.apimanagement.ApiManagementClient.api_management_service.list`
- `azure.mgmt.apimanagement.ApiManagementClient.api.list_by_service`
- `azure.mgmt.apimanagement.ApiManagementClient.backend.list_by_service`
- `azure.mgmt.apimanagement.ApiManagementClient.named_value.list_by_service`

## Correlation / Joins

- Normalize service-level APIM metadata into operator-first rows
- Join hostname, public exposure, identity, and service inventory into a single service summary
- Keep partial-read gaps explicit when API, backend, or named-value reads are denied

## Blind Spots

- V1 does not inspect APIM subscriptions, policy bodies, or named-value secret content
- Named-value counts show service shape, not whether values are sensitive or retrievable
- Backend count visibility does not prove backend reachability or trust-path abuse
