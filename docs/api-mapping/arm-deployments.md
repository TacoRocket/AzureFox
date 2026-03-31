# arm-deployments API Mapping

## Slice Goal

Surface ARM deployment history that reveals useful configuration context, output exposure, and
linked deployment content.

This first version answers:
"Which deployments expose outputs, linked templates, or failed runs worth operator review?"

## Initial Scope

- Subscription-scope deployment history
- Resource-group deployment history
- Provisioning state, scope, output counts, and linked template/parameter references

## Explicit Non-Goals For V1

- Full template-body analysis
- Secret value extraction from parameters or outputs
- Template Spec, Deployment Script, or deployment stack coverage
- Cross-tenant or management-group deployment analysis

## Primary APIs

- `azure.mgmt.resource.ResourceManagementClient.deployments.list_at_subscription_scope`
- `azure.mgmt.resource.ResourceManagementClient.deployments.list_by_resource_group`

## Correlation / Joins

- Normalize deployment metadata into operator-first rows
- Generate findings for failed deployments, output-bearing deployments, and linked template usage

## Blind Spots

- Linked template URIs are surfaced, but linked content is not fetched in this slice
- Deployment history alone does not prove which outputs were sensitive or broadly readable
