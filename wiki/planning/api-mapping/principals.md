# principals API Mapping

## Slice Goal

Map practical principal context from caller visibility, RBAC scope, and managed identity
attachments.

This first version answers:
"Which principals matter in this subscription, and how are they connected to roles and workload
identities?"

## Initial Scope

- Current-caller identity inclusion from `whoami`
- Principal enumeration from visible RBAC assignments
- Managed identity attachment context folded into principal rows
- Role-name rollups and source tagging

## Explicit Non-Goals For V1

- Full tenant-wide Entra directory census
- Effective-permissions proof
- Consent, ownership, or broader trust-edge modeling beyond adjacent identity context

## Primary APIs

- Reuses AzureFox `whoami`, `rbac`, and `managed-identities` output

## Correlation / Joins

- Join caller context, RBAC-assignment visibility, and workload identity attachment into one
  principal inventory shape
- Keep contradictions explicit when different sources disagree about the same principal

## Blind Spots

- Principal visibility is bounded by readable RBAC scope and adjacent workload context
- Missing principals do not prove absence from the tenant
