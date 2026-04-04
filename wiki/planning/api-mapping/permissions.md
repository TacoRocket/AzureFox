# permissions API Mapping

## Slice Goal

Triage which visible principals hold high-impact Azure RBAC roles without claiming full effective
authorization proof.

This first version answers:
"Which visible principals are privileged here, and how broad does that privilege appear to be?"

## Initial Scope

- High-impact role-name triage for visible principals
- Assignment-count rollups
- Current-identity flagging
- Privileged versus non-privileged classification based on surfaced role evidence

## Explicit Non-Goals For V1

- Full effective-permissions proof
- Deny-assignment, condition, or data-action analysis
- Service-specific privilege modeling outside visible RBAC roles

## Primary APIs

- Reuses AzureFox `principals` and `rbac` output

## Correlation / Joins

- Join principal rows to visible role assignments and classify high-impact roles conservatively
- Keep the command signal-first rather than turning it into a full policy evaluator

## Blind Spots

- A principal can still be powerful through paths not represented in visible RBAC assignments
- Non-privileged output means "not privileged from this read path," not universal safety
