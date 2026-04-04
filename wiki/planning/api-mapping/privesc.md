# privesc API Mapping

## Slice Goal

Surface likely Azure privilege-escalation and role-abuse paths first, without implying a complete
attack-path graph.

This first version answers:
"Which visible Azure identity paths look most likely to produce privileged control if an operator
or attacker can act on them?"

## Initial Scope

- Direct high-impact RBAC abuse paths
- Public workload identity pivot paths where current metadata supports them
- Severity and current-identity cues for operator triage

## Explicit Non-Goals For V1

- Full graph search across every Azure service relationship
- Consent-grant, tenant-boundary, or PIM-specific abuse modeling
- Proof of exploitability or successful abuse

## Primary APIs

- Reuses AzureFox `permissions`, `principals`, `managed-identities`, and `vms` output

## Correlation / Joins

- Join privileged principal visibility with workload identity attachments and public workload cues
- Keep path types explicit and evidence-based instead of inferring broader graph reach

## Blind Spots

- A surfaced path is a lead to review, not proof that abuse will succeed end to end
- V1 intentionally misses broader service-graph and tenant-wide relationship paths

