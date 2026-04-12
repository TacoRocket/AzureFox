# Compute Control Boundary Tasklist

Date: 2026-04-11

This tasklist exists to keep `compute-control` honest while the family is still being shaped.

Goal:
identify which candidate rows truly belong in `compute-control`, which rows should stay in another
family such as `credential-path`, and which rows would mean the family boundary is broader than the
current name implies.

## Core Question

When a candidate row appears during `compute-control` implementation, which of these is true?

1. it belongs in `compute-control`
2. it really belongs in another shipped family
3. it exposes that the family boundary is broader than `compute` and the name should be revisited

## Working Rule

Do not solve boundary confusion ad hoc in code.

For each contested row shape, answer:

- what is the starting surface?
- what is the downstream effect?
- what is the next validating command?

If those three stay aligned with `compute -> control`, the row can stay.
If they do not, move the row out or revisit the family name before implementation hardens.

## Candidate Row Review Buckets

### Bucket A: Keep In `compute-control`

Use this bucket when:

- the starting surface is a compute foothold or running service
- the row has a visible workload-side insertion point
- the row leads to identity-backed Azure control
- the next validating move still feels like the same operator workflow

Likely examples:

- VM or VMSS token-capable workload -> attached identity -> visible Azure control
- App Service or Function App token-capable workload -> attached identity -> visible Azure control

### Bucket B: Move To Another Existing Family

Use this bucket when:

- the real starting surface is not compute
- the downstream story is better explained by a shipped family
- the validating command sequence no longer matches the compute-control workflow

Likely destinations:

- `credential-path` for secret-bearing or credential-shaped starting clues
- `deployment-path` for CI/CD, repo, automation, or trusted-input starting surfaces
- `escalation-path` for current-foothold trust or identity-control transforms that are not rooted in
  compute foothold actionability

### Bucket C: Revisit The Family Name

Use this bucket when:

- the candidate row keeps fitting the same operator workflow
- but the starting surface is repeatedly broader than compute
- and splitting it into multiple commands would create command sprawl rather than clarity

This bucket does not mean `keep everything`.
It means stop and decide whether the public family name is too narrow for the product shape.

## Review Steps

1. Collect candidate row shapes during implementation.
- Keep the example short and concrete.
- Name the starting surface, the stronger outcome, and the next review command.

2. Sort each candidate row into Bucket A, B, or C.
- Do not leave contested shapes unclassified.

3. Track repeated pressure on the family boundary.
- If the same non-compute starter keeps showing up, that is a naming signal, not a one-off exception.

4. Prefer moving rows to an existing family before inventing a new command.
- Avoid command sprawl.
- Add a new family only if the operator workflow is genuinely different.

5. Pause naming decisions only when the contested shapes are still too few to establish a pattern.
- Once a pattern appears, make the naming decision explicit.

## First Candidate Shapes To Watch

Start by watching for these drift patterns:

- secret-bearing compute config that really wants to behave like `credential-path`
- trust-expansion rows tied to an identity but not to a real compute-side insertion point
- deployment-origin rows that only happen to terminate at a compute workload
- generic `workload has identity` rows that do not explain how control progresses
- exposure-only workload rows that do not yet map to identity-backed Azure control

## Current Plumbing Gaps Already Exposed

These are not blockers for the narrow v1.
Track them as follow-on work while implementing `compute-control`:

- web workload token surfaces can exist without a matching explicit identity-anchor row in
  `managed-identities`, which limits how many App Service or Function rows can be admitted honestly
- mixed system-assigned and user-assigned workload identity rows need clearer actor disambiguation
  before they become safe default `compute-control` rows
- some system-assigned compute rows still surface token opportunity without a clean principal-level
  control join, which keeps them in `not yet admitted` territory even when the workload clue is real

## Concrete Candidate Shapes Observed In First Extraction

Treat these as active implementation follow-ons, not just observations:

- `app-empty-mi`:
  stays in Bucket A as a `compute-control` candidate, but it is not admitted until the attached
  system-assigned identity has a visible privileged permission join
- `app-public-api`:
  stays in Bucket A as a `compute-control` candidate, and current code can admit it honestly
  through workload-principal fallback if a privileged permission row appears; no extra command is
  required for that narrow path
- `func-orders`:
  remains out of scope for default admission until mixed system-assigned and user-assigned actor
  selection is explicit enough to defend one row
- `vmss-edge-01`:
  stays in Bucket A as a `compute-control` candidate, but it is not admitted until the system
  identity has a visible privileged control join

## Plumbing Tasks To Carry Forward

- Keep extending `managed-identities` coverage beyond VM-only anchors.
  System-assigned App Service, Function App, and VMSS anchors are now synthesized from workload
  data, and user-assigned web workload attachments are now surfaced as attachment-only anchors.
  Richer live metadata for those user-assigned identities still needs follow-on work.
- Keep row-level evidence honest when a `compute-control` path is admitted through `workloads` plus
  `permissions` without a separate `managed-identities` anchor row.
- Add fixture coverage for:
  - system-assigned web workload admission with a privileged permission join
  - mixed-identity workload exclusion until actor disambiguation is explicit
  - VMSS system-identity admission once a visible control join exists

## Definition Of Done

Treat this boundary tasklist as complete only when:

- contested row shapes were explicitly classified
- the implementation has a stable admission rule for `compute-control`
- repeated non-compute pressure either moved into existing families or triggered an explicit naming
  revisit
- the team can explain why `compute-control` is one command family instead of several overlapping
  ones
