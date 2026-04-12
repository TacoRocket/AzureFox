# `workload-identity-path` Re-entry Checkpoint

Date: 2026-04-11

Purpose:

- answer Task `4.9` from the active execution roadmap against the current merged AzureFox codebase
- decide whether `workload-identity-path` should reopen now, and if so, how narrowly
- prevent the next implementation thread from re-arguing the admission bar from scratch

## Checkpoint Question

Does current AzureFox evidence support a truthful `workload-identity-path` family that can say:

- what the workload-side insertion point is
- what exact thing changes next if that foothold is controlled
- what stronger Azure control follows
- what proof is still missing
- what exact edge a defender would break

## Current Evidence That Now Clears The Bar

One row type is now strong enough to reopen narrowly:

- `direct token opportunity`

Why it clears:

- `tokens-credentials` already surfaces workload-linked `managed-identity-token` rows with a real
  workload-side insertion point such as IMDS or managed-identity token request capability
- `managed-identities` already ties the same workload to the attached identity and now says whether
  direct control is visible or still blocked
- `permissions` already shows whether the attached identity holds meaningful Azure control
- `workloads` can provide the public or workload-anchor context that explains why the operator
  should stop on that row now instead of treating it like generic identity inventory

Plain-language transform:

- if the workload foothold is controlled, the attacker can try to mint a token as the attached
  identity
- that token path can immediately matter because AzureFox can already show the stronger Azure
  control behind the same identity in `permissions` or the managed-identity RBAC join

Practical defender cut points:

- break the workload-side token request path
- break the workload foothold or ingress path that makes the token path meaningful
- detach the managed identity from the workload
- narrow or remove the attached identity's high-impact Azure roles

## Current Evidence That Still Does Not Clear The Bar

These row types should stay out of the family for now:

- `local identity leverage`
- `trust expansion`
- standalone `visibility blocked`

Why they stay blocked:

- `workloads` is still a census-style command; it proves anchor and exposure context, not the
  workload-local subversion point needed for a broad local-leverage row
- `managed-identities` is strong for attachment plus visible RBAC, but a non-token row can still
  collapse into `this workload has identity` plus `this identity has privilege`
- `role-trusts` now carries real transform truth such as `usable_identity_result` and
  `defender_cut_point`, but those trust rows are still identity-centric rather than anchored to a
  workload-side subversion point
- a visibility-blocked row with no direct token clue would still read too much like `maybe, if
  several unknown things line up`

Short rule:

- no token-capable workload-side transform, no default `workload-identity-path` row yet

## Decision

Task `4.9` passes only as a narrow re-entry.

Reopen `workload-identity-path` for one truthful v1 slice built around `direct token opportunity`
rows only.

Do not reopen the broader family taxonomy yet.

## Recommended Next Slice

The next implementation thread should be a narrow `workload-identity-path` extraction and ranking
slice with this admission rule:

- keep a row only when `tokens-credentials` shows a `managed-identity-token` surface
- require a same-workload join into `managed-identities`
- require a same-identity join into visible Azure control from `permissions` or the
  managed-identity RBAC enrichment
- use `workloads` only as supporting insertion-point context, not as an admission substitute
- keep `role-trusts` out of default row admission until the trust transform is also tied to a real
  workload-side subversion point

Recommended first row order:

1. public or externally reachable token-capable workload plus direct control visible
2. token-capable workload plus direct control visible
3. token-capable workload plus visibility-bounded direct control

## Explicit Non-goals For The Next Slice

- do not ship generic `has identity` rows
- do not ship trust-expansion rows just because the attached identity also appears in
  `role-trusts`
- do not let `workloads` exposure context outrank explicit token-capable proof
- do not make `visibility blocked` a catch-all row type that survives without a defended transform
