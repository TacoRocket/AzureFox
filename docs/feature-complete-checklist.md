# Feature Complete Checklist

Date: 2026-04-01

This is an internal reference note for deciding when AzureFox is ready to move from
"still adding slices" to "feature complete enough to stabilize and package confidently."

It is not a promise that every possible Azure surface is covered.
It is a checklist for deciding whether the current product boundary is coherent, reliable, and
ready to ship as a real tool.

## What "Feature Complete" Should Mean Here

AzureFox can be treated as feature complete when:

- the planned command surface has a clear stopping point
- each command says only what it can really prove
- the operator workflow feels coherent end to end
- packaging and release steps are repeatable
- remaining work is mostly depth, polish, or new roadmap phases rather than missing core footing

Small example:

- good feature-complete state:
  `dns` clearly covers zone inventory, record-set totals, and namespace context
- not yet feature-complete state:
  `dns` exists, but help text, CSV output, schemas, and fixtures disagree about what it returns

## Product Boundary Checks

- Every roadmap command has a clear v1 boundary.
- Each command has explicit non-goals so future depth does not get confused with current coverage.
- Help text, JSON, table output, CSV output, and findings all describe the same evidence boundary.
- Future follow-on work is parked in roadmap or candidate docs instead of living only in PR memory.
- Commands do not imply exploitability, reachability, or access proof when they only have
  management-plane metadata.

## Reliability Checks

- Commands handle partial-permission reads without silently hiding uncertainty.
- JSON output is deterministic and schema-backed.
- Fixtures, schemas, golden outputs, smoke tests, and full tests all agree on command shape.
- `all-checks` runs cleanly and produces a believable operator workflow.
- Installation and normal local validation do not depend on machine-specific paths or accidental
  editable-install behavior.

## Operator UX Checks

- Command naming is consistent and easy to scan.
- Table output emphasizes the most useful operator decisions first.
- "Why it matters" summaries are evidence-based, concise, and stylistically consistent.
- Help topics explain what the command is for, what it is not for, and how to use the output.
- Cross-command wording stays aligned so similar concepts read the same way in different slices.

## Documentation Checks

- Public roadmap reflects the current real command surface.
- Internal handoff notes identify what is complete, what is parked, and what should happen next.
- API-mapping docs exist for implemented slices that need clear boundary or evidence notes.
- Release and validation instructions still match the actual repo behavior.

## Release Readiness Checks

- A new contributor can install the tool and run a representative command without hidden setup.
- Standard validation commands are written down and pass consistently.
- The repo can produce a releasable Python package without special-case local hacks.
- There is a clear distinction between:
  - supported command behavior
  - known blind spots
  - future roadmap work

## Good Questions To Ask At The End

- If we stopped adding commands today, would the current product still feel coherent?
- If a user found a command in help output, would they understand what it proves and what it
  does not?
- If a bug report came in, would the fixtures and tests make it easy to reproduce?
- If a release had to go out this week, would packaging and validation feel routine instead of
  fragile?

## Branching Recommendation

Do not split AzureFox into:

- a long-lived `dev` branch with tests and docs, and
- a stripped-down `prod` or `main` branch that only keeps runtime files

Why this is risky:

- fixes will drift between branches
- docs and tests will stop matching shipped behavior
- release debugging gets harder because production history no longer reflects real development
- confidence drops because the tested tree and the shipped tree are different

Recommended approach instead:

- keep one real source branch, normally `main`
- keep tests, docs, schemas, fixtures, and tooling in that source repo
- publish runtime artifacts for users rather than maintaining a second stripped branch

Good production outputs can be:

- Python wheel or sdist
- GitHub release artifact
- packaged install instructions
- Docker image, if that becomes useful later

Small example:

- source repo contains `src/`, `tests/`, `docs/`, and `schemas/`
- end users install the built package
- they get the runnable CLI
- the team keeps one trustworthy history instead of two branches that slowly diverge

## Practical "Feature Complete" Decision

For AzureFox, a healthy feature-complete transition would look like this:

1. finish the intended roadmap tranche
2. run a broad review pass for drift across the completed phases
3. do clarity and consistency cleanup without changing product scope
4. confirm release packaging and validation are stable
5. shift future work from "missing basics" to:
   - deeper service follow-ons
   - new roadmap phases
   - packaging and release maturity

If those checks are true, the project can reasonably be treated as feature complete for its
current planned scope, even if many future Azure slices still remain possible.
