# Phase Closeout Tasklist

Date: 2026-04-11

This tasklist turns the remaining active endgame work into one bounded closeout queue.

Goal:
finish the last meaningful chain-family work, resolve the current family-naming cleanup, wrap the
remaining near-term orchestration decisions, and retire stale tasklists or handovers so the repo
does not keep carrying duplicate next-step notes.

## Outcome

By the end of this tasklist, AzureFox should have:

- one explicit decision on the family naming issue exposed by the current `4.9` work
- one explicit decision on the narrow follow-on after Task `4.9`
- one explicit call on whether any extra `deployment-path` target family deserves near-term work
- one explicit wrap-up pass for Task `7.1`
- one explicit wrap-up pass for Task `8.1`
- one small cleanup pass for stale tasklists and superseded handovers
- one reduced set of active planning notes instead of multiple overlapping next-thread guides

## Phase 1: Resolve Family Naming While `4.9` Is Still Fluid

1. Turn the current naming discussion into one bounded naming task.
- Identify the operator-facing family name that best matches the real command boundary.
- Keep the current two-word preference unless the real product boundary clearly needs more.
- Do not let internal chain mechanics drive the name.
- Use `azurefox-references/tasklists/compute-control-boundary-tasklist-2026-04-11.md` to classify
  contested row shapes while the family is still fluid.

2. Use one simple naming test.
- starting surface
- downstream effect
- next validating move

Working rule:
- if those three stay aligned, keep one command family
- if the proposed family keeps drifting across different starter surfaces or different next moves,
  revisit the name before implementation hardens

3. Recheck the family boundary against the working naming direction.
- If the slice remains compute-foothold to Azure-control, a name in the `compute-control` shape
  may fit.
- If the slice keeps pulling in non-compute starters, widen or rethink the public family name
  before shipping.

## Phase 2: Finish The `4.9` Follow-On

4. Turn the `4.9` checkpoint into one narrow implementation slice.
- Use the `workload-identity-path` re-entry result from
  `azurefox-references/repo-internal-notes/workload-identity-path-reentry-checkpoint-2026-04-11.md`.
- Keep the first slice narrow: direct token opportunity rows only.

5. Keep the row-admission rule explicit.
- Require a token-capable workload-side foothold from `tokens-credentials`.
- Require the same-workload identity anchor from `managed-identities`.
- Require visible Azure control from `permissions` or the managed-identity RBAC join.
- Use `workloads` only as supporting compute-context evidence, not as admission by itself.

6. Run Task `4.9a` as a bounded checkpoint, not an expansion wave.
- Decide whether any additional `deployment-path` target family actually clears the current bar.
- Prefer an explicit `not yet` decision over broadening the family with support-only clues.

## Phase 3: Wrap The Remaining Active Later-Lane Items

7. Close Task `7.1` as a bounded loot-behavior review.
- Working ownership: user-owned closeout lane.
- Working closeout direction: decide where `loot` can truthfully treat `high` as a semantic band and
  where it must keep using top-ranked cutoff behavior.
- Treat grouped-chain `priority` and `urgency` as existing family contracts, not the main `7.1`
  redesign target.
- Prefer a short command-by-command truthfulness pass over a new broad ranking redesign.
- Current first-wave semantic-loot commands: `tokens-credentials`, `cross-tenant`,
  `permissions`, and `privesc`.
- Current fallback-only commands should keep ranked-cutoff behavior until they can defend a real
  row-level priority contract.
- Follow-on normalization task: once `privesc` compatibility is rechecked, retire the temporary
  legacy `severity` field and keep `priority` as the operator-facing contract.
- Carry forward any real follow-on plumbing separately if a command still lacks honest semantic
  labels.

8. Close Task `8.1` as an active orchestration decision.
- Working ownership: user-owned closeout lane.
- Working closeout direction: keep `all-checks` removed and clean up stale references only.
- Use flat section help plus grouped `chains` families as the operator-facing replacement.
- Prefer a clear operator-facing recommendation over another broad orchestration redesign.

9. Keep the deferred lanes out of this tasklist.
- `5.1` Go rewrite timing
- `5.2` Go rewrite first-slice planning
- `6.1` `--impact` design
- `6.2` first-wave `--impact`

Working rule:
- do not keep the rewrite or `--impact` lanes in the active phase-closeout queue just because the roadmap still lists them
- only pull one back in if the closeout work exposes a real blocker or forces an immediate boundary decision

## Phase 4: Retire Stale Planning Notes

10. Inventory current tasklists and handovers before deleting anything.
- Identify which notes still contain unique operational guidance.
- Identify which notes are now duplicated by the active roadmap, completed roadmap, or newer checkpoint notes.

11. Classify each planning note into one of three buckets.
- active reference
- historical reference worth keeping
- stale and safe to archive or remove

12. Prioritize stale-tasklist cleanup targets.
- older next-thread handovers that still point to already-merged work
- tasklists whose implementation goals are now completed
- temporary `tmp-*.md` planning notes referenced only by older handovers

Carry-forward rule:
- do not leave older tasklists in place just because they still hold valid items
- move any still-valid work into the active or deferred closeout queues first, then archive the
  older source tasklist deliberately

Current carry-forward targets:
- the older tasklist index in the reference tree is outdated and should be rewritten after the
  carry-forward move is complete
- `viewpoint-validation-tasklist-2026-04-08.md` still has valid work that belongs in the active
  finish-line queue:
  - restricted-view honesty checks for `chains`
  - preserved `next_review` routing under partial visibility
  - fixture/golden coverage for current chain-family and identity-routing surfaces
- `auth-support-tasklist-2026-04-08.md` still has valid work that belongs in the deferred queue:
  - supported auth matrix docs
  - auth-mode classification visibility
  - auth-path tests and error-hint cleanup
- `demo-capture-tasklist-2026-04-11.md` is a separate lane and should stay separate unless the
  team explicitly wants demo work folded into closeout

13. Move historical-but-superseded notes out of the active path.
- prefer an `old-reference-docs/` or equivalent historical folder for notes worth retaining
- keep the active tasklist/readme surfaces limited to documents that still drive execution

14. Remove or rewrite stale references that misstate the next task.
- especially any note that still points to pre-`4.9` sequencing as the active queue
- especially any tasklist index that still treats already-landed work as current

15. Archive the older source tasklists after carry-forward is complete.
- archive `viewpoint-validation-tasklist-2026-04-08.md` once its remaining valid items are covered
  by the active finish-line queue
- archive `auth-support-tasklist-2026-04-08.md` once its remaining valid items are covered by the
  deferred queue
- rewrite the older tasklist index so it points at the new closeout/deferred tasklists or archive
  it if the index itself is no longer needed

## Suggested Execution Order

1. resolve the family naming task while the `4.9` family boundary is still fluid
2. implement the narrow follow-on to Task `4.9`
3. run the `4.9a` target-family admission checkpoint
4. close Task `7.1`
5. close Task `8.1`
6. do the stale-tasklist and stale-handover inventory
7. carry forward remaining valid items from older tasklists
8. archive or rewrite superseded planning surfaces

## Definition Of Done

Treat the closeout queue as complete only when:

- the family naming issue has an explicit working decision
- the `4.9` follow-on is either shipped or explicitly re-parked
- `4.9a` names one admissible next slice or explicitly leaves extra target families out
- Task `7.1` has an explicit loot-band decision for the commands that can support it honestly, plus
  a durable note about where ranked-cutoff behavior still stays in place
- Task `8.1` has an explicit removal-and-cleanup decision for `all-checks`, without more orchestration churn
- valid work from the older viewpoint-validation tasklist is covered here before that source note is archived
- active planning notes no longer disagree on what the next task is
- stale tasklists or handovers are archived, rewritten, or removed
- the remaining active planning surface fits in one short queue instead of multiple overlapping guides
