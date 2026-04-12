# Deferred Platform And Impact Tasklist

Date: 2026-04-11

This tasklist holds the later-lane work that should stay out of the active phase-closeout queue.

Goal:
keep the Go rewrite and `--impact` work visible without letting them block the current finish-line
tasks.

## Deferred Items

1. Carry forward the remaining auth-support lane before archiving the older source tasklist.
- absorb the still-valid items from `auth-support-tasklist-2026-04-08.md` into this deferred lane
- keep the practical set visible:
  - supported auth matrix docs
  - auth-mode classification and metadata visibility
  - auth-path tests and failure-hint cleanup
- once those items are represented here or completed elsewhere, archive the older auth-support
  tasklist

2. Task `5.1` Go rewrite timing checkpoint.
- Revisit only after the active chain families and orchestration follow-ons are stable enough that
  the rewrite is preserving a proven product shape.

3. Task `5.2` Go rewrite first-slice planning.
- Revisit only after Task `5.1` explicitly reactivates the rewrite lane.

4. Task `6.1` `--impact` implementation design.
- Revisit only after the active closeout queue stops changing the command and chain boundaries that
  `--impact` would need to explain.

5. Task `6.2` first-wave `--impact` rollout.
- Revisit only after Task `6.1` locks the design and the active closeout queue is no longer
  reshaping the default operator surface.

## Working Rule

- keep these tasks documented but out of the default near-term queue
- do not let them compete with the remaining chain-family and orchestration closeout work
- pull one back into the active queue only if a completed closeout slice exposes a real blocker or
  a product-boundary decision that cannot wait
