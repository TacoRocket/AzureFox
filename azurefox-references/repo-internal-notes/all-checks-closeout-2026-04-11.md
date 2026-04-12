# `all-checks` Closeout

Date: 2026-04-11

Decision:

- keep `all-checks` removed
- do not rename or narrow it into a new public command
- treat any remaining references as cleanup only

Why this closes Task `8.1`:

- the CLI already rejects `all-checks`
- section help already points operators at the flat commands directly
- grouped follow-up now lives in `chains` where AzureFox can make stronger bounded claims

Operator-facing recommendation:

- use section help to choose the flat commands that match the current question
- use `chains` for grouped follow-up when the repo can defend a real family workflow

Cleanup rule:

- keep one regression test that confirms `all-checks` stays removed
- remove stale examples or normalization tests that still treat `all-checks` like an active command
- do not reopen the command unless a future operator workflow is materially different from both
  section help and grouped `chains`
