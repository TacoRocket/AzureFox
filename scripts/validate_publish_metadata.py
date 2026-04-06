#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys

_FORBIDDEN_PR_TITLE_PATTERNS = (
    re.compile(r"\[\s*codex\s*\]", re.IGNORECASE),
    re.compile(r"\(\s*codex\s*\)", re.IGNORECASE),
    re.compile(r"^\s*codex\s*:", re.IGNORECASE),
)


def validate_branch_name(branch: str) -> list[str]:
    errors: list[str] = []
    if "codex" in branch.lower():
        errors.append(
            "Branch names containing 'codex' are blocked: "
            f"{branch}. Rename the branch before pushing."
        )
    return errors


def validate_pr_title(title: str) -> list[str]:
    errors: list[str] = []
    if any(pattern.search(title) for pattern in _FORBIDDEN_PR_TITLE_PATTERNS):
        errors.append(
            "PR titles cannot include Codex branding such as '[codex]'. "
            "Use a plain descriptive title."
        )
    return errors


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate local branch and PR metadata against AzureFox publish rules."
    )
    parser.add_argument("--branch", help="Branch name to validate.")
    parser.add_argument("--pr-title", help="Pull request title to validate.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    errors: list[str] = []
    if args.branch:
        errors.extend(validate_branch_name(args.branch))
    if args.pr_title:
        errors.extend(validate_pr_title(args.pr_title))

    if not errors:
        return 0

    for error in errors:
        print(f"[guardrail] {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
