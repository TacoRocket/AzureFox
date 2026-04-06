from __future__ import annotations

from scripts.validate_publish_metadata import validate_branch_name, validate_pr_title


def test_validate_branch_name_blocks_codex_branch() -> None:
    errors = validate_branch_name("codex/example")

    assert errors == [
        "Branch names containing 'codex' are blocked: "
        "codex/example. Rename the branch before pushing."
    ]


def test_validate_branch_name_allows_normal_review_branch() -> None:
    assert validate_branch_name("review/publish-metadata-guardrails") == []


def test_validate_pr_title_blocks_codex_tag() -> None:
    errors = validate_pr_title("[codex] tighten publish guardrails")

    assert errors == [
        "PR titles cannot include Codex branding such as '[codex]'. "
        "Use a plain descriptive title."
    ]


def test_validate_pr_title_blocks_codex_prefix() -> None:
    errors = validate_pr_title("Codex: tighten publish guardrails")

    assert errors == [
        "PR titles cannot include Codex branding such as '[codex]'. "
        "Use a plain descriptive title."
    ]


def test_validate_pr_title_allows_plain_title() -> None:
    assert validate_pr_title("Tighten publish guardrails") == []
