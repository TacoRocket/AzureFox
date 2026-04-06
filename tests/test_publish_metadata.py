from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_publish_metadata_module():
    script_path = (
        Path(__file__).resolve().parents[1] / "scripts" / "validate_publish_metadata.py"
    )
    spec = importlib.util.spec_from_file_location("validate_publish_metadata", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_PUBLISH_METADATA = _load_publish_metadata_module()
validate_branch_name = _PUBLISH_METADATA.validate_branch_name
validate_pr_title = _PUBLISH_METADATA.validate_pr_title


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
