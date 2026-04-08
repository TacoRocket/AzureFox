from __future__ import annotations

import json
from pathlib import Path

from azurefox.config import GlobalOptions
from azurefox.models.common import SCHEMA_VERSION, OutputMode
from azurefox.output.writer import write_artifacts


def _options(tmp_path: Path) -> GlobalOptions:
    return GlobalOptions(
        tenant=None,
        subscription=None,
        output=OutputMode.JSON,
        outdir=tmp_path,
        debug=False,
    )


def test_write_artifacts_loot_uses_small_metadata_and_drops_empty_top_level_sections(
    tmp_path: Path,
) -> None:
    surfaces = [
        {
            "asset_name": f"target-{index:02d}",
            "priority": "high" if index < 3 else "medium",
            "summary": f"ranked target {index:02d}",
        }
        for index in range(12)
    ]
    payload = {
        "metadata": {
            "schema_version": SCHEMA_VERSION,
            "command": "tokens-credentials",
            "generated_at": "2026-04-06T12:00:00Z",
            "tenant_id": "tenant-1",
            "subscription_id": "sub-1",
        },
        "surfaces": surfaces,
        "findings": [],
        "issues": [],
    }

    artifact_paths = write_artifacts("tokens-credentials", payload, _options(tmp_path))
    loot_payload = json.loads(artifact_paths["loot"].read_text(encoding="utf-8"))
    json_payload = json.loads(artifact_paths["json"].read_text(encoding="utf-8"))

    assert loot_payload["metadata"] == {
        "schema_version": SCHEMA_VERSION,
        "command": "tokens-credentials",
    }
    assert "generated_at" in json_payload["metadata"]
    assert "tenant_id" not in loot_payload["metadata"]
    assert "findings" not in loot_payload
    assert "issues" not in loot_payload
    assert loot_payload["surfaces"] == json_payload["surfaces"][:10]
    assert loot_payload["loot_scope"] == {
        "selection": "top-ranked-targets",
        "source_count": 12,
        "returned_count": 10,
        "limit": 10,
    }


def test_write_artifacts_loot_keeps_nonempty_findings_and_issues(tmp_path: Path) -> None:
    payload = {
        "metadata": {
            "schema_version": SCHEMA_VERSION,
            "command": "storage",
            "generated_at": "2026-04-06T12:00:00Z",
        },
        "storage_assets": [],
        "findings": [
            {
                "kind": "public_access",
                "summary": "Storage account allows public access.",
                "related_ids": ["storage-1"],
            }
        ],
        "issues": [
            {
                "kind": "permission_denied",
                "message": "storage.accounts: 403 Forbidden",
                "context": {"collector": "storage.accounts"},
            }
        ],
    }

    artifact_paths = write_artifacts("storage", payload, _options(tmp_path))
    loot_payload = json.loads(artifact_paths["loot"].read_text(encoding="utf-8"))

    assert loot_payload["metadata"] == {
        "schema_version": SCHEMA_VERSION,
        "command": "storage",
    }
    assert loot_payload["findings"] == payload["findings"]
    assert loot_payload["issues"] == payload["issues"]


def test_write_artifacts_network_effective_uses_row_mapped_loot_and_csv(tmp_path: Path) -> None:
    exposures = [
        {
            "asset_name": f"vm-web-{index:02d}",
            "effective_exposure": "high" if index < 3 else "medium",
            "endpoint": f"52.160.10.{index}",
        }
        for index in range(12)
    ]
    payload = {
        "metadata": {
            "schema_version": SCHEMA_VERSION,
            "command": "network-effective",
            "generated_at": "2026-04-06T12:00:00Z",
        },
        "effective_exposures": exposures,
        "findings": [],
        "issues": [],
    }

    artifact_paths = write_artifacts("network-effective", payload, _options(tmp_path))
    loot_payload = json.loads(artifact_paths["loot"].read_text(encoding="utf-8"))
    csv_lines = artifact_paths["csv"].read_text(encoding="utf-8").splitlines()

    assert loot_payload["effective_exposures"] == exposures[:10]
    assert loot_payload["loot_scope"] == {
        "selection": "top-ranked-targets",
        "source_count": 12,
        "returned_count": 10,
        "limit": 10,
    }
    assert csv_lines[0].startswith("asset_name,")
    assert len(csv_lines) == 13
