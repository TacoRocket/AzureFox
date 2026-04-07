from __future__ import annotations

import json
from pathlib import Path


def test_command_output_examples_include_flat_and_chain_sources() -> None:
    root = Path(__file__).resolve().parent.parent / "command-output"

    role_trusts_payload = json.loads(
        (root / "role-trusts" / "output.json").read_text(encoding="utf-8")
    )
    assert role_trusts_payload["metadata"]["command"] == "role-trusts"
    assert role_trusts_payload["metadata"]["generated_at"] == "<generated_at>"
    assert len(role_trusts_payload["trusts"]) == 3
    assert "operator_signal" in role_trusts_payload["trusts"][0]
    assert (root / "role-trusts" / "table.txt").is_file()

    credential_path_payload = json.loads(
        (root / "chains" / "credential-path" / "output.json").read_text(encoding="utf-8")
    )
    assert credential_path_payload["metadata"]["command"] == "chains"
    assert credential_path_payload["family"] == "credential-path"
    assert len(credential_path_payload["paths"]) == 3
    assert (root / "chains" / "credential-path" / "table.txt").is_file()
