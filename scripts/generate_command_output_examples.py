from __future__ import annotations

import json
import tempfile
from pathlib import Path

from azurefox.chains import implemented_chain_families, run_chain_family
from azurefox.collectors.provider import FixtureProvider
from azurefox.config import GlobalOptions
from azurefox.models.common import OutputMode
from azurefox.output.writer import PRIMARY_COLLECTION_KEYS
from azurefox.registry import get_command_specs
from azurefox.render.table import render_table

EXAMPLE_ROW_LIMIT = 3
OUTPUT_ROOT = Path("command-output")
FIXTURE_ROOT = Path("tests/fixtures/lab_tenant")


def normalize_payload(payload: dict) -> dict:
    normalized = json.loads(json.dumps(payload))
    metadata = normalized.get("metadata")
    if isinstance(metadata, dict):
        metadata["generated_at"] = "<generated_at>"
        if metadata.get("devops_organization") is None:
            metadata.pop("devops_organization", None)
    return normalized


def trim_payload(command: str, payload: dict, *, limit: int = EXAMPLE_ROW_LIMIT) -> dict:
    primary_key = PRIMARY_COLLECTION_KEYS.get(command)
    if primary_key is None:
        return payload

    trimmed = dict(payload)
    primary_value = trimmed.get(primary_key)
    if isinstance(primary_value, list):
        trimmed[primary_key] = primary_value[:limit]
    return trimmed


def write_example_files(destination: Path, payload: dict, table_text: str) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "output.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (destination / "table.txt").write_text(table_text + "\n", encoding="utf-8")


def generate_flat_command_examples(output_root: Path) -> None:
    provider = FixtureProvider(FIXTURE_ROOT)
    options = GlobalOptions(
        tenant="11111111-1111-1111-1111-111111111111",
        subscription="22222222-2222-2222-2222-222222222222",
        output=OutputMode.TABLE,
        outdir=Path("."),
        debug=False,
    )

    for spec in get_command_specs():
        if spec.name == "all-checks":
            continue
        model = spec.collector(provider, options)
        payload = trim_payload(spec.name, normalize_payload(model.model_dump(mode="json")))
        table_text = render_table(spec.name, payload)
        write_example_files(output_root / spec.name, payload, table_text)


def generate_chain_family_examples(output_root: Path) -> None:
    provider = FixtureProvider(FIXTURE_ROOT)
    with tempfile.TemporaryDirectory(prefix="azurefox-command-output-") as tmp:
        options = GlobalOptions(
            tenant="11111111-1111-1111-1111-111111111111",
            subscription="22222222-2222-2222-2222-222222222222",
            output=OutputMode.TABLE,
            outdir=Path(tmp),
            debug=False,
        )

        for family in implemented_chain_families():
            model = run_chain_family(provider, options, family)
            payload = trim_payload("chains", normalize_payload(model.model_dump(mode="json")))
            table_text = render_table("chains", payload)
            write_example_files(output_root / "chains" / family, payload, table_text)


def main() -> None:
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    generate_flat_command_examples(OUTPUT_ROOT)
    generate_chain_family_examples(OUTPUT_ROOT)


if __name__ == "__main__":
    main()
