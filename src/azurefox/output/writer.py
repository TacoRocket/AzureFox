from __future__ import annotations

import csv
import json
from pathlib import Path

import typer

from azurefox.config import GlobalOptions
from azurefox.models.common import OutputMode
from azurefox.render.table import render_table


def emit_output(command: str, model: object, options: GlobalOptions) -> None:
    payload = model.model_dump(mode="json")
    _write_loot(command, payload, options.loot_dir)

    if options.output == OutputMode.TABLE:
        typer.echo(render_table(command, payload))
        return

    if options.output == OutputMode.JSON:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return

    if options.output == OutputMode.CSV:
        typer.echo(_to_csv(command, payload))
        return

    raise ValueError(f"Unsupported output mode: {options.output}")


def _write_loot(command: str, payload: dict, loot_dir: Path) -> None:
    loot_dir.mkdir(parents=True, exist_ok=True)
    path = loot_dir / f"{command}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _to_csv(command: str, payload: dict) -> str:
    key_mapping = {
        "whoami": None,
        "inventory": None,
        "rbac": "role_assignments",
        "managed-identities": "identities",
        "storage": "storage_assets",
        "vms": "vm_assets",
    }

    key = key_mapping.get(command)
    if key is None:
        rows = [_flatten_single(command, payload)]
    else:
        rows = [_flatten_row(row) for row in payload.get(key, [])]

    if not rows:
        return ""

    headers = sorted({header for row in rows for header in row.keys()})
    out = []
    writer = csv.DictWriter(out := _ListWriter(), fieldnames=headers)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return "".join(out)


def _flatten_single(command: str, payload: dict) -> dict:
    if command == "whoami":
        principal = payload.get("principal") or {}
        subscription = payload.get("subscription") or {}
        return {
            "tenant_id": payload.get("tenant_id"),
            "subscription_id": subscription.get("id"),
            "subscription_name": subscription.get("display_name"),
            "principal_id": principal.get("id"),
            "principal_type": principal.get("principal_type"),
        }

    if command == "inventory":
        return {
            "resource_group_count": payload.get("resource_group_count", 0),
            "resource_count": payload.get("resource_count", 0),
            "top_resource_types": json.dumps(payload.get("top_resource_types", {}), sort_keys=True),
        }

    return _flatten_row(payload)


def _flatten_row(row: dict) -> dict:
    flattened = {}
    for key, value in row.items():
        if isinstance(value, (list, dict)):
            flattened[key] = json.dumps(value, sort_keys=True)
        else:
            flattened[key] = value
    return flattened


class _ListWriter(list):
    def write(self, text: str) -> int:
        self.append(text)
        return len(text)
