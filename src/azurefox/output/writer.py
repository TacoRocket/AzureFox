from __future__ import annotations

import csv
import json
from pathlib import Path

import typer

from azurefox.config import GlobalOptions
from azurefox.models.common import OutputMode
from azurefox.render.table import render_table

LOOT_TARGET_LIMIT = 10

PRIMARY_COLLECTION_KEYS = {
    "automation": "automation_accounts",
    "app-services": "app_services",
    "acr": "registries",
    "databases": "database_servers",
    "dns": "dns_zones",
    "application-gateway": "application_gateways",
    "aks": "aks_clusters",
    "api-mgmt": "api_management_services",
    "functions": "function_apps",
    "arm-deployments": "deployments",
    "endpoints": "endpoints",
    "env-vars": "env_vars",
    "network-effective": "effective_exposures",
    "network-ports": "network_ports",
    "tokens-credentials": "surfaces",
    "rbac": "role_assignments",
    "principals": "principals",
    "permissions": "permissions",
    "privesc": "paths",
    "devops": "pipelines",
    "role-trusts": "trusts",
    "cross-tenant": "cross_tenant_paths",
    "lighthouse": "lighthouse_delegations",
    "resource-trusts": "resource_trusts",
    "auth-policies": "auth_policies",
    "managed-identities": "identities",
    "keyvault": "key_vaults",
    "storage": "storage_assets",
    "chains": "paths",
    "snapshots-disks": "snapshot_disk_assets",
    "nics": "nic_assets",
    "workloads": "workloads",
    "vms": "vm_assets",
    "vmss": "vmss_assets",
}


def emit_output(
    command: str,
    model: object,
    options: GlobalOptions,
    *,
    emit_stdout: bool = True,
) -> dict[str, Path]:
    payload = model.model_dump(mode="json")
    artifact_paths = write_artifacts(command, payload, options)

    if not emit_stdout:
        return artifact_paths

    if options.output == OutputMode.TABLE:
        typer.echo(render_table(command, payload))
        return artifact_paths

    if options.output == OutputMode.JSON:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return artifact_paths

    if options.output == OutputMode.CSV:
        typer.echo(_to_csv(command, payload))
        return artifact_paths

    raise ValueError(f"Unsupported output mode: {options.output}")


def write_artifacts(command: str, payload: dict, options: GlobalOptions) -> dict[str, Path]:
    options.json_dir.mkdir(parents=True, exist_ok=True)
    options.table_dir.mkdir(parents=True, exist_ok=True)
    options.csv_dir.mkdir(parents=True, exist_ok=True)

    loot_path = _write_loot(command, _build_loot_payload(command, payload), options.loot_dir)
    json_path = _write_json(command, payload, options.json_dir)
    table_path = _write_text(
        command,
        render_table(command, payload),
        options.table_dir,
        suffix=".txt",
    )
    csv_path = _write_text(command, _to_csv(command, payload), options.csv_dir, suffix=".csv")

    return {
        "loot": loot_path,
        "json": json_path,
        "table": table_path,
        "csv": csv_path,
    }


def _write_loot(command: str, payload: dict, loot_dir: Path) -> None:
    loot_dir.mkdir(parents=True, exist_ok=True)
    path = loot_dir / f"{command}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _build_loot_payload(command: str, payload: dict) -> dict:
    loot_payload: dict = {}
    primary_key = PRIMARY_COLLECTION_KEYS.get(command)
    truncated_source_count: int | None = None

    for key, value in payload.items():
        if key == "metadata":
            loot_payload[key] = _build_loot_metadata(value)
            continue
        if key == primary_key and isinstance(value, list):
            loot_payload[key] = value[:LOOT_TARGET_LIMIT]
            if len(value) > LOOT_TARGET_LIMIT:
                truncated_source_count = len(value)
            continue
        if key in {"findings", "issues"} and not value:
            continue
        loot_payload[key] = value

    if primary_key and truncated_source_count is not None:
        loot_payload["loot_scope"] = {
            "selection": "top-ranked-targets",
            "source_count": truncated_source_count,
            "returned_count": len(loot_payload[primary_key]),
            "limit": LOOT_TARGET_LIMIT,
        }
    return loot_payload


def _build_loot_metadata(metadata: object) -> object:
    if not isinstance(metadata, dict):
        return metadata
    return {
        key: metadata[key]
        for key in ("schema_version", "command")
        if metadata.get(key) is not None
    }


def _write_json(command: str, payload: dict, outdir: Path) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    path = outdir / f"{command}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def _write_text(command: str, content: str, outdir: Path, *, suffix: str) -> Path:
    outdir.mkdir(parents=True, exist_ok=True)
    path = outdir / f"{command}{suffix}"
    path.write_text(content, encoding="utf-8")
    return path


def _to_csv(command: str, payload: dict) -> str:
    key = PRIMARY_COLLECTION_KEYS.get(command)
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
