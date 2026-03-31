from __future__ import annotations

from pathlib import Path

import typer

from azurefox.config import GlobalOptions
from azurefox.models.common import OutputMode

COMMAND_NARRATION = {
    "whoami": "Checking caller context and active subscription scope.",
    "inventory": "Scoping the visible Azure resource footprint.",
    "arm-deployments": "Reviewing ARM deployment history for config exposure and linked content.",
    "env-vars": "Reviewing App Service and Function App settings for exposed config paths.",
    "rbac": "Collecting raw RBAC assignments across the current subscription.",
    "principals": "Building an operator-first principal census from RBAC and identity context.",
    "permissions": "Ranking principals by high-impact RBAC exposure.",
    "privesc": "Triage likely privilege-escalation and workload identity abuse paths.",
    "role-trusts": "Reviewing high-signal identity trust edges worth operator attention first.",
    "auth-policies": "Reviewing tenant auth controls, findings, and any partial-read gaps.",
    "managed-identities": "Enumerating workload identities and attached privilege exposure.",
    "keyvault": "Reviewing Key Vault posture for exposed or weakly protected secret surfaces.",
    "resource-trusts": (
        "Correlating resource trust surfaces across public network and "
        "private-link paths."
    ),
    "storage": "Checking storage exposure and network posture for likely data targets.",
    "vms": "Summarizing reachable compute assets and identity-bearing workloads.",
    "all-checks": "Running the current AzureFox command set in operator-first sequence.",
}


def emit_context_banner(options: GlobalOptions) -> None:
    typer.echo("AzureFox :: operator-first Azure situational awareness")
    typer.echo(
        "context :: tenant="
        f"{options.tenant or 'auto'} "
        f"subscription={options.subscription or 'auto'} "
        f"output={options.output.value}"
    )
    typer.echo("")


def emit_command_status(command: str, message: str, *, err: bool = False) -> None:
    typer.echo(f"[{command}] {message}", err=err)


def emit_command_intro(command: str, *, err: bool = False) -> None:
    message = COMMAND_NARRATION.get(command, "Running command.")
    emit_command_status(command, message, err=err)


def emit_artifact_paths(command: str, paths: dict[str, Path], options: GlobalOptions) -> None:
    err = options.output == OutputMode.JSON

    if options.output != OutputMode.JSON:
        if table_path := paths.get("table"):
            emit_command_status(command, f"table artifact :: {table_path}", err=err)
        if csv_path := paths.get("csv"):
            emit_command_status(command, f"csv artifact :: {csv_path}", err=err)

    if loot_path := paths.get("loot"):
        emit_command_status(command, f"loot artifact :: {loot_path}", err=err)
