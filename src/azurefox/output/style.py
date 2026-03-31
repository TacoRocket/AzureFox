from __future__ import annotations

from pathlib import Path

import typer

from azurefox.config import GlobalOptions
from azurefox.models.common import OutputMode


def emit_context_banner(options: GlobalOptions) -> None:
    typer.echo("AzureFox :: Azure situational awareness")
    typer.echo(
        "tenant="
        f"{options.tenant or 'auto'} "
        f"subscription={options.subscription or 'auto'} "
        f"output={options.output.value}"
    )


def emit_command_status(command: str, message: str, *, err: bool = False) -> None:
    typer.echo(f"[{command}] {message}", err=err)


def emit_artifact_paths(command: str, paths: dict[str, Path], options: GlobalOptions) -> None:
    err = options.output == OutputMode.JSON

    if options.output != OutputMode.JSON:
        if table_path := paths.get("table"):
            emit_command_status(command, f"Output written to {table_path}", err=err)
        if csv_path := paths.get("csv"):
            emit_command_status(command, f"CSV written to {csv_path}", err=err)

    if loot_path := paths.get("loot"):
        emit_command_status(command, f"Loot written to {loot_path}", err=err)
