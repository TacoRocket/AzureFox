from __future__ import annotations

from pathlib import Path

import typer

from azurefox.collectors.commands import (
    collect_inventory,
    collect_managed_identities,
    collect_rbac,
    collect_storage,
    collect_vms,
    collect_whoami,
)
from azurefox.collectors.provider import get_provider
from azurefox.config import GlobalOptions
from azurefox.errors import AzureFoxError
from azurefox.models.common import OutputMode
from azurefox.output.writer import emit_output

app = typer.Typer(help="AzureFox CLI")
TENANT_OPTION = typer.Option(None, "--tenant", help="Azure tenant ID")
SUBSCRIPTION_OPTION = typer.Option(None, "--subscription", help="Azure subscription ID")
OUTPUT_OPTION = typer.Option(OutputMode.TABLE, "--output", help="Output format")
OUTDIR_OPTION = typer.Option(Path("."), "--outdir", help="Output directory")
DEBUG_OPTION = typer.Option(False, "--debug", help="Enable verbose error output")


@app.callback()
def root(
    ctx: typer.Context,
    tenant: str | None = TENANT_OPTION,
    subscription: str | None = SUBSCRIPTION_OPTION,
    output: OutputMode = OUTPUT_OPTION,
    outdir: Path = OUTDIR_OPTION,
    debug: bool = DEBUG_OPTION,
) -> None:
    ctx.obj = GlobalOptions(
        tenant=tenant,
        subscription=subscription,
        output=output,
        outdir=outdir,
        debug=debug,
    )


@app.command("whoami")
def whoami(ctx: typer.Context) -> None:
    _run_command(ctx, "whoami", collect_whoami)


@app.command("inventory")
def inventory(ctx: typer.Context) -> None:
    _run_command(ctx, "inventory", collect_inventory)


@app.command("rbac")
def rbac(ctx: typer.Context) -> None:
    _run_command(ctx, "rbac", collect_rbac)


@app.command("managed-identities")
def managed_identities(ctx: typer.Context) -> None:
    _run_command(ctx, "managed-identities", collect_managed_identities)


@app.command("storage")
def storage(ctx: typer.Context) -> None:
    _run_command(ctx, "storage", collect_storage)


@app.command("vms")
def vms(ctx: typer.Context) -> None:
    _run_command(ctx, "vms", collect_vms)


def _run_command(ctx: typer.Context, command: str, collector: callable) -> None:
    options: GlobalOptions = ctx.obj
    try:
        provider = get_provider(options)
        model = collector(provider, options)
        emit_output(command, model, options)
    except AzureFoxError as exc:
        typer.echo(f"[{exc.kind}] {exc}", err=True)
        if options.debug and exc.details:
            typer.echo(str(exc.details), err=True)
        raise typer.Exit(code=2) from exc
    except Exception as exc:  # pragma: no cover - safety rail
        typer.echo(f"[unknown] {exc}", err=True)
        raise typer.Exit(code=1) from exc


def main() -> None:
    app()
