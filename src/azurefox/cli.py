from __future__ import annotations

import sys
from pathlib import Path

import typer

from azurefox.collectors.provider import get_provider
from azurefox.config import GlobalOptions
from azurefox.errors import AzureFoxError
from azurefox.help import render_help
from azurefox.models.common import OutputMode
from azurefox.models.run import AllChecksSummary, RunCommandResult
from azurefox.output.style import (
    emit_artifact_paths,
    emit_command_intro,
    emit_command_status,
    emit_context_banner,
)
from azurefox.output.writer import emit_output
from azurefox.registry import SECTION_NAMES, get_command_specs

app = typer.Typer(help="AzureFox CLI")
TENANT_OPTION = typer.Option(None, "--tenant", help="Azure tenant ID")
SUBSCRIPTION_OPTION = typer.Option(None, "--subscription", help="Azure subscription ID")
OUTPUT_OPTION = typer.Option(OutputMode.TABLE, "--output", help="Output format")
OUTDIR_OPTION = typer.Option(Path("."), "--outdir", help="Output directory")
DEBUG_OPTION = typer.Option(False, "--debug", help="Enable verbose error output")
SECTION_OPTION = typer.Option(
    None,
    "--section",
    help=f"Limit all-checks to a section: {', '.join(SECTION_NAMES)}",
)


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
    _run_single(ctx, "whoami")


@app.command("inventory")
def inventory(ctx: typer.Context) -> None:
    _run_single(ctx, "inventory")


@app.command("app-services")
def app_services(ctx: typer.Context) -> None:
    _run_single(ctx, "app-services")


@app.command("acr")
def acr(ctx: typer.Context) -> None:
    _run_single(ctx, "acr")


@app.command("databases")
def databases(ctx: typer.Context) -> None:
    _run_single(ctx, "databases")


@app.command("dns")
def dns(ctx: typer.Context) -> None:
    _run_single(ctx, "dns")


@app.command("functions")
def functions(ctx: typer.Context) -> None:
    _run_single(ctx, "functions")


@app.command("aks")
def aks(ctx: typer.Context) -> None:
    _run_single(ctx, "aks")


@app.command("api-mgmt")
def api_mgmt(ctx: typer.Context) -> None:
    _run_single(ctx, "api-mgmt")


@app.command("arm-deployments")
def arm_deployments(ctx: typer.Context) -> None:
    _run_single(ctx, "arm-deployments")


@app.command("env-vars")
def env_vars(ctx: typer.Context) -> None:
    _run_single(ctx, "env-vars")


@app.command("tokens-credentials")
def tokens_credentials(ctx: typer.Context) -> None:
    _run_single(ctx, "tokens-credentials")


@app.command("rbac")
def rbac(ctx: typer.Context) -> None:
    _run_single(ctx, "rbac")


@app.command("principals")
def principals(ctx: typer.Context) -> None:
    _run_single(ctx, "principals")


@app.command("permissions")
def permissions(ctx: typer.Context) -> None:
    _run_single(ctx, "permissions")


@app.command("privesc")
def privesc(ctx: typer.Context) -> None:
    _run_single(ctx, "privesc")


@app.command("role-trusts")
def role_trusts(ctx: typer.Context) -> None:
    _run_single(ctx, "role-trusts")


@app.command("auth-policies")
def auth_policies(ctx: typer.Context) -> None:
    _run_single(ctx, "auth-policies")


@app.command("managed-identities")
def managed_identities(ctx: typer.Context) -> None:
    _run_single(ctx, "managed-identities")


@app.command("keyvault")
def keyvault(ctx: typer.Context) -> None:
    _run_single(ctx, "keyvault")


@app.command("resource-trusts")
def resource_trusts(ctx: typer.Context) -> None:
    _run_single(ctx, "resource-trusts")


@app.command("storage")
def storage(ctx: typer.Context) -> None:
    _run_single(ctx, "storage")


@app.command("nics")
def nics(ctx: typer.Context) -> None:
    _run_single(ctx, "nics")


@app.command("endpoints")
def endpoints(ctx: typer.Context) -> None:
    _run_single(ctx, "endpoints")


@app.command("network-ports")
def network_ports(ctx: typer.Context) -> None:
    _run_single(ctx, "network-ports")


@app.command("workloads")
def workloads(ctx: typer.Context) -> None:
    _run_single(ctx, "workloads")


@app.command("vms")
def vms(ctx: typer.Context) -> None:
    _run_single(ctx, "vms")


@app.command("all-checks")
def all_checks(
    ctx: typer.Context,
    section: str | None = SECTION_OPTION,
) -> None:
    options: GlobalOptions = ctx.obj
    if section is not None and section not in SECTION_NAMES:
        typer.echo(
            f"[all-checks] Unknown section '{section}'. Valid sections: {', '.join(SECTION_NAMES)}",
            err=True,
        )
        raise typer.Exit(code=2)

    provider = get_provider(options)
    specs = get_command_specs(section)

    if options.output != OutputMode.JSON:
        emit_context_banner(options)

    results: list[RunCommandResult] = []
    for spec in specs:
        emit_command_intro(spec.name, err=options.output == OutputMode.JSON)
        try:
            model = spec.collector(provider, options)
            artifact_paths = emit_output(spec.name, model, options, emit_stdout=False)
            emit_artifact_paths(spec.name, artifact_paths, options)
            results.append(
                RunCommandResult(
                    command=spec.name,
                    section=spec.section,
                    status="ok",
                    artifact_paths={key: str(value) for key, value in artifact_paths.items()},
                )
            )
        except AzureFoxError as exc:
            emit_command_status(spec.name, f"failed: {exc}", err=True)
            results.append(
                RunCommandResult(
                    command=spec.name,
                    section=spec.section,
                    status="error",
                    error=str(exc),
                )
            )
        except Exception as exc:  # pragma: no cover - safety rail
            emit_command_status(spec.name, f"failed: {exc}", err=True)
            results.append(
                RunCommandResult(
                    command=spec.name,
                    section=spec.section,
                    status="error",
                    error=str(exc),
                )
            )

    summary = AllChecksSummary(
        metadata=_build_metadata("all-checks", options),
        section=section,
        results=results,
    )
    summary_path = options.outdir / "run-summary.json"
    summary_path.write_text(
        summary.model_dump_json(indent=2),
        encoding="utf-8",
    )

    if options.output == OutputMode.JSON:
        typer.echo(summary.model_dump_json(indent=2))
    else:
        ok_count = sum(result.status == "ok" for result in results)
        emit_command_status(
            "all-checks",
            f"completed {ok_count}/{len(results)} commands; summary written to {summary_path}",
        )

    if any(result.status != "ok" for result in results):
        raise typer.Exit(code=1)


@app.command("help")
def help_command(topic: str | None = typer.Argument(None)) -> None:
    try:
        typer.echo(render_help(topic))
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


def _run_single(ctx: typer.Context, command: str) -> None:
    options: GlobalOptions = ctx.obj
    try:
        provider = get_provider(options)
        spec = next(spec for spec in get_command_specs() if spec.name == command)
        if options.output != OutputMode.JSON:
            emit_context_banner(options)
            emit_command_intro(command)
        model = spec.collector(provider, options)
        artifact_paths = emit_output(command, model, options)
        emit_artifact_paths(command, artifact_paths, options)
    except AzureFoxError as exc:
        typer.echo(f"[{exc.kind}] {exc}", err=True)
        if options.debug and exc.details:
            typer.echo(str(exc.details), err=True)
        raise typer.Exit(code=2) from exc
    except Exception as exc:  # pragma: no cover - safety rail
        typer.echo(f"[unknown] {exc}", err=True)
        raise typer.Exit(code=1) from exc


def main() -> None:
    sys.argv = _normalize_argv(sys.argv)
    app()


def _build_metadata(command: str, options: GlobalOptions) -> dict[str, str | None]:
    return {
        "command": command,
        "tenant_id": options.tenant,
        "subscription_id": options.subscription,
        "token_source": None,
    }


def _normalize_argv(argv: list[str]) -> list[str]:
    if len(argv) < 2:
        return argv

    if argv[1] in {"-h", "--help"}:
        if len(argv) == 2:
            return [argv[0], "help"]
        return [argv[0], "help", argv[2]]

    return argv
