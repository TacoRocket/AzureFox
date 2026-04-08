from __future__ import annotations

import sys
from dataclasses import replace
from pathlib import Path

import typer

from azurefox.chains import implemented_chain_families, run_chain_family
from azurefox.chains.registry import chain_family_names, get_chain_family_spec
from azurefox.collectors.provider import get_provider
from azurefox.config import GlobalOptions
from azurefox.errors import AzureFoxError
from azurefox.help import help_topic_names, render_help
from azurefox.models.common import OutputMode, RoleTrustsMode
from azurefox.output.style import (
    emit_artifact_paths,
    emit_command_intro,
    emit_context_banner,
)
from azurefox.output.writer import emit_output
from azurefox.registry import get_command_specs

app = typer.Typer(help="AzureFox CLI")
TENANT_OPTION = typer.Option(None, "--tenant", help="Azure tenant ID")
SUBSCRIPTION_OPTION = typer.Option(None, "--subscription", help="Azure subscription ID")
DEVOPS_ORGANIZATION_OPTION = typer.Option(
    None,
    "--devops-organization",
    envvar="AZUREFOX_DEVOPS_ORG",
    help="Azure DevOps organization name for devops command collection",
)
OUTPUT_OPTION = typer.Option(OutputMode.TABLE, "--output", help="Output format")
OUTDIR_OPTION = typer.Option(Path("."), "--outdir", help="Output directory")
DEBUG_OPTION = typer.Option(False, "--debug", help="Enable verbose error output")
ROLE_TRUSTS_MODE_OPTION = typer.Option(
    RoleTrustsMode.FAST,
    "--mode",
    help=(
        "role-trusts collection mode: fast (default), or full for a slower tenant-wide "
        "application sweep with per-app owner and federated credential lookups"
    ),
)
HELP_FLAGS = {"-h", "--help"}
GLOBAL_OPTIONS_WITH_VALUES = {
    "--tenant",
    "--subscription",
    "--devops-organization",
    "--output",
    "--outdir",
}
GLOBAL_FLAG_OPTIONS = {"--debug"}


@app.callback()
def root(
    ctx: typer.Context,
    tenant: str | None = TENANT_OPTION,
    subscription: str | None = SUBSCRIPTION_OPTION,
    devops_organization: str | None = DEVOPS_ORGANIZATION_OPTION,
    output: OutputMode = OUTPUT_OPTION,
    outdir: Path = OUTDIR_OPTION,
    debug: bool = DEBUG_OPTION,
) -> None:
    ctx.obj = GlobalOptions(
        tenant=tenant,
        subscription=subscription,
        devops_organization=devops_organization,
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


@app.command("automation")
def automation(ctx: typer.Context) -> None:
    _run_single(ctx, "automation")


@app.command("devops")
def devops(
    ctx: typer.Context,
    devops_organization: str | None = DEVOPS_ORGANIZATION_OPTION,
) -> None:
    if devops_organization:
        ctx.obj = replace(ctx.obj, devops_organization=devops_organization)
    _run_single(ctx, "devops")


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


@app.command("application-gateway")
def application_gateway(ctx: typer.Context) -> None:
    _run_single(ctx, "application-gateway")


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
def role_trusts(
    ctx: typer.Context,
    mode: RoleTrustsMode = ROLE_TRUSTS_MODE_OPTION,
) -> None:
    _run_single(
        ctx,
        "role-trusts",
        replace(ctx.obj, role_trusts_mode=mode),
    )


@app.command("lighthouse")
def lighthouse(ctx: typer.Context) -> None:
    _run_single(ctx, "lighthouse")


@app.command("cross-tenant")
def cross_tenant(ctx: typer.Context) -> None:
    _run_single(ctx, "cross-tenant")


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


@app.command("snapshots-disks")
def snapshots_disks(ctx: typer.Context) -> None:
    _run_single(ctx, "snapshots-disks")


@app.command("nics")
def nics(ctx: typer.Context) -> None:
    _run_single(ctx, "nics")


@app.command("endpoints")
def endpoints(ctx: typer.Context) -> None:
    _run_single(ctx, "endpoints")


@app.command("network-effective")
def network_effective(ctx: typer.Context) -> None:
    _run_single(ctx, "network-effective")


@app.command("network-ports")
def network_ports(ctx: typer.Context) -> None:
    _run_single(ctx, "network-ports")


@app.command("workloads")
def workloads(ctx: typer.Context) -> None:
    _run_single(ctx, "workloads")


@app.command("vms")
def vms(ctx: typer.Context) -> None:
    _run_single(ctx, "vms")


@app.command("vmss")
def vmss(ctx: typer.Context) -> None:
    _run_single(ctx, "vmss")


@app.command("chains")
def chains(
    ctx: typer.Context,
    family: str = typer.Argument(..., help="Chain family name, for example credential-path"),
) -> None:
    options: GlobalOptions = ctx.obj
    family_spec = get_chain_family_spec(family)
    if family_spec is None:
        typer.echo(
            f"[chains] Unknown chain family '{family}'. Valid families: "
            f"{', '.join(chain_family_names())}",
            err=True,
        )
        raise typer.Exit(code=2)

    if family not in implemented_chain_families():
        typer.echo(
            f"[chains] Chain family '{family}' is not implemented yet. "
            f"Currently supported: {', '.join(implemented_chain_families())}",
            err=True,
        )
        raise typer.Exit(code=2)

    try:
        provider = get_provider(options)
        if options.output != OutputMode.JSON:
            emit_context_banner(options)
            emit_command_intro("chains")
        model = run_chain_family(provider, options, family)
        artifact_paths = emit_output("chains", model, options)
        emit_artifact_paths("chains", artifact_paths, options)
    except AzureFoxError as exc:
        typer.echo(f"[{exc.kind}] {exc}", err=True)
        if options.debug and exc.details:
            typer.echo(str(exc.details), err=True)
        raise typer.Exit(code=2) from exc
    except Exception as exc:  # pragma: no cover - safety rail
        typer.echo(f"[unknown] {exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command("help")
def help_command(topic: str | None = typer.Argument(None)) -> None:
    try:
        typer.echo(render_help(topic))
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


def _run_single(
    ctx: typer.Context,
    command: str,
    options: GlobalOptions | None = None,
) -> None:
    options = options or ctx.obj
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


def _normalize_argv(argv: list[str]) -> list[str]:
    if len(argv) < 2:
        return argv

    if argv[1] in HELP_FLAGS:
        if len(argv) == 2:
            return [argv[0], "help"]
        return [argv[0], "help", argv[2]]

    if len(argv) >= 3 and argv[2] in HELP_FLAGS and _is_help_topic(argv[1]):
        return [argv[0], "help", argv[1]]

    if argv[1] in _command_names():
        return _normalize_command_global_options(argv)

    return argv


def _normalize_command_global_options(argv: list[str]) -> list[str]:
    normalized = [argv[0]]
    global_args: list[str] = []
    command_args = [argv[1]]
    moved_global = False
    index = 2

    while index < len(argv):
        arg = argv[index]

        if arg in GLOBAL_FLAG_OPTIONS:
            global_args.append(arg)
            moved_global = True
            index += 1
            continue

        if arg in GLOBAL_OPTIONS_WITH_VALUES:
            if index + 1 >= len(argv):
                return argv
            global_args.extend([arg, argv[index + 1]])
            moved_global = True
            index += 2
            continue

        matched_value_option = False
        for option in GLOBAL_OPTIONS_WITH_VALUES:
            if arg.startswith(f"{option}="):
                global_args.append(arg)
                moved_global = True
                index += 1
                matched_value_option = True
                break
        if matched_value_option:
            continue

        command_args.append(arg)
        index += 1

    if not moved_global:
        return argv

    normalized.extend(global_args)
    normalized.extend(command_args)
    return normalized


def _command_names() -> set[str]:
    return {spec.name for spec in get_command_specs()} | {"chains"}


def _is_help_topic(token: str) -> bool:
    return token in help_topic_names()
