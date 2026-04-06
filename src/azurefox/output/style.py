from __future__ import annotations

from pathlib import Path

import typer

from azurefox.config import GlobalOptions
from azurefox.models.common import OutputMode

COMMAND_NARRATION = {
    "whoami": "Checking caller context and active subscription scope.",
    "inventory": "Scoping the visible Azure resource footprint.",
    "automation": (
        "Reviewing Azure Automation accounts for identity, execution, webhook, worker, "
        "and secure-asset posture."
    ),
    "devops": (
        "Reviewing Azure DevOps build definitions for named Azure change paths, "
        "secret-bearing support, and trigger posture."
    ),
    "app-services": "Reviewing App Service runtime, hostname, identity, and hardening posture.",
    "acr": (
        "Reviewing Azure Container Registry login, auth, network, and registry "
        "automation/governance cues."
    ),
    "databases": (
        "Reviewing relational database server posture across Azure SQL, PostgreSQL Flexible, "
        "and MySQL Flexible."
    ),
    "dns": "Reviewing public and private DNS zone inventory and namespace boundaries.",
    "aks": (
        "Reviewing AKS control-plane endpoint, identity, auth posture, and Azure-side "
        "federation and addon cues."
    ),
    "api-mgmt": (
        "Reviewing API Management gateway hostnames, identity, subscription, backend, and "
        "secret posture."
    ),
    "functions": (
        "Reviewing Function App runtime, storage binding, identity, and deployment posture."
    ),
    "arm-deployments": "Reviewing ARM deployment history for config exposure and linked content.",
    "endpoints": "Mapping reachable IP and hostname surfaces from compute and web workloads.",
    "network-effective": (
        "Prioritizing likely public-IP reachability by combining visible endpoint and NSG evidence."
    ),
    "env-vars": "Reviewing App Service and Function App settings for exposed config paths.",
    "network-ports": "Tracing likely inbound port exposure from visible NIC and subnet NSG rules.",
    "tokens-credentials": (
        "Correlating token-minting workloads and credential-bearing metadata paths."
    ),
    "rbac": "Collecting raw RBAC assignments across the current subscription.",
    "principals": "Building an operator-first principal census from RBAC and identity context.",
    "permissions": "Ranking principals by high-impact RBAC exposure.",
    "privesc": "Triage likely privilege-escalation and workload identity abuse paths.",
    "role-trusts": (
        "Reviewing high-signal identity trust edges without implying delegated or admin consent."
    ),
    "cross-tenant": (
        "Reviewing outside-tenant trust, delegated management, and tenant policy cues that most "
        "change control or pivot paths."
    ),
    "lighthouse": (
        "Reviewing Azure Lighthouse delegations for cross-tenant management scope and "
        "high-impact access cues."
    ),
    "auth-policies": (
        "Reviewing tenant auth controls, findings, and any partial-read gaps on the "
        "current read path."
    ),
    "managed-identities": "Enumerating workload identities and attached privilege exposure.",
    "keyvault": "Reviewing Key Vault posture for exposed or weakly protected secret surfaces.",
    "resource-trusts": (
        "Correlating resource trust surfaces across public network and private-link paths."
    ),
    "storage": "Checking storage exposure and network posture for likely data targets.",
    "snapshots-disks": (
        "Reviewing managed disks and snapshots for offline-copy, sharing/export, and "
        "encryption posture with highest-value targets first."
    ),
    "nics": "Enumerating NIC attachments, IP context, and network boundary references.",
    "workloads": "Joining workload assets with identity context and visible ingress paths.",
    "vms": "Summarizing reachable compute assets and identity-bearing workloads.",
    "vmss": (
        "Reviewing Virtual Machine Scale Sets (VMSS) for fleet posture, identity, and "
        "frontend network cues."
    ),
    "all-checks": "Running deprecated broad grouped sweep across the current AzureFox command set.",
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
