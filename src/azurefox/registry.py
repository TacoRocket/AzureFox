from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from azurefox.collectors.commands import (
    collect_acr,
    collect_aks,
    collect_api_mgmt,
    collect_app_services,
    collect_arm_deployments,
    collect_auth_policies,
    collect_cross_tenant,
    collect_databases,
    collect_dns,
    collect_endpoints,
    collect_env_vars,
    collect_functions,
    collect_inventory,
    collect_keyvault,
    collect_lighthouse,
    collect_managed_identities,
    collect_network_effective,
    collect_network_ports,
    collect_nics,
    collect_permissions,
    collect_principals,
    collect_privesc,
    collect_rbac,
    collect_resource_trusts,
    collect_role_trusts,
    collect_snapshots_disks,
    collect_storage,
    collect_tokens_credentials,
    collect_vms,
    collect_vmss,
    collect_whoami,
    collect_workloads,
)
from azurefox.collectors.provider import BaseProvider
from azurefox.config import GlobalOptions

Collector = Callable[[BaseProvider, GlobalOptions], object]


@dataclass(frozen=True, slots=True)
class CommandSpec:
    name: str
    section: str
    collector: Collector


COMMAND_SPECS: tuple[CommandSpec, ...] = (
    CommandSpec("whoami", "identity", collect_whoami),
    CommandSpec("inventory", "core", collect_inventory),
    CommandSpec("arm-deployments", "config", collect_arm_deployments),
    CommandSpec("env-vars", "config", collect_env_vars),
    CommandSpec("tokens-credentials", "secrets", collect_tokens_credentials),
    CommandSpec("rbac", "identity", collect_rbac),
    CommandSpec("principals", "identity", collect_principals),
    CommandSpec("permissions", "identity", collect_permissions),
    CommandSpec("privesc", "identity", collect_privesc),
    CommandSpec("role-trusts", "identity", collect_role_trusts),
    CommandSpec("cross-tenant", "identity", collect_cross_tenant),
    CommandSpec("lighthouse", "identity", collect_lighthouse),
    CommandSpec("auth-policies", "identity", collect_auth_policies),
    CommandSpec("managed-identities", "identity", collect_managed_identities),
    CommandSpec("keyvault", "secrets", collect_keyvault),
    CommandSpec("resource-trusts", "resource", collect_resource_trusts),
    CommandSpec("storage", "storage", collect_storage),
    CommandSpec("nics", "network", collect_nics),
    CommandSpec("dns", "network", collect_dns),
    CommandSpec("endpoints", "network", collect_endpoints),
    CommandSpec("network-effective", "network", collect_network_effective),
    CommandSpec("network-ports", "network", collect_network_ports),
    CommandSpec("workloads", "compute", collect_workloads),
    CommandSpec("app-services", "compute", collect_app_services),
    CommandSpec("functions", "compute", collect_functions),
    CommandSpec("aks", "compute", collect_aks),
    CommandSpec("api-mgmt", "resource", collect_api_mgmt),
    CommandSpec("acr", "resource", collect_acr),
    CommandSpec("databases", "resource", collect_databases),
    CommandSpec("vms", "compute", collect_vms),
    CommandSpec("vmss", "compute", collect_vmss),
    CommandSpec("snapshots-disks", "compute", collect_snapshots_disks),
)

SECTION_NAMES: tuple[str, ...] = tuple(
    sorted({command.section for command in COMMAND_SPECS} | {"ai"})
)


def get_command_specs(section: str | None = None) -> tuple[CommandSpec, ...]:
    if section is None:
        return COMMAND_SPECS
    return tuple(command for command in COMMAND_SPECS if command.section == section)
