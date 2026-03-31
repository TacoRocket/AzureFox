from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from azurefox.collectors.commands import (
    collect_inventory,
    collect_managed_identities,
    collect_permissions,
    collect_principals,
    collect_privesc,
    collect_rbac,
    collect_storage,
    collect_vms,
    collect_whoami,
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
    CommandSpec("rbac", "identity", collect_rbac),
    CommandSpec("principals", "identity", collect_principals),
    CommandSpec("permissions", "identity", collect_permissions),
    CommandSpec("privesc", "identity", collect_privesc),
    CommandSpec("managed-identities", "identity", collect_managed_identities),
    CommandSpec("storage", "storage", collect_storage),
    CommandSpec("vms", "compute", collect_vms),
)


SECTION_NAMES: tuple[str, ...] = tuple(
    sorted({command.section for command in COMMAND_SPECS} | {"ai", "azure-only", "network"})
)


def get_command_specs(section: str | None = None) -> tuple[CommandSpec, ...]:
    if section is None:
        return COMMAND_SPECS
    return tuple(command for command in COMMAND_SPECS if command.section == section)
