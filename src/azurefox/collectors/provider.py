from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

from azurefox.auth.session import build_auth_session, decode_jwt_payload
from azurefox.clients.factory import build_clients
from azurefox.clients.graph import GraphClient
from azurefox.config import GlobalOptions
from azurefox.correlation.findings import build_keyvault_findings, build_storage_findings
from azurefox.errors import AzureFoxError, ErrorKind, classify_exception
from azurefox.models.common import (
    Principal,
    RoleAssignment,
    ScopeRef,
    is_private_network_prefix,
)


class BaseProvider(ABC):
    def metadata_context(self) -> dict[str, str | None]:
        return {}

    @abstractmethod
    def whoami(self) -> dict:
        raise NotImplementedError

    @abstractmethod
    def inventory(self) -> dict:
        raise NotImplementedError

    @abstractmethod
    def arm_deployments(self) -> dict:
        raise NotImplementedError

    def app_services(self) -> dict:
        return {"app_services": [], "issues": []}

    def acr(self) -> dict:
        return {"registries": [], "issues": []}

    def databases(self) -> dict:
        return {"database_servers": [], "issues": []}

    def dns(self) -> dict:
        return {"dns_zones": [], "issues": []}

    def aks(self) -> dict:
        return {"aks_clusters": [], "issues": []}

    def api_mgmt(self) -> dict:
        return {"api_management_services": [], "issues": []}

    def functions(self) -> dict:
        return {"function_apps": [], "issues": []}

    @abstractmethod
    def env_vars(self) -> dict:
        raise NotImplementedError

    def web_workloads(self) -> dict:
        return {"workloads": [], "issues": []}

    def tokens_credentials(self) -> dict:
        workload_data = self.web_workloads()
        env_var_data = self.env_vars()
        arm_data = self.arm_deployments()
        vm_data = self.vms()

        surfaces = [
            *_token_credential_surfaces_from_web_workloads(workload_data.get("workloads", [])),
            *_tokens_credentials_surfaces_from_env_vars(env_var_data.get("env_vars", [])),
            *_token_credential_surfaces_from_arm_deployments(arm_data.get("deployments", [])),
            *_token_credential_surfaces_from_vms(vm_data.get("vm_assets", [])),
        ]
        surfaces.sort(key=_token_credential_surface_sort_key)

        return {
            "surfaces": surfaces,
            "issues": [
                *workload_data.get("issues", []),
                *env_var_data.get("issues", []),
                *arm_data.get("issues", []),
                *vm_data.get("issues", []),
            ],
        }

    def endpoints(self) -> dict:
        workload_data = self.web_workloads()
        vm_data = self.vms()

        endpoints = [
            *_endpoints_from_vms(vm_data.get("vm_assets", [])),
            *_endpoints_from_web_workloads(workload_data.get("workloads", [])),
        ]
        endpoints.sort(
            key=lambda item: (
                item.get("endpoint_type") != "ip",
                item.get("source_asset_name") or "",
                item.get("endpoint") or "",
            )
        )

        return {
            "endpoints": endpoints,
            "issues": [*workload_data.get("issues", []), *vm_data.get("issues", [])],
        }

    def workloads(self) -> dict:
        workload_data = self.web_workloads()
        vm_data = self.vms()
        endpoints = [
            *_endpoints_from_vms(vm_data.get("vm_assets", [])),
            *_endpoints_from_web_workloads(workload_data.get("workloads", [])),
        ]
        endpoints_by_asset = _endpoints_by_asset(endpoints)
        workloads = [
            *_workload_rows_from_vms(vm_data.get("vm_assets", []), endpoints_by_asset),
            *_workload_rows_from_web_workloads(
                workload_data.get("workloads", []),
                endpoints_by_asset,
            ),
        ]
        workloads.sort(key=_workload_sort_key)
        return {
            "workloads": workloads,
            "issues": [*workload_data.get("issues", []), *vm_data.get("issues", [])],
        }

    @abstractmethod
    def network_ports(self) -> dict:
        raise NotImplementedError

    @abstractmethod
    def rbac(self) -> dict:
        raise NotImplementedError

    @abstractmethod
    def principals(self) -> dict:
        raise NotImplementedError

    @abstractmethod
    def permissions(self) -> dict:
        raise NotImplementedError

    @abstractmethod
    def privesc(self) -> dict:
        raise NotImplementedError

    @abstractmethod
    def role_trusts(self) -> dict:
        raise NotImplementedError

    @abstractmethod
    def resource_trusts(self) -> dict:
        raise NotImplementedError

    @abstractmethod
    def auth_policies(self) -> dict:
        raise NotImplementedError

    @abstractmethod
    def managed_identities(self) -> dict:
        raise NotImplementedError

    @abstractmethod
    def keyvault(self) -> dict:
        raise NotImplementedError

    @abstractmethod
    def storage(self) -> dict:
        raise NotImplementedError

    @abstractmethod
    def nics(self) -> dict:
        raise NotImplementedError

    @abstractmethod
    def vms(self) -> dict:
        raise NotImplementedError


class FixtureProvider(BaseProvider):
    def __init__(self, fixture_dir: Path) -> None:
        self.fixture_dir = fixture_dir

    def _read(self, name: str) -> dict:
        path = self.fixture_dir / f"{name}.json"
        if not path.exists():
            raise AzureFoxError(ErrorKind.UNKNOWN, f"Fixture file not found: {path}")
        return json.loads(path.read_text(encoding="utf-8"))

    def whoami(self) -> dict:
        return self._read("whoami")

    def inventory(self) -> dict:
        return self._read("inventory")

    def arm_deployments(self) -> dict:
        return self._read("arm_deployments")

    def app_services(self) -> dict:
        return self._read("app_services")

    def acr(self) -> dict:
        return self._read("acr")

    def databases(self) -> dict:
        return self._read("databases")

    def dns(self) -> dict:
        return self._read("dns")

    def aks(self) -> dict:
        return self._read("aks")

    def api_mgmt(self) -> dict:
        return self._read("api_mgmt")

    def functions(self) -> dict:
        return self._read("functions")

    def rbac(self) -> dict:
        return self._read("rbac")

    def principals(self) -> dict:
        return self._read("principals")

    def permissions(self) -> dict:
        return self._read("permissions")

    def privesc(self) -> dict:
        return self._read("privesc")

    def role_trusts(self) -> dict:
        return self._read("role_trusts")

    def resource_trusts(self) -> dict:
        storage_data = self.storage()
        keyvault_data = self.keyvault()
        resource_trusts = _compose_resource_trusts(
            storage_data.get("storage_assets", []),
            keyvault_data.get("key_vaults", []),
        )
        findings = _resource_trust_findings(
            storage_data.get("storage_assets", []),
            keyvault_data.get("key_vaults", []),
        )
        return {
            "resource_trusts": resource_trusts,
            "findings": findings,
            "issues": [*storage_data.get("issues", []), *keyvault_data.get("issues", [])],
        }

    def auth_policies(self) -> dict:
        return self._read("auth_policies")

    def managed_identities(self) -> dict:
        return self._read("managed_identities")

    def keyvault(self) -> dict:
        return self._read("keyvault")

    def env_vars(self) -> dict:
        return self._read("env_vars")

    def web_workloads(self) -> dict:
        return self._read("web_workloads")

    def storage(self) -> dict:
        return self._read("storage")

    def nics(self) -> dict:
        return self._read("nics")

    def network_ports(self) -> dict:
        return self._read("network_ports")

    def vms(self) -> dict:
        return self._read("vms")


class AzureProvider(BaseProvider):
    def __init__(self, options: GlobalOptions) -> None:
        self.options = options
        self.session = build_auth_session(options.tenant)
        self.clients = build_clients(self.session, options.subscription)
        self.graph = GraphClient(self.session.credential)
        self.subscription = self.clients.subscription

    def metadata_context(self) -> dict[str, str | None]:
        return {
            "tenant_id": self.session.tenant_id,
            "subscription_id": self.clients.subscription_id,
            "token_source": self.session.token_source,
        }

    def whoami(self) -> dict:
        claims = decode_jwt_payload(self.session.access_token)
        scope = f"/subscriptions/{self.clients.subscription_id}"
        principal = _principal_from_claims(claims, self.session.tenant_id)

        return {
            "tenant_id": claims.get("tid", self.session.tenant_id),
            "subscription": self.subscription.model_dump(),
            "principal": principal.model_dump(),
            "effective_scopes": [
                ScopeRef(
                    id=scope,
                    scope_type="subscription",
                    display_name=self.subscription.display_name,
                ).model_dump()
            ],
            "token_source": self.session.token_source,
            "issues": [],
        }

    def inventory(self) -> dict:
        rg_count = 0
        resource_count = 0
        resource_types: Counter[str] = Counter()
        issues: list[dict] = []

        try:
            rg_count = sum(1 for _ in self.clients.resource.resource_groups.list())
        except Exception as exc:
            issues.append(_issue_from_exception("resource_groups", exc))

        try:
            for resource in self.clients.resource.resources.list():
                resource_count += 1
                resource_type = getattr(resource, "type", "Unknown")
                resource_types[resource_type] += 1
        except Exception as exc:
            issues.append(_issue_from_exception("resources", exc))

        return {
            "subscription": self.subscription.model_dump(),
            "resource_group_count": rg_count,
            "resource_count": resource_count,
            "top_resource_types": dict(resource_types.most_common(15)),
            "issues": issues,
        }

    def arm_deployments(self) -> dict:
        issues: list[dict] = []
        deployments: list[dict] = []

        try:
            for deployment in self.clients.resource.deployments.list_at_subscription_scope():
                deployments.append(
                    _deployment_summary(
                        deployment,
                        scope=f"/subscriptions/{self.clients.subscription_id}",
                        scope_type="subscription",
                    )
                )
        except Exception as exc:
            issues.append(_issue_from_exception("arm_deployments.subscription", exc))

        resource_groups: list[str] = []
        try:
            resource_groups = [group.name for group in self.clients.resource.resource_groups.list()]
        except Exception as exc:
            issues.append(_issue_from_exception("arm_deployments.resource_groups", exc))

        for resource_group in resource_groups:
            try:
                iterator = self.clients.resource.deployments.list_by_resource_group(resource_group)
                for deployment in iterator:
                    deployments.append(
                        _deployment_summary(
                            deployment,
                            scope=(
                                f"/subscriptions/{self.clients.subscription_id}/resourceGroups/"
                                f"{resource_group}"
                            ),
                            scope_type="resource_group",
                            resource_group=resource_group,
                        )
                    )
            except Exception as exc:
                issues.append(
                    _issue_from_exception(
                        f"arm_deployments.resource_groups[{resource_group}]",
                        exc,
                    )
                )

        deployments = _dedupe_deployments(deployments)
        deployments.sort(
            key=lambda item: (
                item.get("scope_type") != "subscription",
                item.get("resource_group") or "",
                item.get("name") or "",
            )
        )
        return {"deployments": deployments, "issues": issues}

    def env_vars(self) -> dict:
        issues: list[dict] = []
        env_vars: list[dict] = []

        try:
            iterator = self.clients.web.web_apps.list()
            for app in iterator:
                asset_kind = _web_asset_kind(getattr(app, "kind", None))
                if not asset_kind:
                    continue

                app_id = getattr(app, "id", "") or ""
                resource_group = _resource_group_from_id(app_id)
                app_name = getattr(app, "name", None)
                if not resource_group or not app_name:
                    continue

                try:
                    settings = self.clients.web.web_apps.list_application_settings(
                        resource_group,
                        app_name,
                    )
                    for setting_name, setting_value in (
                        getattr(settings, "properties", None) or {}
                    ).items():
                        env_vars.append(
                            _env_var_summary(
                                app,
                                asset_kind=asset_kind,
                                setting_name=setting_name,
                                setting_value=setting_value,
                            )
                        )
                except Exception as exc:
                    issues.append(
                        _issue_from_exception(
                            f"env_vars[{resource_group}/{app_name}]",
                            exc,
                        )
                    )
        except Exception as exc:
            issues.append(_issue_from_exception("env_vars.web_apps", exc))

        return {"env_vars": env_vars, "issues": issues}

    def app_services(self) -> dict:
        issues: list[dict] = []
        app_services: list[dict] = []

        try:
            iterator = self.clients.web.web_apps.list()
            for app in iterator:
                asset_kind = _web_asset_kind(getattr(app, "kind", None))
                if asset_kind != "AppService":
                    continue

                config = None
                app_id = getattr(app, "id", "") or ""
                resource_group = _resource_group_from_id(app_id)
                app_name = getattr(app, "name", None)

                if resource_group and app_name:
                    try:
                        config = self.clients.web.web_apps.get_configuration(
                            resource_group,
                            app_name,
                        )
                    except Exception as exc:
                        issues.append(
                            _issue_from_exception(
                                f"app_services[{resource_group}/{app_name}].configuration",
                                exc,
                            )
                        )

                app_services.append(_app_service_summary(app, config))
        except Exception as exc:
            issues.append(_issue_from_exception("app_services.web_apps", exc))

        app_services.sort(
            key=lambda item: (
                not _app_service_exposure_priority(item),
                item.get("name") or "",
            )
        )
        return {"app_services": app_services, "issues": issues}

    def acr(self) -> dict:
        issues: list[dict] = []
        registries: list[dict] = []

        try:
            iterator = self.clients.container_registry.registries.list()
            for registry in iterator:
                registries.append(_acr_registry_summary(registry))
        except Exception as exc:
            issues.append(_issue_from_exception("acr.registries", exc))

        registries.sort(
            key=lambda item: (
                not _acr_exposure_priority(item),
                item.get("name") or "",
            )
        )
        return {"registries": registries, "issues": issues}

    def databases(self) -> dict:
        issues: list[dict] = []
        database_servers: list[dict] = []

        try:
            iterator = self.clients.sql.servers.list()
            for server in iterator:
                server_id = getattr(server, "id", "") or ""
                resource_group = _resource_group_from_id(server_id)
                server_name = getattr(server, "name", None)
                databases = None

                if resource_group and server_name:
                    try:
                        databases = list(
                            self.clients.sql.databases.list_by_server(
                                resource_group,
                                server_name,
                            )
                        )
                    except Exception as exc:
                        issues.append(
                            _issue_from_exception(
                                f"databases[{resource_group}/{server_name}].databases",
                                exc,
                            )
                        )

                database_servers.append(_database_server_summary(server, databases))
        except Exception as exc:
            issues.append(_issue_from_exception("databases.sql_servers", exc))

        database_servers.sort(
            key=lambda item: (
                not _database_exposure_priority(item),
                item.get("name") or "",
            )
        )
        return {"database_servers": database_servers, "issues": issues}

    def dns(self) -> dict:
        issues: list[dict] = []
        dns_zones: list[dict] = []

        try:
            for resource in self.clients.resource.resources.list():
                resource_type = str(getattr(resource, "type", "") or "").lower()
                if resource_type == "microsoft.network/dnszones":
                    dns_zones.append(_dns_zone_summary(resource, zone_kind="public"))
                elif resource_type == "microsoft.network/privatednszones":
                    dns_zones.append(_dns_zone_summary(resource, zone_kind="private"))
        except Exception as exc:
            issues.append(_issue_from_exception("dns.resources", exc))

        dns_zones.sort(
            key=lambda item: (
                item.get("zone_kind") != "public",
                item.get("name") or "",
            )
        )
        return {"dns_zones": dns_zones, "issues": issues}

    def aks(self) -> dict:
        issues: list[dict] = []
        clusters: list[dict] = []

        try:
            iterator = self.clients.containerservice.managed_clusters.list()
            for cluster in iterator:
                clusters.append(_aks_cluster_summary(cluster))
        except Exception as exc:
            issues.append(_issue_from_exception("aks.managed_clusters", exc))

        clusters.sort(
            key=lambda item: (
                not _aks_exposure_priority(item),
                item.get("name") or "",
            )
        )
        return {"aks_clusters": clusters, "issues": issues}

    def api_mgmt(self) -> dict:
        issues: list[dict] = []
        services: list[dict] = []

        try:
            iterator = self.clients.api_management.api_management_service.list()
            for service in iterator:
                apis = None
                backends = None
                named_values = None
                service_id = getattr(service, "id", "") or ""
                resource_group = _resource_group_from_id(service_id)
                service_name = getattr(service, "name", None)

                if resource_group and service_name:
                    try:
                        apis = list(
                            self.clients.api_management.api.list_by_service(
                                resource_group,
                                service_name,
                            )
                        )
                    except Exception as exc:
                        issues.append(
                            _issue_from_exception(
                                f"api_mgmt[{resource_group}/{service_name}].apis",
                                exc,
                            )
                        )

                    try:
                        backends = list(
                            self.clients.api_management.backend.list_by_service(
                                resource_group,
                                service_name,
                            )
                        )
                    except Exception as exc:
                        issues.append(
                            _issue_from_exception(
                                f"api_mgmt[{resource_group}/{service_name}].backends",
                                exc,
                            )
                        )

                    try:
                        named_values = list(
                            self.clients.api_management.named_value.list_by_service(
                                resource_group,
                                service_name,
                            )
                        )
                    except Exception as exc:
                        issues.append(
                            _issue_from_exception(
                                f"api_mgmt[{resource_group}/{service_name}].named_values",
                                exc,
                            )
                        )

                services.append(_api_mgmt_service_summary(service, apis, backends, named_values))
        except Exception as exc:
            issues.append(_issue_from_exception("api_mgmt.services", exc))

        services.sort(
            key=lambda item: (
                not _api_mgmt_exposure_priority(item),
                item.get("name") or "",
            )
        )
        return {"api_management_services": services, "issues": issues}

    def functions(self) -> dict:
        issues: list[dict] = []
        function_apps: list[dict] = []

        try:
            iterator = self.clients.web.web_apps.list()
            for app in iterator:
                asset_kind = _web_asset_kind(getattr(app, "kind", None))
                if asset_kind != "FunctionApp":
                    continue

                config = None
                settings = None
                app_id = getattr(app, "id", "") or ""
                resource_group = _resource_group_from_id(app_id)
                app_name = getattr(app, "name", None)

                if resource_group and app_name:
                    try:
                        config = self.clients.web.web_apps.get_configuration(
                            resource_group,
                            app_name,
                        )
                    except Exception as exc:
                        issues.append(
                            _issue_from_exception(
                                f"functions[{resource_group}/{app_name}].configuration",
                                exc,
                            )
                        )

                    try:
                        settings = self.clients.web.web_apps.list_application_settings(
                            resource_group,
                            app_name,
                        )
                    except Exception as exc:
                        issues.append(
                            _issue_from_exception(
                                f"functions[{resource_group}/{app_name}].app_settings",
                                exc,
                            )
                        )

                function_apps.append(
                    _function_app_summary(
                        app,
                        config,
                        getattr(settings, "properties", None),
                    )
                )
        except Exception as exc:
            issues.append(_issue_from_exception("functions.web_apps", exc))

        function_apps.sort(
            key=lambda item: (
                not _function_app_exposure_priority(item),
                item.get("name") or "",
            )
        )
        return {"function_apps": function_apps, "issues": issues}

    def web_workloads(self) -> dict:
        issues: list[dict] = []
        workloads: list[dict] = []

        try:
            iterator = self.clients.web.web_apps.list()
            for app in iterator:
                asset_kind = _web_asset_kind(getattr(app, "kind", None))
                if not asset_kind:
                    continue
                workloads.append(_web_workload_summary(app, asset_kind=asset_kind))
        except Exception as exc:
            issues.append(_issue_from_exception("web_workloads.web_apps", exc))

        workloads.sort(
            key=lambda item: ((item.get("asset_name") or ""), item.get("asset_id") or "")
        )
        return {"workloads": workloads, "issues": issues}

    def rbac(self) -> dict:
        scope = f"/subscriptions/{self.clients.subscription_id}"
        issues: list[dict] = []
        assignments: list[RoleAssignment] = []
        principals: dict[str, Principal] = {}
        scopes: dict[str, ScopeRef] = {
            scope: ScopeRef(
                id=scope,
                scope_type="subscription",
                display_name=self.subscription.display_name,
            )
        }
        role_name_cache: dict[str, str] = {}

        try:
            iterator = self.clients.authorization.role_assignments.list_for_scope(scope)
            for assignment in iterator:
                role_definition_id = getattr(assignment, "role_definition_id", None)
                role_name = self._resolve_role_name(scope, role_definition_id, role_name_cache)
                principal_id = getattr(assignment, "principal_id", "unknown")
                principal_type = getattr(assignment, "principal_type", None)
                assignment_scope = getattr(assignment, "scope", scope)

                if assignment_scope not in scopes:
                    scopes[assignment_scope] = ScopeRef(
                        id=assignment_scope,
                        scope_type=_scope_type_from_id(assignment_scope),
                    )

                principals.setdefault(
                    principal_id,
                    Principal(id=principal_id, principal_type=principal_type or "unknown"),
                )

                assignments.append(
                    RoleAssignment(
                        id=getattr(assignment, "id", "unknown"),
                        scope_id=assignment_scope,
                        principal_id=principal_id,
                        principal_type=principal_type,
                        role_definition_id=role_definition_id,
                        role_name=role_name,
                    )
                )
        except Exception as exc:
            issues.append(_issue_from_exception("rbac", exc))

        return {
            "principals": [p.model_dump() for p in principals.values()],
            "scopes": [s.model_dump() for s in scopes.values()],
            "role_assignments": [a.model_dump() for a in assignments],
            "issues": issues,
        }

    def principals(self) -> dict:
        rbac_data = self.rbac()
        whoami_data = self.whoami()
        identity_data = self.managed_identities()

        records: dict[str, dict] = {}
        issues = [
            *rbac_data.get("issues", []),
            *whoami_data.get("issues", []),
            *identity_data.get("issues", []),
        ]

        def ensure_record(principal_id: str) -> dict:
            if principal_id not in records:
                records[principal_id] = {
                    "id": principal_id,
                    "principal_type": "unknown",
                    "display_name": None,
                    "tenant_id": None,
                    "sources": [],
                    "scope_ids": [],
                    "role_names": [],
                    "role_assignment_count": 0,
                    "identity_names": [],
                    "identity_types": [],
                    "attached_to": [],
                    "is_current_identity": False,
                }
            return records[principal_id]

        for principal in rbac_data.get("principals", []):
            principal_id = principal.get("id")
            if not principal_id:
                continue
            record = ensure_record(principal_id)
            _merge_principal_attributes(record, principal)
            _append_unique(record["sources"], "rbac")

        for assignment in rbac_data.get("role_assignments", []):
            principal_id = assignment.get("principal_id")
            if not principal_id:
                continue
            record = ensure_record(principal_id)
            role_name = assignment.get("role_name")
            scope_id = assignment.get("scope_id")
            if role_name:
                _append_unique(record["role_names"], role_name)
            if scope_id:
                _append_unique(record["scope_ids"], scope_id)
            record["role_assignment_count"] += 1
            principal_type = assignment.get("principal_type")
            if principal_type:
                record["principal_type"] = _normalize_principal_type(
                    record["principal_type"],
                    principal_type,
                )
            _append_unique(record["sources"], "rbac")

        principal = whoami_data.get("principal")
        if principal and principal.get("id"):
            record = ensure_record(principal["id"])
            _merge_principal_attributes(record, principal)
            record["is_current_identity"] = True
            for scope in whoami_data.get("effective_scopes", []):
                scope_id = scope.get("id")
                if scope_id:
                    _append_unique(record["scope_ids"], scope_id)
            _append_unique(record["sources"], "whoami")

        for identity in identity_data.get("identities", []):
            principal_id = identity.get("principal_id")
            if not principal_id:
                continue
            record = ensure_record(principal_id)
            if record["principal_type"] == "unknown":
                record["principal_type"] = "ServicePrincipal"
            _append_unique(record["identity_names"], identity.get("name"))
            _append_unique(record["identity_types"], identity.get("identity_type"))
            for scope_id in identity.get("scope_ids", []):
                _append_unique(record["scope_ids"], scope_id)
            for attachment in identity.get("attached_to", []):
                _append_unique(record["attached_to"], attachment)
            _append_unique(record["sources"], "managed-identities")

        principals = sorted(
            records.values(),
            key=lambda item: (
                item.get("display_name") or "",
                item["id"],
            ),
        )
        return {"principals": principals, "issues": issues}

    def permissions(self) -> dict:
        principal_data = self.principals()
        permission_rows: list[dict] = []

        for principal in principal_data.get("principals", []):
            role_names = sorted(set(principal.get("role_names", [])))
            scope_ids = sorted(set(principal.get("scope_ids", [])))
            high_impact_roles = sorted(
                {
                    role_name
                    for role_name in role_names
                    if role_name.lower() in _HIGH_IMPACT_ROLE_NAMES
                }
            )
            permission_rows.append(
                {
                    "principal_id": principal.get("id"),
                    "display_name": principal.get("display_name"),
                    "principal_type": principal.get("principal_type", "unknown"),
                    "high_impact_roles": high_impact_roles,
                    "all_role_names": role_names,
                    "role_assignment_count": principal.get("role_assignment_count", 0),
                    "scope_count": len(scope_ids),
                    "scope_ids": scope_ids,
                    "privileged": len(high_impact_roles) > 0,
                    "is_current_identity": principal.get("is_current_identity", False),
                }
            )

        permission_rows.sort(
            key=lambda item: (
                not item["privileged"],
                not item["is_current_identity"],
                -(item["role_assignment_count"]),
                item.get("display_name") or "",
                item["principal_id"] or "",
            )
        )
        return {"permissions": permission_rows, "issues": principal_data.get("issues", [])}

    def privesc(self) -> dict:
        permissions_data = self.permissions()
        principals_data = self.principals()
        identities_data = self.managed_identities()
        vms_data = self.vms()

        principal_by_id = {
            item.get("id"): item for item in principals_data.get("principals", []) if item.get("id")
        }
        identities_by_principal: dict[str, list[dict]] = {}
        for identity in identities_data.get("identities", []):
            principal_id = identity.get("principal_id")
            if principal_id:
                identities_by_principal.setdefault(principal_id, []).append(identity)

        vm_by_id = {
            item.get("id"): item for item in vms_data.get("vm_assets", []) if item.get("id")
        }
        paths: list[dict] = []

        for permission in permissions_data.get("permissions", []):
            if not permission.get("privileged"):
                continue

            principal_name = (
                permission.get("display_name") or permission.get("principal_id") or "unknown"
            )
            impact_roles = permission.get("high_impact_roles", [])
            principal_id = permission.get("principal_id", "unknown")
            related_ids = [principal_id, *permission.get("scope_ids", [])]

            paths.append(
                {
                    "principal": principal_name,
                    "principal_id": principal_id,
                    "principal_type": permission.get("principal_type", "unknown"),
                    "path_type": "direct-role-abuse",
                    "asset": None,
                    "impact_roles": impact_roles,
                    "severity": "high" if permission.get("is_current_identity") else "medium",
                    "current_identity": permission.get("is_current_identity", False),
                    "summary": (
                        f"Principal '{principal_name}' already holds high-impact role "
                        f"assignments ({', '.join(impact_roles) or 'Unknown'}) in the "
                        "current subscription scope."
                    ),
                    "related_ids": related_ids,
                }
            )

            for identity in identities_by_principal.get(principal_id, []):
                for attached_id in identity.get("attached_to", []):
                    vm_asset = vm_by_id.get(attached_id)
                    if not vm_asset or not vm_asset.get("public_ips"):
                        continue

                    paths.append(
                        {
                            "principal": identity.get("name") or principal_name,
                            "principal_id": principal_id,
                            "principal_type": "ManagedIdentity",
                            "path_type": "public-identity-pivot",
                            "asset": vm_asset.get("name") or attached_id,
                            "impact_roles": impact_roles,
                            "severity": "high",
                            "current_identity": False,
                            "summary": (
                                f"Public workload '{vm_asset.get('name') or attached_id}' carries "
                                f"managed identity '{identity.get('name') or principal_name}' with "
                                "high-impact role assignments "
                                f"({', '.join(impact_roles) or 'Unknown'})."
                            ),
                            "related_ids": [
                                identity.get("id"),
                                principal_id,
                                attached_id,
                                *principal_by_id.get(principal_id, {}).get("scope_ids", []),
                            ],
                        }
                    )

        paths.sort(
            key=lambda item: (
                not item["current_identity"],
                item["path_type"] != "public-identity-pivot",
                item["principal"],
            )
        )
        issues = [
            *permissions_data.get("issues", []),
            *identities_data.get("issues", []),
            *vms_data.get("issues", []),
        ]
        return {"paths": paths, "issues": issues}

    def role_trusts(self) -> dict:
        issues: list[dict] = []
        trusts: list[dict] = []

        service_principals: list[dict] = []
        try:
            service_principals = self.graph.list_service_principals()
        except Exception as exc:
            issues.append(_issue_from_exception("role_trusts.service_principals", exc))

        service_principal_by_id = {
            item.get("id"): item for item in service_principals if item.get("id")
        }
        service_principal_by_app_id = {
            item.get("appId"): item for item in service_principals if item.get("appId")
        }
        applications: list[dict] = []
        application_by_app_id: dict[str, dict] = {}

        try:
            applications = self.graph.list_applications()
        except Exception as exc:
            issues.append(_issue_from_exception("role_trusts.applications", exc))
            applications = []

        for application in applications:
            app_id = application.get("appId")
            if app_id:
                application_by_app_id[app_id] = application

        missing_app_ids = sorted(
            app_id
            for app_id in service_principal_by_app_id
            if app_id and app_id not in application_by_app_id
        )
        for app_id in missing_app_ids:
            try:
                application = self.graph.get_application_by_app_id(app_id)
            except Exception as exc:
                issues.append(
                    _issue_from_exception(
                        f"role_trusts.applications.by_app_id[{app_id}]",
                        exc,
                    )
                )
                application = None
            if application is None:
                continue
            application_by_app_id[app_id] = application
            applications.append(application)

        for application in applications:
            app_object_id = application.get("id")
            if not app_object_id:
                continue
            application_app_id = application.get("appId") or app_object_id

            backing_sp = service_principal_by_app_id.get(application.get("appId"))

            try:
                federated_credentials = self.graph.list_application_federated_credentials(
                    app_object_id
                )
            except Exception as exc:
                issues.append(
                    _issue_from_exception(
                        f"role_trusts.applications[{app_object_id}].federated_credentials",
                        exc,
                    )
                )
                federated_credentials = []

            for credential in federated_credentials:
                related_ids = [app_object_id]
                if credential.get("id"):
                    related_ids.append(credential["id"])
                if backing_sp and backing_sp.get("id"):
                    related_ids.append(backing_sp["id"])

                target_object_id = backing_sp.get("id") if backing_sp else app_object_id
                target_name = (
                    backing_sp.get("displayName") if backing_sp else application.get("displayName")
                )
                target_type = "ServicePrincipal" if backing_sp else "Application"
                issuer = credential.get("issuer") or "unknown issuer"
                subject = credential.get("subject") or "unknown subject"

                trusts.append(
                    {
                        "trust_type": "federated-credential",
                        "source_object_id": app_object_id,
                        "source_name": application.get("displayName"),
                        "source_type": "Application",
                        "target_object_id": target_object_id,
                        "target_name": target_name,
                        "target_type": target_type,
                        "evidence_type": "graph-federated-credential",
                        "confidence": "confirmed",
                        "summary": (
                            "Application "
                            f"'{application.get('displayName') or application_app_id}' trusts "
                            f"federated subject '{subject}' from issuer '{issuer}'."
                        ),
                        "related_ids": related_ids,
                    }
                )

            try:
                owners = self.graph.list_application_owners(app_object_id)
            except Exception as exc:
                issues.append(
                    _issue_from_exception(
                        f"role_trusts.applications[{app_object_id}].owners",
                        exc,
                    )
                )
                owners = []

            for owner in owners:
                owner_id = owner.get("id")
                if not owner_id:
                    continue
                trusts.append(
                    {
                        "trust_type": "app-owner",
                        "source_object_id": owner_id,
                        "source_name": _display_name_for_graph_object(owner),
                        "source_type": _graph_object_type(owner),
                        "target_object_id": app_object_id,
                        "target_name": application.get("displayName"),
                        "target_type": "Application",
                        "evidence_type": "graph-owner",
                        "confidence": "confirmed",
                        "summary": (
                            f"Owner '{_display_name_for_graph_object(owner)}' can modify "
                            f"application '{application.get('displayName') or app_object_id}'."
                        ),
                        "related_ids": [owner_id, app_object_id],
                    }
                )

        for service_principal in service_principals:
            sp_id = service_principal.get("id")
            if not sp_id:
                continue

            try:
                owners = self.graph.list_service_principal_owners(sp_id)
            except Exception as exc:
                issues.append(
                    _issue_from_exception(
                        f"role_trusts.service_principals[{sp_id}].owners",
                        exc,
                    )
                )
                owners = []

            for owner in owners:
                owner_id = owner.get("id")
                if not owner_id:
                    continue
                trusts.append(
                    {
                        "trust_type": "service-principal-owner",
                        "source_object_id": owner_id,
                        "source_name": _display_name_for_graph_object(owner),
                        "source_type": _graph_object_type(owner),
                        "target_object_id": sp_id,
                        "target_name": service_principal.get("displayName"),
                        "target_type": "ServicePrincipal",
                        "evidence_type": "graph-owner",
                        "confidence": "confirmed",
                        "summary": (
                            f"Owner '{_display_name_for_graph_object(owner)}' can modify "
                            f"service principal '{service_principal.get('displayName') or sp_id}'."
                        ),
                        "related_ids": [owner_id, sp_id],
                    }
                )

            try:
                assignments = self.graph.list_app_role_assignments(sp_id)
            except Exception as exc:
                issues.append(
                    _issue_from_exception(
                        f"role_trusts.service_principals[{sp_id}].app_role_assignments",
                        exc,
                    )
                )
                assignments = []

            for assignment in assignments:
                resource_id = assignment.get("resourceId")
                resource = service_principal_by_id.get(resource_id)
                if resource is None and resource_id:
                    try:
                        resource = self.graph.get_service_principal(str(resource_id))
                    except Exception as exc:
                        issues.append(
                            _issue_from_exception(
                                f"role_trusts.service_principals[{sp_id}].resource[{resource_id}]",
                                exc,
                            )
                        )
                        resource = {}
                    else:
                        if resource.get("id"):
                            service_principal_by_id[resource["id"]] = resource
                resource_name = (
                    resource.get("displayName") or resource_id or "unknown"
                )
                assignment_related_ids = [
                    item for item in [assignment.get("id"), resource_id] if item
                ]
                trusts.append(
                    {
                        "trust_type": "app-to-service-principal",
                        "source_object_id": sp_id,
                        "source_name": service_principal.get("displayName"),
                        "source_type": "ServicePrincipal",
                        "target_object_id": resource_id or "unknown",
                        "target_name": resource.get("displayName"),
                        "target_type": "ServicePrincipal",
                        "evidence_type": "graph-app-role-assignment",
                        "confidence": "confirmed",
                        "summary": (
                            f"Service principal '{service_principal.get('displayName') or sp_id}' "
                            "holds an application permission or app-role assignment "
                            f"to '{resource_name}'."
                        ),
                        "related_ids": [sp_id, *assignment_related_ids],
                    }
                )

        trusts = _dedupe_role_trusts(trusts)
        trusts.sort(
            key=lambda item: (
                item["confidence"] != "confirmed",
                item["trust_type"],
                item.get("source_name") or item["source_object_id"],
                item.get("target_name") or item["target_object_id"],
            )
        )
        return {"trusts": trusts, "issues": issues}

    def resource_trusts(self) -> dict:
        storage_data = self.storage()
        keyvault_data = self.keyvault()
        resource_trusts = _compose_resource_trusts(
            storage_data.get("storage_assets", []),
            keyvault_data.get("key_vaults", []),
        )
        findings = _resource_trust_findings(
            storage_data.get("storage_assets", []),
            keyvault_data.get("key_vaults", []),
        )
        issues = [*storage_data.get("issues", []), *keyvault_data.get("issues", [])]
        return {
            "resource_trusts": resource_trusts,
            "findings": findings,
            "issues": issues,
        }

    def auth_policies(self) -> dict:
        issues: list[dict] = []
        auth_policies: list[dict] = []

        try:
            defaults = self.graph.get_identity_security_defaults_policy()
            auth_policies.append(
                {
                    "policy_type": "security-defaults",
                    "name": defaults.get("displayName") or "Security Defaults",
                    "state": "enabled" if defaults.get("isEnabled") else "disabled",
                    "scope": "tenant",
                    "controls": [
                        "baseline-mfa",
                        "legacy-auth-protection",
                    ]
                    if defaults.get("isEnabled")
                    else [],
                    "summary": (
                        "Security defaults are enabled for the tenant."
                        if defaults.get("isEnabled")
                        else "Security defaults are disabled for the tenant."
                    ),
                    "related_ids": [item for item in [defaults.get("id")] if item],
                }
            )
        except Exception as exc:
            issues.append(_issue_from_exception("auth_policies.security_defaults", exc))

        try:
            authorization_policy = self.graph.get_authorization_policy()
            auth_policies.append(_authorization_policy_summary(authorization_policy))
        except Exception as exc:
            issues.append(_issue_from_exception("auth_policies.authorization_policy", exc))

        try:
            conditional_access_policies = self.graph.list_conditional_access_policies()
            auth_policies.extend(
                _conditional_access_policy_summary(item) for item in conditional_access_policies
            )
        except Exception as exc:
            issues.append(_issue_from_exception("auth_policies.conditional_access", exc))

        auth_policies.sort(
            key=lambda item: (
                item["policy_type"] != "security-defaults",
                item["policy_type"] != "authorization-policy",
                item["name"],
            )
        )
        return {"auth_policies": auth_policies, "issues": issues}

    def managed_identities(self) -> dict:
        issues: list[dict] = []
        identities: dict[str, dict] = {}

        def ensure_identity(entry_id: str, name: str, identity_type: str) -> dict:
            if entry_id not in identities:
                identities[entry_id] = {
                    "id": entry_id,
                    "name": name,
                    "identity_type": identity_type,
                    "principal_id": None,
                    "client_id": None,
                    "attached_to": [],
                    "scope_ids": [f"/subscriptions/{self.clients.subscription_id}"],
                }
            return identities[entry_id]

        try:
            for vm in self.clients.compute.virtual_machines.list_all():
                vm_identity = getattr(vm, "identity", None)
                if vm_identity is None:
                    continue

                vm_id = getattr(vm, "id", "unknown")
                if getattr(vm_identity, "principal_id", None):
                    system_id = f"{vm_id}/identities/system"
                    item = ensure_identity(
                        system_id,
                        f"{getattr(vm, 'name', 'vm')}-system",
                        "systemAssigned",
                    )
                    item["principal_id"] = vm_identity.principal_id

                user_assigned = getattr(vm_identity, "user_assigned_identities", None) or {}
                for user_id, user_obj in user_assigned.items():
                    name = user_id.rstrip("/").split("/")[-1]
                    item = ensure_identity(user_id, name, "userAssigned")
                    item["client_id"] = getattr(user_obj, "client_id", None)
                    item["principal_id"] = getattr(user_obj, "principal_id", item["principal_id"])
                    item["attached_to"].append(vm_id)

                if getattr(vm_identity, "principal_id", None):
                    identities[f"{vm_id}/identities/system"]["attached_to"].append(vm_id)
        except Exception as exc:
            issues.append(_issue_from_exception("managed_identities", exc))

        rbac_data = self.rbac()
        assignments = [
            RoleAssignment.model_validate(a) for a in rbac_data.get("role_assignments", [])
        ]
        principal_ids = {
            item.get("principal_id") for item in identities.values() if item.get("principal_id")
        }
        identity_assignments = [a for a in assignments if a.principal_id in principal_ids]

        return {
            "identities": list(identities.values()),
            "role_assignments": [a.model_dump() for a in identity_assignments],
            "issues": issues + rbac_data.get("issues", []),
        }

    def keyvault(self) -> dict:
        key_vaults: list[dict] = []
        issues: list[dict] = []

        try:
            for vault in self.clients.keyvault.vaults.list_by_subscription():
                vault_id = getattr(vault, "id", "unknown")
                properties = getattr(vault, "properties", None)
                network_acls = getattr(properties, "network_acls", None)
                private_endpoints = (
                    getattr(properties, "private_endpoint_connections", None)
                    or getattr(vault, "private_endpoint_connections", None)
                    or []
                )
                sku = getattr(vault, "sku", None)

                key_vaults.append(
                    {
                        "id": vault_id,
                        "name": getattr(vault, "name", "unknown"),
                        "resource_group": _resource_group_from_id(vault_id),
                        "location": getattr(vault, "location", None),
                        "vault_uri": getattr(properties, "vault_uri", None),
                        "tenant_id": _string_value(getattr(properties, "tenant_id", None)),
                        "sku_name": _string_value(getattr(sku, "name", None)),
                        "public_network_access": _string_value(
                            getattr(properties, "public_network_access", None)
                        ),
                        "network_default_action": _string_value(
                            getattr(network_acls, "default_action", None)
                        ),
                        "private_endpoint_enabled": len(private_endpoints) > 0,
                        "purge_protection_enabled": bool(
                            getattr(properties, "enable_purge_protection", False)
                        ),
                        "soft_delete_enabled": bool(
                            getattr(properties, "enable_soft_delete", False)
                        ),
                        "enable_rbac_authorization": bool(
                            getattr(properties, "enable_rbac_authorization", False)
                        ),
                        "access_policy_count": len(
                            getattr(properties, "access_policies", None) or []
                        ),
                    }
                )
        except Exception as exc:
            issues.append(_issue_from_exception("keyvault", exc))

        key_vaults.sort(key=lambda item: ((item.get("name") or ""), item.get("id") or ""))
        return {"key_vaults": key_vaults, "issues": issues}

    def storage(self) -> dict:
        assets: list[dict] = []
        issues: list[dict] = []

        try:
            for account in self.clients.storage.storage_accounts.list():
                account_id = getattr(account, "id", "unknown")
                account_name = getattr(account, "name", "unknown")
                rg_name = _resource_group_from_id(account_id)
                public_access = bool(getattr(account, "allow_blob_public_access", False))

                network_rule_set = getattr(account, "network_rule_set", None)
                default_action = getattr(network_rule_set, "default_action", None)

                private_endpoints = getattr(account, "private_endpoint_connections", None) or []

                container_count, container_issues = self._count_storage_children(
                    "blob_containers",
                    rg_name,
                    account_name,
                )
                share_count, share_issues = self._count_storage_children(
                    "file_shares",
                    rg_name,
                    account_name,
                )
                queue_count, queue_issues = self._count_storage_children(
                    "queue",
                    rg_name,
                    account_name,
                )
                table_count, table_issues = self._count_storage_children(
                    "table",
                    rg_name,
                    account_name,
                )
                issues.extend(container_issues)
                issues.extend(share_issues)
                issues.extend(queue_issues)
                issues.extend(table_issues)

                indicators = []
                if public_access:
                    indicators.append("allow_blob_public_access=true")
                if default_action and str(default_action).lower() == "allow":
                    indicators.append("network_default_action=Allow")

                assets.append(
                    {
                        "id": account_id,
                        "name": account_name,
                        "resource_group": rg_name,
                        "location": getattr(account, "location", None),
                        "public_access": public_access,
                        "anonymous_access_indicators": indicators,
                        "network_default_action": default_action,
                        "private_endpoint_enabled": len(private_endpoints) > 0,
                        "container_count": container_count,
                        "file_share_count": share_count,
                        "queue_count": queue_count,
                        "table_count": table_count,
                    }
                )
        except Exception as exc:
            issues.append(_issue_from_exception("storage", exc))

        assets.sort(key=lambda item: ((item.get("name") or ""), item.get("id") or ""))
        return {"storage_assets": assets, "issues": issues}

    def vms(self) -> dict:
        vm_assets: list[dict] = []
        issues: list[dict] = []
        nic_cache: dict[str, dict] = {}

        try:
            for vm in self.clients.compute.virtual_machines.list_all():
                vm_id = getattr(vm, "id", "unknown")
                network_profile = getattr(vm, "network_profile", None)
                interfaces = getattr(network_profile, "network_interfaces", []) or []
                nic_ids = [n.id for n in interfaces if n and getattr(n, "id", None)]

                private_ips: list[str] = []
                public_ips: list[str] = []
                for nic_id in nic_ids:
                    nic_detail, nic_issues = self._resolve_nic_detail(nic_id, nic_cache)
                    issues.extend(nic_issues)
                    if nic_detail is None:
                        continue
                    private_ips.extend(nic_detail.get("private_ips", []))
                    public_ips.extend(self._resolve_public_ip_addresses(nic_detail))

                identity_ids = []
                vm_identity = getattr(vm, "identity", None)
                if vm_identity is not None:
                    if getattr(vm_identity, "principal_id", None):
                        identity_ids.append(f"{vm_id}/identities/system")
                    user_assigned = getattr(vm_identity, "user_assigned_identities", None) or {}
                    identity_ids.extend(user_assigned.keys())

                vm_assets.append(
                    {
                        "id": vm_id,
                        "name": getattr(vm, "name", "unknown"),
                        "resource_group": _resource_group_from_id(vm_id),
                        "location": getattr(vm, "location", None),
                        "vm_type": "vm",
                        "power_state": _extract_power_state(vm),
                        "private_ips": sorted(set(private_ips)),
                        "public_ips": sorted(set(public_ips)),
                        "identity_ids": sorted(set(identity_ids)),
                        "nic_ids": sorted(set(nic_ids)),
                    }
                )

            for vmss in self.clients.compute.virtual_machine_scale_sets.list_all():
                vmss_id = getattr(vmss, "id", "unknown")
                identity_ids = []
                vmss_identity = getattr(vmss, "identity", None)
                if vmss_identity is not None:
                    if getattr(vmss_identity, "principal_id", None):
                        identity_ids.append(f"{vmss_id}/identities/system")
                    user_assigned = getattr(vmss_identity, "user_assigned_identities", None) or {}
                    identity_ids.extend(user_assigned.keys())

                vm_assets.append(
                    {
                        "id": vmss_id,
                        "name": getattr(vmss, "name", "unknown"),
                        "resource_group": _resource_group_from_id(vmss_id),
                        "location": getattr(vmss, "location", None),
                        "vm_type": "vmss",
                        "power_state": None,
                        "private_ips": [],
                        "public_ips": [],
                        "identity_ids": sorted(set(identity_ids)),
                        "nic_ids": [],
                    }
                )
        except Exception as exc:
            issues.append(_issue_from_exception("vms", exc))

        return {"vm_assets": vm_assets, "issues": issues}

    def nics(self) -> dict:
        nic_assets: list[dict] = []
        issues: list[dict] = []

        try:
            for nic in self.clients.network.network_interfaces.list_all():
                nic_assets.append(_nic_detail_from_resource(nic))
        except Exception as exc:
            issues.append(_issue_from_exception("nics", exc))

        return {"nic_assets": nic_assets, "issues": issues}

    def network_ports(self) -> dict:
        endpoint_data = self.endpoints()
        nic_data = self.nics()
        issues = [*endpoint_data.get("issues", []), *nic_data.get("issues", [])]

        nic_by_asset: dict[str, list[dict]] = {}
        for nic in nic_data.get("nic_assets", []):
            attached_asset_id = nic.get("attached_asset_id")
            if attached_asset_id:
                nic_by_asset.setdefault(str(attached_asset_id), []).append(nic)

        subnet_cache: dict[str, str | None] = {}
        nsg_cache: dict[str, list[dict]] = {}
        network_ports: list[dict] = []
        seen: set[tuple[str, str, str, str, str]] = set()

        for endpoint in endpoint_data.get("endpoints", []):
            if endpoint.get("endpoint_type") != "ip":
                continue
            if endpoint.get("exposure_family") != "public-ip":
                continue

            asset_nics = nic_by_asset.get(str(endpoint.get("source_asset_id") or ""), [])
            for nic in asset_nics:
                rows: list[dict] = []
                visible_nsg = False

                nic_nsg_id = nic.get("network_security_group_id")
                if nic_nsg_id:
                    visible_nsg = True
                    rules, rule_issues = self._resolve_nsg_inbound_allow_rules(
                        str(nic_nsg_id),
                        nsg_cache,
                    )
                    issues.extend(rule_issues)
                    rows.extend(
                        _network_port_rows_from_rules(
                            endpoint=endpoint,
                            nic=nic,
                            rules=rules,
                            scope_type="nic",
                            scope_id=str(nic_nsg_id),
                        )
                    )

                for subnet_id in nic.get("subnet_ids", []):
                    subnet_nsg_id, subnet_issues = self._resolve_subnet_nsg_id(
                        str(subnet_id),
                        subnet_cache,
                    )
                    issues.extend(subnet_issues)
                    if not subnet_nsg_id:
                        continue

                    visible_nsg = True
                    rules, rule_issues = self._resolve_nsg_inbound_allow_rules(
                        subnet_nsg_id,
                        nsg_cache,
                    )
                    issues.extend(rule_issues)
                    rows.extend(
                        _network_port_rows_from_rules(
                            endpoint=endpoint,
                            nic=nic,
                            rules=rules,
                            scope_type="subnet",
                            scope_id=subnet_nsg_id,
                        )
                    )

                # Azure frequently enforces ingress on the subnet instead of the NIC. Only emit the
                # "no NSG visible" row when neither layer is visible from the current read path.
                if not rows and not visible_nsg:
                    rows.append(_network_port_row_without_nsg(endpoint=endpoint, nic=nic))

                for row in rows:
                    key = (
                        row.get("asset_id") or "",
                        row.get("endpoint") or "",
                        row.get("protocol") or "",
                        row.get("port") or "",
                        row.get("allow_source_summary") or "",
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    network_ports.append(row)

        network_ports.sort(
            key=lambda item: (
                {"high": 0, "medium": 1, "low": 2}.get(
                    str(item.get("exposure_confidence") or "").lower(),
                    9,
                ),
                item.get("asset_name") or "",
                item.get("endpoint") or "",
                item.get("port") or "",
            )
        )
        return {"network_ports": network_ports, "issues": issues}

    def _resolve_role_name(
        self,
        scope: str,
        role_definition_id: str | None,
        cache: dict[str, str],
    ) -> str | None:
        if not role_definition_id:
            return None
        if role_definition_id in cache:
            return cache[role_definition_id]

        role_name = None
        try:
            role_key = role_definition_id.rstrip("/").split("/")[-1]
            role = self.clients.authorization.role_definitions.get(scope, role_key)
            role_name = getattr(role, "role_name", None)
        except Exception:
            role_name = None

        cache[role_definition_id] = role_name or "Unknown"
        return cache[role_definition_id]

    def _count_storage_children(
        self,
        op_name: str,
        rg_name: str | None,
        account_name: str,
    ) -> tuple[int | None, list[dict]]:
        if not rg_name:
            return None, []

        operation = getattr(self.clients.storage, op_name, None)
        if operation is None:
            return None, []

        for method_name in ("list", "list_by_storage_account"):
            method = getattr(operation, method_name, None)
            if method is None:
                continue
            try:
                if method_name == "list":
                    return sum(1 for _ in method(rg_name, account_name)), []
                return sum(1 for _ in method(account_name)), []
            except Exception as exc:
                return None, [
                    _issue_from_exception(
                        f"storage[{rg_name}/{account_name}].{op_name}",
                        exc,
                    )
                ]
        return None, []

    def _resolve_nic_detail(
        self,
        nic_id: str,
        cache: dict[str, dict],
    ) -> tuple[dict | None, list[dict]]:
        if nic_id in cache:
            return cache[nic_id], []

        rg_name, nic_name = _resource_group_and_name(nic_id)
        if not rg_name or not nic_name:
            return None, []

        try:
            nic = self.clients.network.network_interfaces.get(rg_name, nic_name)
        except Exception as exc:
            return None, [_issue_from_exception(f"network_interfaces[{nic_id}]", exc)]

        detail = _nic_detail_from_resource(nic)
        cache[nic_id] = detail
        return detail, []

    def _resolve_public_ip_addresses(self, nic_detail: dict) -> list[str]:
        public_ips: list[str] = []

        for public_ip_id in nic_detail.get("public_ip_ids", []):
            pub_rg, pub_name = _resource_group_and_name(public_ip_id)
            if not pub_rg or not pub_name:
                continue

            try:
                pip = self.clients.network.public_ip_addresses.get(pub_rg, pub_name)
            except Exception:
                continue

            ip_addr = getattr(pip, "ip_address", None)
            if ip_addr:
                public_ips.append(str(ip_addr))

        return _dedupe_strings(public_ips)

    def _resolve_subnet_nsg_id(
        self,
        subnet_id: str,
        cache: dict[str, str | None],
    ) -> tuple[str | None, list[dict]]:
        if subnet_id in cache:
            return cache[subnet_id], []

        rg_name, vnet_name, subnet_name = _subnet_components_from_id(subnet_id)
        if not rg_name or not vnet_name or not subnet_name:
            cache[subnet_id] = None
            return None, []

        try:
            subnet = self.clients.network.subnets.get(rg_name, vnet_name, subnet_name)
        except Exception as exc:
            return None, [_issue_from_exception(f"subnets[{subnet_id}]", exc)]

        network_security_group = getattr(subnet, "network_security_group", None)
        nsg_id = str(getattr(network_security_group, "id", "") or "") or None
        cache[subnet_id] = nsg_id
        return nsg_id, []

    def _resolve_nsg_inbound_allow_rules(
        self,
        nsg_id: str,
        cache: dict[str, list[dict]],
    ) -> tuple[list[dict], list[dict]]:
        if nsg_id in cache:
            return cache[nsg_id], []

        rg_name, nsg_name = _resource_group_and_name(nsg_id)
        if not rg_name or not nsg_name:
            cache[nsg_id] = []
            return [], []

        try:
            nsg = self.clients.network.network_security_groups.get(rg_name, nsg_name)
        except Exception as exc:
            return [], [_issue_from_exception(f"network_security_groups[{nsg_id}]", exc)]

        rules = _inbound_allow_rules_from_nsg(nsg)
        cache[nsg_id] = rules
        return rules, []


def get_provider(options: GlobalOptions) -> BaseProvider:
    fixture_dir = _fixture_dir_from_env()
    if fixture_dir is not None:
        return FixtureProvider(fixture_dir)
    return AzureProvider(options)


def _fixture_dir_from_env() -> Path | None:
    from os import getenv

    value = getenv("AZUREFOX_FIXTURE_DIR")
    if not value:
        return None
    path = Path(value).expanduser().resolve()
    return path


def _issue_from_exception(area: str, exc: Exception) -> dict:
    return {
        "kind": classify_exception(exc).value,
        "message": f"{area}: {exc}",
        "context": {"collector": area},
    }


def _principal_from_claims(claims: dict[str, str], tenant_id: str | None) -> Principal:
    principal_id = claims.get("oid") or claims.get("appid") or "unknown"

    user_markers = (
        claims.get("upn"),
        claims.get("preferred_username"),
        claims.get("unique_name"),
        claims.get("scp"),
    )
    principal_type = "ServicePrincipal"
    if claims.get("idtyp", "").lower() != "app" and (
        any(user_markers) or (claims.get("oid") and not claims.get("appid"))
    ):
        principal_type = "User"
    elif not claims.get("appid") and claims.get("oid"):
        principal_type = "User"

    return Principal(
        id=principal_id,
        principal_type=principal_type,
        display_name=claims.get("name")
        or claims.get("upn")
        or claims.get("preferred_username")
        or claims.get("appid"),
        tenant_id=claims.get("tid", tenant_id),
    )


def _merge_principal_attributes(record: dict, principal: dict) -> None:
    display_name = principal.get("display_name")
    tenant_id = principal.get("tenant_id")
    principal_type = principal.get("principal_type")

    if display_name and not record["display_name"]:
        record["display_name"] = display_name
    if tenant_id and not record["tenant_id"]:
        record["tenant_id"] = tenant_id
    if principal_type:
        record["principal_type"] = _normalize_principal_type(
            record["principal_type"],
            principal_type,
        )


def _append_unique(items: list[str], value: str | None) -> None:
    if value and value not in items:
        items.append(value)


def _normalize_principal_type(existing: str | None, candidate: str | None) -> str:
    normalized_existing = existing or "unknown"
    if not candidate:
        return normalized_existing

    normalized = {
        "serviceprincipal": "ServicePrincipal",
        "user": "User",
        "group": "Group",
        "managedidentity": "ManagedIdentity",
    }.get(candidate.replace(" ", "").lower(), candidate)

    if normalized_existing != "unknown":
        return normalized_existing
    return normalized


def _display_name_for_graph_object(item: dict) -> str:
    return (
        item.get("displayName")
        or item.get("userPrincipalName")
        or item.get("appId")
        or item.get("id")
        or "unknown"
    )


def _graph_object_type(item: dict) -> str:
    odata_type = item.get("@odata.type")
    if isinstance(odata_type, str) and odata_type:
        value = odata_type.rsplit(".", 1)[-1]
        return value[:1].upper() + value[1:]

    if item.get("servicePrincipalType") is not None or item.get("appId") is not None:
        return "ServicePrincipal"
    if item.get("userPrincipalName") is not None:
        return "User"
    return "DirectoryObject"


def _dedupe_role_trusts(items: list[dict]) -> list[dict]:
    deduped: list[dict] = []
    seen: set[tuple[str, str, str, str, str]] = set()

    for item in items:
        key = (
            item.get("trust_type") or "",
            item.get("source_object_id") or "",
            item.get("target_object_id") or "",
            item.get("evidence_type") or "",
            item.get("summary") or "",
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    return deduped


def _authorization_policy_summary(policy: dict) -> dict:
    controls: list[str] = []

    invite_setting = policy.get("allowInvitesFrom")
    if invite_setting:
        controls.append(f"guest-invites:{invite_setting}")

    if policy.get("allowUserConsentForRiskyApps") is True:
        controls.append("risky-app-consent:enabled")

    if policy.get("allowedToUseSSPR") is True:
        controls.append("sspr:enabled")

    if policy.get("blockMsolPowerShell") is True:
        controls.append("legacy-msol-powershell:blocked")

    default_permissions = policy.get("defaultUserRolePermissions") or {}
    if default_permissions.get("allowedToCreateApps") is True:
        controls.append("users-can-register-apps")
    if default_permissions.get("allowedToCreateSecurityGroups") is True:
        controls.append("users-can-create-security-groups")

    permission_grants = default_permissions.get("permissionGrantPoliciesAssigned") or []
    if permission_grants:
        controls.append("user-consent:self-service")

    summary_parts = []
    if invite_setting:
        summary_parts.append(f"guest invites: {invite_setting}")
    summary_parts.append(
        "users can register apps"
        if default_permissions.get("allowedToCreateApps")
        else "users cannot register apps"
    )
    if permission_grants:
        summary_parts.append("self-service permission grant policies assigned")
    if policy.get("allowUserConsentForRiskyApps") is True:
        summary_parts.append("risky app consent enabled")
    if policy.get("blockMsolPowerShell") is True:
        summary_parts.append("legacy MSOL PowerShell blocked")

    return {
        "policy_type": "authorization-policy",
        "name": policy.get("displayName") or "Authorization Policy",
        "state": "configured",
        "scope": "tenant",
        "controls": controls,
        "summary": "; ".join(summary_parts) if summary_parts else "Authorization policy retrieved.",
        "related_ids": [item for item in [policy.get("id")] if item],
    }


def _conditional_access_policy_summary(policy: dict) -> dict:
    grant_controls = (policy.get("grantControls") or {}).get("builtInControls") or []
    session_controls = [
        key
        for key, value in (policy.get("sessionControls") or {}).items()
        if value not in (None, False, [], {})
    ]
    auth_strength = ((policy.get("grantControls") or {}).get("authenticationStrength") or {}).get(
        "displayName"
    )
    if auth_strength:
        grant_controls = [*grant_controls, f"authentication-strength:{auth_strength}"]

    users = (policy.get("conditions") or {}).get("users") or {}
    applications = (policy.get("conditions") or {}).get("applications") or {}

    scope_parts = []
    if "All" in (users.get("includeUsers") or []):
        scope_parts.append("users:all")
    if users.get("includeRoles"):
        scope_parts.append(f"roles:{len(users['includeRoles'])}")
    if "All" in (applications.get("includeApplications") or []):
        scope_parts.append("apps:all")
    elif applications.get("includeApplications"):
        scope_parts.append(f"apps:{len(applications['includeApplications'])}")

    summary_parts = [f"state: {policy.get('state') or 'unknown'}"]
    if grant_controls:
        summary_parts.append(f"grants: {', '.join(str(item) for item in grant_controls)}")
    if session_controls:
        summary_parts.append(f"session: {', '.join(session_controls)}")
    if scope_parts:
        summary_parts.append(f"scope: {', '.join(scope_parts)}")

    return {
        "policy_type": "conditional-access",
        "name": policy.get("displayName") or policy.get("id") or "Conditional Access",
        "state": policy.get("state") or "unknown",
        "scope": ", ".join(scope_parts) if scope_parts else "scoped",
        "controls": [*grant_controls, *session_controls],
        "summary": "; ".join(summary_parts),
        "related_ids": [item for item in [policy.get("id")] if item],
    }


_HIGH_IMPACT_ROLE_NAMES = {
    "owner",
    "contributor",
    "user access administrator",
}


def _resource_group_from_id(resource_id: str) -> str | None:
    parts = [p for p in resource_id.split("/") if p]
    try:
        idx = [p.lower() for p in parts].index("resourcegroups")
        return parts[idx + 1]
    except (ValueError, IndexError):
        return None


def _resource_group_and_name(resource_id: str) -> tuple[str | None, str | None]:
    parts = [p for p in resource_id.split("/") if p]
    rg = None
    name = parts[-1] if parts else None
    try:
        idx = [p.lower() for p in parts].index("resourcegroups")
        rg = parts[idx + 1]
    except (ValueError, IndexError):
        pass
    return rg, name


def _resource_name_from_id(resource_id: str | None) -> str | None:
    if not resource_id:
        return None
    parts = [part for part in resource_id.split("/") if part]
    if not parts:
        return None
    return parts[-1]


def _subnet_components_from_id(subnet_id: str) -> tuple[str | None, str | None, str | None]:
    parts = [part for part in subnet_id.split("/") if part]
    lowered = [part.lower() for part in parts]

    try:
        rg_index = lowered.index("resourcegroups")
        vnet_index = lowered.index("virtualnetworks")
        subnet_index = lowered.index("subnets")
    except ValueError:
        return None, None, None

    try:
        return parts[rg_index + 1], parts[vnet_index + 1], parts[subnet_index + 1]
    except IndexError:
        return None, None, None


def _vnet_id_from_subnet_id(subnet_id: str) -> str | None:
    parts = [part for part in subnet_id.split("/") if part]
    lowered = [part.lower() for part in parts]
    try:
        subnet_index = lowered.index("subnets")
    except ValueError:
        return None
    return "/" + "/".join(parts[:subnet_index])


def _string_value(value: object) -> str | None:
    if value is None:
        return None
    return str(getattr(value, "value", value))


def _int_value(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _property_value(container: object, *names: str) -> object | None:
    if container is None:
        return None

    for name in names:
        if isinstance(container, dict) and name in container:
            return container[name]

        direct = getattr(container, name, None)
        if direct is not None:
            return direct

        snake_name = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
        snake_value = getattr(container, snake_name, None)
        if snake_value is not None:
            return snake_value

    return None


def _resource_trusts_from_storage(storage_assets: list[dict]) -> list[dict]:
    trusts: list[dict] = []

    for asset in storage_assets:
        resource_id = asset.get("id")
        if not resource_id:
            continue

        name = asset.get("name")
        if asset.get("public_access"):
            trusts.append(
                {
                    "resource_id": resource_id,
                    "resource_name": name,
                    "resource_type": "StorageAccount",
                    "trust_type": "anonymous-blob-access",
                    "target": "public-network",
                    "exposure": "high",
                    "confidence": "confirmed",
                    "summary": (
                        f"Storage account '{name or resource_id}' permits public blob access from "
                        "the public network."
                    ),
                    "related_ids": [resource_id],
                }
            )

        if (asset.get("network_default_action") or "").lower() == "allow":
            trusts.append(
                {
                    "resource_id": resource_id,
                    "resource_name": name,
                    "resource_type": "StorageAccount",
                    "trust_type": "public-network-default",
                    "target": "public-network",
                    "exposure": "medium",
                    "confidence": "confirmed",
                    "summary": (
                        f"Storage account '{name or resource_id}' accepts public network traffic "
                        "by default."
                    ),
                    "related_ids": [resource_id],
                }
            )

        if asset.get("private_endpoint_enabled"):
            trusts.append(
                {
                    "resource_id": resource_id,
                    "resource_name": name,
                    "resource_type": "StorageAccount",
                    "trust_type": "private-endpoint",
                    "target": "private-link",
                    "exposure": "restricted",
                    "confidence": "confirmed",
                    "summary": (
                        f"Storage account '{name or resource_id}' exposes a private endpoint path "
                        "through Azure Private Link."
                    ),
                    "related_ids": [resource_id],
                }
            )

    return trusts


def _resource_trusts_from_keyvault(key_vaults: list[dict]) -> list[dict]:
    trusts: list[dict] = []

    for vault in key_vaults:
        resource_id = vault.get("id")
        if not resource_id:
            continue

        name = vault.get("name")
        public_network_access = (vault.get("public_network_access") or "").lower()
        network_default_action = (vault.get("network_default_action") or "").lower()
        if public_network_access == "enabled":
            exposure = (
                "high"
                if network_default_action == "allow" or not network_default_action
                else "medium"
            )
            trusts.append(
                {
                    "resource_id": resource_id,
                    "resource_name": name,
                    "resource_type": "KeyVault",
                    "trust_type": "public-network",
                    "target": "public-network",
                    "exposure": exposure,
                    "confidence": "confirmed",
                    "summary": (
                        f"Key Vault '{name or resource_id}' remains reachable through a public "
                        "network path."
                    ),
                    "related_ids": [resource_id],
                }
            )

        if vault.get("private_endpoint_enabled"):
            trusts.append(
                {
                    "resource_id": resource_id,
                    "resource_name": name,
                    "resource_type": "KeyVault",
                    "trust_type": "private-endpoint",
                    "target": "private-link",
                    "exposure": "restricted",
                    "confidence": "confirmed",
                    "summary": (
                        f"Key Vault '{name or resource_id}' exposes a private endpoint path "
                        "through Azure Private Link."
                    ),
                    "related_ids": [resource_id],
                }
            )

    return trusts


def _scope_type_from_id(scope_id: str) -> str:
    lower = scope_id.lower()
    if "/providers/" in lower:
        return "resource"
    if "/resourcegroups/" in lower:
        return "resource_group"
    return "subscription"


def _deployment_summary(
    deployment: object,
    *,
    scope: str,
    scope_type: str,
    resource_group: str | None = None,
) -> dict:
    properties = getattr(deployment, "properties", None)
    output_resources = getattr(properties, "output_resources", None) or []
    template_link = getattr(getattr(properties, "template_link", None), "uri", None)
    parameters_link = getattr(getattr(properties, "parameters_link", None), "uri", None)
    providers = []
    for provider in getattr(properties, "providers", None) or []:
        namespace = getattr(provider, "namespace", None)
        if namespace and namespace not in providers:
            providers.append(str(namespace))

    name = getattr(deployment, "name", "unknown")
    state = getattr(properties, "provisioning_state", None)
    output_count = len(getattr(properties, "outputs", None) or {})
    provider_summary = f"{len(providers)} providers" if providers else "no providers recorded"
    output_summary = f"{output_count} outputs" if output_count else "no outputs recorded"
    summary = (
        f"{scope_type.replace('_', ' ')} deployment '{name}' is "
        f"{state or 'unknown'} with {output_summary}; {provider_summary}."
    )

    deployment_id = getattr(
        deployment,
        "id",
        f"{scope}/providers/Microsoft.Resources/deployments/{name}",
    )

    return {
        "id": deployment_id,
        "name": name,
        "scope": scope,
        "scope_type": scope_type,
        "resource_group": resource_group or _resource_group_from_id(getattr(deployment, "id", "")),
        "provisioning_state": state,
        "mode": _string_value(getattr(properties, "mode", None)),
        "timestamp": _string_value(getattr(properties, "timestamp", None)),
        "duration": _string_value(getattr(properties, "duration", None)),
        "outputs_count": output_count,
        "output_resource_count": len(output_resources),
        "providers": providers,
        "template_link": _string_value(template_link),
        "parameters_link": _string_value(parameters_link),
        "summary": summary,
        "related_ids": [item for item in [deployment_id] if item],
    }


_ENV_VAR_SENSITIVE_TOKENS = {
    "key",
    "secret",
    "token",
    "password",
    "passwd",
    "connectionstring",
    "connection_string",
    "connstr",
    "clientsecret",
}

_TOKENS_CREDENTIALS_PLAIN_TEXT_NAMES = {
    "azurewebjobsstorage",
}


def _web_workload_summary(app: object, *, asset_kind: str) -> dict:
    app_id = getattr(app, "id", "") or ""
    app_name = getattr(app, "name", "unknown")
    identity = getattr(app, "identity", None)

    return {
        "asset_id": app_id or f"/unknown/{app_name}",
        "asset_name": app_name,
        "asset_kind": asset_kind,
        "resource_group": _resource_group_from_id(app_id),
        "location": _string_value(getattr(app, "location", None)),
        "workload_identity_type": _string_value(getattr(identity, "type", None)),
        "workload_principal_id": _string_value(getattr(identity, "principal_id", None)),
        "workload_client_id": _string_value(getattr(identity, "client_id", None)),
        "workload_identity_ids": sorted(
            str(identity_id)
            for identity_id in (getattr(identity, "user_assigned_identities", None) or {}).keys()
        ),
        "default_hostname": _string_value(getattr(app, "default_host_name", None)),
    }


def _app_service_summary(app: object, config: object | None) -> dict:
    app_id = getattr(app, "id", "") or ""
    app_name = getattr(app, "name", "unknown")
    identity = getattr(app, "identity", None)
    public_network_access = _string_value(getattr(app, "public_network_access", None))
    runtime_stack = _app_service_runtime_stack(config)
    min_tls_version = _string_value(getattr(config, "min_tls_version", None))
    ftps_state = _string_value(getattr(config, "ftps_state", None))
    workload_identity_type = _string_value(getattr(identity, "type", None))
    workload_principal_id = _string_value(getattr(identity, "principal_id", None))
    workload_client_id = _string_value(getattr(identity, "client_id", None))
    workload_identity_ids = sorted(
        str(identity_id)
        for identity_id in (getattr(identity, "user_assigned_identities", None) or {}).keys()
    )

    return {
        "id": app_id or f"/unknown/{app_name}",
        "name": app_name,
        "resource_group": _resource_group_from_id(app_id),
        "location": _string_value(getattr(app, "location", None)),
        "state": _string_value(getattr(app, "state", None)),
        "default_hostname": _string_value(getattr(app, "default_host_name", None)),
        "app_service_plan_id": _string_value(getattr(app, "server_farm_id", None)),
        "public_network_access": public_network_access,
        "https_only": bool(getattr(app, "https_only", False)),
        "client_cert_enabled": bool(getattr(app, "client_cert_enabled", False)),
        "min_tls_version": min_tls_version,
        "ftps_state": ftps_state,
        "runtime_stack": runtime_stack,
        "workload_identity_type": workload_identity_type,
        "workload_principal_id": workload_principal_id,
        "workload_client_id": workload_client_id,
        "workload_identity_ids": workload_identity_ids,
        "summary": _app_service_operator_summary(
            app_name=app_name,
            default_hostname=_string_value(getattr(app, "default_host_name", None)),
            public_network_access=public_network_access,
            https_only=bool(getattr(app, "https_only", False)),
            runtime_stack=runtime_stack,
            workload_identity_type=workload_identity_type,
            min_tls_version=min_tls_version,
            ftps_state=ftps_state,
        ),
        "related_ids": _dedupe_strings(
            [
                app_id,
                workload_principal_id,
                *workload_identity_ids,
                _string_value(getattr(app, "server_farm_id", None)),
            ]
        ),
    }


def _api_mgmt_service_summary(
    service: object,
    apis: list[object] | None,
    backends: list[object] | None,
    named_values: list[object] | None,
) -> dict:
    service_id = getattr(service, "id", "") or ""
    service_name = getattr(service, "name", "unknown")
    identity = getattr(service, "identity", None)
    sku = getattr(service, "sku", None)
    hostname_configurations = getattr(service, "hostname_configurations", None) or []
    gateway_hostnames, management_hostnames, portal_hostnames = _api_mgmt_hostnames(
        service,
        hostname_configurations,
    )
    public_ip_address_id = _string_value(getattr(service, "public_ip_address_id", None))
    public_ip_addresses = _dedupe_strings(
        [str(item) for item in (getattr(service, "public_ip_addresses", None) or []) if item]
    )
    private_ip_addresses = _dedupe_strings(
        [str(item) for item in (getattr(service, "private_ip_addresses", None) or []) if item]
    )
    workload_identity_ids = sorted(
        str(identity_id)
        for identity_id in (getattr(identity, "user_assigned_identities", None) or {}).keys()
    )
    workload_identity_type = _string_value(getattr(identity, "type", None))
    workload_principal_id = _string_value(getattr(identity, "principal_id", None))
    workload_client_id = _string_value(getattr(identity, "client_id", None))
    api_count = len(apis) if apis is not None else None
    backend_count = len(backends) if backends is not None else None
    named_value_count = len(named_values) if named_values is not None else None
    gateway_enabled = (
        None
        if getattr(service, "disable_gateway", None) is None
        else not bool(getattr(service, "disable_gateway", False))
    )

    return {
        "id": service_id or f"/unknown/{service_name}",
        "name": service_name,
        "resource_group": _resource_group_from_id(service_id),
        "location": _string_value(getattr(service, "location", None)),
        "state": _string_value(getattr(service, "provisioning_state", None)),
        "sku_name": _string_value(getattr(sku, "name", None)),
        "sku_capacity": getattr(sku, "capacity", None),
        "public_network_access": _string_value(getattr(service, "public_network_access", None)),
        "virtual_network_type": _string_value(getattr(service, "virtual_network_type", None)),
        "public_ip_address_id": public_ip_address_id,
        "public_ip_addresses": public_ip_addresses,
        "private_ip_addresses": private_ip_addresses,
        "gateway_hostnames": gateway_hostnames,
        "management_hostnames": management_hostnames,
        "portal_hostnames": portal_hostnames,
        "workload_identity_type": workload_identity_type,
        "workload_principal_id": workload_principal_id,
        "workload_client_id": workload_client_id,
        "workload_identity_ids": workload_identity_ids,
        "gateway_enabled": gateway_enabled,
        "developer_portal_status": _string_value(getattr(service, "developer_portal_status", None)),
        "legacy_portal_status": _string_value(getattr(service, "legacy_portal_status", None)),
        "api_count": api_count,
        "backend_count": backend_count,
        "named_value_count": named_value_count,
        "summary": _api_mgmt_operator_summary(
            service_name=service_name,
            gateway_hostnames=gateway_hostnames,
            management_hostnames=management_hostnames,
            portal_hostnames=portal_hostnames,
            public_network_access=_string_value(getattr(service, "public_network_access", None)),
            virtual_network_type=_string_value(getattr(service, "virtual_network_type", None)),
            sku_name=_string_value(getattr(sku, "name", None)),
            workload_identity_type=workload_identity_type,
            api_count=api_count,
            backend_count=backend_count,
            named_value_count=named_value_count,
            gateway_enabled=gateway_enabled,
            developer_portal_status=_string_value(
                getattr(service, "developer_portal_status", None)
            ),
        ),
        "related_ids": _dedupe_strings(
            [
                service_id,
                workload_principal_id,
                *workload_identity_ids,
                public_ip_address_id,
            ]
        ),
    }


def _function_app_summary(
    app: object,
    config: object | None,
    settings: dict[str, object] | None,
) -> dict:
    app_id = getattr(app, "id", "") or ""
    app_name = getattr(app, "name", "unknown")
    identity = getattr(app, "identity", None)
    public_network_access = _string_value(getattr(app, "public_network_access", None))
    runtime_stack = _app_service_runtime_stack(config)
    min_tls_version = _string_value(getattr(config, "min_tls_version", None))
    ftps_state = _string_value(getattr(config, "ftps_state", None))
    functions_extension_version = _string_value(
        getattr(config, "functions_extension_version", None)
    )
    always_on = getattr(config, "always_on", None)
    workload_identity_type = _string_value(getattr(identity, "type", None))
    workload_principal_id = _string_value(getattr(identity, "principal_id", None))
    workload_client_id = _string_value(getattr(identity, "client_id", None))
    workload_identity_ids = sorted(
        str(identity_id)
        for identity_id in (getattr(identity, "user_assigned_identities", None) or {}).keys()
    )
    settings_readable = settings is not None
    azure_webjobs_storage_value = settings.get("AzureWebJobsStorage") if settings_readable else None
    azure_webjobs_storage_value_type = (
        "missing"
        if settings_readable and "AzureWebJobsStorage" not in settings
        else (
            _env_var_value_type(azure_webjobs_storage_value)
            if settings_readable
            else None
        )
    )
    azure_webjobs_storage_reference_target = (
        _env_var_reference_target(azure_webjobs_storage_value)
        if azure_webjobs_storage_value_type == "keyvault-ref"
        else None
    )
    run_from_package = _run_from_package_signal(settings)
    key_vault_reference_count = (
        sum(_env_var_value_type(value) == "keyvault-ref" for value in settings.values())
        if settings_readable
        else None
    )

    return {
        "id": app_id or f"/unknown/{app_name}",
        "name": app_name,
        "resource_group": _resource_group_from_id(app_id),
        "location": _string_value(getattr(app, "location", None)),
        "state": _string_value(getattr(app, "state", None)),
        "default_hostname": _string_value(getattr(app, "default_host_name", None)),
        "app_service_plan_id": _string_value(getattr(app, "server_farm_id", None)),
        "public_network_access": public_network_access,
        "https_only": bool(getattr(app, "https_only", False)),
        "client_cert_enabled": bool(getattr(app, "client_cert_enabled", False)),
        "min_tls_version": min_tls_version,
        "ftps_state": ftps_state,
        "runtime_stack": runtime_stack,
        "functions_extension_version": functions_extension_version,
        "always_on": bool(always_on) if always_on is not None else None,
        "workload_identity_type": workload_identity_type,
        "workload_principal_id": workload_principal_id,
        "workload_client_id": workload_client_id,
        "workload_identity_ids": workload_identity_ids,
        "azure_webjobs_storage_value_type": azure_webjobs_storage_value_type,
        "azure_webjobs_storage_reference_target": azure_webjobs_storage_reference_target,
        "run_from_package": run_from_package,
        "key_vault_reference_count": key_vault_reference_count,
        "summary": _function_app_operator_summary(
            app_name=app_name,
            default_hostname=_string_value(getattr(app, "default_host_name", None)),
            public_network_access=public_network_access,
            https_only=bool(getattr(app, "https_only", False)),
            runtime_stack=runtime_stack,
            functions_extension_version=functions_extension_version,
            workload_identity_type=workload_identity_type,
            azure_webjobs_storage_value_type=azure_webjobs_storage_value_type,
            azure_webjobs_storage_reference_target=azure_webjobs_storage_reference_target,
            run_from_package=run_from_package,
            key_vault_reference_count=key_vault_reference_count,
            min_tls_version=min_tls_version,
            ftps_state=ftps_state,
            always_on=bool(always_on) if always_on is not None else None,
        ),
        "related_ids": _dedupe_strings(
            [
                app_id,
                workload_principal_id,
                *workload_identity_ids,
                _string_value(getattr(app, "server_farm_id", None)),
            ]
        ),
    }


def _env_var_summary(
    app: object,
    *,
    asset_kind: str,
    setting_name: str,
    setting_value: object,
) -> dict:
    app_id = getattr(app, "id", "") or ""
    app_name = getattr(app, "name", "unknown")
    identity = getattr(app, "identity", None)
    value_type = _env_var_value_type(setting_value)
    looks_sensitive = _looks_sensitive_setting_name(setting_name)
    reference_target = _env_var_reference_target(setting_value)
    workload_identity_type = _string_value(getattr(identity, "type", None))
    workload_principal_id = _string_value(getattr(identity, "principal_id", None))
    workload_client_id = _string_value(getattr(identity, "client_id", None))
    workload_identity_ids = sorted(
        str(identity_id)
        for identity_id in (getattr(identity, "user_assigned_identities", None) or {}).keys()
    )
    key_vault_reference_identity = _string_value(getattr(app, "key_vault_reference_identity", None))
    kv_identity_summary = _key_vault_reference_identity_summary(key_vault_reference_identity)

    if value_type == "keyvault-ref":
        summary = (
            f"{asset_kind} '{app_name}' maps setting '{setting_name}' to Key Vault-backed "
            f"configuration{f' ({reference_target})' if reference_target else ''}"
            f"{f' via {kv_identity_summary}' if kv_identity_summary else ''}."
        )
    elif looks_sensitive and value_type == "plain-text":
        summary = (
            f"{asset_kind} '{app_name}' stores sensitive-looking setting '{setting_name}' as "
            "plain-text app configuration."
        )
    else:
        summary = (
            f"{asset_kind} '{app_name}' exposes setting '{setting_name}' through management-plane "
            f"app settings ({value_type})."
        )

    return {
        "asset_id": app_id or f"/unknown/{app_name}",
        "asset_name": app_name,
        "asset_kind": asset_kind,
        "resource_group": _resource_group_from_id(app_id),
        "location": _string_value(getattr(app, "location", None)),
        "workload_identity_type": workload_identity_type,
        "workload_principal_id": workload_principal_id,
        "workload_client_id": workload_client_id,
        "workload_identity_ids": workload_identity_ids,
        "key_vault_reference_identity": key_vault_reference_identity,
        "setting_name": setting_name,
        "value_type": value_type,
        "looks_sensitive": looks_sensitive,
        "reference_target": reference_target,
        "summary": summary,
        "related_ids": [item for item in [app_id] if item],
    }


def _web_asset_kind(kind: object) -> str | None:
    value = str(kind or "").lower()
    if "workflowapp" in value:
        return None
    if "functionapp" in value:
        return "FunctionApp"
    if not value or "app" in value:
        return "AppService"
    return None


def _app_service_runtime_stack(config: object | None) -> str | None:
    if config is None:
        return None

    linux_fx_version = _string_value(getattr(config, "linux_fx_version", None))
    if linux_fx_version:
        return linux_fx_version

    windows_fx_version = _string_value(getattr(config, "windows_fx_version", None))
    if windows_fx_version:
        return windows_fx_version

    runtime_parts: list[str] = []
    for attr_name, label in (
        ("python_version", "python"),
        ("node_version", "node"),
        ("power_shell_version", "powershell"),
        ("java_version", "java"),
        ("php_version", "php"),
        ("net_framework_version", ".net"),
    ):
        value = _string_value(getattr(config, attr_name, None))
        if value:
            runtime_parts.append(f"{label}={value}")

    if runtime_parts:
        return "; ".join(runtime_parts)
    return None


def _app_service_operator_summary(
    *,
    app_name: str,
    default_hostname: str | None,
    public_network_access: str | None,
    https_only: bool,
    runtime_stack: str | None,
    workload_identity_type: str | None,
    min_tls_version: str | None,
    ftps_state: str | None,
) -> str:
    hostname_phrase = (
        f"publishes hostname '{default_hostname}'"
        if default_hostname
        else "has no default hostname visible from the current read path"
    )
    runtime_phrase = (
        f"runs runtime '{runtime_stack}'"
        if runtime_stack
        else "does not expose a readable runtime summary from the current read path"
    )
    identity_phrase = (
        f"uses managed identity ({workload_identity_type})"
        if workload_identity_type
        else "has no managed identity visible from the current read path"
    )

    posture_parts = [
        f"public network access {public_network_access or 'unknown'}",
        f"HTTPS-only {'enabled' if https_only else 'disabled'}",
    ]
    if min_tls_version:
        posture_parts.append(f"TLS {min_tls_version}")
    if ftps_state:
        posture_parts.append(f"FTPS {ftps_state}")

    return (
        f"App Service '{app_name}' {hostname_phrase}, {runtime_phrase}, and {identity_phrase}. "
        f"Visible posture: {', '.join(posture_parts)}."
    )


def _app_service_exposure_priority(item: dict) -> bool:
    return bool(item.get("default_hostname")) or (
        str(item.get("public_network_access") or "").lower() == "enabled"
    )


def _acr_registry_summary(registry: object) -> dict:
    registry_id = getattr(registry, "id", "") or ""
    registry_name = getattr(registry, "name", "unknown")
    identity = getattr(registry, "identity", None)
    sku = getattr(registry, "sku", None)
    network_rule_set = getattr(registry, "network_rule_set", None)
    private_endpoint_connections = getattr(registry, "private_endpoint_connections", None) or []
    workload_identity_ids = sorted(
        str(identity_id)
        for identity_id in (getattr(identity, "user_assigned_identities", None) or {}).keys()
    )
    workload_identity_type = _string_value(getattr(identity, "type", None))
    workload_principal_id = _string_value(getattr(identity, "principal_id", None))
    workload_client_id = _string_value(getattr(identity, "client_id", None))
    public_network_access = _string_value(getattr(registry, "public_network_access", None))
    network_rule_default_action = _string_value(
        getattr(network_rule_set, "default_action", None)
    )
    network_rule_bypass_options = _string_value(
        getattr(registry, "network_rule_bypass_options", None)
    )
    admin_user_enabled = getattr(registry, "admin_user_enabled", None)
    anonymous_pull_enabled = getattr(registry, "anonymous_pull_enabled", None)
    data_endpoint_enabled = getattr(registry, "data_endpoint_enabled", None)
    private_endpoint_connection_count = len(private_endpoint_connections)
    login_server = _string_value(getattr(registry, "login_server", None))
    sku_name = _string_value(getattr(sku, "name", None))

    return {
        "id": registry_id or f"/unknown/{registry_name}",
        "name": registry_name,
        "resource_group": _resource_group_from_id(registry_id),
        "location": _string_value(getattr(registry, "location", None)),
        "state": _string_value(getattr(registry, "provisioning_state", None)),
        "login_server": login_server,
        "sku_name": sku_name,
        "public_network_access": public_network_access,
        "network_rule_default_action": network_rule_default_action,
        "network_rule_bypass_options": network_rule_bypass_options,
        "admin_user_enabled": admin_user_enabled,
        "anonymous_pull_enabled": anonymous_pull_enabled,
        "data_endpoint_enabled": data_endpoint_enabled,
        "private_endpoint_connection_count": private_endpoint_connection_count,
        "workload_identity_type": workload_identity_type,
        "workload_principal_id": workload_principal_id,
        "workload_client_id": workload_client_id,
        "workload_identity_ids": workload_identity_ids,
        "summary": _acr_operator_summary(
            registry_name=registry_name,
            login_server=login_server,
            workload_identity_type=workload_identity_type,
            public_network_access=public_network_access,
            network_rule_default_action=network_rule_default_action,
            network_rule_bypass_options=network_rule_bypass_options,
            admin_user_enabled=admin_user_enabled,
            anonymous_pull_enabled=anonymous_pull_enabled,
            data_endpoint_enabled=data_endpoint_enabled,
            private_endpoint_connection_count=private_endpoint_connection_count,
            sku_name=sku_name,
        ),
        "related_ids": _dedupe_strings(
            [
                registry_id,
                workload_principal_id,
                *workload_identity_ids,
            ]
        ),
    }


def _acr_operator_summary(
    *,
    registry_name: str,
    login_server: str | None,
    workload_identity_type: str | None,
    public_network_access: str | None,
    network_rule_default_action: str | None,
    network_rule_bypass_options: str | None,
    admin_user_enabled: bool | None,
    anonymous_pull_enabled: bool | None,
    data_endpoint_enabled: bool | None,
    private_endpoint_connection_count: int,
    sku_name: str | None,
) -> str:
    login_phrase = (
        f"publishes login server '{login_server}'"
        if login_server
        else "does not expose a readable login server from the current read path"
    )
    identity_phrase = (
        f"uses managed identity ({workload_identity_type})"
        if workload_identity_type
        else "has no managed identity visible from the current read path"
    )

    auth_parts: list[str] = []
    if admin_user_enabled is True:
        auth_parts.append("admin user enabled")
    elif admin_user_enabled is False:
        auth_parts.append("admin user disabled")
    if anonymous_pull_enabled is True:
        auth_parts.append("anonymous pull enabled")
    elif anonymous_pull_enabled is False:
        auth_parts.append("anonymous pull disabled")

    network_parts = [f"public network access {public_network_access or 'unknown'}"]
    if network_rule_default_action:
        network_parts.append(f"default action {network_rule_default_action}")
    if network_rule_bypass_options:
        network_parts.append(f"bypass {network_rule_bypass_options}")
    if private_endpoint_connection_count > 0:
        network_parts.append(f"{private_endpoint_connection_count} private endpoint(s)")
    else:
        network_parts.append("no private endpoints visible")

    service_parts: list[str] = []
    if sku_name:
        service_parts.append(f"SKU {sku_name}")
    if data_endpoint_enabled is True:
        service_parts.append("data endpoint enabled")
    elif data_endpoint_enabled is False:
        service_parts.append("data endpoint disabled")

    auth_phrase = (
        f"Visible auth posture: {', '.join(auth_parts)}."
        if auth_parts
        else "Auth posture is not fully readable from the current read path."
    )
    service_phrase = (
        f"Visible service shape: {', '.join(service_parts)}."
        if service_parts
        else "Service shape is not fully readable from the current read path."
    )

    return (
        f"Container Registry '{registry_name}' {login_phrase} and {identity_phrase}. "
        f"{auth_phrase} Visible network posture: {', '.join(network_parts)}. "
        f"{service_phrase}"
    )


def _acr_exposure_priority(item: dict) -> bool:
    return (
        str(item.get("public_network_access") or "").lower() == "enabled"
        or item.get("admin_user_enabled") is True
        or item.get("anonymous_pull_enabled") is True
    )


def _database_server_summary(
    server: object,
    databases: list[object] | None,
) -> dict:
    server_id = getattr(server, "id", "") or ""
    server_name = getattr(server, "name", "unknown")
    identity = getattr(server, "identity", None)
    user_databases = _visible_user_databases(databases)
    user_database_names = sorted(
        str(getattr(database, "name", "") or "")
        for database in user_databases
        if getattr(database, "name", None)
    )
    workload_identity_ids = sorted(
        str(identity_id)
        for identity_id in (getattr(identity, "user_assigned_identities", None) or {}).keys()
    )
    workload_identity_type = _string_value(getattr(identity, "type", None))
    workload_principal_id = _string_value(getattr(identity, "principal_id", None))
    workload_client_id = _string_value(getattr(identity, "client_id", None))
    fully_qualified_domain_name = _string_value(
        getattr(server, "fully_qualified_domain_name", None)
    )
    public_network_access = _string_value(getattr(server, "public_network_access", None))
    minimal_tls_version = _string_value(getattr(server, "minimal_tls_version", None))
    server_version = _string_value(getattr(server, "version", None))
    database_count = len(user_databases) if databases is not None else None

    return {
        "id": server_id or f"/unknown/{server_name}",
        "name": server_name,
        "resource_group": _resource_group_from_id(server_id),
        "location": _string_value(getattr(server, "location", None)),
        "state": _string_value(getattr(server, "state", None)),
        "engine": "AzureSql",
        "fully_qualified_domain_name": fully_qualified_domain_name,
        "server_version": server_version,
        "public_network_access": public_network_access,
        "minimal_tls_version": minimal_tls_version,
        "database_count": database_count,
        "user_database_names": user_database_names,
        "workload_identity_type": workload_identity_type,
        "workload_principal_id": workload_principal_id,
        "workload_client_id": workload_client_id,
        "workload_identity_ids": workload_identity_ids,
        "summary": _database_server_operator_summary(
            server_name=server_name,
            fully_qualified_domain_name=fully_qualified_domain_name,
            workload_identity_type=workload_identity_type,
            public_network_access=public_network_access,
            minimal_tls_version=minimal_tls_version,
            server_version=server_version,
            database_count=database_count,
            user_database_names=user_database_names,
        ),
        "related_ids": _dedupe_strings(
            [
                server_id,
                workload_principal_id,
                *workload_identity_ids,
            ]
        ),
    }


def _database_server_operator_summary(
    *,
    server_name: str,
    fully_qualified_domain_name: str | None,
    workload_identity_type: str | None,
    public_network_access: str | None,
    minimal_tls_version: str | None,
    server_version: str | None,
    database_count: int | None,
    user_database_names: list[str],
) -> str:
    endpoint_phrase = (
        f"publishes endpoint '{fully_qualified_domain_name}'"
        if fully_qualified_domain_name
        else "does not expose a readable SQL endpoint from the current read path"
    )
    identity_phrase = (
        f"uses managed identity ({workload_identity_type})"
        if workload_identity_type
        else "has no managed identity visible from the current read path"
    )

    inventory_parts: list[str] = []
    if database_count is not None:
        inventory_parts.append(f"{database_count} user database(s)")
    if user_database_names:
        inventory_parts.append(f"names: {', '.join(user_database_names)}")

    posture_parts = [f"public network access {public_network_access or 'unknown'}"]
    if minimal_tls_version:
        posture_parts.append(f"minimal TLS {minimal_tls_version}")
    if server_version:
        posture_parts.append(f"server version {server_version}")

    inventory_phrase = (
        f"Visible inventory: {', '.join(inventory_parts)}."
        if inventory_parts
        else "Database inventory is not fully readable from the current read path."
    )

    return (
        f"Azure SQL server '{server_name}' {endpoint_phrase} and {identity_phrase}. "
        f"{inventory_phrase} Visible posture: {', '.join(posture_parts)}."
    )


def _dns_zone_summary(resource: object, *, zone_kind: str) -> dict:
    resource_id = getattr(resource, "id", "") or ""
    zone_name = getattr(resource, "name", "unknown")
    properties = getattr(resource, "properties", None)
    record_set_count = _int_value(
        _property_value(properties, "numberOfRecordSets", "number_of_record_sets")
    )
    max_record_set_count = _int_value(
        _property_value(properties, "maxNumberOfRecordSets", "max_number_of_record_sets")
    )
    name_servers = _dedupe_strings(
        [
            str(item)
            for item in (_property_value(properties, "nameServers", "name_servers") or [])
            if item
        ]
    )
    linked_virtual_network_count = _int_value(
        _property_value(
            properties,
            "numberOfVirtualNetworkLinks",
            "number_of_virtual_network_links",
        )
    )
    registration_virtual_network_count = _int_value(
        _property_value(
            properties,
            "numberOfVirtualNetworkLinksWithRegistration",
            "number_of_virtual_network_links_with_registration",
        )
    )

    return {
        "id": resource_id or f"/unknown/{zone_name}",
        "name": zone_name,
        "resource_group": _resource_group_from_id(resource_id),
        "location": _string_value(getattr(resource, "location", None)),
        "zone_kind": zone_kind,
        "record_set_count": record_set_count,
        "max_record_set_count": max_record_set_count,
        "name_servers": name_servers,
        "linked_virtual_network_count": linked_virtual_network_count,
        "registration_virtual_network_count": registration_virtual_network_count,
        "summary": _dns_zone_operator_summary(
            zone_name=zone_name,
            zone_kind=zone_kind,
            record_set_count=record_set_count,
            name_server_count=len(name_servers),
            linked_virtual_network_count=linked_virtual_network_count,
            registration_virtual_network_count=registration_virtual_network_count,
        ),
        "related_ids": [resource_id] if resource_id else [],
    }


def _dns_zone_operator_summary(
    *,
    zone_name: str,
    zone_kind: str,
    record_set_count: int | None,
    name_server_count: int,
    linked_virtual_network_count: int | None,
    registration_virtual_network_count: int | None,
) -> str:
    inventory_phrase = (
        f"shows {record_set_count} visible record set(s)"
        if record_set_count is not None
        else "does not expose a readable record-set total from the current read path"
    )

    if zone_kind == "public":
        namespace_phrase = (
            f"delegates authority through {name_server_count} visible Azure name server(s)"
            if name_server_count
            else "does not expose readable name server delegation details"
        )
        return f"Public DNS zone '{zone_name}' {inventory_phrase} and {namespace_phrase}."

    link_parts: list[str] = []
    if linked_virtual_network_count is not None:
        link_parts.append(f"{linked_virtual_network_count} virtual network link(s)")
    if registration_virtual_network_count is not None:
        link_parts.append(
            f"{registration_virtual_network_count} registration-enabled link(s)"
        )

    namespace_phrase = (
        f"tracks {', '.join(link_parts)}"
        if link_parts
        else "does not expose readable virtual network link counts"
    )
    return f"Private DNS zone '{zone_name}' {inventory_phrase} and {namespace_phrase}."


def _visible_user_databases(databases: list[object] | None) -> list[object]:
    if databases is None:
        return []

    visible: list[object] = []
    for database in databases:
        database_name = str(getattr(database, "name", "") or "").lower()
        if database_name == "master":
            continue
        visible.append(database)
    return visible


def _database_exposure_priority(item: dict) -> bool:
    return bool(item.get("fully_qualified_domain_name")) or (
        str(item.get("public_network_access") or "").lower() == "enabled"
    )


def _aks_cluster_summary(cluster: object) -> dict:
    cluster_id = getattr(cluster, "id", "") or ""
    cluster_name = getattr(cluster, "name", "unknown")
    identity = getattr(cluster, "identity", None)
    service_principal_profile = getattr(cluster, "service_principal_profile", None)
    aad_profile = getattr(cluster, "aad_profile", None)
    api_server_access_profile = getattr(cluster, "api_server_access_profile", None)
    network_profile = getattr(cluster, "network_profile", None)
    sku = getattr(cluster, "sku", None)
    agent_pool_profiles = getattr(cluster, "agent_pool_profiles", None) or []

    cluster_identity_ids = sorted(
        str(identity_id)
        for identity_id in (getattr(identity, "user_assigned_identities", None) or {}).keys()
    )
    cluster_identity_type = _string_value(getattr(identity, "type", None))
    cluster_principal_id = _string_value(getattr(identity, "principal_id", None))
    cluster_client_id = _string_value(getattr(identity, "client_id", None))
    if not cluster_identity_type:
        service_principal_client_id = _string_value(
            getattr(service_principal_profile, "client_id", None)
        )
        if service_principal_client_id:
            cluster_identity_type = "ServicePrincipal"
            cluster_client_id = service_principal_client_id
    private_cluster_enabled = getattr(api_server_access_profile, "enable_private_cluster", None)
    public_fqdn_enabled = getattr(
        api_server_access_profile,
        "enable_private_cluster_public_fqdn",
        None,
    )
    aad_managed = getattr(aad_profile, "managed", None)
    azure_rbac_enabled = getattr(aad_profile, "enable_azure_rbac", None)
    local_accounts_disabled = getattr(cluster, "disable_local_accounts", None)
    agent_pool_count = len(agent_pool_profiles)

    return {
        "id": cluster_id or f"/unknown/{cluster_name}",
        "name": cluster_name,
        "resource_group": _resource_group_from_id(cluster_id),
        "location": _string_value(getattr(cluster, "location", None)),
        "provisioning_state": _string_value(getattr(cluster, "provisioning_state", None)),
        "kubernetes_version": _string_value(getattr(cluster, "kubernetes_version", None)),
        "sku_tier": _string_value(getattr(sku, "tier", None)),
        "node_resource_group": _string_value(getattr(cluster, "node_resource_group", None)),
        "fqdn": _string_value(getattr(cluster, "fqdn", None)),
        "private_fqdn": _string_value(getattr(cluster, "private_fqdn", None)),
        "private_cluster_enabled": private_cluster_enabled,
        "public_fqdn_enabled": public_fqdn_enabled,
        "cluster_identity_type": cluster_identity_type,
        "cluster_principal_id": cluster_principal_id,
        "cluster_client_id": cluster_client_id,
        "cluster_identity_ids": cluster_identity_ids,
        "aad_managed": aad_managed,
        "azure_rbac_enabled": azure_rbac_enabled,
        "local_accounts_disabled": local_accounts_disabled,
        "network_plugin": _string_value(getattr(network_profile, "network_plugin", None)),
        "network_policy": _string_value(getattr(network_profile, "network_policy", None)),
        "outbound_type": _string_value(getattr(network_profile, "outbound_type", None)),
        "agent_pool_count": agent_pool_count,
        "summary": _aks_operator_summary(
            cluster_name=cluster_name,
            kubernetes_version=_string_value(getattr(cluster, "kubernetes_version", None)),
            fqdn=_string_value(getattr(cluster, "fqdn", None)),
            private_fqdn=_string_value(getattr(cluster, "private_fqdn", None)),
            private_cluster_enabled=private_cluster_enabled,
            public_fqdn_enabled=public_fqdn_enabled,
            cluster_identity_type=cluster_identity_type,
            cluster_client_id=cluster_client_id,
            aad_managed=aad_managed,
            azure_rbac_enabled=azure_rbac_enabled,
            local_accounts_disabled=local_accounts_disabled,
            network_plugin=_string_value(getattr(network_profile, "network_plugin", None)),
            network_policy=_string_value(getattr(network_profile, "network_policy", None)),
            outbound_type=_string_value(getattr(network_profile, "outbound_type", None)),
            agent_pool_count=agent_pool_count,
        ),
        "related_ids": _dedupe_strings(
            [cluster_id, cluster_principal_id, *cluster_identity_ids]
        ),
    }


def _aks_operator_summary(
    *,
    cluster_name: str,
    kubernetes_version: str | None,
    fqdn: str | None,
    private_fqdn: str | None,
    private_cluster_enabled: bool | None,
    public_fqdn_enabled: bool | None,
    cluster_identity_type: str | None,
    cluster_client_id: str | None,
    aad_managed: bool | None,
    azure_rbac_enabled: bool | None,
    local_accounts_disabled: bool | None,
    network_plugin: str | None,
    network_policy: str | None,
    outbound_type: str | None,
    agent_pool_count: int | None,
) -> str:
    if private_cluster_enabled is True and private_fqdn and public_fqdn_enabled and fqdn:
        endpoint_phrase = (
            f"uses private API endpoint '{private_fqdn}' and keeps public FQDN '{fqdn}' enabled"
        )
    elif private_cluster_enabled is True and private_fqdn:
        endpoint_phrase = f"uses private API endpoint '{private_fqdn}'"
    elif fqdn:
        endpoint_phrase = f"publishes API endpoint '{fqdn}'"
    else:
        endpoint_phrase = "does not expose a readable API endpoint from the current read path"

    if cluster_identity_type == "ServicePrincipal":
        if cluster_client_id:
            identity_phrase = f"uses service principal client '{cluster_client_id}'"
        else:
            identity_phrase = "uses service principal-backed cluster credentials"
    elif cluster_identity_type:
        identity_phrase = f"uses cluster identity ({cluster_identity_type})"
    else:
        identity_phrase = "has no cluster identity context visible from the current read path"

    auth_parts: list[str] = []
    if aad_managed is True:
        auth_parts.append("AAD-managed auth")
    elif aad_managed is False:
        auth_parts.append("AAD profile not managed")
    if azure_rbac_enabled is True:
        auth_parts.append("Azure RBAC enabled")
    elif azure_rbac_enabled is False:
        auth_parts.append("Azure RBAC disabled")
    if local_accounts_disabled is True:
        auth_parts.append("local accounts disabled")
    elif local_accounts_disabled is False:
        auth_parts.append("local accounts enabled")

    network_parts: list[str] = []
    if private_cluster_enabled is True:
        network_parts.append("private cluster enabled")
    elif private_cluster_enabled is False:
        network_parts.append("private cluster disabled")
    if network_plugin:
        network_parts.append(f"network plugin {network_plugin}")
    if network_policy:
        network_parts.append(f"network policy {network_policy}")
    if outbound_type:
        network_parts.append(f"outbound {outbound_type}")

    inventory_parts: list[str] = []
    if kubernetes_version:
        inventory_parts.append(f"Kubernetes {kubernetes_version}")
    if agent_pool_count is not None:
        inventory_parts.append(f"{agent_pool_count} agent pool(s)")

    auth_phrase = (
        f"Visible auth posture: {', '.join(auth_parts)}."
        if auth_parts
        else "Auth posture is not fully readable from the current read path."
    )
    network_phrase = (
        f"Visible network shape: {', '.join(network_parts)}."
        if network_parts
        else "Network shape is not fully readable from the current read path."
    )
    inventory_phrase = (
        f"Visible inventory: {', '.join(inventory_parts)}."
        if inventory_parts
        else "Cluster version and pool counts are not fully readable from the current read path."
    )

    return (
        f"AKS cluster '{cluster_name}' {endpoint_phrase} and {identity_phrase}. "
        f"{inventory_phrase} {auth_phrase} {network_phrase}"
    )


def _aks_exposure_priority(item: dict) -> bool:
    return bool(item.get("fqdn")) and item.get("private_cluster_enabled") is not True


def _api_mgmt_operator_summary(
    *,
    service_name: str,
    gateway_hostnames: list[str],
    management_hostnames: list[str],
    portal_hostnames: list[str],
    public_network_access: str | None,
    virtual_network_type: str | None,
    sku_name: str | None,
    workload_identity_type: str | None,
    api_count: int | None,
    backend_count: int | None,
    named_value_count: int | None,
    gateway_enabled: bool | None,
    developer_portal_status: str | None,
) -> str:
    host_parts: list[str] = []
    if gateway_hostnames:
        host_parts.append(f"gateway hostnames {', '.join(gateway_hostnames)}")
    if management_hostnames:
        host_parts.append(f"management hostnames {', '.join(management_hostnames)}")
    if portal_hostnames:
        host_parts.append(f"portal hostnames {', '.join(portal_hostnames)}")
    host_phrase = (
        f"publishes {'; '.join(host_parts)}"
        if host_parts
        else "does not expose readable gateway or portal hostnames from the current read path"
    )

    inventory_parts: list[str] = []
    if api_count is not None:
        inventory_parts.append(f"{api_count} APIs")
    if backend_count is not None:
        inventory_parts.append(f"{backend_count} backends")
    if named_value_count is not None:
        inventory_parts.append(f"{named_value_count} named values")
    inventory_phrase = (
        f"Visible inventory: {', '.join(inventory_parts)}."
        if inventory_parts
        else "Inventory counts are not fully readable from the current read path."
    )

    posture_parts = [
        f"public network access {public_network_access or 'unknown'}",
        f"virtual network type {virtual_network_type or 'none'}",
    ]
    if sku_name:
        posture_parts.append(f"SKU {sku_name}")
    if gateway_enabled is not None:
        posture_parts.append(f"gateway {'enabled' if gateway_enabled else 'disabled'}")
    if developer_portal_status:
        posture_parts.append(f"developer portal {developer_portal_status}")

    identity_phrase = (
        f"uses managed identity ({workload_identity_type})"
        if workload_identity_type
        else "has no managed identity visible from the current read path"
    )

    return (
        f"API Management service '{service_name}' {host_phrase} and {identity_phrase}. "
        f"{inventory_phrase} Visible posture: {', '.join(posture_parts)}."
    )


def _api_mgmt_hostnames(
    service: object,
    hostname_configurations: list[object],
) -> tuple[list[str], list[str], list[str]]:
    gateway = _dedupe_strings(
        [
            *[
                _string_value(getattr(item, "host_name", None))
                for item in hostname_configurations
                if str(getattr(item, "type", "")).lower() == "proxy"
            ],
            _hostname_from_url(_string_value(getattr(service, "gateway_url", None))),
        ]
    )
    management = _dedupe_strings(
        [
            *[
                _string_value(getattr(item, "host_name", None))
                for item in hostname_configurations
                if str(getattr(item, "type", "")).lower() == "management"
            ],
            _hostname_from_url(_string_value(getattr(service, "management_api_url", None))),
        ]
    )
    portal = _dedupe_strings(
        [
            *[
                _string_value(getattr(item, "host_name", None))
                for item in hostname_configurations
                if str(getattr(item, "type", "")).lower() in {"portal", "developerportal"}
            ],
            _hostname_from_url(_string_value(getattr(service, "portal_url", None))),
            _hostname_from_url(_string_value(getattr(service, "developer_portal_url", None))),
        ]
    )
    return gateway, management, portal


def _hostname_from_url(value: str | None) -> str | None:
    if not value:
        return None
    parsed = urlparse(value)
    if parsed.hostname:
        return parsed.hostname
    return value


def _api_mgmt_exposure_priority(item: dict) -> bool:
    return bool(item.get("gateway_hostnames")) or (
        str(item.get("public_network_access") or "").lower() == "enabled"
    )


def _function_app_operator_summary(
    *,
    app_name: str,
    default_hostname: str | None,
    public_network_access: str | None,
    https_only: bool,
    runtime_stack: str | None,
    functions_extension_version: str | None,
    workload_identity_type: str | None,
    azure_webjobs_storage_value_type: str | None,
    azure_webjobs_storage_reference_target: str | None,
    run_from_package: bool | None,
    key_vault_reference_count: int | None,
    min_tls_version: str | None,
    ftps_state: str | None,
    always_on: bool | None,
) -> str:
    hostname_phrase = (
        f"publishes hostname '{default_hostname}'"
        if default_hostname
        else "has no default hostname visible from the current read path"
    )
    runtime_phrase = (
        f"runs runtime '{runtime_stack}'"
        if runtime_stack
        else "does not expose a readable runtime summary from the current read path"
    )
    functions_phrase = (
        f"targets Functions runtime '{functions_extension_version}'"
        if functions_extension_version
        else "does not expose a readable Functions runtime version from the current read path"
    )
    identity_phrase = (
        f"uses managed identity ({workload_identity_type})"
        if workload_identity_type
        else "has no managed identity visible from the current read path"
    )

    deployment_parts: list[str] = []
    if azure_webjobs_storage_value_type == "keyvault-ref":
        target = (
            f" ({azure_webjobs_storage_reference_target})"
            if azure_webjobs_storage_reference_target
            else ""
        )
        deployment_parts.append(f"AzureWebJobsStorage via Key Vault reference{target}")
    elif azure_webjobs_storage_value_type == "plain-text":
        deployment_parts.append("AzureWebJobsStorage as plain-text app setting")
    elif azure_webjobs_storage_value_type == "empty":
        deployment_parts.append("AzureWebJobsStorage visible but empty")
    elif azure_webjobs_storage_value_type == "missing":
        deployment_parts.append("no AzureWebJobsStorage setting visible")

    if run_from_package is True:
        deployment_parts.append("run-from-package enabled")
    elif run_from_package is False:
        deployment_parts.append("run-from-package disabled")

    if key_vault_reference_count is not None:
        deployment_parts.append(f"{key_vault_reference_count} Key Vault-backed setting(s)")

    posture_parts = [
        f"public network access {public_network_access or 'unknown'}",
        f"HTTPS-only {'enabled' if https_only else 'disabled'}",
    ]
    if min_tls_version:
        posture_parts.append(f"TLS {min_tls_version}")
    if ftps_state:
        posture_parts.append(f"FTPS {ftps_state}")
    if always_on is not None:
        posture_parts.append(f"Always On {'enabled' if always_on else 'disabled'}")

    deployment_phrase = (
        f"Deployment signals: {', '.join(deployment_parts)}."
        if deployment_parts
        else "Deployment signals are not readable from the current read path."
    )

    return (
        f"Function App '{app_name}' {hostname_phrase}, {runtime_phrase}, {functions_phrase}, "
        f"and {identity_phrase}. {deployment_phrase} Visible posture: "
        f"{', '.join(posture_parts)}."
    )


def _function_app_exposure_priority(item: dict) -> bool:
    return bool(item.get("default_hostname")) or (
        str(item.get("public_network_access") or "").lower() == "enabled"
    )


def _run_from_package_signal(settings: dict[str, object] | None) -> bool | None:
    if settings is None or "WEBSITE_RUN_FROM_PACKAGE" not in settings:
        return None

    value = _string_value(settings.get("WEBSITE_RUN_FROM_PACKAGE"))
    if value is None:
        return None

    normalized = value.strip().lower()
    if not normalized:
        return None
    if normalized in {"0", "false", "no", "off", "disabled"}:
        return False
    return True


def _env_var_value_type(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return "empty"
    if text.startswith("@Microsoft.KeyVault("):
        return "keyvault-ref"
    return "plain-text"


def _looks_sensitive_setting_name(setting_name: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "", setting_name.lower())
    return any(token in normalized for token in _ENV_VAR_SENSITIVE_TOKENS)


def _token_credential_surfaces_from_web_workloads(workloads: list[dict]) -> list[dict]:
    surfaces: list[dict] = []

    for item in workloads:
        asset_id = item.get("asset_id")
        asset_name = item.get("asset_name") or asset_id or "unknown"
        asset_kind = item.get("asset_kind") or "Workload"
        related_ids = [
            *([asset_id] if asset_id else []),
            *[str(identity_id) for identity_id in item.get("workload_identity_ids", [])],
        ]
        if item.get("workload_principal_id"):
            related_ids.append(str(item.get("workload_principal_id")))

        if not item.get("workload_identity_type"):
            continue

        identity_signal = str(item.get("workload_identity_type"))
        user_assigned_count = len(item.get("workload_identity_ids", []))
        if user_assigned_count:
            identity_signal = f"{identity_signal}; user-assigned={user_assigned_count}"

        surfaces.append(
            {
                "asset_id": asset_id or f"/unknown/{asset_name}",
                "asset_name": asset_name,
                "asset_kind": asset_kind,
                "resource_group": item.get("resource_group"),
                "location": item.get("location"),
                "surface_type": "managed-identity-token",
                "access_path": "workload-identity",
                "priority": "medium",
                "operator_signal": identity_signal,
                "summary": (
                    f"{asset_kind} '{asset_name}' can request tokens through attached "
                    f"managed identity ({item.get('workload_identity_type')})."
                ),
                "related_ids": _dedupe_strings(related_ids),
            }
        )

    return surfaces


def _endpoints_from_vms(vm_assets: list[dict]) -> list[dict]:
    endpoints: list[dict] = []

    for item in vm_assets:
        asset_id = item.get("id")
        asset_name = item.get("name") or asset_id or "unknown"

        for public_ip in [str(value) for value in item.get("public_ips", []) if value]:
            endpoints.append(
                {
                    "endpoint": public_ip,
                    "endpoint_type": "ip",
                    "source_asset_id": asset_id or f"/unknown/{asset_name}",
                    "source_asset_name": asset_name,
                    "source_asset_kind": str(item.get("vm_type") or "vm").upper(),
                    "exposure_family": "public-ip",
                    "ingress_path": "direct-vm-ip",
                    "summary": (
                        f"{str(item.get('vm_type') or 'vm').upper()} '{asset_name}' exposes "
                        f"public IP {public_ip}. Review direct ingress path alongside NIC and "
                        "NSG context."
                    ),
                    "related_ids": _dedupe_strings(
                        [asset_id, *item.get("nic_ids", []), *item.get("identity_ids", [])]
                    ),
                }
            )

    return endpoints


def _endpoints_from_web_workloads(workloads: list[dict]) -> list[dict]:
    endpoints: list[dict] = []

    for item in workloads:
        default_hostname = str(item.get("default_hostname") or "")
        if not default_hostname:
            continue

        asset_id = item.get("asset_id")
        asset_name = item.get("asset_name") or asset_id or "unknown"
        asset_kind = item.get("asset_kind") or "WebWorkload"
        ingress_path = (
            "azure-functions-default-hostname"
            if asset_kind == "FunctionApp"
            else "azurewebsites-default-hostname"
        )

        endpoints.append(
            {
                "endpoint": default_hostname,
                "endpoint_type": "hostname",
                "source_asset_id": asset_id or f"/unknown/{asset_name}",
                "source_asset_name": asset_name,
                "source_asset_kind": asset_kind,
                "exposure_family": "managed-web-hostname",
                "ingress_path": ingress_path,
                "summary": (
                    f"{asset_kind} '{asset_name}' publishes Azure-managed hostname "
                    f"'{default_hostname}'. Validate whether that ingress path is intended and "
                    "how it is constrained."
                ),
                "related_ids": _dedupe_strings(
                    [
                        asset_id,
                        item.get("workload_principal_id"),
                        *item.get("workload_identity_ids", []),
                    ]
                ),
            }
        )

    return endpoints


def _endpoints_by_asset(endpoints: list[dict]) -> dict[str, list[dict]]:
    endpoints_by_asset: dict[str, list[dict]] = {}
    for endpoint in endpoints:
        source_asset_id = endpoint.get("source_asset_id")
        if not source_asset_id:
            continue
        endpoints_by_asset.setdefault(str(source_asset_id), []).append(endpoint)
    return endpoints_by_asset


def _workload_rows_from_vms(
    vm_assets: list[dict],
    endpoints_by_asset: dict[str, list[dict]],
) -> list[dict]:
    workloads: list[dict] = []

    for item in vm_assets:
        asset_id = item.get("id")
        asset_name = item.get("name") or asset_id or "unknown"
        normalized_asset_id = str(asset_id or f"/unknown/{asset_name}")
        asset_endpoints = endpoints_by_asset.get(normalized_asset_id, [])
        identity_ids = _dedupe_strings(item.get("identity_ids", []))
        identity_type = _vm_identity_type(identity_ids)
        endpoints = _dedupe_strings([endpoint.get("endpoint") for endpoint in asset_endpoints])
        ingress_paths = _dedupe_strings(
            [endpoint.get("ingress_path") for endpoint in asset_endpoints]
        )
        exposure_families = _dedupe_strings(
            [endpoint.get("exposure_family") for endpoint in asset_endpoints]
        )

        network_signals: list[str] = []
        if item.get("public_ips"):
            network_signals.append(f"public-ip={len(item.get('public_ips', []))}")
        if item.get("private_ips"):
            network_signals.append(f"private-ip={len(item.get('private_ips', []))}")
        if item.get("nic_ids"):
            network_signals.append(f"nic={len(item.get('nic_ids', []))}")

        workloads.append(
            {
                "asset_id": normalized_asset_id,
                "asset_name": asset_name,
                "asset_kind": str(item.get("vm_type") or "vm").upper(),
                "resource_group": item.get("resource_group"),
                "location": item.get("location"),
                "identity_type": identity_type,
                "identity_principal_id": None,
                "identity_client_id": None,
                "identity_ids": identity_ids,
                "endpoints": endpoints,
                "ingress_paths": ingress_paths,
                "exposure_families": exposure_families,
                "summary": _workload_summary_text(
                    asset_kind=str(item.get("vm_type") or "vm").upper(),
                    asset_name=asset_name,
                    endpoints=endpoints,
                    exposure_families=exposure_families,
                    identity_type=identity_type,
                    network_signals=network_signals,
                ),
                "related_ids": _dedupe_strings([asset_id, *identity_ids, *item.get("nic_ids", [])]),
            }
        )

    return workloads


def _workload_rows_from_web_workloads(
    workloads_raw: list[dict],
    endpoints_by_asset: dict[str, list[dict]],
) -> list[dict]:
    workloads: list[dict] = []

    for item in workloads_raw:
        asset_id = item.get("asset_id")
        asset_name = item.get("asset_name") or asset_id or "unknown"
        normalized_asset_id = str(asset_id or f"/unknown/{asset_name}")
        asset_kind = str(item.get("asset_kind") or "WebWorkload")
        identity_ids = _dedupe_strings(item.get("workload_identity_ids", []))
        identity_type = item.get("workload_identity_type")
        asset_endpoints = endpoints_by_asset.get(normalized_asset_id, [])
        endpoints = _dedupe_strings([endpoint.get("endpoint") for endpoint in asset_endpoints])
        ingress_paths = _dedupe_strings(
            [endpoint.get("ingress_path") for endpoint in asset_endpoints]
        )
        exposure_families = _dedupe_strings(
            [endpoint.get("exposure_family") for endpoint in asset_endpoints]
        )

        network_signals: list[str] = []
        if item.get("default_hostname"):
            network_signals.append("default-hostname")
        if identity_ids:
            network_signals.append(f"user-assigned={len(identity_ids)}")

        workloads.append(
            {
                "asset_id": normalized_asset_id,
                "asset_name": asset_name,
                "asset_kind": asset_kind,
                "resource_group": item.get("resource_group"),
                "location": item.get("location"),
                "identity_type": identity_type,
                "identity_principal_id": item.get("workload_principal_id"),
                "identity_client_id": item.get("workload_client_id"),
                "identity_ids": identity_ids,
                "endpoints": endpoints,
                "ingress_paths": ingress_paths,
                "exposure_families": exposure_families,
                "summary": _workload_summary_text(
                    asset_kind=asset_kind,
                    asset_name=asset_name,
                    endpoints=endpoints,
                    exposure_families=exposure_families,
                    identity_type=identity_type,
                    network_signals=network_signals,
                ),
                "related_ids": _dedupe_strings(
                    [
                        asset_id,
                        item.get("workload_principal_id"),
                        *identity_ids,
                    ]
                ),
            }
        )

    return workloads


def _vm_identity_type(identity_ids: list[str]) -> str | None:
    has_system = any(
        str(identity_id).endswith("/identities/system") for identity_id in identity_ids
    )
    has_user = any(
        not str(identity_id).endswith("/identities/system") for identity_id in identity_ids
    )
    if has_system and has_user:
        return "SystemAssigned, UserAssigned"
    if has_system:
        return "SystemAssigned"
    if has_user:
        return "UserAssigned"
    return None


def _workload_summary_text(
    *,
    asset_kind: str,
    asset_name: str,
    endpoints: list[str],
    exposure_families: list[str],
    identity_type: object,
    network_signals: list[str],
) -> str:
    if endpoints:
        if exposure_families and all(family == "public-ip" for family in exposure_families):
            endpoint_phrase = (
                f"exposes reachable endpoint '{endpoints[0]}'"
                if len(endpoints) == 1
                else f"exposes {len(endpoints)} reachable endpoints ({', '.join(endpoints)})"
            )
        else:
            endpoint_phrase = (
                f"publishes visible endpoint hostname '{endpoints[0]}'"
                if len(endpoints) == 1
                else f"publishes {len(endpoints)} visible endpoint paths ({', '.join(endpoints)})"
            )
    else:
        endpoint_phrase = "has no visible endpoint path from the current read path"

    if identity_type:
        identity_phrase = f"carries managed identity context ({identity_type})"
    else:
        identity_phrase = "has no managed identity context visible from the current read path"

    signal_phrase = ""
    if network_signals:
        signal_phrase = f" Visible signals: {', '.join(network_signals)}."

    return (
        f"{asset_kind} '{asset_name}' {endpoint_phrase} and {identity_phrase}."
        f"{signal_phrase} Use this as a quick workload census pivot before deeper "
        "service-specific review."
    )


def _workload_sort_key(item: dict) -> tuple[bool, bool, int, str]:
    kind_order = {"VM": 0, "AppService": 1, "FunctionApp": 2, "VMSS": 3}
    return (
        not bool(item.get("endpoints")),
        not bool(item.get("identity_type")),
        kind_order.get(str(item.get("asset_kind") or ""), 9),
        str(item.get("asset_name") or ""),
    )


def _tokens_credentials_surfaces_from_env_vars(env_vars: list[dict]) -> list[dict]:
    surfaces: list[dict] = []

    for item in env_vars:
        asset_id = item.get("asset_id")
        asset_name = item.get("asset_name") or asset_id or "unknown"
        asset_kind = item.get("asset_kind") or "Workload"
        related_ids = [
            *([asset_id] if asset_id else []),
            *[str(identity_id) for identity_id in item.get("workload_identity_ids", [])],
        ]
        if item.get("workload_principal_id"):
            related_ids.append(str(item.get("workload_principal_id")))

        setting_name = str(item.get("setting_name") or "")
        normalized_setting_name = re.sub(r"[^a-z0-9]+", "", setting_name.lower())
        plain_text_credential = item.get("value_type") == "plain-text" and (
            item.get("looks_sensitive")
            or normalized_setting_name in _TOKENS_CREDENTIALS_PLAIN_TEXT_NAMES
        )
        if plain_text_credential:
            surfaces.append(
                {
                    "asset_id": asset_id or f"/unknown/{asset_name}",
                    "asset_name": asset_name,
                    "asset_kind": asset_kind,
                    "resource_group": item.get("resource_group"),
                    "location": item.get("location"),
                    "surface_type": "plain-text-secret",
                    "access_path": "app-setting",
                    "priority": "high",
                    "operator_signal": f"setting={setting_name}",
                    "summary": (
                        f"{asset_kind} '{asset_name}' exposes credential-like setting "
                        f"'{setting_name}' as plain-text management-plane app configuration."
                    ),
                    "related_ids": _dedupe_strings(related_ids),
                }
            )

        if item.get("value_type") == "keyvault-ref":
            signal_parts = [f"target={item.get('reference_target') or 'unknown'}"]
            kv_identity = _key_vault_reference_identity_summary(
                item.get("key_vault_reference_identity")
            )
            if kv_identity:
                signal_parts.append(f"identity={kv_identity}")
            target_suffix = (
                f" ({item.get('reference_target')})" if item.get("reference_target") else ""
            )
            identity_suffix = f" via {kv_identity}" if kv_identity else ""

            surfaces.append(
                {
                    "asset_id": asset_id or f"/unknown/{asset_name}",
                    "asset_name": asset_name,
                    "asset_kind": asset_kind,
                    "resource_group": item.get("resource_group"),
                    "location": item.get("location"),
                    "surface_type": "keyvault-reference",
                    "access_path": "app-setting",
                    "priority": "medium",
                    "operator_signal": "; ".join(signal_parts),
                    "summary": (
                        f"{asset_kind} '{asset_name}' uses setting '{setting_name}' to reach "
                        f"Key Vault-backed secret material{target_suffix}{identity_suffix}."
                    ),
                    "related_ids": _dedupe_strings(related_ids),
                }
            )

    return surfaces


def _token_credential_surfaces_from_arm_deployments(deployments: list[dict]) -> list[dict]:
    surfaces: list[dict] = []

    for item in deployments:
        deployment_id = item.get("id")
        deployment_name = item.get("name") or deployment_id or "unknown"
        related_ids = [str(deployment_id)] if deployment_id else []

        if (item.get("outputs_count") or 0) > 0:
            surfaces.append(
                {
                    "asset_id": deployment_id or f"/unknown/{deployment_name}",
                    "asset_name": deployment_name,
                    "asset_kind": "ArmDeployment",
                    "resource_group": item.get("resource_group"),
                    "location": None,
                    "surface_type": "deployment-output",
                    "access_path": "deployment-history",
                    "priority": "medium",
                    "operator_signal": (
                        f"outputs={item.get('outputs_count', 0)}; "
                        f"providers={len(item.get('providers', []))}"
                    ),
                    "summary": (
                        f"Deployment '{deployment_name}' recorded {item.get('outputs_count', 0)} "
                        "output values in deployment history."
                    ),
                    "related_ids": related_ids,
                }
            )

        if item.get("template_link") or item.get("parameters_link"):
            link_parts: list[str] = []
            if item.get("template_link"):
                link_parts.append(f"template={_compact_link(item.get('template_link'))}")
            if item.get("parameters_link"):
                link_parts.append(f"parameters={_compact_link(item.get('parameters_link'))}")

            surfaces.append(
                {
                    "asset_id": deployment_id or f"/unknown/{deployment_name}",
                    "asset_name": deployment_name,
                    "asset_kind": "ArmDeployment",
                    "resource_group": item.get("resource_group"),
                    "location": None,
                    "surface_type": "linked-deployment-content",
                    "access_path": "deployment-history",
                    "priority": "low",
                    "operator_signal": "; ".join(link_parts),
                    "summary": (
                        f"Deployment '{deployment_name}' references remote template or parameter "
                        "content that may expose reusable configuration or credential context."
                    ),
                    "related_ids": related_ids,
                }
            )

    return surfaces


def _token_credential_surfaces_from_vms(vm_assets: list[dict]) -> list[dict]:
    surfaces: list[dict] = []

    for item in vm_assets:
        identity_ids = [str(identity_id) for identity_id in item.get("identity_ids", [])]
        if not identity_ids:
            continue

        asset_id = item.get("id")
        asset_name = item.get("name") or asset_id or "unknown"
        public_ips = [str(ip) for ip in item.get("public_ips", [])]
        public_signal = f"public-ip={public_ips[0]}" if public_ips else "public-ip=none"
        priority = "high" if public_ips else "medium"

        surfaces.append(
            {
                "asset_id": asset_id or f"/unknown/{asset_name}",
                "asset_name": asset_name,
                "asset_kind": str(item.get("vm_type") or "vm").upper(),
                "resource_group": item.get("resource_group"),
                "location": item.get("location"),
                "surface_type": "managed-identity-token",
                "access_path": "imds",
                "priority": priority,
                "operator_signal": f"{public_signal}; identities={len(identity_ids)}",
                "summary": (
                    f"{str(item.get('vm_type') or 'vm').upper()} '{asset_name}' is publicly "
                    "reachable and exposes a token minting path through IMDS for its attached "
                    "managed identity."
                    if public_ips
                    else f"{str(item.get('vm_type') or 'vm').upper()} '{asset_name}' exposes a "
                    "token minting path through IMDS for its attached managed identity."
                ),
                "related_ids": _dedupe_strings([*([asset_id] if asset_id else []), *identity_ids]),
            }
        )

    return surfaces


def _compose_resource_trusts(storage_assets: list[dict], key_vaults: list[dict]) -> list[dict]:
    resource_trusts = [
        *_resource_trusts_from_storage(storage_assets),
        *_resource_trusts_from_keyvault(key_vaults),
    ]
    resource_trusts.sort(
        key=lambda item: (
            item.get("exposure") != "high",
            item.get("resource_type") or "",
            item.get("resource_name") or item.get("resource_id") or "",
            item.get("trust_type") or "",
        )
    )
    return resource_trusts


def _resource_trust_findings(storage_assets: list[dict], key_vaults: list[dict]) -> list[dict]:
    keyvault_findings = [
        finding
        for finding in build_keyvault_findings(key_vaults)
        if not str(finding.get("id") or "").startswith("keyvault-purge-protection-disabled-")
    ]
    return [*build_storage_findings(storage_assets), *keyvault_findings]


def _token_credential_surface_sort_key(item: dict) -> tuple[int, str, str, str]:
    priority_rank = {"high": 0, "medium": 1, "low": 2}
    return (
        priority_rank.get(str(item.get("priority") or "").lower(), 9),
        str(item.get("asset_name") or ""),
        str(item.get("surface_type") or ""),
        str(item.get("operator_signal") or ""),
    )


def _dedupe_strings(values: list[object]) -> list[str]:
    items: list[str] = []
    for value in values:
        text = str(value or "")
        if text and text not in items:
            items.append(text)
    return items


def _nic_detail_from_resource(nic: object) -> dict:
    nic_id = str(getattr(nic, "id", "") or "")
    ip_configurations = getattr(nic, "ip_configurations", None) or []
    virtual_machine = getattr(nic, "virtual_machine", None)
    network_security_group = getattr(nic, "network_security_group", None)

    private_ips: list[str] = []
    public_ip_ids: list[str] = []
    subnet_ids: list[str] = []
    vnet_ids: list[str] = []

    for config in ip_configurations:
        private_ip = getattr(config, "private_ip_address", None)
        if private_ip:
            private_ips.append(str(private_ip))

        public_ip = getattr(config, "public_ip_address", None)
        public_ip_id = getattr(public_ip, "id", None)
        if public_ip_id:
            public_ip_ids.append(str(public_ip_id))

        subnet = getattr(config, "subnet", None)
        subnet_id = getattr(subnet, "id", None)
        if subnet_id:
            subnet_ids.append(str(subnet_id))
            vnet_id = _vnet_id_from_subnet_id(str(subnet_id))
            if vnet_id:
                vnet_ids.append(vnet_id)

    attached_asset_id = str(getattr(virtual_machine, "id", "") or "") or None

    return {
        "id": nic_id or f"/unknown/{getattr(nic, 'name', 'nic')}",
        "name": getattr(nic, "name", "unknown"),
        "attached_asset_id": attached_asset_id,
        "attached_asset_name": (
            _resource_name_from_id(attached_asset_id) if attached_asset_id else None
        ),
        "private_ips": _dedupe_strings(private_ips),
        "public_ip_ids": _dedupe_strings(public_ip_ids),
        "subnet_ids": _dedupe_strings(subnet_ids),
        "vnet_ids": _dedupe_strings(vnet_ids),
        "network_security_group_id": (str(getattr(network_security_group, "id", "") or "") or None),
    }


def _inbound_allow_rules_from_nsg(nsg: object) -> list[dict]:
    rules: list[dict] = []

    for rule in getattr(nsg, "security_rules", None) or []:
        access = str(_string_value(getattr(rule, "access", None)) or "").lower()
        direction = str(_string_value(getattr(rule, "direction", None)) or "").lower()
        if access != "allow" or direction != "inbound":
            continue

        rules.append(
            {
                "name": str(getattr(rule, "name", "allow-rule") or "allow-rule"),
                "protocol": _normalized_network_protocol(getattr(rule, "protocol", None)),
                "ports": _normalized_destination_ports(rule),
                "sources": _normalized_rule_sources(rule),
            }
        )

    return rules


def _normalized_network_protocol(value: object) -> str:
    text = str(_string_value(value) or "").strip()
    if not text or text == "*":
        return "Any"
    return text.upper()


def _normalized_destination_ports(rule: object) -> list[str]:
    destination_port_range = getattr(rule, "destination_port_range", None)
    ports = [
        *[str(item) for item in (getattr(rule, "destination_port_ranges", None) or []) if item],
        *([str(destination_port_range)] if destination_port_range else []),
    ]
    if not ports:
        return ["any"]
    return _dedupe_strings(["any" if port == "*" else port for port in ports])


def _normalized_rule_sources(rule: object) -> list[str]:
    source_address_prefix = getattr(rule, "source_address_prefix", None)
    sources = [
        *[str(item) for item in (getattr(rule, "source_address_prefixes", None) or []) if item],
        *([str(source_address_prefix)] if source_address_prefix else []),
    ]
    if not sources:
        return ["Any"]
    return _dedupe_strings(["Any" if source == "*" else source for source in sources])


def _network_port_rows_from_rules(
    *,
    endpoint: dict,
    nic: dict,
    rules: list[dict],
    scope_type: str,
    scope_id: str,
) -> list[dict]:
    rows: list[dict] = []

    for rule in rules:
        source_summary = _network_rule_source_summary(rule.get("sources", []))
        confidence = _network_port_confidence(rule.get("sources", []))
        scope_label = _network_scope_label(scope_type, scope_id, rule.get("name"))
        protocol = str(rule.get("protocol") or "Any")

        for port in rule.get("ports", []):
            asset_name = (
                endpoint.get("source_asset_name")
                or nic.get("attached_asset_name")
                or nic.get("name")
                or "unknown"
            )
            rows.append(
                {
                    "asset_id": endpoint.get("source_asset_id")
                    or nic.get("attached_asset_id")
                    or nic.get("id"),
                    "asset_name": asset_name,
                    "endpoint": endpoint.get("endpoint") or "unknown",
                    "protocol": protocol,
                    "port": str(port),
                    "allow_source_summary": f"{source_summary} via {scope_label}",
                    "exposure_confidence": confidence,
                    "summary": (
                        f"Asset '{asset_name}' has inbound {protocol} {port} allow evidence for "
                        f"endpoint {endpoint.get('endpoint') or 'unknown'} from {source_summary} "
                        f"via {scope_label}."
                    ),
                    "related_ids": _dedupe_strings(
                        [
                            endpoint.get("source_asset_id"),
                            nic.get("id"),
                            scope_id,
                            *endpoint.get("related_ids", []),
                        ]
                    ),
                }
            )

    return rows


def _network_port_row_without_nsg(*, endpoint: dict, nic: dict) -> dict:
    asset_name = (
        endpoint.get("source_asset_name")
        or nic.get("attached_asset_name")
        or nic.get("name")
        or "unknown"
    )
    return {
        "asset_id": (
            endpoint.get("source_asset_id") or nic.get("attached_asset_id") or nic.get("id")
        ),
        "asset_name": asset_name,
        "endpoint": endpoint.get("endpoint") or "unknown",
        "protocol": "any",
        "port": "any",
        "allow_source_summary": "no Azure NSG visible on NIC or subnet",
        "exposure_confidence": "low",
        "summary": (
            f"Asset '{asset_name}' exposes endpoint {endpoint.get('endpoint') or 'unknown'} with "
            "no NIC or subnet NSG visible from the current Azure read path. Azure network port "
            "restrictions are not evident here, but guest or service controls may still apply."
        ),
        "related_ids": _dedupe_strings(
            [endpoint.get("source_asset_id"), nic.get("id"), *endpoint.get("related_ids", [])]
        ),
    }


def _network_rule_source_summary(sources: list[object]) -> str:
    values = _dedupe_strings(list(sources))
    if not values:
        return "unknown sources"
    return ", ".join(values)


def _network_port_confidence(sources: list[object]) -> str:
    values = [str(source).strip() for source in sources if str(source or "").strip()]
    lowered = [value.lower() for value in values]

    if any(value in {"any", "internet", "0.0.0.0/0", "::/0"} for value in lowered):
        return "high"
    if any(value == "azureloadbalancer" for value in lowered):
        return "medium"
    if any(not is_private_network_prefix(value) and "/" in value for value in values):
        return "medium"
    if any(value == "virtualnetwork" for value in lowered):
        return "low"
    if any(is_private_network_prefix(value) for value in values):
        return "low"
    return "medium"


def _network_scope_label(scope_type: str, scope_id: str, rule_name: object) -> str:
    scope_name = _resource_name_from_id(scope_id) or scope_id or "unknown"
    resource_group = _resource_group_from_id(scope_id)
    label = "nic-nsg" if scope_type == "nic" else "subnet-nsg"
    scope_ref = f"{resource_group}/{scope_name}" if resource_group else scope_name
    return f"{label}:{scope_ref}/{str(rule_name or 'allow-rule')}"


def _compact_link(value: object) -> str:
    text = str(value or "")
    if not text:
        return "-"

    parsed = urlparse(text)
    if parsed.netloc and parsed.path:
        return f"{parsed.netloc}{parsed.path}"
    return text


def _env_var_reference_target(value: object) -> str | None:
    text = str(value or "").strip()
    if not text.startswith("@Microsoft.KeyVault("):
        return None

    match = re.search(r"SecretUri=([^)]+)", text)
    if match:
        parsed = urlparse(match.group(1).strip())
        if parsed.netloc and parsed.path:
            return f"{parsed.netloc}{parsed.path}"
        return match.group(1).strip()

    vault_name = _keyvault_reference_part(text, "VaultName")
    secret_name = _keyvault_reference_part(text, "SecretName")
    secret_version = _keyvault_reference_part(text, "SecretVersion")
    if not vault_name or not secret_name:
        return None

    target = f"{vault_name}.vault.azure.net/secrets/{secret_name}"
    if secret_version:
        target = f"{target}/{secret_version}"
    return target


def _keyvault_reference_part(text: str, key: str) -> str | None:
    match = re.search(rf"{key}=([^;)]*)", text)
    if not match:
        return None
    value = match.group(1).strip()
    return value or None


def _key_vault_reference_identity_summary(value: str | None) -> str | None:
    if not value:
        return None
    if value.lower() == "systemassigned":
        return "SystemAssigned"
    parts = [part for part in value.split("/") if part]
    if parts:
        return parts[-1]
    return value


def _dedupe_deployments(deployments: list[dict]) -> list[dict]:
    deduped: list[dict] = []
    seen: set[tuple[str, str]] = set()

    for item in deployments:
        key = (item.get("id") or "", item.get("scope") or "")
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    return deduped


def _extract_power_state(vm: object) -> str | None:
    view = getattr(vm, "instance_view", None)
    statuses = getattr(view, "statuses", None) or []
    for status in statuses:
        code = getattr(status, "code", "")
        if isinstance(code, str) and code.startswith("PowerState/"):
            return code.replace("PowerState/", "", 1)
    return None
