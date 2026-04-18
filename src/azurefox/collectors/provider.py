from __future__ import annotations

import json
import re
import ssl
from abc import ABC, abstractmethod
from collections import Counter
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen

import certifi

from azurefox.auth.session import (
    DEVOPS_SCOPE,
    MANAGEMENT_SCOPE,
    build_auth_session,
    decode_jwt_payload,
)
from azurefox.clients.factory import build_clients
from azurefox.clients.graph import GraphBatchRequest, GraphClient
from azurefox.config import GlobalOptions
from azurefox.correlation.findings import build_keyvault_findings, build_storage_findings
from azurefox.devops_hints import describe_trusted_input, devops_next_review_hint
from azurefox.env_var_hints import env_var_next_review_hint
from azurefox.errors import AzureFoxError, ErrorKind, classify_exception
from azurefox.models.common import (
    Principal,
    RoleAssignment,
    RoleTrustsMode,
    ScopeRef,
    is_private_network_prefix,
)
from azurefox.privesc_hints import (
    privesc_missing_proof,
    privesc_next_review_hint,
    privesc_operator_signal,
    privesc_path_sort_rank,
    privesc_path_type,
    privesc_proven_path,
    privesc_summary,
)
from azurefox.target_matching import looks_like_exact_target_value
from azurefox.tokens_credential_hints import tokens_credential_next_review_hint

_DNS_RESOURCE_API_VERSION = {
    "microsoft.network/dnszones": "2018-05-01",
    "microsoft.network/privatednszones": "2020-06-01",
}
_DEVOPS_BUILD_NAMESPACE_ID = "33344d9c-fc72-4d6f-aba5-fa317101a7e9"
_DEVOPS_GIT_NAMESPACE_ID = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87"
_DEVOPS_SECURE_FILE_ROLE_SCOPE_ID = "distributedtask.securefile"
_KEYVAULT_SECRET_READ_ROLE_NAMES = {
    "key vault administrator",
    "key vault secrets officer",
    "key vault secrets user",
}


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

    def automation(self) -> dict:
        return {"automation_accounts": [], "issues": []}

    def devops(self) -> dict:
        return {"pipelines": [], "issues": []}

    def app_services(self) -> dict:
        return {"app_services": [], "issues": []}

    def acr(self) -> dict:
        return {"registries": [], "issues": []}

    def databases(self) -> dict:
        return {"database_servers": [], "issues": []}

    def dns(self) -> dict:
        return {"dns_zones": [], "issues": []}

    def application_gateway(self) -> dict:
        return {"application_gateways": [], "issues": []}

    def aks(self) -> dict:
        return {"aks_clusters": [], "issues": []}

    def api_mgmt(self) -> dict:
        return {"api_management_services": [], "issues": []}

    def functions(self) -> dict:
        return {"function_apps": [], "issues": []}

    def container_apps(self) -> dict:
        return {"container_apps": [], "issues": []}

    def container_instances(self) -> dict:
        return {"container_instances": [], "issues": []}

    @abstractmethod
    def env_vars(self) -> dict:
        raise NotImplementedError

    def web_workloads(self) -> dict:
        return {"workloads": [], "issues": []}

    def tokens_credentials(self) -> dict:
        workload_data = self.web_workloads()
        container_instance_data = self.container_instances()
        env_var_data = self.env_vars()
        arm_data = self.arm_deployments()
        vm_data = self.vms()

        surfaces = [
            *_token_credential_surfaces_from_web_workloads(workload_data.get("workloads", [])),
            *_token_credential_surfaces_from_container_instances(
                container_instance_data.get("container_instances", [])
            ),
            *_tokens_credentials_surfaces_from_env_vars(env_var_data.get("env_vars", [])),
            *_token_credential_surfaces_from_arm_deployments(arm_data.get("deployments", [])),
            *_token_credential_surfaces_from_vms(vm_data.get("vm_assets", [])),
        ]
        surfaces.sort(key=_token_credential_surface_sort_key)

        return {
            "surfaces": surfaces,
            "issues": [
                *workload_data.get("issues", []),
                *container_instance_data.get("issues", []),
                *env_var_data.get("issues", []),
                *arm_data.get("issues", []),
                *vm_data.get("issues", []),
            ],
        }

    def endpoints(self) -> dict:
        workload_data = self.web_workloads()
        container_instance_data = self.container_instances()
        vm_data = self.vms()

        endpoints = [
            *_endpoints_from_vms(vm_data.get("vm_assets", [])),
            *_endpoints_from_web_workloads(workload_data.get("workloads", [])),
            *_endpoints_from_container_instances(
                container_instance_data.get("container_instances", [])
            ),
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
            "issues": [
                *workload_data.get("issues", []),
                *container_instance_data.get("issues", []),
                *vm_data.get("issues", []),
            ],
        }

    def workloads(self) -> dict:
        workload_data = self.web_workloads()
        container_instance_data = self.container_instances()
        vm_data = self.vms()
        endpoints = [
            *_endpoints_from_vms(vm_data.get("vm_assets", [])),
            *_endpoints_from_web_workloads(workload_data.get("workloads", [])),
            *_endpoints_from_container_instances(
                container_instance_data.get("container_instances", [])
            ),
        ]
        endpoints_by_asset = _endpoints_by_asset(endpoints)
        workloads = [
            *_workload_rows_from_vms(vm_data.get("vm_assets", []), endpoints_by_asset),
            *_workload_rows_from_web_workloads(
                workload_data.get("workloads", []),
                endpoints_by_asset,
            ),
            *_workload_rows_from_container_instances(
                container_instance_data.get("container_instances", []),
                endpoints_by_asset,
            ),
        ]
        workloads.sort(key=_workload_sort_key)
        return {
            "workloads": workloads,
            "issues": [
                *workload_data.get("issues", []),
                *container_instance_data.get("issues", []),
                *vm_data.get("issues", []),
            ],
        }

    def network_effective(self) -> dict:
        endpoint_data = self.endpoints()
        network_port_data = self.network_ports(endpoint_data=endpoint_data)
        effective_exposures = _compose_network_effective(
            endpoint_data.get("endpoints", []),
            network_port_data.get("network_ports", []),
        )
        return {
            "effective_exposures": effective_exposures,
            "issues": [*network_port_data.get("issues", [])],
        }

    @abstractmethod
    def network_ports(self, endpoint_data: dict | None = None) -> dict:
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
    def role_trusts(self, mode: RoleTrustsMode = RoleTrustsMode.FAST) -> dict:
        raise NotImplementedError

    @abstractmethod
    def lighthouse(self) -> dict:
        raise NotImplementedError

    @abstractmethod
    def cross_tenant(self) -> dict:
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

    def keyvault_secret_access(
        self,
        *,
        vault_name: str,
        vault_resource_id: str | None,
        secret_name: str,
        secret_version: str | None = None,
    ) -> dict:
        return {"state": "unknown", "basis": None, "issues": []}

    @abstractmethod
    def storage(self) -> dict:
        raise NotImplementedError

    @abstractmethod
    def snapshots_disks(self) -> dict:
        raise NotImplementedError

    @abstractmethod
    def nics(self) -> dict:
        raise NotImplementedError

    @abstractmethod
    def vms(self) -> dict:
        raise NotImplementedError

    @abstractmethod
    def vmss(self) -> dict:
        raise NotImplementedError


class FixtureProvider(BaseProvider):
    def __init__(self, fixture_dir: Path) -> None:
        self.fixture_dir = fixture_dir

    def _read(self, name: str) -> dict:
        path = self.fixture_dir / f"{name}.json"
        if not path.exists():
            raise AzureFoxError(ErrorKind.UNKNOWN, f"Fixture file not found: {path}")
        return json.loads(path.read_text(encoding="utf-8"))

    def _read_optional(self, name: str, *, empty_key: str) -> dict:
        path = self.fixture_dir / f"{name}.json"
        if not path.exists():
            return {empty_key: [], "issues": []}
        return json.loads(path.read_text(encoding="utf-8"))

    def whoami(self) -> dict:
        return self._read("whoami")

    def inventory(self) -> dict:
        return self._read("inventory")

    def arm_deployments(self) -> dict:
        return self._read("arm_deployments")

    def automation(self) -> dict:
        return self._read("automation")

    def devops(self) -> dict:
        return self._read("devops")

    def app_services(self) -> dict:
        return self._read("app_services")

    def acr(self) -> dict:
        return self._read("acr")

    def databases(self) -> dict:
        return self._read("databases")

    def dns(self) -> dict:
        return self._read("dns")

    def application_gateway(self) -> dict:
        return self._read("application_gateway")

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

    def role_trusts(self, mode: RoleTrustsMode = RoleTrustsMode.FAST) -> dict:
        return self._read("role_trusts")

    def lighthouse(self) -> dict:
        return self._read("lighthouse")

    def cross_tenant(self) -> dict:
        return self._read("cross_tenant")

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

    def keyvault_secret_access(
        self,
        *,
        vault_name: str,
        vault_resource_id: str | None,
        secret_name: str,
        secret_version: str | None = None,
    ) -> dict:
        path = self.fixture_dir / "keyvault_secret_access.json"
        if not path.exists():
            return {"state": "unknown", "basis": None, "issues": []}

        payload = json.loads(path.read_text(encoding="utf-8"))
        for check in payload.get("checks", []):
            if (
                check.get("vault_name") == vault_name
                and check.get("secret_name") == secret_name
                and (check.get("secret_version") or None) == secret_version
            ):
                return {
                    "state": str(check.get("state") or "unknown"),
                    "basis": check.get("basis"),
                    "issues": payload.get("issues", []),
                }

        return {
            "state": "unknown",
            "basis": None,
            "issues": payload.get("issues", []),
        }

    def env_vars(self) -> dict:
        return self._read("env_vars")

    def container_apps(self) -> dict:
        return self._read_optional("container_apps", empty_key="container_apps")

    def container_instances(self) -> dict:
        return self._read_optional("container_instances", empty_key="container_instances")

    def web_workloads(self) -> dict:
        data = self._read("web_workloads")
        container_app_data = self.container_apps()
        workloads = [
            *data.get("workloads", []),
            *[
                _container_app_workload_summary(item)
                for item in container_app_data.get("container_apps", [])
            ],
        ]
        workloads.sort(
            key=lambda item: ((item.get("asset_name") or ""), item.get("asset_id") or "")
        )
        return {
            "workloads": workloads,
            "issues": [*data.get("issues", []), *container_app_data.get("issues", [])],
        }

    def storage(self) -> dict:
        return self._read("storage")

    def snapshots_disks(self) -> dict:
        return self._read("snapshots_disks")

    def nics(self) -> dict:
        return self._read("nics")

    def network_ports(self, endpoint_data: dict | None = None) -> dict:
        data = self._read("network_ports")
        if endpoint_data is None:
            return data
        return {
            "network_ports": data.get("network_ports", []),
            "issues": [*endpoint_data.get("issues", []), *data.get("issues", [])],
        }

    def vms(self) -> dict:
        return self._read("vms")

    def vmss(self) -> dict:
        return self._read("vmss")


class AzureProvider(BaseProvider):
    def __init__(self, options: GlobalOptions) -> None:
        self.options = options
        self.session = build_auth_session(options.tenant)
        self.clients = build_clients(self.session, options.subscription)
        self.graph = GraphClient(self.session.credential)
        self.subscription = self.clients.subscription
        self._devops_namespace_actions_cache: dict[str, dict[str, int]] = {}
        self._devops_current_operator_cache: dict[str, dict[str, object]] = {}
        self._devops_secure_files_cache: dict[str, dict[str, dict[str, object]]] = {}
        self._devops_secure_file_roles_cache: dict[str, list[dict[str, object]]] = {}
        self._devops_feed_permissions_cache: dict[str, list[dict[str, object]]] = {}
        self._rbac_cache: dict | None = None

    def metadata_context(self) -> dict[str, str | None]:
        return {
            "tenant_id": self.session.tenant_id,
            "subscription_id": self.clients.subscription_id,
            "token_source": self.session.token_source,
            "auth_mode": self.session.auth_mode,
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
            "auth_mode": self.session.auth_mode,
            "issues": [],
        }

    def keyvault_secret_access(
        self,
        *,
        vault_name: str,
        vault_resource_id: str | None,
        secret_name: str,
        secret_version: str | None = None,
    ) -> dict:
        issues: list[dict] = []
        if not vault_name or not secret_name:
            return {"state": "unknown", "basis": None, "issues": issues}

        live_result = self._keyvault_live_secret_access(
            vault_name=vault_name,
            secret_name=secret_name,
            secret_version=secret_version,
        )
        if live_result["state"] != "unknown":
            return live_result
        issues.extend(live_result.get("issues", []))

        current_principal_id = str(
            ((self.whoami().get("principal") or {}).get("id")) or "unknown"
        )
        if current_principal_id == "unknown":
            return {"state": "unknown", "basis": None, "issues": issues}

        policy_result = self._keyvault_policy_secret_access(
            current_principal_id=current_principal_id,
            vault_name=vault_name,
            vault_resource_id=vault_resource_id,
        )
        if policy_result["state"] != "unknown":
            return {
                "state": policy_result["state"],
                "basis": policy_result.get("basis"),
                "issues": [*issues, *policy_result.get("issues", [])],
            }

        return {
            "state": "unknown",
            "basis": None,
            "issues": [*issues, *policy_result.get("issues", [])],
        }

    def _keyvault_live_secret_access(
        self,
        *,
        vault_name: str,
        secret_name: str,
        secret_version: str | None,
    ) -> dict:
        try:
            from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
            from azure.keyvault.secrets import SecretClient
        except ImportError:
            return {"state": "unknown", "basis": None, "issues": []}

        try:
            client = SecretClient(
                vault_url=f"https://{vault_name}.vault.azure.net/",
                credential=self.session.credential,
            )
            if secret_version:
                client.get_secret(secret_name, secret_version)
            else:
                client.get_secret(secret_name)
            return {"state": "can-read", "basis": "live-read", "issues": []}
        except HttpResponseError as exc:
            status = getattr(exc, "status_code", None)
            if status in {401, 403}:
                return {"state": "cannot-read", "basis": "live-read-denied", "issues": []}
            if status == 404:
                return {
                    "state": "appears-able",
                    "basis": "live-read-secret-missing",
                    "issues": [],
                }
            return {
                "state": "unknown",
                "basis": None,
                "issues": [
                    _issue_from_exception(
                        f"keyvault.secret_access[{vault_name}/{secret_name}]",
                        exc,
                    )
                ],
            }
        except ClientAuthenticationError as exc:
            return {
                "state": "unknown",
                "basis": None,
                "issues": [
                    _issue_from_exception(
                        f"keyvault.secret_access[{vault_name}/{secret_name}]",
                        exc,
                    )
                ],
            }
        except Exception as exc:
            return {
                "state": "unknown",
                "basis": None,
                "issues": [
                    _issue_from_exception(
                        f"keyvault.secret_access[{vault_name}/{secret_name}]",
                        exc,
                    )
                ],
            }

    def _keyvault_policy_secret_access(
        self,
        *,
        current_principal_id: str,
        vault_name: str,
        vault_resource_id: str | None,
    ) -> dict:
        issues: list[dict] = []

        if vault_resource_id:
            resource_group, resource_name = _resource_group_and_name(vault_resource_id)
            if resource_group and resource_name:
                try:
                    vault = self.clients.keyvault.vaults.get(resource_group, resource_name)
                    properties = getattr(vault, "properties", None)
                    if bool(getattr(properties, "enable_rbac_authorization", False)):
                        role_names = self._current_identity_keyvault_role_names(vault_resource_id)
                        if any(
                            role_name.lower() in _KEYVAULT_SECRET_READ_ROLE_NAMES
                            for role_name in role_names
                        ):
                            return {"state": "appears-able", "basis": "keyvault-rbac", "issues": []}
                    else:
                        for policy in getattr(properties, "access_policies", None) or []:
                            object_id = str(getattr(policy, "object_id", None) or "")
                            application_id = str(getattr(policy, "application_id", None) or "")
                            if current_principal_id not in {object_id, application_id}:
                                continue
                            permissions = getattr(policy, "permissions", None)
                            secret_permissions = {
                                str(value).lower()
                                for value in getattr(permissions, "secrets", None) or []
                                if value
                            }
                            if "get" in secret_permissions:
                                return {
                                    "state": "appears-able",
                                    "basis": "keyvault-access-policy",
                                    "issues": [],
                                }
                except Exception as exc:
                    issues.append(
                        _issue_from_exception(
                            f"keyvault.access_model[{vault_name}]",
                            exc,
                        )
                    )

        role_names = self._current_identity_keyvault_role_names(vault_resource_id)
        if any(role_name.lower() in _KEYVAULT_SECRET_READ_ROLE_NAMES for role_name in role_names):
            return {"state": "appears-able", "basis": "keyvault-rbac", "issues": issues}

        return {"state": "unknown", "basis": None, "issues": issues}

    def _current_identity_keyvault_role_names(self, vault_resource_id: str | None) -> set[str]:
        if not vault_resource_id:
            return set()

        rbac_data = self._rbac_cache
        if rbac_data is None:
            rbac_data = self.rbac()
            self._rbac_cache = rbac_data

        current_principal_id = str(
            ((self.whoami().get("principal") or {}).get("id")) or "unknown"
        )
        role_names: set[str] = set()
        for assignment in rbac_data.get("role_assignments", []):
            if assignment.get("principal_id") != current_principal_id:
                continue
            scope_id = str(assignment.get("scope_id") or "")
            if not _scope_applies_to_resource(scope_id, vault_resource_id):
                continue
            role_name = str(assignment.get("role_name") or "").strip()
            if role_name:
                role_names.add(role_name)
        return role_names

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
            iterator = self.clients.resource_deployments.deployments.list_at_subscription_scope()
            for deployment in iterator:
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
                iterator = self.clients.resource_deployments.deployments.list_by_resource_group(
                    resource_group
                )
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

    def automation(self) -> dict:
        issues: list[dict] = []
        automation_accounts: list[dict] = []
        automation_subcollections = (
            ("runbooks", ("runbook", "runbooks")),
            ("schedules", ("schedule", "schedules")),
            ("job_schedules", ("job_schedule", "job_schedules")),
            ("webhooks", ("webhook", "webhooks")),
            ("credentials", ("credential", "credentials")),
            ("certificates", ("certificate", "certificates")),
            ("connections", ("connection", "connections")),
            ("variables", ("variable", "variables")),
            (
                "hybrid_worker_groups",
                ("hybrid_runbook_worker_group", "hybrid_runbook_worker_groups"),
            ),
        )

        try:
            iterator = _call_automation_operation(
                self.clients.automation,
                ("automation_account", "automation_accounts"),
                "list",
            )
            for account in iterator:
                account_id = getattr(account, "id", "") or ""
                resource_group = _resource_group_from_id(account_id)
                account_name = getattr(account, "name", None)
                hydrated_account = account
                subcollections: dict[str, list[object] | None] = {
                    name: None for name, _attrs in automation_subcollections
                }

                if resource_group and account_name:
                    hydrated_account, issue = _automation_get_account(
                        self.clients.automation,
                        resource_group,
                        account_name,
                        fallback=account,
                    )
                    if issue:
                        issues.append(issue)

                    for collection_name, attrs in automation_subcollections:
                        values, issue = _automation_list_by_account(
                            self.clients.automation,
                            attrs,
                            resource_group,
                            account_name,
                        )
                        subcollections[collection_name] = values
                        if issue:
                            issues.append(issue)

                automation_accounts.append(
                    _automation_account_summary(
                        hydrated_account,
                        runbooks=subcollections["runbooks"],
                        schedules=subcollections["schedules"],
                        job_schedules=subcollections["job_schedules"],
                        webhooks=subcollections["webhooks"],
                        credentials=subcollections["credentials"],
                        certificates=subcollections["certificates"],
                        connections=subcollections["connections"],
                        variables=subcollections["variables"],
                        hybrid_worker_groups=subcollections["hybrid_worker_groups"],
                    )
                )
        except Exception as exc:
            issues.append(_issue_from_exception("automation.accounts", exc))

        return {"automation_accounts": automation_accounts, "issues": issues}

    def devops(self) -> dict:
        organization = self.options.devops_organization
        if not organization:
            return {
                "pipelines": [],
                "issues": [
                    {
                        "kind": ErrorKind.UNKNOWN.value,
                        "message": (
                            "devops: Azure DevOps organization not configured; rerun with "
                            "--devops-organization or set AZUREFOX_DEVOPS_ORG."
                        ),
                        "context": {"collector": "devops"},
                    }
                ],
            }

        issues: list[dict] = []
        pipelines: list[dict] = []

        try:
            projects = self._devops_list_values(
                f"https://dev.azure.com/{organization}/_apis/projects?api-version=7.1&$top=200"
            )
        except Exception as exc:
            issues.append(_issue_from_exception("devops.projects", exc))
            return {"pipelines": [], "issues": issues}

        current_operator: dict[str, object] | None = None
        try:
            current_operator = self._devops_current_operator_identity(organization=organization)
        except Exception as exc:
            issues.append(_issue_from_exception("devops.current_operator", exc))

        project_contexts: list[dict[str, object]] = []
        all_repositories: list[dict[str, object]] = []

        for project in projects:
            project_name = str(project.get("name") or "")
            if not project_name:
                continue
            project_path = quote(project_name, safe="")

            try:
                service_endpoints = self._devops_list_values(
                    "https://dev.azure.com/"
                    f"{organization}/{project_path}/_apis/serviceendpoint/endpoints"
                    "?api-version=7.1"
                )
            except Exception as exc:
                issues.append(
                    _issue_from_exception(
                        f"devops[{project_name}].service_endpoints",
                        exc,
                    )
                )
                service_endpoints = []

            try:
                variable_groups = self._devops_list_values(
                    "https://dev.azure.com/"
                    f"{organization}/{project_path}/_apis/distributedtask/variablegroups"
                    "?api-version=7.1"
                )
            except Exception as exc:
                issues.append(
                    _issue_from_exception(
                        f"devops[{project_name}].variable_groups",
                        exc,
                    )
                )
                variable_groups = []

            try:
                repositories = self._devops_list_values(
                    "https://dev.azure.com/"
                    f"{organization}/{project_path}/_apis/git/repositories"
                    "?includeAllUrls=true&api-version=7.1"
                )
            except Exception as exc:
                issues.append(
                    _issue_from_exception(
                        f"devops[{project_name}].repositories",
                        exc,
                    )
                )
                repositories = []

            try:
                definitions = self._devops_list_values(
                    "https://dev.azure.com/"
                    f"{organization}/{project_path}/_apis/build/definitions"
                    "?includeAllProperties=true&api-version=7.1&$top=200"
                )
            except Exception as exc:
                issues.append(
                    _issue_from_exception(
                        f"devops[{project_name}].build_definitions",
                        exc,
                    )
                )
                definitions = []

            project_contexts.append(
                {
                    "project": project,
                    "service_endpoints": service_endpoints,
                    "variable_groups": variable_groups,
                    "repositories": repositories,
                    "definitions": definitions,
                }
            )
            all_repositories.extend(
                [repository for repository in repositories if isinstance(repository, dict)]
            )

        repositories_by_id, repositories_by_name = _devops_repository_maps(all_repositories)
        pipeline_issues_by_key: dict[str, list[dict[str, object]]] = {}
        collected_pipelines: list[dict[str, object]] = []

        for context in project_contexts:
            project = context["project"]
            project_name = str(project.get("name") or "")
            service_endpoints_by_id, service_endpoints_by_name = _devops_service_endpoint_maps(
                [
                    endpoint
                    for endpoint in (context.get("service_endpoints") or [])
                    if isinstance(endpoint, dict)
                ]
            )
            variable_groups_by_id = _devops_variable_group_map(
                [
                    group
                    for group in (context.get("variable_groups") or [])
                    if isinstance(group, dict)
                ]
            )

            for definition in context.get("definitions") or []:
                if not isinstance(definition, dict):
                    continue
                try:
                    pipeline, definition_issues = _devops_pipeline_summary(
                        organization=organization,
                        project=project,
                        definition=definition,
                        service_endpoints_by_id=service_endpoints_by_id,
                        service_endpoints_by_name=service_endpoints_by_name,
                        repositories_by_id=repositories_by_id,
                        repositories_by_name=repositories_by_name,
                        variable_groups_by_id=variable_groups_by_id,
                    )
                except Exception as exc:
                    definition_label = str(definition.get("id") or "") or str(
                        definition.get("name") or "unknown"
                    )
                    issues.append(
                        _issue_from_exception(
                            f"devops[{project_name}].definitions[{definition_label}]",
                            exc,
                        )
                    )
                    continue

                try:
                    pipeline.update(
                        self._devops_build_definition_permissions(
                            organization=organization,
                            project_id=str(pipeline.get("project_id") or ""),
                            definition_id=str(pipeline.get("definition_id") or ""),
                        )
                    )
                except Exception as exc:
                    definition_key = (
                        pipeline.get("definition_id") or pipeline.get("name") or "unknown"
                    )
                    issues.append(
                        _issue_from_exception(
                            f"devops[{project_name}].build_permissions[{definition_key}]",
                            exc,
                        )
                    )

                if pipeline.get("repository_host_type") == "azure-repos":
                    try:
                        pipeline.update(
                            self._devops_git_repository_permissions(
                                organization=organization,
                                project_id=str(pipeline.get("project_id") or ""),
                                repository_id=str(pipeline.get("repository_id") or ""),
                            )
                        )
                    except Exception as exc:
                        repo_key = (
                            pipeline.get("repository_id")
                            or pipeline.get("repository_name")
                            or "unknown"
                        )
                        issues.append(
                            _issue_from_exception(
                                f"devops[{project_name}].repo_permissions[{repo_key}]",
                                exc,
                            )
                        )

                pipeline["trusted_inputs"] = _devops_finalize_trusted_inputs(
                    trusted_inputs=[
                        dict(item)
                        for item in (pipeline.get("trusted_inputs") or [])
                        if isinstance(item, dict)
                    ],
                    source_join_ids=[
                        str(value) for value in (pipeline.get("source_join_ids") or [])
                    ],
                    current_operator_can_view_source=pipeline.get(
                        "current_operator_can_view_source"
                    ),
                    current_operator_can_contribute_source=pipeline.get(
                        "current_operator_can_contribute_source"
                    ),
                )
                try:
                    pipeline["trusted_inputs"] = self._devops_enrich_non_artifact_trusted_inputs(
                        organization=organization,
                        project_name=project_name,
                        project_id=str(pipeline.get("project_id") or ""),
                        trusted_inputs=[
                            dict(item)
                            for item in (pipeline.get("trusted_inputs") or [])
                            if isinstance(item, dict)
                        ],
                        current_operator=current_operator,
                    )
                except Exception as exc:
                    pipeline_key = (
                        pipeline.get("definition_id") or pipeline.get("name") or "unknown"
                    )
                    definition_issues.append(
                        _partial_collection_issue(
                            "devops.trusted_input_proof",
                            (
                                "trusted-input proof lookup failed for "
                                f"{pipeline_key}: {exc}"
                            ),
                            asset_id=str(pipeline.get("id") or "") or None,
                            asset_name=str(pipeline.get("name") or "") or None,
                        )
                    )
                _devops_refresh_pipeline_state(
                    pipeline,
                    definition_issues=definition_issues,
                )
                definition_key = _devops_pipeline_key(pipeline)
                pipeline_issues_by_key[definition_key] = definition_issues
                collected_pipelines.append(pipeline)

        pipeline_lookup = _devops_pipeline_lookup(collected_pipelines)
        for pipeline in collected_pipelines:
            definition_issues = pipeline_issues_by_key.get(_devops_pipeline_key(pipeline), [])
            project_name = str(pipeline.get("project_name") or "")
            try:
                pipeline["trusted_inputs"] = _devops_enrich_artifact_trusted_inputs(
                    pipeline=pipeline,
                    trusted_inputs=[
                        dict(item)
                        for item in (pipeline.get("trusted_inputs") or [])
                        if isinstance(item, dict)
                    ],
                    pipelines_by_project_and_name=pipeline_lookup,
                )
            except Exception as exc:
                pipeline_key = pipeline.get("definition_id") or pipeline.get("name") or "unknown"
                definition_issues.append(
                    _partial_collection_issue(
                        "devops.artifact_proof",
                        f"artifact producer proof lookup failed for {pipeline_key}: {exc}",
                        asset_id=str(pipeline.get("id") or "") or None,
                        asset_name=str(pipeline.get("name") or "") or None,
                    )
                )
            _devops_refresh_pipeline_state(
                pipeline,
                definition_issues=definition_issues,
            )
            issues.extend(definition_issues)
            if _devops_pipeline_is_interesting(pipeline):
                pipelines.append(pipeline)

        return {"pipelines": pipelines, "issues": issues}

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
                webhooks = None
                replications = None
                registry_id = getattr(registry, "id", "") or ""
                resource_group = _resource_group_from_id(registry_id)
                registry_name = getattr(registry, "name", None)

                if resource_group and registry_name:
                    try:
                        webhooks = list(
                            self.clients.container_registry.webhooks.list(
                                resource_group,
                                registry_name,
                            )
                        )
                    except Exception as exc:
                        issues.append(
                            _issue_from_exception(
                                f"acr[{resource_group}/{registry_name}].webhooks",
                                exc,
                            )
                        )

                    try:
                        replications = list(
                            self.clients.container_registry.replications.list(
                                resource_group,
                                registry_name,
                            )
                        )
                    except Exception as exc:
                        issues.append(
                            _issue_from_exception(
                                f"acr[{resource_group}/{registry_name}].replications",
                                exc,
                            )
                        )

                    if _acr_registry_needs_hydration(registry):
                        try:
                            registry = self.clients.container_registry.registries.get(
                                resource_group,
                                registry_name,
                            )
                        except Exception as exc:
                            issues.append(
                                _issue_from_exception(
                                    f"acr[{resource_group}/{registry_name}].registry",
                                    exc,
                                )
                            )

                registries.append(_acr_registry_summary(registry, webhooks, replications))
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

        try:
            iterator = self.clients.postgresql_flexible.servers.list()
            for server in iterator:
                server_id = getattr(server, "id", "") or ""
                resource_group = _resource_group_from_id(server_id)
                server_name = getattr(server, "name", None)
                databases = None

                if resource_group and server_name:
                    try:
                        databases = list(
                            self.clients.postgresql_flexible.databases.list_by_server(
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

                database_servers.append(
                    _database_server_summary(
                        server,
                        databases,
                        engine="PostgreSqlFlexible",
                    )
                )
        except Exception as exc:
            issues.append(_issue_from_exception("databases.postgresql_flexible_servers", exc))

        try:
            iterator = self.clients.mysql_flexible.servers.list()
            for server in iterator:
                server_id = getattr(server, "id", "") or ""
                resource_group = _resource_group_from_id(server_id)
                server_name = getattr(server, "name", None)
                databases = None

                if resource_group and server_name:
                    try:
                        databases = list(
                            self.clients.mysql_flexible.databases.list_by_server(
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

                database_servers.append(
                    _database_server_summary(
                        server,
                        databases,
                        engine="MySqlFlexible",
                    )
                )
        except Exception as exc:
            issues.append(_issue_from_exception("databases.mysql_flexible_servers", exc))

        database_servers.sort(
            key=lambda item: (
                not _database_exposure_priority(item),
                item.get("engine") or "",
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
                    resource = self._hydrate_dns_resource(resource, issues)
                    dns_zones.append(_dns_zone_summary(resource, zone_kind="public"))
                elif resource_type == "microsoft.network/privatednszones":
                    resource = self._hydrate_dns_resource(resource, issues)
                    dns_zones.append(_dns_zone_summary(resource, zone_kind="private"))
        except Exception as exc:
            issues.append(_issue_from_exception("dns.resources", exc))

        private_zone_reference_ids: dict[str, set[str]] = {}
        try:
            for private_endpoint in self.clients.network.private_endpoints.list_by_subscription():
                private_endpoint_id = getattr(private_endpoint, "id", "") or ""
                private_endpoint_name = getattr(private_endpoint, "name", None)
                resource_group = _resource_group_from_id(private_endpoint_id)
                if not private_endpoint_name or not resource_group:
                    continue

                try:
                    for zone_group in self.clients.network.private_dns_zone_groups.list(
                        private_endpoint_name,
                        resource_group,
                    ):
                        for zone_config in (
                            getattr(zone_group, "private_dns_zone_configs", None) or []
                        ):
                            zone_id = _arm_id_join_key(
                                getattr(zone_config, "private_dns_zone_id", None)
                            )
                            if not zone_id:
                                continue
                            private_zone_reference_ids.setdefault(zone_id, set()).add(
                                private_endpoint_id
                            )
                except Exception as exc:
                    issues.append(
                        _issue_from_exception(
                            f"dns.private_dns_zone_groups[{resource_group}/{private_endpoint_name}]",
                            exc,
                        )
                    )
        except Exception as exc:
            issues.append(_issue_from_exception("dns.private_endpoints", exc))

        for zone in dns_zones:
            if zone.get("zone_kind") != "private":
                continue
            zone_id = _arm_id_join_key(zone.get("id"))
            private_endpoint_ids = sorted(private_zone_reference_ids.get(zone_id, set()))
            zone["private_endpoint_reference_count"] = len(private_endpoint_ids)
            zone["summary"] = _dns_zone_operator_summary(
                zone_name=str(zone.get("name") or "unknown"),
                zone_kind="private",
                record_set_count=zone.get("record_set_count"),
                name_server_count=len(zone.get("name_servers", [])),
                linked_virtual_network_count=zone.get("linked_virtual_network_count"),
                registration_virtual_network_count=zone.get("registration_virtual_network_count"),
                private_endpoint_reference_count=zone.get("private_endpoint_reference_count"),
            )
            zone["related_ids"] = _dedupe_strings(
                [*zone.get("related_ids", []), *private_endpoint_ids]
            )

        dns_zones.sort(
            key=lambda item: (
                item.get("zone_kind") != "public",
                item.get("name") or "",
            )
        )
        return {"dns_zones": dns_zones, "issues": issues}

    def application_gateway(self) -> dict:
        issues: list[dict] = []
        application_gateways: list[dict] = []
        public_ip_lookup: dict[str, str] = {}

        try:
            for public_ip in self.clients.network.public_ip_addresses.list_all():
                public_ip_id = _arm_id_join_key(getattr(public_ip, "id", None))
                public_ip_address = _string_value(getattr(public_ip, "ip_address", None))
                if public_ip_id and public_ip_address:
                    public_ip_lookup[public_ip_id] = public_ip_address
        except Exception as exc:
            issues.append(_issue_from_exception("application_gateway.public_ip_addresses", exc))

        try:
            for gateway in self.clients.network.application_gateways.list_all():
                application_gateways.append(
                    _application_gateway_summary(
                        gateway,
                        public_ip_lookup=public_ip_lookup,
                    )
                )
        except Exception as exc:
            issues.append(_issue_from_exception("application_gateway.gateways", exc))

        application_gateways.sort(
            key=lambda item: (
                not bool(item.get("public_frontend_count")),
                item.get("name") or "",
            )
        )
        return {"application_gateways": application_gateways, "issues": issues}

    def aks(self) -> dict:
        issues: list[dict] = []
        clusters: list[dict] = []

        try:
            iterator = self.clients.containerservice.managed_clusters.list()
            for cluster in iterator:
                cluster_id = getattr(cluster, "id", "") or ""
                resource_group = _resource_group_from_id(cluster_id)
                cluster_name = getattr(cluster, "name", None)
                if resource_group and cluster_name and _aks_cluster_needs_hydration(cluster):
                    try:
                        cluster = self.clients.containerservice.managed_clusters.get(
                            resource_group,
                            cluster_name,
                        )
                    except Exception as exc:
                        issues.append(
                            _issue_from_exception(
                                f"aks[{resource_group}/{cluster_name}].cluster",
                                exc,
                            )
                        )
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

    def _hydrate_dns_resource(self, resource: object, issues: list[dict]) -> object:
        resource_type = str(getattr(resource, "type", "") or "").lower()
        api_version = _DNS_RESOURCE_API_VERSION.get(resource_type)
        resource_id = _string_value(getattr(resource, "id", None))
        if not api_version or not resource_id or not _dns_resource_needs_hydration(resource):
            return resource

        try:
            return self.clients.resource.resources.get_by_id(resource_id, api_version)
        except Exception as exc:
            issues.append(
                _issue_from_exception(
                    f"dns.resource[{resource_type}/{resource_id}]",
                    exc,
                )
            )
            return resource

    def api_mgmt(self) -> dict:
        issues: list[dict] = []
        services: list[dict] = []

        try:
            iterator = self.clients.api_management.api_management_service.list()
            for service in iterator:
                apis = None
                subscriptions = None
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
                        subscriptions = list(
                            self.clients.api_management.subscription.list(
                                resource_group,
                                service_name,
                            )
                        )
                    except Exception as exc:
                        issues.append(
                            _issue_from_exception(
                                f"api_mgmt[{resource_group}/{service_name}].subscriptions",
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

                services.append(
                    _api_mgmt_service_summary(
                        service,
                        apis,
                        subscriptions,
                        backends,
                        named_values,
                    )
                )
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

    def container_apps(self) -> dict:
        container_apps, issues = _collect_resource_type_summaries(
            resources_client=self.clients.resource.resources,
            resource_type="Microsoft.App/containerApps",
            api_version="2024-03-01",
            summary_fn=_container_app_summary,
            list_issue_scope="container_apps.resources",
            hydrate_issue_scope="container_apps.hydrate",
        )
        return {"container_apps": container_apps, "issues": issues}

    def container_instances(self) -> dict:
        container_instances, issues = _collect_resource_type_summaries(
            resources_client=self.clients.resource.resources,
            resource_type="Microsoft.ContainerInstance/containerGroups",
            api_version="2023-05-01",
            summary_fn=_container_instance_summary,
            list_issue_scope="container_instances.resources",
            hydrate_issue_scope="container_instances.hydrate",
        )
        return {"container_instances": container_instances, "issues": issues}

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

        container_app_data = self.container_apps()
        workloads.extend(
            _container_app_workload_summary(item)
            for item in container_app_data.get("container_apps", [])
        )
        issues.extend(container_app_data.get("issues", []))

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
        principals, issues, _assignment_scope_ids_by_principal = _principal_records_from_sources(
            rbac_data=rbac_data,
            whoami_data=whoami_data,
            identity_data=identity_data,
        )
        return {"principals": principals, "issues": issues}

    def permissions(self) -> dict:
        rbac_data = self.rbac()
        whoami_data = self.whoami()
        identity_data = self.managed_identities()
        principals, issues, assignment_scope_ids_by_principal = _principal_records_from_sources(
            rbac_data=rbac_data,
            whoami_data=whoami_data,
            identity_data=identity_data,
        )
        permission_rows: list[dict] = []

        for principal in principals:
            role_names = sorted(set(principal.get("role_names", [])))
            principal_id = str(principal.get("id") or "")
            scope_ids = sorted(
                set(
                    assignment_scope_ids_by_principal.get(principal_id)
                    or principal.get("scope_ids", [])
                )
            )
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
        return {"permissions": permission_rows, "issues": issues}

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
        current_foothold_label = next(
            (
                item.get("display_name") or item.get("id")
                for item in principals_data.get("principals", [])
                if item.get("is_current_identity")
            ),
            None,
        )

        for permission in permissions_data.get("permissions", []):
            if not permission.get("privileged"):
                continue

            principal_name = (
                permission.get("display_name") or permission.get("principal_id") or "unknown"
            )
            impact_roles = permission.get("high_impact_roles", [])
            principal_id = permission.get("principal_id", "unknown")
            related_ids = [principal_id, *permission.get("scope_ids", [])]
            current_identity = permission.get("is_current_identity", False)
            path_type = privesc_path_type(
                path_type="direct-role-abuse",
                current_identity=current_identity,
            )
            starting_foothold = _privesc_starting_foothold(
                current_identity=current_identity,
                principal_name=principal_name,
                current_foothold_label=current_foothold_label,
            )
            operator_signal = privesc_operator_signal(
                path_type="direct-role-abuse",
                current_identity=current_identity,
            )
            proven_path = privesc_proven_path(
                principal_name=principal_name,
                path_type="direct-role-abuse",
                asset_name=None,
                impact_roles=impact_roles,
                current_identity=current_identity,
            )
            missing_proof = privesc_missing_proof(
                path_type="direct-role-abuse",
                current_identity=current_identity,
            )
            next_review = privesc_next_review_hint(
                path_type="direct-role-abuse",
                current_identity=current_identity,
            )

            paths.append(
                {
                    "principal": principal_name,
                    "principal_id": principal_id,
                    "principal_type": permission.get("principal_type", "unknown"),
                    "path_type": path_type,
                    "asset": None,
                    "starting_foothold": starting_foothold,
                    "impact_roles": impact_roles,
                    "priority": "high" if current_identity else "medium",
                    "current_identity": current_identity,
                    "operator_signal": operator_signal,
                    "proven_path": proven_path,
                    "missing_proof": missing_proof,
                    "next_review": next_review,
                    "summary": privesc_summary(
                        proven_path=proven_path,
                        missing_proof=missing_proof,
                        next_review=next_review,
                    ),
                    "related_ids": related_ids,
                }
            )

            for identity in identities_by_principal.get(principal_id, []):
                for attached_id in identity.get("attached_to", []):
                    vm_asset = vm_by_id.get(attached_id)
                    if not vm_asset or not vm_asset.get("public_ips"):
                        continue

                    identity_name = identity.get("name") or principal_name
                    path_type = privesc_path_type(
                        path_type="public-identity-pivot",
                        current_identity=False,
                    )
                    starting_foothold = _privesc_starting_foothold(
                        current_identity=False,
                        principal_name=identity_name,
                        current_foothold_label=current_foothold_label,
                    )
                    operator_signal = privesc_operator_signal(
                        path_type="public-identity-pivot",
                        current_identity=False,
                    )
                    proven_path = privesc_proven_path(
                        principal_name=identity_name,
                        path_type="public-identity-pivot",
                        asset_name=vm_asset.get("name") or attached_id,
                        impact_roles=impact_roles,
                        current_identity=False,
                    )
                    missing_proof = privesc_missing_proof(
                        path_type="public-identity-pivot",
                        current_identity=False,
                    )
                    next_review = privesc_next_review_hint(
                        path_type="public-identity-pivot",
                        current_identity=False,
                    )

                    paths.append(
                        {
                            "principal": identity_name,
                            "principal_id": principal_id,
                            "principal_type": "ManagedIdentity",
                            "path_type": path_type,
                            "asset": vm_asset.get("name") or attached_id,
                            "starting_foothold": starting_foothold,
                            "impact_roles": impact_roles,
                            "priority": "medium",
                            "current_identity": False,
                            "operator_signal": operator_signal,
                            "proven_path": proven_path,
                            "missing_proof": missing_proof,
                            "next_review": next_review,
                            "summary": privesc_summary(
                                proven_path=proven_path,
                                missing_proof=missing_proof,
                                next_review=next_review,
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
            key=_privesc_sort_key,
        )
        issues = [
            *permissions_data.get("issues", []),
            *identities_data.get("issues", []),
            *vms_data.get("issues", []),
        ]
        return {"paths": paths, "issues": issues}

    def role_trusts(self, mode: RoleTrustsMode = RoleTrustsMode.FAST) -> dict:
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

        if mode == RoleTrustsMode.FULL:
            try:
                applications = self.graph.list_applications()
            except Exception as exc:
                issues.append(_issue_from_exception("role_trusts.applications", exc))
                applications = []

        for application in applications:
            app_id = application.get("appId")
            if app_id:
                application_by_app_id[app_id] = application

        seeded_app_ids = sorted(
            app_id
            for app_id in service_principal_by_app_id
            if app_id and app_id not in application_by_app_id
        )
        seeded_applications, seeded_application_errors = _graph_batch_list_with_fallback(
            self.graph,
            [
                GraphBatchRequest(
                    key=app_id,
                    path="/applications",
                    params={
                        "$filter": "appId eq '{}'".format(str(app_id).replace("'", "''")),
                        "$select": "id,appId,displayName,signInAudience",
                    },
                )
                for app_id in seeded_app_ids
            ],
            lambda request: _graph_optional_list(
                self.graph.get_application_by_app_id(str(request.key))
            ),
        )
        for app_id in seeded_app_ids:
            exc = seeded_application_errors.get(app_id)
            if exc is not None:
                issues.append(
                    _issue_from_exception(
                        f"role_trusts.applications.by_app_id[{app_id}]",
                        exc,
                    )
                )
                continue
            application_items = seeded_applications.get(app_id, [])
            if not application_items:
                continue
            application = application_items[0]
            application_by_app_id[app_id] = application
            applications.append(application)

        federated_credentials_by_application, federated_credential_errors = (
            _graph_batch_list_with_fallback(
                self.graph,
                [
                    GraphBatchRequest(
                        key=app_object_id,
                        path=f"/applications/{app_object_id}/federatedIdentityCredentials",
                        params={"$select": "id,name,issuer,subject,audiences"},
                    )
                    for application in applications
                    if (app_object_id := application.get("id"))
                ],
                lambda request: self.graph.list_application_federated_credentials(str(request.key)),
            )
        )
        application_owners_by_id, application_owner_errors = _graph_batch_list_with_fallback(
            self.graph,
            [
                GraphBatchRequest(
                    key=app_object_id,
                    path=f"/applications/{app_object_id}/owners",
                    params={
                        "$select": "id,displayName,userPrincipalName,appId,servicePrincipalType"
                    },
                )
                for application in applications
                if (app_object_id := application.get("id"))
            ],
            lambda request: self.graph.list_application_owners(str(request.key)),
        )

        for application in applications:
            app_object_id = application.get("id")
            if not app_object_id:
                continue
            application_app_id = application.get("appId") or app_object_id

            backing_sp = service_principal_by_app_id.get(application.get("appId"))

            exc = federated_credential_errors.get(app_object_id)
            if exc is not None:
                issues.append(
                    _issue_from_exception(
                        f"role_trusts.applications[{app_object_id}].federated_credentials",
                        exc,
                    )
                )
                federated_credentials = []
            else:
                federated_credentials = federated_credentials_by_application.get(app_object_id, [])

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

            exc = application_owner_errors.get(app_object_id)
            if exc is not None:
                issues.append(
                    _issue_from_exception(
                        f"role_trusts.applications[{app_object_id}].owners",
                        exc,
                    )
                )
                owners = []
            else:
                owners = application_owners_by_id.get(app_object_id, [])

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

        service_principal_owners_by_id, service_principal_owner_errors = (
            _graph_batch_list_with_fallback(
                self.graph,
                [
                    GraphBatchRequest(
                        key=sp_id,
                        path=f"/servicePrincipals/{sp_id}/owners",
                        params={
                            "$select": "id,displayName,userPrincipalName,appId,servicePrincipalType"
                        },
                    )
                    for service_principal in service_principals
                    if (sp_id := service_principal.get("id"))
                ],
                lambda request: self.graph.list_service_principal_owners(str(request.key)),
            )
        )
        assignments_by_service_principal_id, assignment_errors = _graph_batch_list_with_fallback(
            self.graph,
            [
                GraphBatchRequest(
                    key=sp_id,
                    path=f"/servicePrincipals/{sp_id}/appRoleAssignments",
                    params={"$select": "id,appRoleId,principalId,resourceId"},
                )
                for service_principal in service_principals
                if (sp_id := service_principal.get("id"))
            ],
            lambda request: self.graph.list_app_role_assignments(str(request.key)),
        )
        missing_resource_ids = sorted(
            {
                str(assignment.get("resourceId"))
                for assignments in assignments_by_service_principal_id.values()
                for assignment in assignments
                if assignment.get("resourceId")
                and assignment.get("resourceId") not in service_principal_by_id
            }
        )
        resources_by_id, resource_errors = _graph_batch_get_with_fallback(
            self.graph,
            [
                GraphBatchRequest(
                    key=resource_id,
                    path=f"/servicePrincipals/{resource_id}",
                    params={
                        "$select": (
                            "id,appId,displayName,servicePrincipalType,appOwnerOrganizationId"
                        )
                    },
                )
                for resource_id in missing_resource_ids
            ],
            lambda request: self.graph.get_service_principal(str(request.key)),
        )
        for resource_id in missing_resource_ids:
            resource = resources_by_id.get(resource_id, {})
            if resource.get("id"):
                service_principal_by_id[resource["id"]] = resource

        for service_principal in service_principals:
            sp_id = service_principal.get("id")
            if not sp_id:
                continue

            exc = service_principal_owner_errors.get(sp_id)
            if exc is not None:
                issues.append(
                    _issue_from_exception(
                        f"role_trusts.service_principals[{sp_id}].owners",
                        exc,
                    )
                )
                owners = []
            else:
                owners = service_principal_owners_by_id.get(sp_id, [])

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

            exc = assignment_errors.get(sp_id)
            if exc is not None:
                issues.append(
                    _issue_from_exception(
                        f"role_trusts.service_principals[{sp_id}].app_role_assignments",
                        exc,
                    )
                )
                assignments = []
            else:
                assignments = assignments_by_service_principal_id.get(sp_id, [])

            for assignment in assignments:
                resource_id = assignment.get("resourceId")
                resource = service_principal_by_id.get(resource_id)
                if resource is None and resource_id:
                    exc = resource_errors.get(str(resource_id))
                    if exc is not None:
                        issues.append(
                            _issue_from_exception(
                                f"role_trusts.service_principals[{sp_id}].resource[{resource_id}]",
                                exc,
                            )
                        )
                        resource = {}
                    else:
                        resource = resources_by_id.get(str(resource_id), {})
                        if resource.get("id"):
                            service_principal_by_id[resource["id"]] = resource
                resource_name = resource.get("displayName") or resource_id or "unknown"
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

    def lighthouse(self) -> dict:
        issues: list[dict] = []
        lighthouse_delegations: list[dict] = []
        role_name_cache: dict[str, str] = {}
        seen_assignment_ids: set[str] = set()
        subscription_scope = f"/subscriptions/{self.clients.subscription_id}"

        try:
            assignments = self._list_managed_services_assignments(subscription_scope)
            for assignment in assignments:
                assignment_id = str(assignment.get("id") or "")
                if assignment_id in seen_assignment_ids:
                    continue
                seen_assignment_ids.add(assignment_id)
                lighthouse_delegations.append(
                    _lighthouse_delegation_summary(
                        assignment,
                        subscription_scope,
                        lambda scope, role_definition_id: self._resolve_role_name(
                            scope,
                            role_definition_id,
                            role_name_cache,
                        ),
                    )
                )
        except Exception as exc:
            issues.append(_issue_from_exception("lighthouse.subscription", exc))

        resource_groups: list[str] = []
        try:
            resource_groups = [group.name for group in self.clients.resource.resource_groups.list()]
        except Exception as exc:
            issues.append(_issue_from_exception("lighthouse.resource_groups", exc))

        for resource_group in resource_groups:
            scope = f"{subscription_scope}/resourceGroups/{resource_group}"
            try:
                assignments = self._list_managed_services_assignments(scope)
                for assignment in assignments:
                    assignment_id = str(assignment.get("id") or "")
                    if assignment_id in seen_assignment_ids:
                        continue
                    seen_assignment_ids.add(assignment_id)
                    lighthouse_delegations.append(
                        _lighthouse_delegation_summary(
                            assignment,
                            scope,
                            lambda assignment_scope, role_definition_id: self._resolve_role_name(
                                assignment_scope,
                                role_definition_id,
                                role_name_cache,
                            ),
                        )
                    )
            except Exception as exc:
                issues.append(
                    _issue_from_exception(
                        f"lighthouse.resource_group[{resource_group}]",
                        exc,
                    )
                )

        return {"lighthouse_delegations": lighthouse_delegations, "issues": issues}

    def cross_tenant(self) -> dict:
        issues: list[dict] = []
        tenant_id = self.session.tenant_id

        lighthouse_data = self.lighthouse()
        auth_policy_data = self.auth_policies()
        principal_data = self.principals()

        issues.extend(lighthouse_data.get("issues", []))
        issues.extend(auth_policy_data.get("issues", []))
        issues.extend(principal_data.get("issues", []))

        principal_by_id = {
            item.get("id"): item
            for item in principal_data.get("principals", [])
            if isinstance(item, dict) and item.get("id")
        }

        cross_tenant_paths = [
            _cross_tenant_lighthouse_row(item)
            for item in lighthouse_data.get("lighthouse_delegations", [])
            if isinstance(item, dict)
        ]

        if tenant_id:
            try:
                service_principals = self.graph.list_service_principals()
            except Exception as exc:
                issues.append(_issue_from_exception("cross_tenant.service_principals", exc))
                service_principals = []

            for service_principal in service_principals:
                owner_tenant_id = service_principal.get("appOwnerOrganizationId")
                principal_id = service_principal.get("id")
                if (
                    not principal_id
                    or not owner_tenant_id
                    or str(owner_tenant_id).lower() == str(tenant_id).lower()
                ):
                    continue

                principal = principal_by_id.get(principal_id)
                cross_tenant_paths.append(
                    _cross_tenant_external_service_principal_row(service_principal, principal)
                )

        cross_tenant_paths.extend(
            _cross_tenant_policy_rows(auth_policy_data.get("auth_policies", []), tenant_id)
        )
        return {"cross_tenant_paths": cross_tenant_paths, "issues": issues}

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
                        "public_network_access": _string_value(
                            getattr(account, "public_network_access", None)
                        ),
                        "network_default_action": default_action,
                        "private_endpoint_enabled": len(private_endpoints) > 0,
                        "allow_shared_key_access": _bool_or_none(
                            getattr(account, "allow_shared_key_access", None)
                        ),
                        "minimum_tls_version": _string_value(
                            getattr(account, "minimum_tls_version", None)
                        ),
                        "https_traffic_only_enabled": _bool_or_none(
                            getattr(account, "enable_https_traffic_only", None)
                        ),
                        "is_hns_enabled": _bool_or_none(getattr(account, "is_hns_enabled", None)),
                        "is_sftp_enabled": _bool_or_none(getattr(account, "is_sftp_enabled", None)),
                        "nfs_v3_enabled": _bool_or_none(getattr(account, "enable_nfs_v3", None)),
                        "dns_endpoint_type": _string_value(
                            getattr(account, "dns_endpoint_type", None)
                        ),
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

    def snapshots_disks(self) -> dict:
        assets: list[dict] = []
        issues: list[dict] = []
        attachment_context: dict[str, dict[str, str | None]] = {}

        try:
            for vm in self.clients.compute.virtual_machines.list_all():
                vm_id = getattr(vm, "id", "unknown")
                vm_name = getattr(vm, "name", "unknown")
                storage_profile = getattr(vm, "storage_profile", None)
                if storage_profile is None:
                    continue

                os_disk = getattr(storage_profile, "os_disk", None)
                os_disk_id = getattr(getattr(os_disk, "managed_disk", None), "id", None)
                if os_disk_id:
                    attachment_context[str(os_disk_id)] = {
                        "attached_to_id": vm_id,
                        "attached_to_name": vm_name,
                        "disk_role": "os-disk",
                    }

                for data_disk in getattr(storage_profile, "data_disks", None) or []:
                    disk_id = getattr(getattr(data_disk, "managed_disk", None), "id", None)
                    if not disk_id:
                        continue
                    attachment_context[str(disk_id)] = {
                        "attached_to_id": vm_id,
                        "attached_to_name": vm_name,
                        "disk_role": "data-disk",
                    }
        except Exception as exc:
            issues.append(_issue_from_exception("snapshots_disks.vm_attachment_context", exc))

        try:
            for disk in self.clients.compute.disks.list():
                disk_id = getattr(disk, "id", "unknown")
                attachment = attachment_context.get(str(disk_id), {})
                creation_data = getattr(disk, "creation_data", None)
                source_resource_id = _string_value(
                    getattr(creation_data, "source_resource_id", None)
                )
                encryption = getattr(disk, "encryption", None)
                attached_to_id = _string_value(
                    attachment.get("attached_to_id") or getattr(disk, "managed_by", None)
                )
                asset = {
                    "id": disk_id,
                    "name": getattr(disk, "name", "unknown"),
                    "asset_kind": "disk",
                    "resource_group": _resource_group_from_id(disk_id),
                    "location": getattr(disk, "location", None),
                    "disk_role": _string_value(attachment.get("disk_role")),
                    "attachment_state": "attached" if attached_to_id else "detached",
                    "attached_to_id": attached_to_id,
                    "attached_to_name": _string_value(attachment.get("attached_to_name"))
                    or _resource_name_from_id(attached_to_id),
                    "source_resource_id": source_resource_id,
                    "source_resource_name": _resource_name_from_id(source_resource_id),
                    "source_resource_kind": _snapshot_disk_source_kind(source_resource_id),
                    "os_type": _string_value(getattr(disk, "os_type", None)),
                    "size_gb": getattr(disk, "disk_size_gb", None),
                    "time_created": _datetime_to_string(getattr(disk, "time_created", None)),
                    "incremental": None,
                    "network_access_policy": _string_value(
                        getattr(disk, "network_access_policy", None)
                    ),
                    "public_network_access": _string_value(
                        getattr(disk, "public_network_access", None)
                    ),
                    "disk_access_id": _string_value(getattr(disk, "disk_access_id", None)),
                    "max_shares": getattr(disk, "max_shares", None),
                    "encryption_type": _string_value(getattr(encryption, "type", None)),
                    "disk_encryption_set_id": _string_value(
                        getattr(encryption, "disk_encryption_set_id", None)
                    ),
                }
                asset["summary"] = _snapshot_disk_summary(asset)
                asset["related_ids"] = [
                    item
                    for item in (
                        asset.get("attached_to_id"),
                        asset.get("source_resource_id"),
                        asset.get("disk_access_id"),
                        asset.get("disk_encryption_set_id"),
                    )
                    if item
                ]
                assets.append(asset)
        except Exception as exc:
            issues.append(_issue_from_exception("snapshots_disks.disks", exc))

        try:
            for snapshot in self.clients.compute.snapshots.list():
                snapshot_id = getattr(snapshot, "id", "unknown")
                creation_data = getattr(snapshot, "creation_data", None)
                source_resource_id = _string_value(
                    getattr(creation_data, "source_resource_id", None)
                )
                encryption = getattr(snapshot, "encryption", None)
                asset = {
                    "id": snapshot_id,
                    "name": getattr(snapshot, "name", "unknown"),
                    "asset_kind": "snapshot",
                    "resource_group": _resource_group_from_id(snapshot_id),
                    "location": getattr(snapshot, "location", None),
                    "disk_role": None,
                    "attachment_state": "snapshot",
                    "attached_to_id": None,
                    "attached_to_name": None,
                    "source_resource_id": source_resource_id,
                    "source_resource_name": _resource_name_from_id(source_resource_id),
                    "source_resource_kind": _snapshot_disk_source_kind(source_resource_id),
                    "os_type": _string_value(getattr(snapshot, "os_type", None)),
                    "size_gb": getattr(snapshot, "disk_size_gb", None),
                    "time_created": _datetime_to_string(getattr(snapshot, "time_created", None)),
                    "incremental": _bool_or_none(getattr(snapshot, "incremental", None)),
                    "network_access_policy": _string_value(
                        getattr(snapshot, "network_access_policy", None)
                    ),
                    "public_network_access": _string_value(
                        getattr(snapshot, "public_network_access", None)
                    ),
                    "disk_access_id": _string_value(getattr(snapshot, "disk_access_id", None)),
                    "max_shares": getattr(snapshot, "max_shares", None),
                    "encryption_type": _string_value(getattr(encryption, "type", None)),
                    "disk_encryption_set_id": _string_value(
                        getattr(encryption, "disk_encryption_set_id", None)
                    ),
                }
                asset["summary"] = _snapshot_disk_summary(asset)
                asset["related_ids"] = [
                    item
                    for item in (
                        asset.get("source_resource_id"),
                        asset.get("disk_access_id"),
                        asset.get("disk_encryption_set_id"),
                    )
                    if item
                ]
                assets.append(asset)
        except Exception as exc:
            issues.append(_issue_from_exception("snapshots_disks.snapshots", exc))

        return {"snapshot_disk_assets": assets, "issues": issues}

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
                    resolved_public_ips, public_ip_issues = self._resolve_public_ip_addresses(
                        nic_detail
                    )
                    issues.extend(public_ip_issues)
                    public_ips.extend(resolved_public_ips)

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

        except Exception as exc:
            issues.append(_issue_from_exception("vms", exc))

        return {"vm_assets": vm_assets, "issues": issues}

    def vmss(self) -> dict:
        vmss_assets: list[dict] = []
        issues: list[dict] = []

        try:
            for vmss in self.clients.compute.virtual_machine_scale_sets.list_all():
                vmss_asset, vmss_issues = _vmss_summary(vmss)
                vmss_assets.append(vmss_asset)
                issues.extend(vmss_issues)
        except Exception as exc:
            issues.append(_issue_from_exception("vmss", exc))

        return {"vmss_assets": vmss_assets, "issues": issues}

    def nics(self) -> dict:
        nic_assets: list[dict] = []
        issues: list[dict] = []

        try:
            for nic in self.clients.network.network_interfaces.list_all():
                nic_assets.append(_nic_detail_from_resource(nic))
        except Exception as exc:
            issues.append(_issue_from_exception("nics", exc))

        return {"nic_assets": nic_assets, "issues": issues}

    def network_ports(self, endpoint_data: dict | None = None) -> dict:
        if endpoint_data is None:
            endpoint_data = self.endpoints()
        nic_data = self.nics()
        issues = [*endpoint_data.get("issues", []), *nic_data.get("issues", [])]

        nic_by_asset: dict[str, list[dict]] = {}
        for nic in nic_data.get("nic_assets", []):
            attached_asset_key = _arm_id_join_key(nic.get("attached_asset_id"))
            if attached_asset_key:
                nic_by_asset.setdefault(attached_asset_key, []).append(nic)

        subnet_cache: dict[str, str | None] = {}
        nsg_cache: dict[str, list[dict]] = {}
        network_ports: list[dict] = []
        seen: set[tuple[str, str, str, str, str]] = set()

        for endpoint in endpoint_data.get("endpoints", []):
            if endpoint.get("endpoint_type") != "ip":
                continue
            if endpoint.get("exposure_family") != "public-ip":
                continue

            asset_nics = nic_by_asset.get(
                _arm_id_join_key(endpoint.get("source_asset_id")) or "",
                [],
            )
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
        role_key = role_definition_id.rstrip("/").split("/")[-1].lower()
        try:
            role = self.clients.authorization.role_definitions.get(scope, role_key)
            role_name = getattr(role, "role_name", None)
        except Exception:
            role_name = _HIGH_IMPACT_ROLE_IDS.get(role_key)

        cache[role_definition_id] = role_name or "Unknown"
        return cache[role_definition_id]

    def _list_managed_services_assignments(self, scope: str) -> list[dict]:
        return self._arm_list(
            f"{scope}/providers/Microsoft.ManagedServices/registrationAssignments",
            params={
                "api-version": "2022-10-01",
                "$expandRegistrationDefinition": "true",
            },
        )

    def _arm_list(
        self,
        path_or_url: str,
        params: dict[str, str] | None = None,
    ) -> list[dict[str, object]]:
        url = path_or_url
        if not path_or_url.startswith("https://"):
            url = f"https://management.azure.com{path_or_url}"
        if params:
            url = f"{url}?{urlencode(params)}"

        items: list[dict[str, object]] = []
        next_url: str | None = url
        while next_url:
            payload = self._arm_get(next_url)
            values = payload.get("value", [])
            if isinstance(values, list):
                items.extend(item for item in values if isinstance(item, dict))
            next_link = payload.get("nextLink")
            next_url = next_link if isinstance(next_link, str) else None
        return items

    def _arm_get(self, url: str) -> dict[str, object]:
        token = self.session.credential.get_token(MANAGEMENT_SCOPE).token
        request = Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
        )
        try:
            with urlopen(request, context=_arm_ssl_context(), timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="ignore")
            raise AzureFoxError(
                classify_exception(exc),
                f"ARM request failed for {url}: {exc.code} {exc.reason}",
                details={"body": body[:500]},
            ) from exc
        except URLError as exc:
            raise AzureFoxError(
                classify_exception(exc),
                f"ARM request failed for {url}: {exc.reason}",
            ) from exc

    def _devops_list_values(self, url: str) -> list[dict[str, object]]:
        items: list[dict[str, object]] = []
        continuation_token: str | None = None

        while True:
            request_url = url
            if continuation_token:
                request_url = _set_query_param(url, "continuationToken", continuation_token)

            payload, headers = self._devops_get(request_url)
            values = payload.get("value", [])
            if isinstance(values, list):
                items.extend(item for item in values if isinstance(item, dict))

            continuation_token = headers.get("x-ms-continuationtoken") or headers.get(
                "continuationtoken"
            )
            if not continuation_token:
                break

        return items

    def _devops_get(self, url: str) -> tuple[dict[str, object], dict[str, str]]:
        token = self.session.credential.get_token(DEVOPS_SCOPE).token
        request = Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
        )
        try:
            with urlopen(request, context=_arm_ssl_context(), timeout=30) as response:
                payload = json.loads(response.read().decode("utf-8"))
                headers = {key.lower(): value for key, value in response.headers.items()}
                return payload, headers
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="ignore")
            raise AzureFoxError(
                classify_exception(exc),
                f"Azure DevOps request failed for {url}: {exc.code} {exc.reason}",
                details={"body": body[:500]},
            ) from exc
        except URLError as exc:
            raise AzureFoxError(
                classify_exception(exc),
                f"Azure DevOps request failed for {url}: {exc.reason}",
            ) from exc

    def _devops_post(
        self,
        url: str,
        payload: dict[str, object],
    ) -> tuple[dict[str, object], dict[str, str]]:
        token = self.session.credential.get_token(DEVOPS_SCOPE).token
        request = Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, context=_arm_ssl_context(), timeout=30) as response:
                body = response.read()
                parsed = json.loads(body.decode("utf-8")) if body else {}
                headers = {key.lower(): value for key, value in response.headers.items()}
                return parsed, headers
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="ignore")
            raise AzureFoxError(
                classify_exception(exc),
                f"Azure DevOps request failed for {url}: {exc.code} {exc.reason}",
                details={"body": body[:500]},
            ) from exc
        except URLError as exc:
            raise AzureFoxError(
                classify_exception(exc),
                f"Azure DevOps request failed for {url}: {exc.reason}",
            ) from exc

    def _devops_build_definition_permissions(
        self,
        *,
        organization: str,
        project_id: str,
        definition_id: str,
    ) -> dict[str, bool | None]:
        if not project_id or not definition_id:
            return {
                "current_operator_can_view_definition": None,
                "current_operator_can_queue": None,
                "current_operator_can_edit": None,
            }

        action_bits = self._devops_namespace_action_bits(
            organization=organization,
            namespace_id=_DEVOPS_BUILD_NAMESPACE_ID,
            action_names=("ViewBuildDefinition", "QueueBuilds", "EditBuildDefinition"),
        )
        token = f"{project_id}/{definition_id}"
        evaluations = [
            {
                "securityNamespaceId": _DEVOPS_BUILD_NAMESPACE_ID,
                "token": token,
                "permissions": bit,
            }
            for bit in action_bits.values()
            if bit is not None
        ]
        if not evaluations:
            return {
                "current_operator_can_view_definition": None,
                "current_operator_can_queue": None,
                "current_operator_can_edit": None,
            }

        payload, _headers = self._devops_post(
            f"https://dev.azure.com/{organization}/_apis/security/permissionevaluationbatch?api-version=7.1",
            {
                "alwaysAllowAdministrators": False,
                "evaluations": evaluations,
            },
        )
        results: dict[int, bool] = {}
        for item in (
            payload.get("evaluations", []) if isinstance(payload.get("evaluations"), list) else []
        ):
            if not isinstance(item, dict):
                continue
            permission_bit = item.get("permissions")
            value = item.get("value")
            if isinstance(permission_bit, int) and isinstance(value, bool):
                results[permission_bit] = value

        return {
            "current_operator_can_view_definition": results.get(
                action_bits.get("ViewBuildDefinition", -1)
            ),
            "current_operator_can_queue": results.get(action_bits.get("QueueBuilds", -1)),
            "current_operator_can_edit": results.get(action_bits.get("EditBuildDefinition", -1)),
        }

    def _devops_git_repository_permissions(
        self,
        *,
        organization: str,
        project_id: str,
        repository_id: str,
    ) -> dict[str, bool | None]:
        if not project_id or not repository_id:
            return {
                "current_operator_can_view_source": None,
                "current_operator_can_contribute_source": None,
            }

        action_bits = self._devops_namespace_action_bits(
            organization=organization,
            namespace_id=_DEVOPS_GIT_NAMESPACE_ID,
            action_names=("GenericRead", "GenericContribute"),
        )
        token = f"repoV2/{project_id}/{repository_id}"
        evaluations = [
            {
                "securityNamespaceId": _DEVOPS_GIT_NAMESPACE_ID,
                "token": token,
                "permissions": bit,
            }
            for bit in action_bits.values()
            if bit is not None
        ]
        if not evaluations:
            return {
                "current_operator_can_view_source": None,
                "current_operator_can_contribute_source": None,
            }

        payload, _headers = self._devops_post(
            f"https://dev.azure.com/{organization}/_apis/security/permissionevaluationbatch?api-version=7.1",
            {
                "alwaysAllowAdministrators": False,
                "evaluations": evaluations,
            },
        )
        results: dict[int, bool] = {}
        for item in (
            payload.get("evaluations", []) if isinstance(payload.get("evaluations"), list) else []
        ):
            if not isinstance(item, dict):
                continue
            permission_bit = item.get("permissions")
            value = item.get("value")
            if isinstance(permission_bit, int) and isinstance(value, bool):
                results[permission_bit] = value

        return {
            "current_operator_can_view_source": results.get(action_bits.get("GenericRead", -1)),
            "current_operator_can_contribute_source": results.get(
                action_bits.get("GenericContribute", -1)
            ),
        }

    def _devops_namespace_action_bits(
        self,
        *,
        organization: str,
        namespace_id: str,
        action_names: tuple[str, ...],
    ) -> dict[str, int | None]:
        cache_key = f"{organization}:{namespace_id}"
        if cache_key not in self._devops_namespace_actions_cache:
            payload, _headers = self._devops_get(
                f"https://dev.azure.com/{organization}/_apis/securitynamespaces/{namespace_id}?api-version=7.1"
            )
            description = payload
            if isinstance(payload.get("value"), list) and payload["value"]:
                first = payload["value"][0]
                if isinstance(first, dict):
                    description = first
            actions = description.get("actions", []) if isinstance(description, dict) else []
            self._devops_namespace_actions_cache[cache_key] = {
                str(item.get("name")): int(item.get("bit"))
                for item in actions
                if isinstance(item, dict) and item.get("name") and isinstance(item.get("bit"), int)
            }
        action_map = self._devops_namespace_actions_cache[cache_key]
        return {name: action_map.get(name) for name in action_names}

    def _devops_current_operator_identity(
        self,
        *,
        organization: str,
    ) -> dict[str, object]:
        cached = self._devops_current_operator_cache.get(organization)
        if cached is not None:
            return dict(cached)

        profile, _headers = self._devops_get(
            "https://app.vssps.visualstudio.com/_apis/profile/profiles/me?api-version=7.1"
        )
        profile_id = str(profile.get("id") or "") or None
        descriptor = None
        if profile_id:
            descriptor_payload, _headers = self._devops_get(
                "https://vssps.dev.azure.com/"
                f"{organization}/_apis/graph/descriptors/{quote(profile_id, safe='')}"
                "?api-version=7.1-preview.1"
            )
            descriptor = str(descriptor_payload.get("value") or "") or None

        subject_descriptors: list[str] = []
        if descriptor:
            subject_descriptors.append(descriptor)
            memberships, _headers = self._devops_get(
                "https://vssps.dev.azure.com/"
                f"{organization}/_apis/graph/Memberships/{quote(descriptor, safe='')}"
                "?direction=up&depth=1&api-version=7.1-preview.1"
            )
            for membership in memberships.get("value", []) if isinstance(
                memberships.get("value"), list
            ) else []:
                if not isinstance(membership, dict):
                    continue
                container_descriptor = str(membership.get("containerDescriptor") or "") or None
                if container_descriptor:
                    subject_descriptors.append(container_descriptor)

        result = {
            "profile_id": profile_id,
            "descriptor": descriptor,
            "subject_descriptors": _dedupe_strings(subject_descriptors),
        }
        self._devops_current_operator_cache[organization] = dict(result)
        return result

    def _devops_secure_files(
        self,
        *,
        organization: str,
        project_name: str,
    ) -> dict[str, dict[str, object]]:
        cache_key = f"{organization}:{project_name}"
        cached = self._devops_secure_files_cache.get(cache_key)
        if cached is not None:
            return {key: dict(value) for key, value in cached.items()}

        project_path = quote(project_name, safe="")
        secure_files = self._devops_list_values(
            "https://dev.azure.com/"
            f"{organization}/{project_path}/_apis/distributedtask/securefiles?api-version=7.1"
        )
        mapped = {
            str(item.get("name") or "").strip().lower(): item
            for item in secure_files
            if str(item.get("name") or "").strip()
        }
        self._devops_secure_files_cache[cache_key] = mapped
        return {key: dict(value) for key, value in mapped.items()}

    def _devops_secure_file_role_assignments(
        self,
        *,
        organization: str,
        project_id: str,
        secure_file_id: str,
    ) -> list[dict[str, object]]:
        if not project_id or not secure_file_id:
            return []

        candidate_resource_ids = _dedupe_strings(
            [
                f"{project_id}${secure_file_id}",
                f"{project_id}_{secure_file_id}",
                f"{project_id}/{secure_file_id}",
                secure_file_id,
            ]
        )
        last_error: Exception | None = None
        for resource_id in candidate_resource_ids:
            cache_key = (
                f"{organization}:{_DEVOPS_SECURE_FILE_ROLE_SCOPE_ID}:{resource_id}"
            )
            if cache_key in self._devops_secure_file_roles_cache:
                return [
                    dict(item) for item in self._devops_secure_file_roles_cache[cache_key]
                ]

            try:
                payload, _headers = self._devops_get(
                    "https://dev.azure.com/"
                    f"{organization}/_apis/securityroles/scopes/"
                    f"{quote(_DEVOPS_SECURE_FILE_ROLE_SCOPE_ID, safe='')}/roleassignments/"
                    f"resources/{quote(resource_id, safe='')}"
                    "?api-version=7.1-preview.1"
                )
            except AzureFoxError as exc:
                last_error = exc
                continue

            assignments = [
                item for item in payload.get("value", []) if isinstance(item, dict)
            ] if isinstance(payload.get("value"), list) else (
                [item for item in payload if isinstance(item, dict)]
                if isinstance(payload, list)
                else []
            )
            self._devops_secure_file_roles_cache[cache_key] = assignments
            return [dict(item) for item in assignments]

        if last_error is not None:
            raise last_error
        return []

    def _devops_feed_permissions(
        self,
        *,
        organization: str,
        project_name: str | None,
        feed_name: str,
        identity_descriptor: str,
    ) -> list[dict[str, object]]:
        if not feed_name or not identity_descriptor:
            return []

        project_cache_key = project_name or "_org"
        cache_key = f"{organization}:{project_cache_key}:{feed_name}:{identity_descriptor}"
        cached = self._devops_feed_permissions_cache.get(cache_key)
        if cached is not None:
            return [dict(item) for item in cached]

        project_path = f"{quote(project_name, safe='')}/" if project_name else ""
        payload, _headers = self._devops_get(
            "https://feeds.dev.azure.com/"
            f"{organization}/{project_path}_apis/packaging/Feeds/"
            f"{quote(feed_name, safe='')}/permissions"
            f"?includeIds=true&excludeInheritedPermissions=false&identityDescriptor="
            f"{quote(identity_descriptor, safe='')}&api-version=7.1"
        )
        permissions = [
            item for item in payload.get("value", []) if isinstance(item, dict)
        ] if isinstance(payload.get("value"), list) else []
        self._devops_feed_permissions_cache[cache_key] = permissions
        return [dict(item) for item in permissions]

    def _devops_enrich_non_artifact_trusted_inputs(
        self,
        *,
        organization: str,
        project_name: str,
        project_id: str,
        trusted_inputs: list[dict[str, object]],
        current_operator: dict[str, object] | None,
    ) -> list[dict[str, object]]:
        enriched: list[dict[str, object]] = []
        descriptor = (
            str(current_operator.get("descriptor") or "")
            if isinstance(current_operator, dict)
            else ""
        )
        for trusted_input in trusted_inputs:
            item = dict(trusted_input)
            input_type = str(item.get("input_type") or "")
            if input_type == "template-repository":
                repo_project_id, repo_id = _devops_repo_project_and_id(item.get("join_ids") or [])
                if repo_project_id and repo_id:
                    permissions = self._devops_git_repository_permissions(
                        organization=organization,
                        project_id=repo_project_id,
                        repository_id=repo_id,
                    )
                    item = _devops_apply_repository_permission_proof(
                        item,
                        can_view=permissions.get("current_operator_can_view_source"),
                        can_contribute=permissions.get("current_operator_can_contribute_source"),
                        permission_source="azure-devops-git-permissions",
                    )
            elif input_type == "package-feed" and descriptor:
                feed_project_name, feed_name = _devops_feed_scope_from_trusted_input(item)
                if feed_name:
                    item = _devops_apply_feed_permission_proof(
                        item,
                        permissions=self._devops_feed_permissions(
                            organization=organization,
                            project_name=feed_project_name,
                            feed_name=feed_name,
                            identity_descriptor=descriptor,
                        ),
                    )
            elif input_type == "secure-file":
                secure_file_name = _devops_secure_file_name_from_trusted_input(item)
                secure_file = None
                if secure_file_name:
                    secure_file = self._devops_secure_files(
                        organization=organization,
                        project_name=project_name,
                    ).get(secure_file_name.strip().lower())
                if secure_file is not None:
                    item = _devops_apply_secure_file_role_proof(
                        item,
                        role_assignments=self._devops_secure_file_role_assignments(
                            organization=organization,
                            project_id=project_id,
                            secure_file_id=str(secure_file.get("id") or ""),
                        ),
                        current_operator=current_operator,
                    )
            enriched.append(item)
        return _devops_merge_trusted_inputs(enriched)

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

    def _resolve_public_ip_addresses(self, nic_detail: dict) -> tuple[list[str], list[dict]]:
        public_ips: list[str] = []
        issues: list[dict] = []

        for public_ip_id in nic_detail.get("public_ip_ids", []):
            pub_rg, pub_name = _resource_group_and_name(public_ip_id)
            if not pub_rg or not pub_name:
                continue

            try:
                pip = self.clients.network.public_ip_addresses.get(pub_rg, pub_name)
            except Exception as exc:
                issues.append(_issue_from_exception(f"public_ip_addresses[{public_ip_id}]", exc))
                continue

            ip_addr = getattr(pip, "ip_address", None)
            if ip_addr:
                public_ips.append(str(ip_addr))

        return _dedupe_strings(public_ips), issues

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
        "scope": area,
        "context": {"collector": area},
    }


def _collect_resource_type_summaries(
    *,
    resources_client: object,
    resource_type: str,
    api_version: str,
    summary_fn,
    list_issue_scope: str,
    hydrate_issue_scope: str,
) -> tuple[list[dict], list[dict]]:
    rows: list[dict] = []
    issues: list[dict] = []

    try:
        resources = resources_client.list(filter=f"resourceType eq '{resource_type}'")
        for resource in resources:
            resource_id = _string_value(getattr(resource, "id", None))
            hydrated = resource
            if resource_id:
                try:
                    hydrated = resources_client.get_by_id(resource_id, api_version)
                except Exception as exc:
                    issues.append(
                        _issue_from_exception(f"{hydrate_issue_scope}[{resource_id}]", exc)
                    )
                    hydrated = resource
            rows.append(summary_fn(hydrated))
    except Exception as exc:
        issues.append(_issue_from_exception(list_issue_scope, exc))

    return rows, issues


def _call_automation_operation(
    client: object,
    attrs: tuple[str, ...],
    method_name: str,
    *args,
) -> object:
    for attr in attrs:
        operation = getattr(client, attr, None)
        if operation is None:
            continue
        method = getattr(operation, method_name, None)
        if method is None:
            continue
        return method(*args)
    raise AttributeError(f"Automation client missing operation {attrs}::{method_name}")


def _automation_list_by_account(
    client: object,
    attrs: tuple[str, ...],
    resource_group: str,
    account_name: str,
) -> tuple[list[object] | None, dict | None]:
    collector_name = f"automation[{resource_group}/{account_name}].{attrs[0]}"
    try:
        result = _call_automation_operation(
            client,
            attrs,
            "list_by_automation_account",
            resource_group,
            account_name,
        )
        return list(result), None
    except Exception as exc:
        return None, _issue_from_exception(collector_name, exc)


def _automation_get_account(
    client: object,
    resource_group: str,
    account_name: str,
    *,
    fallback: object,
) -> tuple[object, dict | None]:
    collector_name = f"automation[{resource_group}/{account_name}].account"
    try:
        account = _call_automation_operation(
            client,
            ("automation_account", "automation_accounts"),
            "get",
            resource_group,
            account_name,
        )
        return account, None
    except Exception as exc:
        return fallback, _issue_from_exception(collector_name, exc)


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


def _automation_account_summary(
    account: object,
    *,
    runbooks: list[object] | None,
    schedules: list[object] | None,
    job_schedules: list[object] | None,
    webhooks: list[object] | None,
    credentials: list[object] | None,
    certificates: list[object] | None,
    connections: list[object] | None,
    variables: list[object] | None,
    hybrid_worker_groups: list[object] | None,
) -> dict:
    account_id = getattr(account, "id", "") or ""
    resource_group = _resource_group_from_id(account_id)
    identity = getattr(account, "identity", None)
    user_assigned_identities = getattr(identity, "user_assigned_identities", None) or {}
    identity_ids = sorted(str(key) for key in user_assigned_identities.keys())

    published_runbook_count = None
    if runbooks is not None:
        published_runbook_count = sum(
            str(
                getattr(getattr(runbook, "properties", None), "state", None)
                or getattr(runbook, "state", None)
                or ""
            ).lower()
            == "published"
            for runbook in runbooks
        )

    encrypted_variable_count = None
    if variables is not None:
        encrypted_variable_count = sum(
            bool(
                getattr(getattr(variable, "properties", None), "is_encrypted", None)
                if getattr(variable, "properties", None) is not None
                else getattr(variable, "is_encrypted", None)
            )
            for variable in variables
        )

    start_modes = _automation_start_modes(
        published_runbook_count=published_runbook_count,
        schedule_count=_len_or_none(schedules),
        job_schedule_count=_len_or_none(job_schedules),
        webhook_count=_len_or_none(webhooks),
        hybrid_worker_group_count=_len_or_none(hybrid_worker_groups),
    )
    published_runbook_names = _automation_published_runbook_names(runbooks)
    schedule_runbook_names = _automation_schedule_runbook_names(job_schedules)
    webhook_runbook_names = _automation_webhook_runbook_names(webhooks)
    primary_start_mode, primary_runbook_name = _automation_primary_run_path(
        start_modes=start_modes,
        published_runbook_names=published_runbook_names,
        schedule_runbook_names=schedule_runbook_names,
        webhook_runbook_names=webhook_runbook_names,
        hybrid_worker_group_count=_len_or_none(hybrid_worker_groups),
    )
    hybrid_worker_group_ids = _dedupe_strings(
        _string_value(getattr(group, "id", None)) for group in (hybrid_worker_groups or [])
    )
    trigger_join_ids = _dedupe_strings(
        [
            *(
                _automation_object_join_ids(job_schedules, prefix="automation-job-schedule")
                if job_schedules is not None
                else []
            ),
            *(
                _automation_object_join_ids(webhooks, prefix="automation-webhook")
                if webhooks is not None
                else []
            ),
            *(
                _automation_object_join_ids(hybrid_worker_groups, prefix="automation-hybrid-worker")
                if hybrid_worker_groups is not None
                else []
            ),
        ]
    )
    identity_join_ids = _dedupe_strings(
        [
            *identity_ids,
            _string_value(getattr(identity, "principal_id", None)) or "",
            _string_value(getattr(identity, "client_id", None)) or "",
        ]
    )
    secret_support_types = _automation_secret_support_types(
        credential_count=_len_or_none(credentials),
        certificate_count=_len_or_none(certificates),
        connection_count=_len_or_none(connections),
        encrypted_variable_count=encrypted_variable_count,
    )
    secret_dependency_ids = _dedupe_strings(
        [
            *(
                _automation_object_join_ids(credentials, prefix="automation-credential")
                if credentials is not None
                else []
            ),
            *(
                _automation_object_join_ids(certificates, prefix="automation-certificate")
                if certificates is not None
                else []
            ),
            *(
                _automation_object_join_ids(connections, prefix="automation-connection")
                if connections is not None
                else []
            ),
            *(
                _automation_object_join_ids(variables, prefix="automation-variable")
                if variables is not None
                else []
            ),
        ]
    )
    consequence_types = _deployment_consequence_types(
        target_clues=[],
        execution_modes=start_modes,
        secret_support_types=secret_support_types,
        source_command="automation",
    )
    missing_execution_path = not bool(
        [mode for mode in start_modes if mode != "manual-only"]
        or schedule_runbook_names
        or webhook_runbook_names
    )

    return {
        "id": account_id,
        "name": getattr(account, "name", None),
        "resource_group": resource_group,
        "location": getattr(account, "location", None),
        "state": getattr(account, "state", None),
        "sku_name": getattr(getattr(account, "sku", None), "name", None),
        "identity_type": getattr(identity, "type", None),
        "principal_id": getattr(identity, "principal_id", None),
        "client_id": getattr(identity, "client_id", None),
        "identity_ids": identity_ids,
        "runbook_count": _len_or_none(runbooks),
        "published_runbook_count": published_runbook_count,
        "published_runbook_names": published_runbook_names,
        "schedule_count": _len_or_none(schedules),
        "job_schedule_count": _len_or_none(job_schedules),
        "webhook_count": _len_or_none(webhooks),
        "hybrid_worker_group_count": _len_or_none(hybrid_worker_groups),
        "credential_count": _len_or_none(credentials),
        "certificate_count": _len_or_none(certificates),
        "connection_count": _len_or_none(connections),
        "variable_count": _len_or_none(variables),
        "encrypted_variable_count": encrypted_variable_count,
        "start_modes": start_modes,
        "primary_start_mode": primary_start_mode,
        "primary_runbook_name": primary_runbook_name,
        "schedule_runbook_names": schedule_runbook_names,
        "webhook_runbook_names": webhook_runbook_names,
        "hybrid_worker_group_ids": hybrid_worker_group_ids,
        "trigger_join_ids": trigger_join_ids,
        "identity_join_ids": identity_join_ids,
        "secret_support_types": secret_support_types,
        "secret_dependency_ids": secret_dependency_ids,
        "consequence_types": consequence_types,
        "missing_execution_path": missing_execution_path,
        "missing_target_mapping": True,
        "summary": _automation_account_operator_summary(
            account_name=getattr(account, "name", None) or "unknown",
            identity_type=getattr(identity, "type", None),
            runbook_count=_len_or_none(runbooks),
            published_runbook_count=published_runbook_count,
            schedule_count=_len_or_none(schedules),
            job_schedule_count=_len_or_none(job_schedules),
            webhook_count=_len_or_none(webhooks),
            hybrid_worker_group_count=_len_or_none(hybrid_worker_groups),
            credential_count=_len_or_none(credentials),
            certificate_count=_len_or_none(certificates),
            connection_count=_len_or_none(connections),
            variable_count=_len_or_none(variables),
            encrypted_variable_count=encrypted_variable_count,
        ),
        "related_ids": _dedupe_strings([account_id, *identity_ids]),
    }


def _automation_account_operator_summary(
    *,
    account_name: str,
    identity_type: object,
    runbook_count: int | None,
    published_runbook_count: int | None,
    schedule_count: int | None,
    job_schedule_count: int | None,
    webhook_count: int | None,
    hybrid_worker_group_count: int | None,
    credential_count: int | None,
    certificate_count: int | None,
    connection_count: int | None,
    variable_count: int | None,
    encrypted_variable_count: int | None,
) -> str:
    identity_clause = (
        f"uses managed identity ({identity_type})"
        if identity_type
        else "has no managed identity visible from the current read path"
    )
    runbook_clause = _automation_runbook_clause(runbook_count, published_runbook_count)
    trigger_clause = _automation_trigger_clause(
        schedule_count=schedule_count,
        job_schedule_count=job_schedule_count,
        webhook_count=webhook_count,
    )
    worker_clause = _automation_worker_clause(hybrid_worker_group_count)
    asset_clause = _automation_asset_clause(
        credential_count=credential_count,
        certificate_count=certificate_count,
        connection_count=connection_count,
        variable_count=variable_count,
        encrypted_variable_count=encrypted_variable_count,
    )
    return (
        f"Automation account '{account_name}' {identity_clause}. "
        f"Visible execution shape: {runbook_clause}; {trigger_clause}; {worker_clause}. "
        f"Secure asset posture: {asset_clause}."
    )


def _automation_runbook_clause(
    runbook_count: int | None,
    published_runbook_count: int | None,
) -> str:
    if runbook_count is None:
        return "runbook visibility unreadable"
    if published_runbook_count is None:
        return f"{runbook_count} runbook(s)"
    return f"{published_runbook_count}/{runbook_count} published runbook(s)"


def _automation_trigger_clause(
    *,
    schedule_count: int | None,
    job_schedule_count: int | None,
    webhook_count: int | None,
) -> str:
    parts: list[str] = []
    parts.append(
        "schedules unreadable" if schedule_count is None else f"{schedule_count} schedule(s)"
    )
    parts.append(
        "job schedules unreadable"
        if job_schedule_count is None
        else f"{job_schedule_count} job schedule(s)"
    )
    parts.append("webhooks unreadable" if webhook_count is None else f"{webhook_count} webhook(s)")
    return ", ".join(parts)


def _automation_worker_clause(hybrid_worker_group_count: int | None) -> str:
    if hybrid_worker_group_count is None:
        return "Hybrid Runbook Worker visibility unreadable"
    if hybrid_worker_group_count == 0:
        return "no Hybrid Runbook Worker groups visible"
    return f"{hybrid_worker_group_count} Hybrid Runbook Worker group(s)"


def _automation_asset_clause(
    *,
    credential_count: int | None,
    certificate_count: int | None,
    connection_count: int | None,
    variable_count: int | None,
    encrypted_variable_count: int | None,
) -> str:
    parts = [
        _count_or_unreadable("credentials", credential_count),
        _count_or_unreadable("certificates", certificate_count),
        _count_or_unreadable("connections", connection_count),
    ]
    if variable_count is None:
        parts.append("variables unreadable")
    elif encrypted_variable_count is None:
        parts.append(f"variables {variable_count}")
    else:
        parts.append(f"variables {variable_count} ({encrypted_variable_count} encrypted)")
    return ", ".join(parts)


def _automation_start_modes(
    *,
    published_runbook_count: int | None,
    schedule_count: int | None,
    job_schedule_count: int | None,
    webhook_count: int | None,
    hybrid_worker_group_count: int | None,
) -> list[str]:
    modes: list[str] = []
    if schedule_count and schedule_count > 0:
        modes.append("schedule")
    if job_schedule_count and job_schedule_count > 0:
        modes.append("job-schedule")
    if webhook_count and webhook_count > 0:
        modes.append("webhook")
    if hybrid_worker_group_count and hybrid_worker_group_count > 0:
        modes.append("hybrid-worker")
    if published_runbook_count and published_runbook_count > 0 and not modes:
        modes.append("manual-only")
    return _dedupe_strings(modes)


def _automation_published_runbook_names(runbooks: list[object] | None) -> list[str]:
    if runbooks is None:
        return []
    published_names: list[str] = []
    for runbook in runbooks:
        state = str(
            getattr(getattr(runbook, "properties", None), "state", None)
            or getattr(runbook, "state", None)
            or ""
        ).lower()
        if state != "published":
            continue
        name = _automation_runbook_name(runbook)
        if name:
            published_names.append(name)
    return _dedupe_strings(published_names)


def _automation_primary_run_path(
    *,
    start_modes: list[str],
    published_runbook_names: list[str],
    schedule_runbook_names: list[str],
    webhook_runbook_names: list[str],
    hybrid_worker_group_count: int | None,
) -> tuple[str | None, str | None]:
    if webhook_runbook_names:
        return "webhook", webhook_runbook_names[0]
    if schedule_runbook_names:
        return "schedule", schedule_runbook_names[0]
    if published_runbook_names:
        if "manual-only" in start_modes:
            return "manual-only", published_runbook_names[0]
        return "published-runbook", published_runbook_names[0]
    if hybrid_worker_group_count and hybrid_worker_group_count > 0:
        return "hybrid-worker", None
    return None, None


def _automation_schedule_runbook_names(job_schedules: list[object] | None) -> list[str]:
    if job_schedules is None:
        return []
    return _dedupe_strings(_automation_runbook_name(item) for item in job_schedules)


def _automation_webhook_runbook_names(webhooks: list[object] | None) -> list[str]:
    if webhooks is None:
        return []
    return _dedupe_strings(_automation_runbook_name(item) for item in webhooks)


def _automation_runbook_name(item: object) -> str | None:
    properties = getattr(item, "properties", None)
    for candidate in (
        getattr(item, "name", None),
        getattr(properties, "name", None),
        getattr(item, "runbook_name", None),
        getattr(properties, "runbook_name", None),
        getattr(getattr(item, "runbook", None), "name", None),
        getattr(getattr(properties, "runbook", None), "name", None),
    ):
        text = _string_value(candidate)
        if text:
            return text
    return None


def _automation_object_join_ids(items: list[object] | None, *, prefix: str) -> list[str]:
    if items is None:
        return []
    ids: list[str] = []
    for item in items:
        raw_id = _string_value(getattr(item, "id", None))
        if raw_id:
            ids.append(raw_id)
        name = _string_value(getattr(item, "name", None))
        if name:
            ids.append(f"{prefix}:{name}")
    return _dedupe_strings(ids)


def _automation_secret_support_types(
    *,
    credential_count: int | None,
    certificate_count: int | None,
    connection_count: int | None,
    encrypted_variable_count: int | None,
) -> list[str]:
    types: list[str] = []
    if credential_count and credential_count > 0:
        types.append("credentials")
    if certificate_count and certificate_count > 0:
        types.append("certificates")
    if connection_count and connection_count > 0:
        types.append("connections")
    if encrypted_variable_count and encrypted_variable_count > 0:
        types.append("encrypted-variables")
    return types


def _count_or_unreadable(label: str, count: int | None) -> str:
    if count is None:
        return f"{label} unreadable"
    return f"{label} {count}"


def _len_or_none(items: list[object] | None) -> int | None:
    return None if items is None else len(items)


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


def _principal_records_from_sources(
    *,
    rbac_data: dict,
    whoami_data: dict,
    identity_data: dict,
) -> tuple[list[dict], list[dict], dict[str, list[str]]]:
    records: dict[str, dict] = {}
    assignment_scope_ids_by_principal: dict[str, list[str]] = {}
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
            assignment_scope_ids_by_principal.setdefault(principal_id, [])
            _append_unique(assignment_scope_ids_by_principal[principal_id], scope_id)
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

    principals = sorted(records.values(), key=_principal_sort_key)
    return principals, issues, assignment_scope_ids_by_principal


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


def _graph_optional_list(item: dict | None) -> list[dict]:
    if item is None:
        return []
    return [item]


def _graph_batch_list_with_fallback(
    graph: object,
    requests: list[GraphBatchRequest],
    serial_fetch,
) -> tuple[dict[str, list[dict]], dict[str, Exception]]:
    return _graph_batch_with_fallback(
        graph=graph,
        requests=requests,
        batch_method_name="batch_list_objects_by_key",
        serial_fetch=serial_fetch,
    )


def _graph_batch_get_with_fallback(
    graph: object,
    requests: list[GraphBatchRequest],
    serial_fetch,
) -> tuple[dict[str, dict], dict[str, Exception]]:
    return _graph_batch_with_fallback(
        graph=graph,
        requests=requests,
        batch_method_name="batch_get_objects_by_key",
        serial_fetch=serial_fetch,
    )


def _graph_batch_with_fallback(
    *,
    graph: object,
    requests: list[GraphBatchRequest],
    batch_method_name: str,
    serial_fetch,
) -> tuple[dict, dict[str, Exception]]:
    if not requests:
        return {}, {}

    batch_fetch = getattr(graph, batch_method_name, None)
    if callable(batch_fetch):
        return batch_fetch(requests)

    results: dict = {}
    errors: dict[str, Exception] = {}
    for request in requests:
        try:
            results[request.key] = serial_fetch(request)
        except Exception as exc:
            errors[request.key] = exc
    return results, errors


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
_HIGH_IMPACT_ROLE_IDS = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
}


def _principal_sort_key(item: dict) -> tuple[bool, bool, int, int, str, str]:
    try:
        assignment_count = int(item.get("role_assignment_count") or 0)
    except (TypeError, ValueError):
        assignment_count = 0
    return (
        not _principal_has_high_impact_roles(item.get("role_names", [])),
        not bool(item.get("attached_to")),
        -len(item.get("scope_ids", []) or []),
        -assignment_count,
        item.get("display_name") or "",
        item.get("id") or "",
    )


def _principal_has_high_impact_roles(role_names: list[object]) -> bool:
    return any(
        str(role).lower() in _HIGH_IMPACT_ROLE_NAMES for role in role_names if isinstance(role, str)
    )


def _privesc_sort_key(item: dict) -> tuple[int, bool, int, str, str]:
    return (
        {"high": 0, "medium": 1, "low": 2}.get(str(item.get("priority") or "").lower(), 9),
        not bool(item.get("current_identity")),
        privesc_path_sort_rank(str(item.get("path_type") or "")),
        str(item.get("principal") or ""),
        str(item.get("asset") or ""),
    )


def _privesc_starting_foothold(
    *, current_identity: bool, principal_name: str, current_foothold_label: str | None
) -> str:
    if current_identity:
        return f"{principal_name} (current foothold)"
    if current_foothold_label:
        return f"{current_foothold_label} (current foothold)"
    return "unknown current foothold"


def _arm_id_join_key(resource_id: object | None) -> str | None:
    text = str(resource_id or "").strip()
    if not text:
        return None
    return text.rstrip("/").lower()


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


def _scope_applies_to_resource(scope_id: str | None, resource_id: str | None) -> bool:
    if not scope_id or not resource_id:
        return False
    normalized_scope = str(scope_id).rstrip("/").lower()
    normalized_resource = str(resource_id).rstrip("/").lower()
    return normalized_resource == normalized_scope or normalized_resource.startswith(
        normalized_scope + "/"
    )


def _lighthouse_delegation_summary(
    assignment: dict,
    scope: str,
    resolve_role_name,
) -> dict:
    assignment_id = str(assignment.get("id") or "")
    properties = assignment.get("properties", {}) if isinstance(assignment, dict) else {}
    if not isinstance(properties, dict):
        properties = {}

    definition = properties.get("registrationDefinition", {})
    if not isinstance(definition, dict):
        definition = {}
    definition_properties = definition.get("properties", {})
    if not isinstance(definition_properties, dict):
        definition_properties = {}

    authorizations = definition_properties.get("authorizations", [])
    if not isinstance(authorizations, list):
        authorizations = []
    eligible_authorizations = definition_properties.get("eligibleAuthorizations", [])
    if not isinstance(eligible_authorizations, list):
        eligible_authorizations = []

    role_names = _dedupe_strings(
        [
            _lighthouse_resolved_role_name(item, scope, resolve_role_name)
            for item in authorizations
            if isinstance(item, dict)
        ]
    )
    eligible_role_names = _dedupe_strings(
        [
            _lighthouse_resolved_role_name(item, scope, resolve_role_name)
            for item in eligible_authorizations
            if isinstance(item, dict)
        ]
    )

    principal_ids = {
        str(item.get("principalId"))
        for item in authorizations
        if isinstance(item, dict) and item.get("principalId")
    }
    eligible_principal_ids = {
        str(item.get("principalId"))
        for item in eligible_authorizations
        if isinstance(item, dict) and item.get("principalId")
    }

    strongest_role_name = _lighthouse_strongest_role_name([*role_names, *eligible_role_names])
    all_role_names = [*role_names, *eligible_role_names]
    has_owner_role = any(str(name).lower() == "owner" for name in all_role_names)
    has_user_access_administrator = any(
        str(name).lower() == "user access administrator" for name in all_role_names
    )
    has_delegated_role_assignments = any(
        isinstance(item, dict) and bool(item.get("delegatedRoleDefinitionIds"))
        for item in authorizations
    )

    scope_id = assignment_id.rsplit(
        "/providers/Microsoft.ManagedServices/registrationAssignments/",
        1,
    )[0]
    if not scope_id:
        scope_id = scope
    scope_type = "resource_group" if "/resourcegroups/" in scope_id.lower() else "subscription"
    resource_group = _resource_group_from_id(scope_id)
    scope_display_name = resource_group or _resource_name_from_id(scope_id)

    plan = definition.get("plan", {})
    if not isinstance(plan, dict):
        plan = {}

    summary_parts: list[str] = []
    managed_by_name = definition_properties.get("managedByTenantName") or definition_properties.get(
        "managedByTenantId"
    )
    if managed_by_name:
        summary_parts.append(f"managed by {managed_by_name}")
    if strongest_role_name:
        summary_parts.append(f"strongest role {strongest_role_name}")
    if eligible_authorizations:
        summary_parts.append(f"{len(eligible_authorizations)} eligible authorization(s)")
    assignment_state = properties.get("provisioningState")
    if assignment_state and str(assignment_state).lower() != "succeeded":
        summary_parts.append(f"assignment state {assignment_state}")

    summary = "; ".join(summary_parts) or "Azure Lighthouse delegation visible at this scope."

    related_ids = [
        item
        for item in [assignment_id, scope_id, properties.get("registrationDefinitionId")]
        if item
    ]

    return {
        "id": assignment_id,
        "name": assignment.get("name") or _resource_name_from_id(assignment_id) or "unknown",
        "scope_id": scope_id,
        "scope_type": scope_type,
        "scope_display_name": scope_display_name,
        "resource_group": resource_group,
        "managed_by_tenant_id": definition_properties.get("managedByTenantId"),
        "managed_by_tenant_name": definition_properties.get("managedByTenantName"),
        "managee_tenant_id": definition_properties.get("manageeTenantId"),
        "managee_tenant_name": definition_properties.get("manageeTenantName"),
        "registration_definition_id": properties.get("registrationDefinitionId"),
        "registration_definition_name": definition_properties.get("registrationDefinitionName")
        or definition.get("name"),
        "description": definition_properties.get("description"),
        "authorization_count": len(authorizations),
        "eligible_authorization_count": len(eligible_authorizations),
        "principal_count": len(principal_ids),
        "eligible_principal_count": len(eligible_principal_ids),
        "role_names": role_names,
        "eligible_role_names": eligible_role_names,
        "strongest_role_name": strongest_role_name,
        "has_user_access_administrator": has_user_access_administrator,
        "has_owner_role": has_owner_role,
        "has_delegated_role_assignments": has_delegated_role_assignments,
        "provisioning_state": assignment_state,
        "definition_provisioning_state": definition_properties.get("provisioningState"),
        "plan_name": plan.get("name"),
        "plan_product": plan.get("product"),
        "plan_publisher": plan.get("publisher"),
        "summary": summary,
        "related_ids": related_ids,
    }


def _cross_tenant_lighthouse_row(item: dict) -> dict:
    scope_label = item.get("scope_display_name") or _resource_name_from_id(item.get("scope_id"))
    scope_type = item.get("scope_type") or "scope"
    if scope_type == "resource_group":
        scope = f"resource-group::{scope_label}"
    else:
        scope = f"subscription::{scope_label}"

    strongest_role = item.get("strongest_role_name") or "unknown"
    posture_parts = [f"strongest={strongest_role}"]
    posture_parts.append(f"eligible={item.get('eligible_authorization_count', 0)}")
    if item.get("has_delegated_role_assignments"):
        posture_parts.append("delegated-role-assign=yes")

    priority = "medium"
    if scope_type == "subscription" and (
        item.get("has_owner_role") or item.get("has_user_access_administrator")
    ):
        priority = "high"
    elif scope_type == "subscription" or item.get("has_owner_role"):
        priority = "medium"
    else:
        priority = "low"

    return {
        "id": item.get("id"),
        "signal_type": "lighthouse",
        "name": item.get("registration_definition_name") or item.get("name") or "lighthouse",
        "tenant_id": item.get("managed_by_tenant_id"),
        "tenant_name": item.get("managed_by_tenant_name"),
        "scope": scope,
        "posture": "; ".join(posture_parts),
        "attack_path": "control",
        "priority": priority,
        "summary": item.get("summary")
        or "Outside tenant has delegated management visibility at this scope.",
        "related_ids": item.get("related_ids", []),
    }


def _cross_tenant_external_service_principal_row(
    service_principal: dict,
    principal: dict | None,
) -> dict:
    principal_data = principal if isinstance(principal, dict) else {}
    role_names = principal_data.get("role_names", [])
    try:
        assignment_count = int(principal_data.get("role_assignment_count") or 0)
    except (TypeError, ValueError):
        assignment_count = 0

    scope_ids = principal_data.get("scope_ids", [])
    role_names = principal_data.get("role_names", [])
    high_impact = any(
        str(role).lower() in _HIGH_IMPACT_ROLE_NAMES for role in role_names if isinstance(role, str)
    )
    if high_impact:
        priority = "high"
    elif assignment_count > 0:
        priority = "medium"
    else:
        priority = "low"

    posture_parts = []
    if role_names:
        posture_parts.append(f"roles={','.join(role_names[:3])}")
    else:
        posture_parts.append("roles=none-visible")
    posture_parts.append(f"assignments={assignment_count}")
    posture_parts.append(f"scopes={len(scope_ids)}")

    display_name = (
        service_principal.get("displayName")
        or principal_data.get("display_name")
        or service_principal.get("appId")
        or service_principal.get("id")
        or "external service principal"
    )
    if high_impact:
        summary = (
            f"Service principal '{display_name}' appears to be owned by another tenant and holds "
            "high-impact Azure role assignments in the current environment."
        )
    elif assignment_count > 0:
        summary = (
            f"Service principal '{display_name}' appears to be owned by another tenant and also "
            "holds visible Azure role assignments in the current environment."
        )
    else:
        summary = (
            f"Service principal '{display_name}' appears to be owned by another tenant and is "
            "readable in the current tenant, but no Azure role assignments are visible through "
            "the current read path."
        )

    return {
        "id": service_principal.get("id"),
        "signal_type": "external-sp",
        "name": display_name,
        "tenant_id": service_principal.get("appOwnerOrganizationId"),
        "tenant_name": None,
        "scope": "tenant",
        "posture": "; ".join(posture_parts),
        "attack_path": "pivot",
        "priority": priority,
        "summary": summary,
        "related_ids": [item for item in [service_principal.get("id")] if item],
    }


def _cross_tenant_policy_rows(auth_policies: list[dict], tenant_id: str | None) -> list[dict]:
    rows: list[dict] = []
    for policy in auth_policies:
        if policy.get("policy_type") != "authorization-policy":
            continue

        controls = [str(item) for item in policy.get("controls", [])]
        guest_invites = next(
            (item.split(":", 1)[1] for item in controls if item.startswith("guest-invites:")),
            None,
        )
        users_can_register_apps = "users-can-register-apps" in controls
        user_consent = "user-consent:self-service" in controls
        if not (guest_invites or users_can_register_apps or user_consent):
            continue

        posture_parts = []
        if guest_invites:
            posture_parts.append(f"guest-invites={guest_invites}")
        if users_can_register_apps:
            posture_parts.append("app-registration=yes")
        if user_consent:
            posture_parts.append("user-consent=self-service")

        priority = "low"
        if guest_invites == "everyone":
            priority = "high"
        elif users_can_register_apps or user_consent:
            priority = "medium"

        rows.append(
            {
                "id": policy.get("related_ids", [policy.get("name")])[0],
                "signal_type": "policy",
                "name": policy.get("name") or "Authorization Policy",
                "tenant_id": tenant_id,
                "tenant_name": None,
                "scope": "tenant",
                "posture": "; ".join(posture_parts),
                "attack_path": "entry",
                "priority": priority,
                "summary": policy.get("summary")
                or "Tenant policy may make outside-tenant entry or consent easier to extend.",
                "related_ids": policy.get("related_ids", []),
            }
        )
    return rows


def _lighthouse_resolved_role_name(
    authorization: dict,
    scope: str,
    resolve_role_name,
) -> str | None:
    role_definition_id = authorization.get("roleDefinitionId")
    role_name = resolve_role_name(scope, role_definition_id)
    if role_name and role_name != "Unknown":
        return role_name
    if role_definition_id:
        return str(role_definition_id).rstrip("/").split("/")[-1]
    return None


def _lighthouse_strongest_role_name(role_names: list[str]) -> str | None:
    if not role_names:
        return None
    return min(role_names, key=_lighthouse_role_priority)


def _lighthouse_role_priority(role_name: str) -> tuple[int, str]:
    normalized = role_name.strip().lower()
    if normalized == "owner":
        return 0, normalized
    if normalized == "user access administrator":
        return 1, normalized
    if normalized == "contributor":
        return 2, normalized
    if normalized == "reader":
        return 4, normalized
    if normalized:
        return 3, normalized
    return 5, normalized


def _snapshot_disk_source_kind(resource_id: str | None) -> str | None:
    if not resource_id:
        return None
    normalized = resource_id.lower()
    if "/providers/microsoft.compute/disks/" in normalized:
        return "disk"
    if "/providers/microsoft.compute/snapshots/" in normalized:
        return "snapshot"
    return "resource"


def _datetime_to_string(value: object) -> str | None:
    if value is None:
        return None
    isoformat = getattr(value, "isoformat", None)
    if callable(isoformat):
        return str(isoformat())
    return str(value)


def _arm_ssl_context() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=certifi.where())


def _snapshot_disk_summary(item: dict) -> str:
    parts: list[str] = []

    if item.get("asset_kind") == "snapshot":
        parts.append(f"Snapshot of {item.get('source_resource_name') or 'source resource'}")
        if item.get("incremental") is True:
            parts.append("incremental copy path visible")
    elif item.get("attached_to_name"):
        role = item.get("disk_role") or "managed disk"
        parts.append(f"Attached {role} for {item.get('attached_to_name')}")
    else:
        parts.append("Detached managed disk")

    posture_bits: list[str] = []
    if item.get("public_network_access"):
        posture_bits.append(f"public network {item.get('public_network_access')}")
    if item.get("network_access_policy"):
        posture_bits.append(f"network access {item.get('network_access_policy')}")
    if item.get("max_shares") not in (None, 1):
        posture_bits.append(f"max shares {item.get('max_shares')}")
    if item.get("disk_access_id"):
        posture_bits.append("disk access resource visible")
    if posture_bits:
        parts.append(", ".join(posture_bits))

    encryption_bits: list[str] = []
    if item.get("encryption_type"):
        encryption_bits.append(str(item.get("encryption_type")))
    if item.get("disk_encryption_set_id"):
        encryption_bits.append("disk encryption set linked")
    if encryption_bits:
        parts.append(f"encryption posture: {', '.join(encryption_bits)}")

    return "; ".join(parts) + "."


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


def _bool_or_none(value: object) -> bool | None:
    if value is None:
        return None
    return bool(value)


def _normalized_arm_enum(value: object) -> str | None:
    text = str(_string_value(value) or "").strip()
    if not text:
        return None
    if "." in text:
        text = text.rsplit(".", 1)[-1]
    text = text.replace("_", "-").replace(" ", "-")
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "-", text)
    text = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "-", text)
    text = re.sub(r"-{2,}", "-", text)
    return text.lower()


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


def _application_gateway_summary(
    gateway: object,
    *,
    public_ip_lookup: dict[str, str] | None = None,
) -> dict:
    gateway_id = getattr(gateway, "id", "") or ""
    gateway_name = getattr(gateway, "name", "unknown")
    sku = getattr(gateway, "sku", None)
    frontend_ip_configurations = getattr(gateway, "frontend_ip_configurations", None) or []
    backend_address_pools = getattr(gateway, "backend_address_pools", None) or []
    waf_configuration = getattr(gateway, "web_application_firewall_configuration", None)
    firewall_policy_id = _string_value(
        getattr(getattr(gateway, "firewall_policy", None), "id", None)
    )

    public_ip_address_ids: list[str] = []
    private_frontend_ips: list[str] = []
    subnet_ids: list[str] = []
    for frontend in frontend_ip_configurations:
        public_ip_address_id = _string_value(
            getattr(getattr(frontend, "public_ip_address", None), "id", None)
        )
        if public_ip_address_id:
            public_ip_address_ids.append(public_ip_address_id)

        private_frontend_ip = _string_value(getattr(frontend, "private_ip_address", None))
        if private_frontend_ip:
            private_frontend_ips.append(private_frontend_ip)

        subnet_id = _string_value(getattr(getattr(frontend, "subnet", None), "id", None))
        if subnet_id:
            subnet_ids.append(subnet_id)

    public_ip_address_ids = _dedupe_strings(public_ip_address_ids)
    private_frontend_ips = _dedupe_strings(private_frontend_ips)
    subnet_ids = _dedupe_strings(subnet_ids)
    public_ip_addresses = _dedupe_strings(
        [
            public_ip_lookup.get(_arm_id_join_key(public_ip_address_id))
            for public_ip_address_id in public_ip_address_ids
            if public_ip_lookup and _arm_id_join_key(public_ip_address_id)
        ]
    )

    waf_enabled = _bool_or_none(getattr(waf_configuration, "enabled", None))
    waf_mode = _string_value(getattr(waf_configuration, "firewall_mode", None))

    return {
        "id": gateway_id or f"/unknown/{gateway_name}",
        "name": gateway_name,
        "resource_group": _resource_group_from_id(gateway_id),
        "location": _string_value(getattr(gateway, "location", None)),
        "state": _string_value(getattr(gateway, "operational_state", None)),
        "sku_name": _string_value(getattr(sku, "name", None)),
        "sku_tier": _string_value(getattr(sku, "tier", None)),
        "public_frontend_count": len(public_ip_address_ids),
        "private_frontend_count": len(private_frontend_ips),
        "public_ip_address_ids": public_ip_address_ids,
        "public_ip_addresses": public_ip_addresses,
        "private_frontend_ips": private_frontend_ips,
        "subnet_ids": subnet_ids,
        "listener_count": len(getattr(gateway, "http_listeners", None) or []),
        "request_routing_rule_count": len(getattr(gateway, "request_routing_rules", None) or []),
        "backend_pool_count": len(backend_address_pools),
        "backend_target_count": _application_gateway_backend_target_count(backend_address_pools),
        "url_path_map_count": len(getattr(gateway, "url_path_maps", None) or []),
        "redirect_configuration_count": len(
            getattr(gateway, "redirect_configurations", None) or []
        ),
        "rewrite_rule_set_count": len(getattr(gateway, "rewrite_rule_sets", None) or []),
        "waf_enabled": waf_enabled,
        "waf_mode": waf_mode,
        "firewall_policy_id": firewall_policy_id,
        "summary": _application_gateway_operator_summary(
            gateway_name=gateway_name,
            public_frontend_count=len(public_ip_address_ids),
            private_frontend_count=len(private_frontend_ips),
            public_ip_addresses=public_ip_addresses,
            listener_count=len(getattr(gateway, "http_listeners", None) or []),
            request_routing_rule_count=len(getattr(gateway, "request_routing_rules", None) or []),
            backend_pool_count=len(backend_address_pools),
            backend_target_count=_application_gateway_backend_target_count(backend_address_pools),
            waf_enabled=waf_enabled,
            waf_mode=waf_mode,
            firewall_policy_id=firewall_policy_id,
        ),
        "related_ids": _dedupe_strings(
            [
                gateway_id,
                *public_ip_address_ids,
                *subnet_ids,
                firewall_policy_id,
            ]
        ),
    }


def _api_mgmt_service_summary(
    service: object,
    apis: list[object] | None,
    subscriptions: list[object] | None,
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
    api_subscription_required_count = _api_mgmt_api_subscription_required_count(apis)
    subscription_count = len(subscriptions) if subscriptions is not None else None
    active_subscription_count = _api_mgmt_active_subscription_count(subscriptions)
    backend_count = len(backends) if backends is not None else None
    backend_hostnames = _api_mgmt_backend_hostnames(backends)
    named_value_count = len(named_values) if named_values is not None else None
    named_value_secret_count = _api_mgmt_named_value_secret_count(named_values)
    named_value_key_vault_count = _api_mgmt_named_value_key_vault_count(named_values)
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
        "api_subscription_required_count": api_subscription_required_count,
        "subscription_count": subscription_count,
        "active_subscription_count": active_subscription_count,
        "backend_count": backend_count,
        "backend_hostnames": backend_hostnames,
        "named_value_count": named_value_count,
        "named_value_secret_count": named_value_secret_count,
        "named_value_key_vault_count": named_value_key_vault_count,
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
            api_subscription_required_count=api_subscription_required_count,
            subscription_count=subscription_count,
            active_subscription_count=active_subscription_count,
            backend_count=backend_count,
            backend_hostnames=backend_hostnames,
            named_value_count=named_value_count,
            named_value_secret_count=named_value_secret_count,
            named_value_key_vault_count=named_value_key_vault_count,
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
        else (_env_var_value_type(azure_webjobs_storage_value) if settings_readable else None)
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


def _container_app_summary(resource: object) -> dict:
    resource_id = _string_value(getattr(resource, "id", None)) or ""
    name = _string_value(getattr(resource, "name", None)) or "unknown"
    identity = getattr(resource, "identity", None)
    properties = getattr(resource, "properties", None)
    configuration = _property_value(properties, "configuration")
    ingress = _property_value(configuration, "ingress")

    workload_identity_ids = sorted(
        str(identity_id)
        for identity_id in (
            _property_value(identity, "userAssignedIdentities", "user_assigned_identities") or {}
        ).keys()
    )
    workload_identity_type = _string_value(_property_value(identity, "type"))
    workload_principal_id = _string_value(_property_value(identity, "principalId", "principal_id"))
    workload_client_id = _string_value(_property_value(identity, "clientId", "client_id"))
    default_hostname = _string_value(_property_value(ingress, "fqdn"))
    external_ingress_enabled = _bool_or_none(_property_value(ingress, "external"))
    ingress_target_port = _int_value(_property_value(ingress, "targetPort", "target_port"))
    ingress_transport = _string_value(_property_value(ingress, "transport"))
    revision_mode = _string_value(
        _property_value(configuration, "activeRevisionsMode", "active_revisions_mode")
    )
    latest_revision_name = _string_value(
        _property_value(properties, "latestRevisionName", "latest_revision_name")
    )
    latest_ready_revision_name = _string_value(
        _property_value(properties, "latestReadyRevisionName", "latest_ready_revision_name")
    )
    environment_id = _string_value(
        _property_value(properties, "managedEnvironmentId", "managed_environment_id")
    )

    ingress_parts: list[str] = []
    if external_ingress_enabled is True:
        ingress_parts.append("external ingress enabled")
    elif external_ingress_enabled is False:
        ingress_parts.append("internal ingress only")
    if ingress_target_port is not None:
        ingress_parts.append(f"target port {ingress_target_port}")
    if ingress_transport:
        ingress_parts.append(f"transport {ingress_transport}")

    revision_parts: list[str] = []
    if revision_mode:
        revision_parts.append(f"revision mode {revision_mode}")
    if latest_ready_revision_name:
        revision_parts.append(f"latest ready revision {latest_ready_revision_name}")
    elif latest_revision_name:
        revision_parts.append(f"latest revision {latest_revision_name}")

    endpoint_phrase = (
        f"publishes hostname '{default_hostname}'"
        if default_hostname
        else "has no visible hostname from the current read path"
    )
    identity_phrase = (
        f"uses managed identity ({workload_identity_type})"
        if workload_identity_type
        else "has no managed identity visible from the current read path"
    )
    posture_parts = ingress_parts + revision_parts
    posture_phrase = (
        f" Visible posture: {', '.join(posture_parts)}."
        if posture_parts
        else ""
    )

    return {
        "id": resource_id or f"/unknown/{name}",
        "name": name,
        "resource_group": _resource_group_from_id(resource_id),
        "location": _string_value(getattr(resource, "location", None)),
        "environment_id": environment_id,
        "default_hostname": default_hostname,
        "external_ingress_enabled": external_ingress_enabled,
        "ingress_target_port": ingress_target_port,
        "ingress_transport": ingress_transport,
        "revision_mode": revision_mode,
        "latest_revision_name": latest_revision_name,
        "latest_ready_revision_name": latest_ready_revision_name,
        "workload_identity_type": workload_identity_type,
        "workload_principal_id": workload_principal_id,
        "workload_client_id": workload_client_id,
        "workload_identity_ids": workload_identity_ids,
        "summary": (
            f"Container App '{name}' {endpoint_phrase} and {identity_phrase}.{posture_phrase}"
        ),
        "related_ids": _dedupe_strings(
            [
                resource_id,
                environment_id,
                workload_principal_id,
                *workload_identity_ids,
            ]
        ),
    }


def _container_app_workload_summary(item: dict) -> dict:
    return {
        "asset_id": item.get("id") or f"/unknown/{item.get('name') or 'container-app'}",
        "asset_name": item.get("name") or "unknown",
        "asset_kind": "ContainerApp",
        "resource_group": item.get("resource_group"),
        "location": item.get("location"),
        "default_hostname": item.get("default_hostname"),
        "external_ingress_enabled": item.get("external_ingress_enabled"),
        "workload_identity_type": item.get("workload_identity_type"),
        "workload_principal_id": item.get("workload_principal_id"),
        "workload_client_id": item.get("workload_client_id"),
        "workload_identity_ids": list(item.get("workload_identity_ids") or []),
    }


def _container_instance_summary(resource: object) -> dict:
    resource_id = _string_value(getattr(resource, "id", None)) or ""
    name = _string_value(getattr(resource, "name", None)) or "unknown"
    identity = getattr(resource, "identity", None)
    properties = getattr(resource, "properties", None)
    ip_address = _property_value(properties, "ipAddress", "ip_address")
    containers = _property_value(properties, "containers") or []

    workload_identity_ids = sorted(
        str(identity_id)
        for identity_id in (
            _property_value(identity, "userAssignedIdentities", "user_assigned_identities") or {}
        ).keys()
    )
    workload_identity_type = _string_value(_property_value(identity, "type"))
    workload_principal_id = _string_value(_property_value(identity, "principalId", "principal_id"))
    workload_client_id = _string_value(_property_value(identity, "clientId", "client_id"))

    fqdn = _string_value(_property_value(ip_address, "fqdn"))
    public_ip_address = _string_value(_property_value(ip_address, "ip"))
    exposed_ports = sorted(
        {
            port
            for port in (
                _int_value(_property_value(item, "port"))
                for item in (_property_value(ip_address, "ports") or [])
            )
            if port is not None
        }
    )
    subnet_ids = _dedupe_strings(
        [
            _string_value(_property_value(item, "id"))
            for item in (_property_value(properties, "subnetIds", "subnet_ids") or [])
        ]
    )
    container_images = _dedupe_strings(
        [
            _string_value(_property_value(_property_value(item, "properties"), "image"))
            for item in containers
        ]
    )
    restart_policy = _string_value(
        _property_value(properties, "restartPolicy", "restart_policy")
    )
    os_type = _string_value(_property_value(properties, "osType", "os_type"))
    provisioning_state = _string_value(
        _property_value(properties, "provisioningState", "provisioning_state")
    )

    endpoint_parts: list[str] = []
    if fqdn:
        endpoint_parts.append(f"publishes FQDN '{fqdn}'")
    if public_ip_address:
        endpoint_parts.append(f"uses public IP {public_ip_address}")
    if not endpoint_parts:
        endpoint_parts.append("has no public endpoint visible from the current read path")

    posture_parts: list[str] = []
    if os_type:
        posture_parts.append(f"os {os_type}")
    if restart_policy:
        posture_parts.append(f"restart {restart_policy}")
    if exposed_ports:
        posture_parts.append(
            "ports " + ", ".join(str(port) for port in exposed_ports[:5])
            + ("..." if len(exposed_ports) > 5 else "")
        )
    if subnet_ids:
        posture_parts.append(f"subnets {len(subnet_ids)}")
    if containers:
        posture_parts.append(f"containers {len(containers)}")

    identity_phrase = (
        f"uses managed identity ({workload_identity_type})"
        if workload_identity_type
        else "has no managed identity visible from the current read path"
    )
    posture_phrase = (
        f" Visible posture: {', '.join(posture_parts)}."
        if posture_parts
        else ""
    )

    return {
        "id": resource_id or f"/unknown/{name}",
        "name": name,
        "resource_group": _resource_group_from_id(resource_id),
        "location": _string_value(getattr(resource, "location", None)),
        "os_type": os_type,
        "restart_policy": restart_policy,
        "provisioning_state": provisioning_state,
        "public_ip_address": public_ip_address,
        "fqdn": fqdn,
        "exposed_ports": exposed_ports,
        "subnet_ids": subnet_ids,
        "container_count": len(containers),
        "container_images": container_images,
        "workload_identity_type": workload_identity_type,
        "workload_principal_id": workload_principal_id,
        "workload_client_id": workload_client_id,
        "workload_identity_ids": workload_identity_ids,
        "summary": (
            f"Container group '{name}' {' and '.join(endpoint_parts)} and {identity_phrase}."
            f"{posture_phrase}"
        ),
        "related_ids": _dedupe_strings(
            [
                resource_id,
                public_ip_address,
                workload_principal_id,
                *workload_identity_ids,
                *subnet_ids,
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

    next_review_hint = env_var_next_review_hint(
        setting_name=setting_name,
        value_type=value_type,
        looks_sensitive=looks_sensitive,
        reference_target=reference_target,
        workload_identity_type=workload_identity_type,
    )
    summary = f"{summary[:-1]} {next_review_hint}"

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


def _application_gateway_operator_summary(
    *,
    gateway_name: str,
    public_frontend_count: int,
    private_frontend_count: int,
    public_ip_addresses: list[str],
    listener_count: int,
    request_routing_rule_count: int,
    backend_pool_count: int,
    backend_target_count: int,
    waf_enabled: bool | None,
    waf_mode: str | None,
    firewall_policy_id: str | None,
) -> str:
    if public_frontend_count:
        exposure_phrase = f"publishes {public_frontend_count} public frontend(s)" + (
            f" ({', '.join(public_ip_addresses)})" if public_ip_addresses else ""
        )
    elif private_frontend_count:
        exposure_phrase = (
            "is private-only from the current read path "
            f"({private_frontend_count} private frontend(s))"
        )
    else:
        exposure_phrase = "does not expose readable frontend IP posture from the current read path"

    routing_parts: list[str] = []
    if listener_count:
        routing_parts.append(f"{listener_count} listener(s)")
    if request_routing_rule_count:
        routing_parts.append(f"{request_routing_rule_count} routing rule(s)")
    if backend_pool_count:
        routing_parts.append(f"{backend_pool_count} backend pool(s)")
    if backend_target_count:
        routing_parts.append(f"{backend_target_count} backend target(s)")
    routing_phrase = (
        "Visible routing breadth: " + ", ".join(routing_parts) + "."
        if routing_parts
        else "Routing breadth is not fully readable from the current read path."
    )

    if firewall_policy_id and waf_mode:
        waf_phrase = f"WAF policy is attached and running in {waf_mode} mode."
    elif firewall_policy_id:
        waf_phrase = "WAF policy is attached."
    elif waf_enabled is True and waf_mode:
        waf_phrase = f"Gateway-level WAF is enabled in {waf_mode} mode."
    elif waf_enabled is True:
        waf_phrase = "Gateway-level WAF is enabled."
    elif waf_enabled is False:
        waf_phrase = "Visible WAF protection is disabled."
    else:
        waf_phrase = "No visible WAF protection is configured from the current read path."

    if public_frontend_count and _application_gateway_has_shared_breadth(
        listener_count=listener_count,
        request_routing_rule_count=request_routing_rule_count,
        backend_pool_count=backend_pool_count,
        backend_target_count=backend_target_count,
    ):
        why_phrase = (
            "This is a shared front door, so if the edge is weak "
            "the apps behind it may deserve review next."
        )
    elif public_frontend_count:
        why_phrase = (
            "Because this gateway is public, weak edge controls here "
            "would make the backend path worth checking next."
        )
    else:
        why_phrase = (
            "This is still useful shared-ingress context, but it is not "
            "an obvious internet-first path."
        )

    return (
        f"Application Gateway '{gateway_name}' {exposure_phrase}. "
        f"{routing_phrase} {waf_phrase} {why_phrase}"
    )


def _application_gateway_has_shared_breadth(
    *,
    listener_count: int,
    request_routing_rule_count: int,
    backend_pool_count: int,
    backend_target_count: int,
) -> bool:
    return any(
        value > 1
        for value in (
            listener_count,
            request_routing_rule_count,
            backend_pool_count,
            backend_target_count,
        )
    )


def _app_service_exposure_priority(item: dict) -> bool:
    return bool(item.get("default_hostname")) or (
        str(item.get("public_network_access") or "").lower() == "enabled"
    )


def _application_gateway_backend_target_count(backend_address_pools: list[object]) -> int:
    backend_targets: list[str] = []
    for pool in backend_address_pools:
        for address in getattr(pool, "backend_addresses", None) or []:
            fqdn = _string_value(getattr(address, "fqdn", None))
            ip_address = _string_value(getattr(address, "ip_address", None))
            if fqdn:
                backend_targets.append(f"fqdn:{fqdn}")
            elif ip_address:
                backend_targets.append(f"ip:{ip_address}")

        for ip_configuration in getattr(pool, "backend_ip_configurations", None) or []:
            ip_configuration_id = _string_value(getattr(ip_configuration, "id", None))
            if ip_configuration_id:
                backend_targets.append(f"id:{ip_configuration_id}")

    return len(_dedupe_strings(backend_targets))


def _acr_registry_summary(
    registry: object,
    webhooks: list[object] | None = None,
    replications: list[object] | None = None,
) -> dict:
    registry_id = getattr(registry, "id", "") or ""
    registry_name = getattr(registry, "name", "unknown")
    identity = getattr(registry, "identity", None)
    sku = getattr(registry, "sku", None)
    policies = getattr(registry, "policies", None)
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
    network_rule_default_action = _string_value(getattr(network_rule_set, "default_action", None))
    network_rule_bypass_options = _string_value(
        getattr(registry, "network_rule_bypass_options", None)
    )
    admin_user_enabled = getattr(registry, "admin_user_enabled", None)
    anonymous_pull_enabled = getattr(registry, "anonymous_pull_enabled", None)
    data_endpoint_enabled = getattr(registry, "data_endpoint_enabled", None)
    private_endpoint_connection_count = len(private_endpoint_connections)
    login_server = _string_value(getattr(registry, "login_server", None))
    sku_name = _string_value(getattr(sku, "name", None))
    webhook_count = len(webhooks) if webhooks is not None else None
    enabled_webhook_count = _acr_enabled_webhook_count(webhooks)
    webhook_action_types = _acr_webhook_action_types(webhooks)
    broad_webhook_scope_count = _acr_broad_webhook_scope_count(webhooks)
    replication_count = len(replications) if replications is not None else None
    replication_regions = _acr_replication_regions(replications)
    quarantine_policy = getattr(policies, "quarantine_policy", None)
    retention_policy = getattr(policies, "retention_policy", None)
    trust_policy = getattr(policies, "trust_policy", None)
    quarantine_policy_status = _normalized_arm_enum(getattr(quarantine_policy, "status", None))
    retention_policy_status = _normalized_arm_enum(getattr(retention_policy, "status", None))
    retention_policy_days = _int_value(getattr(retention_policy, "days", None))
    trust_policy_status = _normalized_arm_enum(getattr(trust_policy, "status", None))
    trust_policy_type = _normalized_arm_enum(getattr(trust_policy, "type", None))

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
        "webhook_count": webhook_count,
        "enabled_webhook_count": enabled_webhook_count,
        "webhook_action_types": webhook_action_types,
        "broad_webhook_scope_count": broad_webhook_scope_count,
        "replication_count": replication_count,
        "replication_regions": replication_regions,
        "quarantine_policy_status": quarantine_policy_status,
        "retention_policy_status": retention_policy_status,
        "retention_policy_days": retention_policy_days,
        "trust_policy_status": trust_policy_status,
        "trust_policy_type": trust_policy_type,
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
            webhook_count=webhook_count,
            enabled_webhook_count=enabled_webhook_count,
            webhook_action_types=webhook_action_types,
            broad_webhook_scope_count=broad_webhook_scope_count,
            replication_count=replication_count,
            replication_regions=replication_regions,
            quarantine_policy_status=quarantine_policy_status,
            retention_policy_status=retention_policy_status,
            retention_policy_days=retention_policy_days,
            trust_policy_status=trust_policy_status,
            trust_policy_type=trust_policy_type,
        ),
        "related_ids": _dedupe_strings(
            [
                registry_id,
                workload_principal_id,
                *workload_identity_ids,
                *[_string_value(getattr(webhook, "id", None)) for webhook in (webhooks or [])],
                *[
                    _string_value(getattr(replication, "id", None))
                    for replication in (replications or [])
                ],
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
    webhook_count: int | None,
    enabled_webhook_count: int | None,
    webhook_action_types: list[str],
    broad_webhook_scope_count: int | None,
    replication_count: int | None,
    replication_regions: list[str],
    quarantine_policy_status: str | None,
    retention_policy_status: str | None,
    retention_policy_days: int | None,
    trust_policy_status: str | None,
    trust_policy_type: str | None,
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
    depth_parts: list[str] = []
    if webhook_count is not None:
        webhook_phrase = f"{webhook_count} webhooks"
        if enabled_webhook_count is not None:
            webhook_phrase += f" ({enabled_webhook_count} enabled)"
        depth_parts.append(webhook_phrase)
    if broad_webhook_scope_count:
        depth_parts.append(f"{broad_webhook_scope_count} broad webhook scope(s)")
    if webhook_action_types:
        depth_parts.append(f"webhook actions {', '.join(webhook_action_types)}")
    if replication_count is not None and replication_regions:
        depth_parts.append(
            f"{replication_count} replications across {', '.join(replication_regions)}"
        )
    elif replication_count is not None:
        depth_parts.append(f"{replication_count} replications")
    if quarantine_policy_status:
        depth_parts.append(f"quarantine {quarantine_policy_status}")
    if retention_policy_status == "enabled" and retention_policy_days is not None:
        depth_parts.append(f"retention enabled ({retention_policy_days}d)")
    elif retention_policy_status:
        depth_parts.append(f"retention {retention_policy_status}")
    if trust_policy_status == "enabled" and trust_policy_type:
        depth_parts.append(f"content trust enabled ({trust_policy_type})")
    elif trust_policy_status:
        depth_parts.append(f"content trust {trust_policy_status}")
    depth_phrase = f" Depth cues: {', '.join(depth_parts)}." if depth_parts else ""

    return (
        f"Container Registry '{registry_name}' {login_phrase} and {identity_phrase}. "
        f"{auth_phrase} Visible network posture: {', '.join(network_parts)}. "
        f"{service_phrase}{depth_phrase}"
    )


def _acr_exposure_priority(item: dict) -> bool:
    return (
        str(item.get("public_network_access") or "").lower() == "enabled"
        or item.get("admin_user_enabled") is True
        or item.get("anonymous_pull_enabled") is True
    )


def _acr_registry_needs_hydration(registry: object) -> bool:
    identity = getattr(registry, "identity", None)
    return (
        _string_value(getattr(registry, "public_network_access", None)) is None
        or _string_value(getattr(identity, "type", None)) is None
    )


def _acr_enabled_webhook_count(webhooks: list[object] | None) -> int | None:
    if webhooks is None:
        return None
    return sum(
        _normalized_arm_enum(getattr(webhook, "status", None)) == "enabled" for webhook in webhooks
    )


def _acr_webhook_action_types(webhooks: list[object] | None) -> list[str]:
    if webhooks is None:
        return []
    return sorted(
        {
            normalized
            for webhook in webhooks
            for action in (getattr(webhook, "actions", None) or [])
            if (normalized := _normalized_arm_enum(action))
        }
    )


def _acr_broad_webhook_scope_count(webhooks: list[object] | None) -> int | None:
    if webhooks is None:
        return None
    return sum(_acr_has_broad_webhook_scope(webhook) for webhook in webhooks)


def _acr_has_broad_webhook_scope(webhook: object) -> bool:
    scope = str(_string_value(getattr(webhook, "scope", None)) or "").strip()
    return not scope or "*" in scope


def _acr_replication_regions(replications: list[object] | None) -> list[str]:
    if replications is None:
        return []
    return sorted(
        {
            region
            for replication in replications
            if (region := _string_value(getattr(replication, "location", None)))
        }
    )


def _database_server_summary(
    server: object,
    databases: list[object] | None,
    *,
    engine: str = "AzureSql",
) -> dict:
    server_id = getattr(server, "id", "") or ""
    server_name = getattr(server, "name", "unknown")
    identity = getattr(server, "identity", None)
    network = getattr(server, "network", None)
    high_availability = getattr(server, "high_availability", None)
    user_databases = _visible_user_databases(databases, engine=engine)
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
    public_network_access = _string_value(
        getattr(server, "public_network_access", None)
    ) or _string_value(getattr(network, "public_network_access", None))
    minimal_tls_version = _string_value(getattr(server, "minimal_tls_version", None))
    server_version = _string_value(getattr(server, "version", None))
    high_availability_mode = _normalized_arm_enum(getattr(high_availability, "mode", None))
    delegated_subnet_resource_id = _string_value(
        getattr(network, "delegated_subnet_resource_id", None)
    )
    private_dns_zone_resource_id = _string_value(
        getattr(network, "private_dns_zone_arm_resource_id", None)
    ) or _string_value(getattr(network, "private_dns_zone_resource_id", None))
    database_count = len(user_databases) if databases is not None else None

    return {
        "id": server_id or f"/unknown/{server_name}",
        "name": server_name,
        "resource_group": _resource_group_from_id(server_id),
        "location": _string_value(getattr(server, "location", None)),
        "state": _string_value(getattr(server, "state", None)),
        "engine": engine,
        "fully_qualified_domain_name": fully_qualified_domain_name,
        "server_version": server_version,
        "public_network_access": public_network_access,
        "minimal_tls_version": minimal_tls_version,
        "high_availability_mode": high_availability_mode,
        "delegated_subnet_resource_id": delegated_subnet_resource_id,
        "private_dns_zone_resource_id": private_dns_zone_resource_id,
        "database_count": database_count,
        "user_database_names": user_database_names,
        "workload_identity_type": workload_identity_type,
        "workload_principal_id": workload_principal_id,
        "workload_client_id": workload_client_id,
        "workload_identity_ids": workload_identity_ids,
        "summary": _database_server_operator_summary(
            engine=engine,
            server_name=server_name,
            fully_qualified_domain_name=fully_qualified_domain_name,
            workload_identity_type=workload_identity_type,
            public_network_access=public_network_access,
            minimal_tls_version=minimal_tls_version,
            server_version=server_version,
            high_availability_mode=high_availability_mode,
            delegated_subnet_resource_id=delegated_subnet_resource_id,
            private_dns_zone_resource_id=private_dns_zone_resource_id,
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
    engine: str,
    server_name: str,
    fully_qualified_domain_name: str | None,
    workload_identity_type: str | None,
    public_network_access: str | None,
    minimal_tls_version: str | None,
    server_version: str | None,
    high_availability_mode: str | None,
    delegated_subnet_resource_id: str | None,
    private_dns_zone_resource_id: str | None,
    database_count: int | None,
    user_database_names: list[str],
) -> str:
    engine_label = _database_engine_label(engine)
    endpoint_phrase = (
        f"publishes endpoint '{fully_qualified_domain_name}'"
        if fully_qualified_domain_name
        else "does not expose a readable database endpoint from the current read path"
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
    if high_availability_mode:
        posture_parts.append(f"HA {high_availability_mode}")
    if delegated_subnet_resource_id:
        posture_parts.append("delegated subnet configured")
    if private_dns_zone_resource_id:
        posture_parts.append("private DNS configured")

    inventory_phrase = (
        f"Visible inventory: {', '.join(inventory_parts)}."
        if inventory_parts
        else "Database inventory is not fully readable from the current read path."
    )

    return (
        f"{engine_label} server '{server_name}' {endpoint_phrase} and {identity_phrase}. "
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
        "private_endpoint_reference_count": None,
        "summary": _dns_zone_operator_summary(
            zone_name=zone_name,
            zone_kind=zone_kind,
            record_set_count=record_set_count,
            name_server_count=len(name_servers),
            linked_virtual_network_count=linked_virtual_network_count,
            registration_virtual_network_count=registration_virtual_network_count,
            private_endpoint_reference_count=None,
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
    private_endpoint_reference_count: int | None,
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
        link_parts.append(f"{registration_virtual_network_count} registration-enabled link(s)")
    if private_endpoint_reference_count is not None:
        link_parts.append(
            f"{private_endpoint_reference_count} visible private endpoint reference(s)"
        )

    namespace_phrase = (
        f"tracks {', '.join(link_parts)}"
        if link_parts
        else "does not expose readable virtual network link counts"
    )
    return f"Private DNS zone '{zone_name}' {inventory_phrase} and {namespace_phrase}."


def _dns_resource_needs_hydration(resource: object) -> bool:
    resource_type = str(getattr(resource, "type", "") or "").lower()
    properties = getattr(resource, "properties", None)

    record_set_count = _int_value(
        _property_value(properties, "numberOfRecordSets", "number_of_record_sets")
    )
    if record_set_count is None:
        return True

    if resource_type == "microsoft.network/dnszones":
        name_servers = _property_value(properties, "nameServers", "name_servers") or []
        return len([item for item in name_servers if item]) == 0

    if resource_type == "microsoft.network/privatednszones":
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
        return linked_virtual_network_count is None or registration_virtual_network_count is None

    return False


def _visible_user_databases(databases: list[object] | None, *, engine: str) -> list[object]:
    if databases is None:
        return []

    visible: list[object] = []
    for database in databases:
        database_name = str(getattr(database, "name", "") or "").lower()
        if database_name in _system_database_names(engine):
            continue
        visible.append(database)
    return visible


def _system_database_names(engine: str) -> set[str]:
    if engine == "AzureSql":
        return {"master"}
    if engine == "PostgreSqlFlexible":
        return {"postgres", "azure_maintenance"}
    if engine == "MySqlFlexible":
        return {"mysql", "information_schema", "performance_schema", "sys"}
    return set()


def _database_engine_label(engine: str) -> str:
    labels = {
        "AzureSql": "Azure SQL",
        "PostgreSqlFlexible": "PostgreSQL Flexible",
        "MySqlFlexible": "MySQL Flexible",
    }
    return labels.get(engine, engine)


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
    oidc_issuer_profile = getattr(cluster, "oidc_issuer_profile", None)
    security_profile = getattr(cluster, "security_profile", None)
    ingress_profile = getattr(cluster, "ingress_profile", None)
    addon_profiles = getattr(cluster, "addon_profiles", None) or {}
    sku = getattr(cluster, "sku", None)
    agent_pool_profiles = getattr(cluster, "agent_pool_profiles", None) or []
    workload_identity = getattr(security_profile, "workload_identity", None)
    web_app_routing = getattr(ingress_profile, "web_app_routing", None)

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
    oidc_issuer_enabled = getattr(oidc_issuer_profile, "enabled", None)
    oidc_issuer_url = _string_value(getattr(oidc_issuer_profile, "issuer_url", None))
    workload_identity_enabled = getattr(workload_identity, "enabled", None)
    addon_names = sorted(
        addon_name
        for addon_name, addon_profile in addon_profiles.items()
        if getattr(addon_profile, "enabled", False)
    )
    web_app_routing_enabled = getattr(web_app_routing, "enabled", None)
    web_app_routing_dns_zone_ids = getattr(web_app_routing, "dns_zone_resource_ids", None)
    web_app_routing_dns_zone_count = (
        len(web_app_routing_dns_zone_ids) if web_app_routing_dns_zone_ids is not None else None
    )

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
        "oidc_issuer_enabled": oidc_issuer_enabled,
        "oidc_issuer_url": oidc_issuer_url,
        "workload_identity_enabled": workload_identity_enabled,
        "addon_names": addon_names,
        "web_app_routing_enabled": web_app_routing_enabled,
        "web_app_routing_dns_zone_count": web_app_routing_dns_zone_count,
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
            oidc_issuer_enabled=oidc_issuer_enabled,
            oidc_issuer_url=oidc_issuer_url,
            workload_identity_enabled=workload_identity_enabled,
            addon_names=addon_names,
            web_app_routing_enabled=web_app_routing_enabled,
            web_app_routing_dns_zone_count=web_app_routing_dns_zone_count,
        ),
        "related_ids": _dedupe_strings([cluster_id, cluster_principal_id, *cluster_identity_ids]),
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
    oidc_issuer_enabled: bool | None,
    oidc_issuer_url: str | None,
    workload_identity_enabled: bool | None,
    addon_names: list[str],
    web_app_routing_enabled: bool | None,
    web_app_routing_dns_zone_count: int | None,
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
    if oidc_issuer_enabled is True:
        auth_parts.append("OIDC issuer enabled")
    elif oidc_issuer_enabled is False:
        auth_parts.append("OIDC issuer disabled")
    if workload_identity_enabled is True:
        auth_parts.append("workload identity enabled")
    elif workload_identity_enabled is False:
        auth_parts.append("workload identity disabled")

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
    if web_app_routing_enabled is True:
        if web_app_routing_dns_zone_count is not None:
            network_parts.append(
                f"web app routing enabled ({web_app_routing_dns_zone_count} DNS zone links)"
            )
        else:
            network_parts.append("web app routing enabled")
    elif web_app_routing_enabled is False:
        network_parts.append("web app routing disabled")

    inventory_parts: list[str] = []
    if kubernetes_version:
        inventory_parts.append(f"Kubernetes {kubernetes_version}")
    if agent_pool_count is not None:
        inventory_parts.append(f"{agent_pool_count} agent pool(s)")
    if addon_names:
        inventory_parts.append(f"addons {', '.join(addon_names)}")

    depth_parts: list[str] = []
    if oidc_issuer_enabled is True and oidc_issuer_url:
        depth_parts.append(f"OIDC issuer {oidc_issuer_url}")
    elif oidc_issuer_enabled is True:
        depth_parts.append("OIDC issuer enabled")
    if workload_identity_enabled is True:
        depth_parts.append("workload identity enabled")
    if addon_names:
        depth_parts.append(f"enabled addons {', '.join(addon_names)}")
    depth_phrase = f" Depth cues: {', '.join(depth_parts)}." if depth_parts else ""

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
        f"{inventory_phrase}{depth_phrase} {auth_phrase} {network_phrase}"
    )


def _aks_exposure_priority(item: dict) -> bool:
    return bool(item.get("fqdn")) and item.get("private_cluster_enabled") is not True


def _aks_cluster_needs_hydration(cluster: object) -> bool:
    api_server_access_profile = getattr(cluster, "api_server_access_profile", None)
    security_profile = getattr(cluster, "security_profile", None)
    ingress_profile = getattr(cluster, "ingress_profile", None)
    workload_identity = getattr(security_profile, "workload_identity", None)
    web_app_routing = getattr(ingress_profile, "web_app_routing", None)

    return any(
        value is None
        for value in (
            getattr(api_server_access_profile, "enable_private_cluster", None),
            getattr(workload_identity, "enabled", None),
            getattr(web_app_routing, "enabled", None),
        )
    )


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
    api_subscription_required_count: int | None,
    subscription_count: int | None,
    active_subscription_count: int | None,
    backend_count: int | None,
    backend_hostnames: list[str],
    named_value_count: int | None,
    named_value_secret_count: int | None,
    named_value_key_vault_count: int | None,
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
    if api_subscription_required_count is not None:
        if api_count is not None:
            inventory_parts.append(f"{api_subscription_required_count} require subscriptions")
        else:
            inventory_parts.append(f"{api_subscription_required_count} APIs require subscriptions")
    if subscription_count is not None:
        if active_subscription_count is not None:
            inventory_parts.append(
                f"{subscription_count} subscriptions ({active_subscription_count} active)"
            )
        else:
            inventory_parts.append(f"{subscription_count} subscriptions")
    if backend_count is not None:
        inventory_parts.append(f"{backend_count} backends")
    if named_value_count is not None:
        inventory_parts.append(f"{named_value_count} named values")
    inventory_phrase = (
        f"Visible inventory: {', '.join(inventory_parts)}."
        if inventory_parts
        else "Inventory counts are not fully readable from the current read path."
    )

    depth_parts: list[str] = []
    if named_value_secret_count is not None:
        depth_parts.append(f"{named_value_secret_count} named values marked secret")
    if named_value_key_vault_count is not None:
        depth_parts.append(f"{named_value_key_vault_count} Key Vault-backed named values")
    if backend_hostnames:
        depth_parts.append(f"backend hosts {', '.join(backend_hostnames)}")
    depth_phrase = f" Depth cues: {', '.join(depth_parts)}." if depth_parts else ""

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
        f"{inventory_phrase}{depth_phrase} Visible posture: {', '.join(posture_parts)}."
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


def _api_mgmt_api_subscription_required_count(apis: list[object] | None) -> int | None:
    if apis is None:
        return None
    return sum(bool(getattr(api, "subscription_required", False)) for api in apis)


def _api_mgmt_active_subscription_count(subscriptions: list[object] | None) -> int | None:
    if subscriptions is None:
        return None
    return sum(
        str(getattr(subscription, "state", "")).strip().lower() == "active"
        for subscription in subscriptions
    )


def _api_mgmt_backend_hostnames(backends: list[object] | None) -> list[str]:
    if backends is None:
        return []
    return _dedupe_strings(
        [
            _hostname_from_url(
                _string_value(
                    getattr(backend, "url", None)
                    or getattr(getattr(backend, "properties", None), "url", None)
                )
            )
            for backend in backends
        ]
    )


def _api_mgmt_named_value_secret_count(named_values: list[object] | None) -> int | None:
    if named_values is None:
        return None
    return sum(bool(getattr(named_value, "secret", False)) for named_value in named_values)


def _api_mgmt_named_value_key_vault_count(named_values: list[object] | None) -> int | None:
    if named_values is None:
        return None
    return sum(
        bool(
            _string_value(
                getattr(getattr(named_value, "key_vault", None), "secret_identifier", None)
            )
        )
        for named_value in named_values
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

        next_review_hint = tokens_credential_next_review_hint(
            surface_type="managed-identity-token",
            access_path="workload-identity",
            operator_signal=identity_signal,
        )
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
                    f"managed identity ({item.get('workload_identity_type')}). "
                    f"{next_review_hint}"
                ),
                "related_ids": _dedupe_strings(related_ids),
            }
        )

    return surfaces


def _token_credential_surfaces_from_container_instances(
    container_instances: list[dict],
) -> list[dict]:
    surfaces: list[dict] = []

    for item in container_instances:
        asset_id = item.get("id")
        asset_name = item.get("name") or asset_id or "unknown"
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

        next_review_hint = tokens_credential_next_review_hint(
            surface_type="managed-identity-token",
            access_path="workload-identity",
            operator_signal=identity_signal,
        )
        surfaces.append(
            {
                "asset_id": asset_id or f"/unknown/{asset_name}",
                "asset_name": asset_name,
                "asset_kind": "ContainerInstance",
                "resource_group": item.get("resource_group"),
                "location": item.get("location"),
                "surface_type": "managed-identity-token",
                "access_path": "workload-identity",
                "priority": "medium",
                "operator_signal": identity_signal,
                "summary": (
                    f"ContainerInstance '{asset_name}' can request tokens through attached "
                    f"managed identity ({item.get('workload_identity_type')}). "
                    f"{next_review_hint}"
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
        asset_kind = item.get("asset_kind") or "WebWorkload"
        if asset_kind == "ContainerApp" and item.get("external_ingress_enabled") is not True:
            continue
        default_hostname = str(item.get("default_hostname") or "")
        if not default_hostname:
            continue

        asset_id = item.get("asset_id")
        asset_name = item.get("asset_name") or asset_id or "unknown"
        ingress_path = (
            "azure-functions-default-hostname"
            if asset_kind == "FunctionApp"
            else (
                "azure-container-apps-default-hostname"
                if asset_kind == "ContainerApp"
                else "azurewebsites-default-hostname"
            )
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


def _endpoints_from_container_instances(container_instances: list[dict]) -> list[dict]:
    endpoints: list[dict] = []

    for item in container_instances:
        asset_id = item.get("id")
        asset_name = item.get("name") or asset_id or "unknown"
        related_ids = _dedupe_strings(
            [
                asset_id,
                item.get("workload_principal_id"),
                *item.get("workload_identity_ids", []),
                *item.get("subnet_ids", []),
            ]
        )

        if item.get("public_ip_address"):
            endpoints.append(
                {
                    "endpoint": str(item.get("public_ip_address")),
                    "endpoint_type": "ip",
                    "source_asset_id": asset_id or f"/unknown/{asset_name}",
                    "source_asset_name": asset_name,
                    "source_asset_kind": "ContainerInstance",
                    "exposure_family": "public-ip",
                    "ingress_path": "azure-container-instances-public-ip",
                    "summary": (
                        f"ContainerInstance '{asset_name}' exposes public IP "
                        f"{item.get('public_ip_address')}. Review the visible ingress path, "
                        "ports, and runtime posture together."
                    ),
                    "related_ids": related_ids,
                }
            )

        if item.get("fqdn"):
            endpoints.append(
                {
                    "endpoint": str(item.get("fqdn")),
                    "endpoint_type": "hostname",
                    "source_asset_id": asset_id or f"/unknown/{asset_name}",
                    "source_asset_name": asset_name,
                    "source_asset_kind": "ContainerInstance",
                    "exposure_family": "managed-container-fqdn",
                    "ingress_path": "azure-container-instances-fqdn",
                    "summary": (
                        f"ContainerInstance '{asset_name}' publishes hostname "
                        f"'{item.get('fqdn')}'. Validate whether that ingress path is intended "
                        "and how it is constrained."
                    ),
                    "related_ids": related_ids,
                }
            )

    return endpoints


def _endpoints_by_asset(endpoints: list[dict]) -> dict[str, list[dict]]:
    endpoints_by_asset: dict[str, list[dict]] = {}
    for endpoint in endpoints:
        source_asset_key = _arm_id_join_key(endpoint.get("source_asset_id"))
        if not source_asset_key:
            continue
        endpoints_by_asset.setdefault(source_asset_key, []).append(endpoint)
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
        asset_endpoints = endpoints_by_asset.get(
            _arm_id_join_key(asset_id or f"/unknown/{asset_name}") or "",
            [],
        )
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
        asset_endpoints = endpoints_by_asset.get(
            _arm_id_join_key(asset_id or f"/unknown/{asset_name}") or "",
            [],
        )
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
        if item.get("external_ingress_enabled") is True:
            network_signals.append("external-ingress")
        elif item.get("external_ingress_enabled") is False:
            network_signals.append("internal-only")
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


def _workload_rows_from_container_instances(
    container_instances: list[dict],
    endpoints_by_asset: dict[str, list[dict]],
) -> list[dict]:
    workloads: list[dict] = []

    for item in container_instances:
        asset_id = item.get("id")
        asset_name = item.get("name") or asset_id or "unknown"
        normalized_asset_id = str(asset_id or f"/unknown/{asset_name}")
        identity_ids = _dedupe_strings(item.get("workload_identity_ids", []))
        identity_type = item.get("workload_identity_type")
        asset_endpoints = endpoints_by_asset.get(
            _arm_id_join_key(asset_id or f"/unknown/{asset_name}") or "",
            [],
        )
        endpoints = _dedupe_strings([endpoint.get("endpoint") for endpoint in asset_endpoints])
        ingress_paths = _dedupe_strings(
            [endpoint.get("ingress_path") for endpoint in asset_endpoints]
        )
        exposure_families = _dedupe_strings(
            [endpoint.get("exposure_family") for endpoint in asset_endpoints]
        )

        network_signals: list[str] = []
        if item.get("public_ip_address"):
            network_signals.append("public-ip")
        if item.get("fqdn"):
            network_signals.append("fqdn")
        if item.get("subnet_ids"):
            network_signals.append(f"subnets={len(item.get('subnet_ids', []))}")
        if item.get("exposed_ports"):
            network_signals.append(f"ports={len(item.get('exposed_ports', []))}")
        if item.get("container_count") is not None:
            network_signals.append(f"containers={item.get('container_count')}")
        if identity_ids:
            network_signals.append(f"user-assigned={len(identity_ids)}")

        workloads.append(
            {
                "asset_id": normalized_asset_id,
                "asset_name": asset_name,
                "asset_kind": "ContainerInstance",
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
                    asset_kind="ContainerInstance",
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
                        *item.get("subnet_ids", []),
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
    kind_order = {
        "VM": 0,
        "AppService": 1,
        "FunctionApp": 2,
        "ContainerApp": 3,
        "ContainerInstance": 4,
        "VMSS": 5,
    }
    return (
        not bool(item.get("endpoints")),
        not bool(item.get("identity_type")),
        kind_order.get(str(item.get("asset_kind") or ""), 9),
        str(item.get("asset_name") or ""),
    )


def _compose_network_effective(endpoints: list[dict], network_ports: list[dict]) -> list[dict]:
    rows_by_key: dict[tuple[str, str], list[dict]] = {}
    for row in network_ports:
        key = (str(row.get("asset_id") or ""), str(row.get("endpoint") or ""))
        rows_by_key.setdefault(key, []).append(row)

    effective_exposures: list[dict] = []
    for endpoint in endpoints:
        if endpoint.get("endpoint_type") != "ip":
            continue
        if endpoint.get("exposure_family") != "public-ip":
            continue

        asset_id = str(endpoint.get("source_asset_id") or "")
        endpoint_value = str(endpoint.get("endpoint") or "")
        rows = rows_by_key.get((asset_id, endpoint_value), [])
        effective_exposures.append(
            _network_effective_row_from_endpoint(endpoint=endpoint, network_ports=rows)
        )

    effective_exposures.sort(
        key=lambda item: (
            {"high": 0, "medium": 1, "low": 2}.get(str(item.get("effective_exposure")), 9),
            str(item.get("asset_name") or ""),
            str(item.get("endpoint") or ""),
        )
    )
    return effective_exposures


def _network_effective_row_from_endpoint(*, endpoint: dict, network_ports: list[dict]) -> dict:
    asset_id = str(
        endpoint.get("source_asset_id") or f"/unknown/{endpoint.get('source_asset_name')}"
    )
    asset_name = str(endpoint.get("source_asset_name") or asset_id or "unknown")
    endpoint_value = str(endpoint.get("endpoint") or "unknown")

    confidence_order = {"high": 0, "medium": 1, "low": 2}
    highest = "low"
    if network_ports:
        highest = min(
            (str(item.get("exposure_confidence") or "low").lower() for item in network_ports),
            key=lambda value: confidence_order.get(value, 9),
        )

    explicit_allow_rows = [
        item for item in network_ports if not _network_port_is_no_nsg_observation(item)
    ]

    internet_exposed_ports = _dedupe_strings(
        [
            _network_port_label(item)
            for item in explicit_allow_rows
            if _network_port_has_broad_internet_source(item)
        ]
    )
    constrained_ports = _dedupe_strings(
        [
            _network_port_label(item)
            for item in explicit_allow_rows
            if not _network_port_has_broad_internet_source(item)
        ]
    )
    observed_paths = _dedupe_strings(
        [str(item.get("allow_source_summary") or "") for item in network_ports]
    )
    related_ids = _dedupe_strings(
        [endpoint.get("source_asset_id"), *endpoint.get("related_ids", [])]
        + [related_id for item in network_ports for related_id in item.get("related_ids", [])]
    )

    if explicit_allow_rows:
        internet_phrase = (
            f"internet-facing allow evidence on {', '.join(internet_exposed_ports)}"
            if internet_exposed_ports
            else "no broad internet allow evidence surfaced"
        )
        constrained_phrase = (
            f" and narrower allow evidence on {', '.join(constrained_ports)}"
            if constrained_ports
            else ""
        )
        summary = (
            f"Asset '{asset_name}' endpoint {endpoint_value} has {internet_phrase}"
            f"{constrained_phrase}. Treat this as visible Azure network triage signal, not proof "
            "of full effective reachability."
        )
    elif network_ports:
        summary = (
            f"Asset '{asset_name}' endpoint {endpoint_value} is visible as a public IP path, but "
            "no Azure NSG was visible on the NIC or subnet from the current read path. Treat "
            "this as a low-confidence triage clue rather than proof of exposure."
        )
    else:
        summary = (
            f"Asset '{asset_name}' endpoint {endpoint_value} is visible as a public IP path, but "
            "no inbound-rule evidence was surfaced from the current read path. Treat this as a "
            "low-confidence triage clue rather than proof of exposure."
        )

    return {
        "asset_id": asset_id,
        "asset_name": asset_name,
        "endpoint": endpoint_value,
        "endpoint_type": str(endpoint.get("endpoint_type") or "ip"),
        "effective_exposure": highest,
        "internet_exposed_ports": internet_exposed_ports,
        "constrained_ports": constrained_ports,
        "observed_paths": observed_paths,
        "summary": summary,
        "related_ids": related_ids,
    }


def _network_port_label(item: dict) -> str:
    protocol = str(item.get("protocol") or "any").upper()
    port = str(item.get("port") or "any")
    return f"{protocol}/{port}"


def _network_port_is_no_nsg_observation(item: dict) -> bool:
    return str(item.get("allow_source_summary") or "") == "no Azure NSG visible on NIC or subnet"


def _network_port_has_broad_internet_source(item: dict) -> bool:
    source_summary = str(item.get("allow_source_summary") or "")
    source_fragment = source_summary.split(" via ", 1)[0]
    source_tokens = [token.strip().lower() for token in source_fragment.split(",") if token.strip()]
    return any(token in {"any", "internet", "0.0.0.0/0", "::/0"} for token in source_tokens)


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
            next_review_hint = tokens_credential_next_review_hint(
                surface_type="plain-text-secret",
                access_path="app-setting",
                operator_signal=f"setting={setting_name}",
            )
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
                        f"'{setting_name}' as plain-text management-plane app configuration. "
                        f"{next_review_hint}"
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

            next_review_hint = tokens_credential_next_review_hint(
                surface_type="keyvault-reference",
                access_path="app-setting",
                operator_signal="; ".join(signal_parts),
            )
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
                        f"Key Vault-backed secret material{target_suffix}{identity_suffix}. "
                        f"{next_review_hint}"
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
            output_signal = (
                f"outputs={item.get('outputs_count', 0)}; "
                f"providers={len(item.get('providers', []))}"
            )
            next_review_hint = tokens_credential_next_review_hint(
                surface_type="deployment-output",
                access_path="deployment-history",
                operator_signal=output_signal,
            )
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
                    "operator_signal": output_signal,
                    "summary": (
                        f"Deployment '{deployment_name}' recorded {item.get('outputs_count', 0)} "
                        "output values in deployment history. "
                        f"{next_review_hint}"
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

            next_review_hint = tokens_credential_next_review_hint(
                surface_type="linked-deployment-content",
                access_path="deployment-history",
                operator_signal="; ".join(link_parts),
            )
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
                        "content that may expose reusable configuration or credential context. "
                        f"{next_review_hint}"
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

        next_review_hint = tokens_credential_next_review_hint(
            surface_type="managed-identity-token",
            access_path="imds",
            operator_signal=f"{public_signal}; identities={len(identity_ids)}",
        )
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
                    "managed identity. "
                    f"{next_review_hint}"
                    if public_ips
                    else f"{str(item.get('vm_type') or 'vm').upper()} '{asset_name}' exposes a "
                    "token minting path through IMDS for its attached managed identity. "
                    f"{next_review_hint}"
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


def _vmss_summary(vmss: object) -> tuple[dict, list[dict]]:
    vmss_id = getattr(vmss, "id", "") or ""
    vmss_name = getattr(vmss, "name", "unknown")
    identity = getattr(vmss, "identity", None)
    sku = getattr(vmss, "sku", None)
    upgrade_policy = getattr(vmss, "upgrade_policy", None)

    identity_ids: list[str] = []
    if identity is not None:
        if getattr(identity, "principal_id", None):
            identity_ids.append(f"{vmss_id}/identities/system")
        user_assigned = getattr(identity, "user_assigned_identities", None) or {}
        identity_ids.extend(user_assigned.keys())

    network_cues = _vmss_network_cues(vmss, vmss_id=vmss_id, vmss_name=vmss_name)
    zones = _dedupe_strings(getattr(vmss, "zones", None) or [])
    sku_name = _string_value(getattr(sku, "name", None))
    instance_count = _int_value(getattr(sku, "capacity", None))
    orchestration_mode = _string_value(getattr(vmss, "orchestration_mode", None))
    upgrade_mode = _string_value(getattr(upgrade_policy, "mode", None))
    identity_type = _string_value(getattr(identity, "type", None))
    principal_id = _string_value(getattr(identity, "principal_id", None))
    client_id = _string_value(getattr(identity, "client_id", None))

    summary = _vmss_operator_summary(
        vmss_name=vmss_name,
        sku_name=sku_name,
        instance_count=instance_count,
        orchestration_mode=orchestration_mode,
        upgrade_mode=upgrade_mode,
        overprovision=_bool_or_none(getattr(vmss, "overprovision", None)),
        single_placement_group=_bool_or_none(getattr(vmss, "single_placement_group", None)),
        zone_balance=_bool_or_none(getattr(vmss, "zone_balance", None)),
        zones=zones,
        identity_type=identity_type,
        nic_configuration_count=network_cues["nic_configuration_count"],
        subnet_ids=network_cues["subnet_ids"],
        public_ip_configuration_count=network_cues["public_ip_configuration_count"],
        load_balancer_backend_pool_count=network_cues["load_balancer_backend_pool_count"],
        application_gateway_backend_pool_count=network_cues[
            "application_gateway_backend_pool_count"
        ],
        inbound_nat_pool_count=network_cues["inbound_nat_pool_count"],
        network_detail_complete=bool(network_cues["network_detail_complete"]),
    )

    return (
        {
            "id": vmss_id or f"/unknown/{vmss_name}",
            "name": vmss_name,
            "resource_group": _resource_group_from_id(vmss_id),
            "location": getattr(vmss, "location", None),
            "sku_name": sku_name,
            "instance_count": instance_count,
            "orchestration_mode": orchestration_mode,
            "upgrade_mode": upgrade_mode,
            "overprovision": _bool_or_none(getattr(vmss, "overprovision", None)),
            "single_placement_group": _bool_or_none(getattr(vmss, "single_placement_group", None)),
            "zone_balance": _bool_or_none(getattr(vmss, "zone_balance", None)),
            "zones": zones,
            "identity_type": identity_type,
            "principal_id": principal_id,
            "client_id": client_id,
            "identity_ids": _dedupe_strings(identity_ids),
            "subnet_ids": network_cues["subnet_ids"],
            "nic_configuration_count": network_cues["nic_configuration_count"],
            "public_ip_configuration_count": network_cues["public_ip_configuration_count"],
            "load_balancer_backend_pool_count": network_cues["load_balancer_backend_pool_count"],
            "application_gateway_backend_pool_count": network_cues[
                "application_gateway_backend_pool_count"
            ],
            "inbound_nat_pool_count": network_cues["inbound_nat_pool_count"],
            "summary": summary,
            "related_ids": _dedupe_strings(
                [
                    vmss_id,
                    principal_id,
                    *identity_ids,
                    *network_cues["subnet_ids"],
                    *network_cues["load_balancer_backend_pool_ids"],
                    *network_cues["application_gateway_backend_pool_ids"],
                    *network_cues["inbound_nat_pool_ids"],
                ]
            ),
        },
        list(network_cues["issues"]),
    )


def _vmss_network_cues(vmss: object, *, vmss_id: str, vmss_name: str) -> dict[str, object]:
    virtual_machine_profile = getattr(vmss, "virtual_machine_profile", None)
    if virtual_machine_profile is None:
        return {
            "subnet_ids": [],
            "nic_configuration_count": 0,
            "public_ip_configuration_count": 0,
            "load_balancer_backend_pool_count": 0,
            "application_gateway_backend_pool_count": 0,
            "inbound_nat_pool_count": 0,
            "load_balancer_backend_pool_ids": [],
            "application_gateway_backend_pool_ids": [],
            "inbound_nat_pool_ids": [],
            "network_detail_complete": False,
            "issues": [
                _partial_collection_issue(
                    "vmss.network_profile",
                    (
                        "VM scale set frontend and subnet details were not returned by the "
                        "current SDK list response; frontend counts may be incomplete."
                    ),
                    asset_id=vmss_id,
                    asset_name=vmss_name,
                )
            ],
        }

    network_profile = getattr(virtual_machine_profile, "network_profile", None)
    if network_profile is None:
        return {
            "subnet_ids": [],
            "nic_configuration_count": 0,
            "public_ip_configuration_count": 0,
            "load_balancer_backend_pool_count": 0,
            "application_gateway_backend_pool_count": 0,
            "inbound_nat_pool_count": 0,
            "load_balancer_backend_pool_ids": [],
            "application_gateway_backend_pool_ids": [],
            "inbound_nat_pool_ids": [],
            "network_detail_complete": False,
            "issues": [
                _partial_collection_issue(
                    "vmss.network_profile",
                    (
                        "VM scale set network profile details were not returned by the current "
                        "SDK list response; frontend counts may be incomplete."
                    ),
                    asset_id=vmss_id,
                    asset_name=vmss_name,
                )
            ],
        }

    nic_configs_raw = getattr(network_profile, "network_interface_configurations", None)
    if nic_configs_raw is None:
        return {
            "subnet_ids": [],
            "nic_configuration_count": 0,
            "public_ip_configuration_count": 0,
            "load_balancer_backend_pool_count": 0,
            "application_gateway_backend_pool_count": 0,
            "inbound_nat_pool_count": 0,
            "load_balancer_backend_pool_ids": [],
            "application_gateway_backend_pool_ids": [],
            "inbound_nat_pool_ids": [],
            "network_detail_complete": False,
            "issues": [
                _partial_collection_issue(
                    "vmss.network_interface_configurations",
                    (
                        "VM scale set NIC configuration details were not returned by the current "
                        "SDK list response; subnet and frontend counts may be incomplete."
                    ),
                    asset_id=vmss_id,
                    asset_name=vmss_name,
                )
            ],
        }

    nic_configs = nic_configs_raw or []

    subnet_ids: list[str] = []
    load_balancer_backend_pool_ids: list[str] = []
    application_gateway_backend_pool_ids: list[str] = []
    inbound_nat_pool_ids: list[str] = []
    public_ip_configuration_count = 0

    for nic_config in nic_configs:
        ip_configs_raw = getattr(nic_config, "ip_configurations", None)
        if ip_configs_raw is None:
            return {
                "subnet_ids": [],
                "nic_configuration_count": len(nic_configs),
                "public_ip_configuration_count": 0,
                "load_balancer_backend_pool_count": 0,
                "application_gateway_backend_pool_count": 0,
                "inbound_nat_pool_count": 0,
                "load_balancer_backend_pool_ids": [],
                "application_gateway_backend_pool_ids": [],
                "inbound_nat_pool_ids": [],
                "network_detail_complete": False,
                "issues": [
                    _partial_collection_issue(
                        "vmss.ip_configurations",
                        (
                            "VM scale set IP configuration details were not returned by the "
                            "current SDK list response; subnet and frontend counts may be "
                            "incomplete."
                        ),
                        asset_id=vmss_id,
                        asset_name=vmss_name,
                    )
                ],
            }

        ip_configs = ip_configs_raw or []
        for ip_config in ip_configs:
            subnet = getattr(ip_config, "subnet", None)
            subnet_id = _string_value(getattr(subnet, "id", None))
            if subnet_id:
                subnet_ids.append(subnet_id)

            for pool in getattr(ip_config, "load_balancer_backend_address_pools", None) or []:
                pool_id = _string_value(getattr(pool, "id", None))
                if pool_id:
                    load_balancer_backend_pool_ids.append(pool_id)

            for pool in getattr(ip_config, "application_gateway_backend_address_pools", None) or []:
                pool_id = _string_value(getattr(pool, "id", None))
                if pool_id:
                    application_gateway_backend_pool_ids.append(pool_id)

            for pool in getattr(ip_config, "load_balancer_inbound_nat_pools", None) or []:
                pool_id = _string_value(getattr(pool, "id", None))
                if pool_id:
                    inbound_nat_pool_ids.append(pool_id)

            if getattr(ip_config, "public_ip_configuration", None) is not None:
                public_ip_configuration_count += 1

    return {
        "subnet_ids": _dedupe_strings(subnet_ids),
        "nic_configuration_count": len(nic_configs),
        "public_ip_configuration_count": public_ip_configuration_count,
        "load_balancer_backend_pool_count": len(_dedupe_strings(load_balancer_backend_pool_ids)),
        "application_gateway_backend_pool_count": len(
            _dedupe_strings(application_gateway_backend_pool_ids)
        ),
        "inbound_nat_pool_count": len(_dedupe_strings(inbound_nat_pool_ids)),
        "load_balancer_backend_pool_ids": _dedupe_strings(load_balancer_backend_pool_ids),
        "application_gateway_backend_pool_ids": _dedupe_strings(
            application_gateway_backend_pool_ids
        ),
        "inbound_nat_pool_ids": _dedupe_strings(inbound_nat_pool_ids),
        "network_detail_complete": True,
        "issues": [],
    }


def _vmss_operator_summary(
    *,
    vmss_name: str,
    sku_name: str | None,
    instance_count: int | None,
    orchestration_mode: str | None,
    upgrade_mode: str | None,
    overprovision: bool | None,
    single_placement_group: bool | None,
    zone_balance: bool | None,
    zones: list[str],
    identity_type: str | None,
    nic_configuration_count: int,
    subnet_ids: list[str],
    public_ip_configuration_count: int,
    load_balancer_backend_pool_count: int,
    application_gateway_backend_pool_count: int,
    inbound_nat_pool_count: int,
    network_detail_complete: bool,
) -> str:
    identity_phrase = (
        f"uses managed identity ({identity_type})"
        if identity_type
        else "has no managed identity visible from the current read path"
    )

    footprint_parts: list[str] = []
    if sku_name:
        footprint_parts.append(f"SKU {sku_name}")
    if instance_count is not None:
        footprint_parts.append(f"{instance_count} configured instance(s)")
    if not footprint_parts:
        footprint_parts.append("instance footprint unreadable")

    network_parts: list[str] = []
    if public_ip_configuration_count:
        network_parts.append(f"{public_ip_configuration_count} public IP config(s)")
    if inbound_nat_pool_count:
        network_parts.append(f"{inbound_nat_pool_count} inbound NAT pool ref(s)")
    if load_balancer_backend_pool_count:
        network_parts.append(f"{load_balancer_backend_pool_count} LB backend pool ref(s)")
    if application_gateway_backend_pool_count:
        network_parts.append(f"{application_gateway_backend_pool_count} App Gateway backend ref(s)")
    if nic_configuration_count:
        network_parts.append(f"{nic_configuration_count} NIC config(s)")
    if subnet_ids:
        network_parts.append(f"{len(subnet_ids)} subnet ref(s)")
    network_phrase = (
        "Visible frontend or network cues: " + ", ".join(network_parts) + "."
        if network_parts
        else (
            "Frontend and subnet cues were not fully returned by the current SDK response."
            if not network_detail_complete
            else "No frontend or subnet cues are configured."
        )
    )

    posture_parts: list[str] = []
    if orchestration_mode:
        posture_parts.append(f"orchestration {orchestration_mode}")
    if upgrade_mode:
        posture_parts.append(f"upgrade {upgrade_mode}")
    if single_placement_group is not None:
        posture_parts.append(f"single-placement-group {'yes' if single_placement_group else 'no'}")
    if overprovision is not None:
        posture_parts.append(f"overprovision {'yes' if overprovision else 'no'}")
    if zone_balance is not None:
        posture_parts.append(f"zone-balance {'yes' if zone_balance else 'no'}")
    if zones:
        posture_parts.append(f"zones {','.join(zones)}")

    posture_phrase = f" Visible posture: {', '.join(posture_parts)}." if posture_parts else ""

    return (
        f"Virtual Machine Scale Sets (VMSS) asset '{vmss_name}' carries "
        f"{', '.join(footprint_parts)} and {identity_phrase}. {network_phrase}{posture_phrase}"
    )


def _partial_collection_issue(
    area: str,
    message: str,
    *,
    asset_id: str | None = None,
    asset_name: str | None = None,
) -> dict:
    context = {"collector": area}
    if asset_id:
        context["asset_id"] = asset_id
    if asset_name:
        context["asset_name"] = asset_name
    return {
        "kind": ErrorKind.PARTIAL_COLLECTION.value,
        "message": f"{area}: {message}",
        "scope": area,
        "context": context,
    }


def _set_query_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query[key] = value
    return urlunparse(parsed._replace(query=urlencode(query)))


def _devops_service_endpoint_maps(
    endpoints: list[dict[str, object]],
) -> tuple[dict[str, dict[str, object]], dict[str, dict[str, object]]]:
    by_id: dict[str, dict[str, object]] = {}
    by_name: dict[str, dict[str, object]] = {}
    for endpoint in endpoints:
        endpoint_id = str(endpoint.get("id") or "").strip().lower()
        endpoint_name = str(endpoint.get("name") or "").strip().lower()
        if endpoint_id:
            by_id[endpoint_id] = endpoint
        if endpoint_name:
            by_name[endpoint_name] = endpoint
    return by_id, by_name


def _devops_repository_project_name(repository: dict[str, object]) -> str | None:
    project = repository.get("project")
    if isinstance(project, dict):
        project_name = str(project.get("name") or "").strip()
        if project_name:
            return project_name
    project_name = str(repository.get("projectName") or "").strip()
    return project_name or None


def _devops_repository_project_id(repository: dict[str, object]) -> str | None:
    project = repository.get("project")
    if isinstance(project, dict):
        project_id = str(project.get("id") or "").strip()
        if project_id:
            return project_id
    project_id = str(repository.get("projectId") or "").strip()
    return project_id or None


def _devops_repository_scope(
    *,
    repository_name: str | None,
    repository_project_name: str | None,
) -> tuple[str | None, str | None]:
    scoped_name = str(repository_name or "").strip()
    scoped_project = str(repository_project_name or "").strip()
    if scoped_name and "/" in scoped_name:
        project_name, repo_name = scoped_name.split("/", 1)
        return project_name.strip() or None, repo_name.strip() or None
    return (scoped_project or None), (scoped_name or None)


def _devops_repository_lookup_keys(
    *,
    repository_name: str | None,
    repository_project_name: str | None,
) -> list[str]:
    project_name, resolved_name = _devops_repository_scope(
        repository_name=repository_name,
        repository_project_name=repository_project_name,
    )
    keys: list[str] = []
    if project_name and resolved_name:
        keys.append(f"{project_name.lower()}/{resolved_name.lower()}")
    raw_name = str(repository_name or "").strip().lower()
    if raw_name:
        keys.append(raw_name)
    if resolved_name:
        keys.append(resolved_name.lower())
    return _dedupe_strings(keys)


def _devops_repository_display_name(
    *,
    repository_name: str | None,
    repository_project_name: str | None,
    current_project_name: str | None,
) -> str | None:
    project_name, resolved_name = _devops_repository_scope(
        repository_name=repository_name,
        repository_project_name=repository_project_name,
    )
    if not resolved_name:
        return None
    if project_name and project_name.lower() != str(current_project_name or "").strip().lower():
        return f"{project_name}/{resolved_name}"
    return resolved_name


def _devops_repository_maps(
    repositories: list[dict[str, object]],
) -> tuple[dict[str, dict[str, object]], dict[str, dict[str, object]]]:
    by_id: dict[str, dict[str, object]] = {}
    by_name: dict[str, dict[str, object]] = {}
    for repository in repositories:
        repository_id = str(repository.get("id") or "").strip().lower()
        repository_name = str(repository.get("name") or "").strip().lower()
        repository_project_name = str(_devops_repository_project_name(repository) or "").lower()
        if repository_id:
            by_id[repository_id] = repository
        if repository_name:
            by_name.setdefault(repository_name, repository)
        if repository_project_name and repository_name:
            by_name[f"{repository_project_name}/{repository_name}"] = repository
    return by_id, by_name


def _devops_variable_group_map(
    variable_groups: list[dict[str, object]],
) -> dict[int, dict[str, object]]:
    result: dict[int, dict[str, object]] = {}
    for group in variable_groups:
        group_id = group.get("id")
        if isinstance(group_id, int):
            result[group_id] = group
            continue
        if isinstance(group_id, str) and group_id.isdigit():
            result[int(group_id)] = group
    return result


def _devops_pipeline_is_interesting(item: dict[str, object]) -> bool:
    return any(
        (
            item.get("azure_service_connection_names"),
            item.get("secret_variable_count"),
            item.get("key_vault_group_names"),
            item.get("target_clues"),
            item.get("partial_read"),
        )
    )


def _devops_pipeline_summary(
    *,
    organization: str,
    project: dict[str, object],
    definition: dict[str, object],
    service_endpoints_by_id: dict[str, dict[str, object]],
    service_endpoints_by_name: dict[str, dict[str, object]],
    variable_groups_by_id: dict[int, dict[str, object]],
    repositories_by_id: dict[str, dict[str, object]] | None = None,
    repositories_by_name: dict[str, dict[str, object]] | None = None,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    repositories_by_id = repositories_by_id or {}
    repositories_by_name = repositories_by_name or {}
    definition_project = definition.get("project")
    if not isinstance(definition_project, dict):
        definition_project = {}

    project_name = str(project.get("name") or definition_project.get("name") or "unknown")
    project_id = str(project.get("id") or definition_project.get("id") or "") or None
    definition_id = str(definition.get("id") or "")
    definition_name = str(definition.get("name") or f"definition-{definition_id or 'unknown'}")
    path = str(definition.get("path") or "") or None
    repository = definition.get("repository")
    repository_id = None
    repository_name = None
    repository_type = None
    repository_url = None
    default_branch = None
    if isinstance(repository, dict):
        repository_id = str(repository.get("id") or "") or None
        repository_name = str(repository.get("name") or "") or None
        repository_type = str(repository.get("type") or "") or None
        repository_url = str(repository.get("url") or "") or None
        default_branch = str(repository.get("defaultBranch") or "") or None

    catalog_repository = _devops_resolve_repository(
        repository_id=repository_id,
        repository_name=repository_name,
        repository_project_name=project_name,
        repositories_by_id=repositories_by_id,
        repositories_by_name=repositories_by_name,
    )
    repository_project_name = project_name
    if catalog_repository is not None:
        repository_id = str(catalog_repository.get("id") or repository_id or "") or None
        repository_name = str(catalog_repository.get("name") or repository_name or "") or None
        repository_project_name = (
            _devops_repository_project_name(catalog_repository) or repository_project_name
        )
        project_id = _devops_repository_project_id(catalog_repository) or project_id
        repository_url = (
            str(
                catalog_repository.get("webUrl")
                or catalog_repository.get("url")
                or catalog_repository.get("remoteUrl")
                or repository_url
                or ""
            )
            or None
        )
        default_branch = (
            str(catalog_repository.get("defaultBranch") or default_branch or "") or None
        )

    repository_host_type = _devops_repository_host_type(repository_type)
    source_visibility_state = _devops_source_visibility_state(
        repository_host_type=repository_host_type,
        repository_name=repository_name,
        catalog_repository=catalog_repository,
    )

    inline_secret_count, inline_secret_names = _devops_secret_details(definition.get("variables"))

    referenced_group_ids = _devops_definition_variable_group_ids(definition)
    referenced_groups: list[dict[str, object]] = []
    unresolved_group_ids: list[str] = []
    for group_id in referenced_group_ids:
        group = variable_groups_by_id.get(group_id)
        if group is None:
            unresolved_group_ids.append(str(group_id))
            continue
        referenced_groups.append(group)

    variable_group_names = _dedupe_strings(group.get("name") for group in referenced_groups)
    group_secret_count = 0
    group_secret_names: list[str] = []
    key_vault_group_names: list[str] = []
    key_vault_names: list[str] = []
    provider_endpoint_ids: list[str] = []
    for group in referenced_groups:
        secret_count, secret_names = _devops_secret_details(group.get("variables"))
        group_secret_count += secret_count
        group_secret_names.extend(secret_names)
        if _devops_variable_group_is_key_vault_backed(group):
            group_name = str(group.get("name") or "")
            if group_name:
                key_vault_group_names.append(group_name)
            key_vault_names.extend(_devops_key_vault_names(group.get("providerData")))
        provider_endpoint_ids.extend(
            _devops_service_endpoint_ids_from_provider_data(group.get("providerData"))
        )

    referenced_endpoints, unresolved_endpoint_refs = _devops_definition_endpoint_refs(
        definition,
        service_endpoints_by_id=service_endpoints_by_id,
        service_endpoints_by_name=service_endpoints_by_name,
    )
    unresolved_provider_endpoint_ids: list[str] = []
    for endpoint_id in provider_endpoint_ids:
        endpoint = service_endpoints_by_id.get(endpoint_id.lower())
        if endpoint is None:
            unresolved_provider_endpoint_ids.append(endpoint_id)
            continue
        referenced_endpoints.append(endpoint)

    azure_endpoints = [
        endpoint for endpoint in referenced_endpoints if _devops_is_azure_endpoint(endpoint)
    ]
    azure_service_connection_names = _dedupe_strings(
        endpoint.get("name") for endpoint in azure_endpoints
    )
    azure_service_connection_types = _dedupe_strings(
        endpoint.get("type") for endpoint in azure_endpoints
    )
    azure_service_connection_auth_schemes = _dedupe_strings(
        _devops_endpoint_auth_scheme(endpoint) for endpoint in azure_endpoints
    )
    azure_service_connection_ids = _dedupe_strings(
        endpoint.get("id") for endpoint in azure_endpoints
    )
    azure_service_connection_principal_ids = _dedupe_strings(
        _devops_endpoint_principal_id(endpoint) for endpoint in azure_endpoints
    )
    azure_service_connection_client_ids = _dedupe_strings(
        _devops_endpoint_client_id(endpoint) for endpoint in azure_endpoints
    )
    azure_service_connection_tenant_ids = _dedupe_strings(
        _devops_endpoint_tenant_id(endpoint) for endpoint in azure_endpoints
    )
    azure_service_connection_subscription_ids = _dedupe_strings(
        _devops_endpoint_subscription_id(endpoint) for endpoint in azure_endpoints
    )

    trigger_types = _devops_trigger_types(definition)
    execution_modes = _devops_execution_modes(trigger_types)
    upstream_sources = _devops_upstream_sources(
        organization=organization,
        project_name=project_name,
        repository_host_type=repository_host_type,
        repository_id=repository_id,
        repository_name=repository_name,
        default_branch=default_branch,
        repository_url=repository_url,
        execution_modes=execution_modes,
    )
    secret_variable_names = _dedupe_strings([*inline_secret_names, *group_secret_names])
    secret_variable_count = inline_secret_count + group_secret_count
    key_vault_group_names = _dedupe_strings(key_vault_group_names)
    key_vault_names = _dedupe_strings(key_vault_names)
    secret_support_types = _devops_secret_support_types(
        secret_variable_names=secret_variable_names,
        key_vault_group_names=key_vault_group_names,
        key_vault_names=key_vault_names,
        variable_group_names=variable_group_names,
    )
    secret_dependency_ids = _dedupe_strings(
        [
            *[str(group.get("id") or "") for group in referenced_groups],
            *[f"keyvault:{name}" for name in key_vault_names],
        ]
    )
    target_clues = _devops_target_clues(definition)
    consequence_types = _deployment_consequence_types(
        target_clues=target_clues,
        execution_modes=execution_modes,
        secret_support_types=secret_support_types,
        source_command="devops",
    )
    risk_cues = _devops_risk_cues(
        trigger_types=trigger_types,
        azure_service_connection_names=azure_service_connection_names,
        secret_variable_count=secret_variable_count,
        key_vault_group_names=key_vault_group_names,
        unresolved_group_count=len(unresolved_group_ids),
        unresolved_service_connection_count=(
            len(unresolved_endpoint_refs) + len(unresolved_provider_endpoint_ids)
        ),
    )
    partial_read_reasons = _devops_partial_read_reasons(
        unresolved_group_ids=unresolved_group_ids,
        unresolved_endpoint_refs=unresolved_endpoint_refs,
        unresolved_provider_endpoint_ids=unresolved_provider_endpoint_ids,
    )
    partial_read = bool(partial_read_reasons)
    trigger_join_ids = _devops_trigger_join_ids(
        organization=organization,
        project_name=project_name,
        definition_id=definition_id or definition_name,
        execution_modes=execution_modes,
        upstream_sources=upstream_sources,
    )
    source_join_ids = _devops_source_join_ids(
        organization=organization,
        project_id=project_id,
        project_name=project_name,
        repository_id=repository_id,
        repository_name=repository_name,
        repository_project_name=repository_project_name,
        repository_url=repository_url,
        repository_host_type=repository_host_type,
    )
    trusted_inputs = _devops_finalize_trusted_inputs(
        trusted_inputs=_devops_trusted_inputs(
            organization=organization,
            project_id=project_id,
            project_name=project_name,
            definition=definition,
            repository_id=repository_id,
            repository_name=repository_name,
            repository_url=repository_url,
            repository_host_type=repository_host_type,
            repository_project_name=repository_project_name,
            source_visibility_state=source_visibility_state,
            default_branch=default_branch,
            execution_modes=execution_modes,
            repositories_by_id=repositories_by_id,
            repositories_by_name=repositories_by_name,
        ),
        source_join_ids=source_join_ids,
        current_operator_can_view_source=None,
        current_operator_can_contribute_source=None,
    )
    primary_trusted_input = _devops_primary_trusted_input(trusted_inputs)
    identity_join_ids = _dedupe_strings(
        [
            *azure_service_connection_ids,
            *azure_service_connection_principal_ids,
            *azure_service_connection_client_ids,
        ]
    )
    injection_surface_types = _devops_injection_surface_types(
        trusted_inputs=trusted_inputs,
    )
    missing_execution_path = _devops_missing_execution_path(
        repository_name=repository_name,
        execution_modes=execution_modes,
    )
    missing_injection_point = True
    missing_target_mapping = not bool(target_clues)

    related_ids = _dedupe_strings(
        [
            *(
                [
                    "https://dev.azure.com/"
                    f"{organization}/{quote(project_name, safe='')}/_build?definitionId="
                    f"{definition_id}"
                ]
                if definition_id
                else []
            ),
            *[str(endpoint.get("id") or "") for endpoint in azure_endpoints],
            *[str(group.get("id") or "") for group in referenced_groups],
            *(key_vault_names or []),
        ]
    )

    pipeline = {
        "id": (
            "https://dev.azure.com/"
            f"{organization}/{quote(project_name, safe='')}/_build?definitionId={definition_id}"
            if definition_id
            else f"devops://{organization}/{project_name}/{definition_name}"
        ),
        "definition_id": definition_id or definition_name,
        "name": definition_name,
        "project_id": project_id,
        "project_name": project_name,
        "path": path,
        "repository_id": repository_id,
        "repository_name": repository_name,
        "repository_type": repository_type,
        "repository_url": repository_url,
        "repository_host_type": repository_host_type,
        "source_visibility_state": source_visibility_state,
        "default_branch": default_branch,
        "trigger_types": trigger_types,
        "variable_group_names": variable_group_names,
        "secret_variable_count": secret_variable_count,
        "secret_variable_names": secret_variable_names,
        "key_vault_group_names": key_vault_group_names,
        "key_vault_names": key_vault_names,
        "azure_service_connection_names": azure_service_connection_names,
        "azure_service_connection_types": azure_service_connection_types,
        "azure_service_connection_auth_schemes": azure_service_connection_auth_schemes,
        "azure_service_connection_ids": azure_service_connection_ids,
        "azure_service_connection_principal_ids": azure_service_connection_principal_ids,
        "azure_service_connection_client_ids": azure_service_connection_client_ids,
        "azure_service_connection_tenant_ids": azure_service_connection_tenant_ids,
        "azure_service_connection_subscription_ids": azure_service_connection_subscription_ids,
        "target_clues": target_clues,
        "risk_cues": risk_cues,
        "execution_modes": execution_modes,
        "upstream_sources": upstream_sources,
        "trusted_inputs": trusted_inputs,
        "trusted_input_types": _dedupe_strings(item.get("input_type") for item in trusted_inputs),
        "trusted_input_refs": _dedupe_strings(item.get("ref") for item in trusted_inputs),
        "trusted_input_join_ids": _dedupe_strings(
            join_id for item in trusted_inputs for join_id in (item.get("join_ids") or [])
        ),
        "primary_injection_surface": (
            str((primary_trusted_input.get("surface_types") or [None])[0])
            if primary_trusted_input
            else None
        ),
        "primary_trusted_input_ref": (
            str(primary_trusted_input.get("ref")) if primary_trusted_input else None
        ),
        "source_join_ids": source_join_ids,
        "trigger_join_ids": trigger_join_ids,
        "identity_join_ids": identity_join_ids,
        "secret_support_types": secret_support_types,
        "secret_dependency_ids": secret_dependency_ids,
        "injection_surface_types": injection_surface_types,
        "current_operator_injection_surface_types": [],
        "edit_path_state": "repo-backed" if repository_name else "definition-visible",
        "queue_path_state": "unknown",
        "rerun_path_state": "unknown",
        "approval_path_state": "unknown",
        "current_operator_can_view_source": None,
        "current_operator_can_contribute_source": None,
        "consequence_types": consequence_types,
        "missing_execution_path": missing_execution_path,
        "missing_injection_point": missing_injection_point,
        "missing_target_mapping": missing_target_mapping,
        "partial_read": partial_read,
        "summary": _devops_operator_summary(
            definition_name=definition_name,
            project_name=project_name,
            trusted_inputs=trusted_inputs,
            primary_injection_surface=(
                str((primary_trusted_input.get("surface_types") or [None])[0])
                if primary_trusted_input
                else None
            ),
            primary_trusted_input_ref=(
                str(primary_trusted_input.get("ref")) if primary_trusted_input else None
            ),
            trigger_types=trigger_types,
            execution_modes=execution_modes,
            injection_surface_types=injection_surface_types,
            azure_service_connection_names=azure_service_connection_names,
            variable_group_names=variable_group_names,
            secret_variable_count=secret_variable_count,
            key_vault_group_names=key_vault_group_names,
            key_vault_names=key_vault_names,
            target_clues=target_clues,
            partial_read_reasons=partial_read_reasons,
        ),
        "related_ids": related_ids,
    }
    issues = [
        _partial_collection_issue(
            "devops.definition",
            reason,
            asset_id=str(pipeline["id"]),
            asset_name=definition_name,
        )
        for reason in partial_read_reasons
    ]
    return pipeline, issues


def _devops_refresh_pipeline_state(
    pipeline: dict[str, object],
    *,
    definition_issues: list[dict[str, object]],
) -> None:
    primary_trusted_input = _devops_primary_trusted_input(
        [
            dict(item)
            for item in (pipeline.get("trusted_inputs") or [])
            if isinstance(item, dict)
        ]
    )
    pipeline["trusted_input_types"] = _dedupe_strings(
        item.get("input_type") for item in (pipeline.get("trusted_inputs") or [])
    )
    pipeline["trusted_input_refs"] = _dedupe_strings(
        item.get("ref") for item in (pipeline.get("trusted_inputs") or [])
    )
    pipeline["trusted_input_join_ids"] = _dedupe_strings(
        join_id
        for item in (pipeline.get("trusted_inputs") or [])
        if isinstance(item, dict)
        for join_id in (item.get("join_ids") or [])
    )
    pipeline["primary_injection_surface"] = (
        str((primary_trusted_input.get("surface_types") or [None])[0])
        if primary_trusted_input
        else None
    )
    pipeline["primary_trusted_input_ref"] = (
        str(primary_trusted_input.get("ref")) if primary_trusted_input else None
    )
    pipeline["current_operator_injection_surface_types"] = (
        _devops_current_operator_injection_surfaces(
            trusted_inputs=[
                dict(item)
                for item in (pipeline.get("trusted_inputs") or [])
                if isinstance(item, dict)
            ],
            current_operator_can_edit=pipeline.get("current_operator_can_edit"),
        )
    )
    pipeline["missing_execution_path"] = _devops_missing_execution_path(
        repository_name=_string_value(pipeline.get("repository_name")),
        execution_modes=[str(value) for value in (pipeline.get("execution_modes") or [])],
        current_operator_can_queue=pipeline.get("current_operator_can_queue"),
        current_operator_can_edit=pipeline.get("current_operator_can_edit"),
    )
    pipeline["missing_injection_point"] = not bool(
        pipeline.get("current_operator_injection_surface_types")
    )
    partial_read_reasons = [
        issue["message"].split(": ", 1)[1]
        for issue in definition_issues
        if issue.get("kind") == ErrorKind.PARTIAL_COLLECTION.value
        and isinstance(issue.get("message"), str)
        and ": " in issue["message"]
    ]
    pipeline["partial_read"] = bool(partial_read_reasons)
    risk_cues = [str(value) for value in (pipeline.get("risk_cues") or []) if value]
    if partial_read_reasons:
        risk_cues.append("partial-read")
    pipeline["risk_cues"] = _dedupe_strings(risk_cues)
    pipeline["summary"] = _devops_operator_summary(
        definition_name=str(pipeline.get("name") or "unknown"),
        project_name=str(pipeline.get("project_name") or "unknown"),
        trusted_inputs=[
            dict(item)
            for item in (pipeline.get("trusted_inputs") or [])
            if isinstance(item, dict)
        ],
        primary_injection_surface=_string_value(pipeline.get("primary_injection_surface")),
        primary_trusted_input_ref=_string_value(pipeline.get("primary_trusted_input_ref")),
        trigger_types=[str(value) for value in (pipeline.get("trigger_types") or [])],
        execution_modes=[str(value) for value in (pipeline.get("execution_modes") or [])],
        injection_surface_types=[
            str(value) for value in (pipeline.get("injection_surface_types") or [])
        ],
        azure_service_connection_names=[
            str(value) for value in (pipeline.get("azure_service_connection_names") or [])
        ],
        variable_group_names=[
            str(value) for value in (pipeline.get("variable_group_names") or [])
        ],
        secret_variable_count=int(pipeline.get("secret_variable_count") or 0),
        key_vault_group_names=[
            str(value) for value in (pipeline.get("key_vault_group_names") or [])
        ],
        key_vault_names=[str(value) for value in (pipeline.get("key_vault_names") or [])],
        target_clues=[str(value) for value in (pipeline.get("target_clues") or [])],
        partial_read_reasons=partial_read_reasons,
        current_operator_can_queue=pipeline.get("current_operator_can_queue"),
        current_operator_can_edit=pipeline.get("current_operator_can_edit"),
        current_operator_can_contribute_source=pipeline.get(
            "current_operator_can_contribute_source"
        ),
        current_operator_injection_surface_types=[
            str(value) for value in (pipeline.get("current_operator_injection_surface_types") or [])
        ],
        primary_trusted_input_type=(
            str(primary_trusted_input.get("input_type")) if primary_trusted_input else None
        ),
        primary_trusted_input_access_state=(
            str(primary_trusted_input.get("current_operator_access_state"))
            if primary_trusted_input and primary_trusted_input.get("current_operator_access_state")
            else None
        ),
    )


def _devops_pipeline_key(pipeline: dict[str, object]) -> str:
    project_name = str(pipeline.get("project_name") or "").strip().lower()
    definition_key = (
        str(pipeline.get("definition_id") or pipeline.get("name") or "").strip().lower()
    )
    return f"{project_name}:{definition_key}"


def _devops_secret_details(variables: object) -> tuple[int, list[str]]:
    if not isinstance(variables, dict):
        return 0, []

    count = 0
    names: list[str] = []
    for name, value in variables.items():
        if not isinstance(value, dict):
            continue
        if bool(value.get("isSecret")):
            count += 1
            if name:
                names.append(str(name))
    return count, _dedupe_strings(names)


def _devops_definition_variable_group_ids(definition: dict[str, object]) -> list[int]:
    raw_value = definition.get("variableGroups")
    if not isinstance(raw_value, list):
        return []

    group_ids: list[int] = []
    for item in raw_value:
        if isinstance(item, int):
            group_ids.append(item)
        elif isinstance(item, str) and item.isdigit():
            group_ids.append(int(item))
        elif isinstance(item, dict):
            group_id = item.get("id")
            if isinstance(group_id, int):
                group_ids.append(group_id)
            elif isinstance(group_id, str) and group_id.isdigit():
                group_ids.append(int(group_id))
    return group_ids


def _devops_variable_group_is_key_vault_backed(group: dict[str, object]) -> bool:
    group_type = str(group.get("type") or "").lower()
    if "azurekeyvault" in group_type:
        return True

    provider_data = group.get("providerData")
    if not isinstance(provider_data, dict):
        return False

    return any("vault" in str(key).lower() for key in provider_data.keys())


def _devops_service_endpoint_ids_from_provider_data(provider_data: object) -> list[str]:
    if not isinstance(provider_data, dict):
        return []

    endpoint_ids: list[str] = []
    for key, value in provider_data.items():
        key_text = str(key).lower()
        if "serviceendpoint" not in key_text and "endpoint" not in key_text:
            continue
        if isinstance(value, str):
            endpoint_ids.append(value)
    return _dedupe_strings(endpoint_ids)


def _devops_key_vault_names(provider_data: object) -> list[str]:
    if not isinstance(provider_data, dict):
        return []

    names: list[str] = []
    for key, value in provider_data.items():
        key_text = str(key).lower()
        if "vault" not in key_text:
            continue
        if isinstance(value, str):
            names.append(value)
    return _dedupe_strings(names)


def _devops_definition_endpoint_refs(
    node: object,
    *,
    service_endpoints_by_id: dict[str, dict[str, object]],
    service_endpoints_by_name: dict[str, dict[str, object]],
) -> tuple[list[dict[str, object]], list[str]]:
    endpoint_keys = (
        "serviceconnection",
        "serviceendpoint",
        "connectedservice",
        "azuresubscription",
        "azurecontainerregistry",
        "azureresourcemanagerconnection",
        "kubernetesserviceendpoint",
    )
    matches: list[dict[str, object]] = []
    unresolved_refs: list[str] = []

    def walk(value: object, *, parent_key: str = "") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                walk(child, parent_key=str(key))
            return
        if isinstance(value, list):
            for child in value:
                walk(child, parent_key=parent_key)
            return
        if not isinstance(value, str):
            return

        lowered_parent = parent_key.lower()
        if not any(marker in lowered_parent for marker in endpoint_keys):
            return

        endpoint = service_endpoints_by_id.get(value.strip().lower())
        if endpoint is None:
            endpoint = service_endpoints_by_name.get(value.strip().lower())
        if endpoint is not None:
            matches.append(endpoint)
        else:
            unresolved_refs.append(value.strip())

    walk(node)
    deduped: dict[str, dict[str, object]] = {}
    for endpoint in matches:
        endpoint_key = str(endpoint.get("id") or endpoint.get("name") or "").lower()
        if endpoint_key:
            deduped[endpoint_key] = endpoint
    return list(deduped.values()), _dedupe_strings(unresolved_refs)


def _devops_is_azure_endpoint(endpoint: dict[str, object]) -> bool:
    endpoint_type = str(endpoint.get("type") or "").lower()
    return "azure" in endpoint_type or endpoint_type in {
        "azurerm",
        "dockerregistry",
        "kubernetes",
        "acr",
    }


def _devops_endpoint_auth_scheme(endpoint: dict[str, object]) -> str | None:
    authorization = endpoint.get("authorization")
    if not isinstance(authorization, dict):
        return None
    scheme = authorization.get("scheme")
    return str(scheme) if scheme else None


def _devops_endpoint_principal_id(endpoint: dict[str, object]) -> str | None:
    return _devops_endpoint_lookup(
        endpoint,
        "serviceprincipalobjectid",
        "spnobjectid",
        "aadspobjectid",
        "principalobjectid",
    )


def _devops_endpoint_client_id(endpoint: dict[str, object]) -> str | None:
    return _devops_endpoint_lookup(
        endpoint,
        "serviceprincipalid",
        "clientid",
        "appid",
        "applicationid",
    )


def _devops_endpoint_tenant_id(endpoint: dict[str, object]) -> str | None:
    return _devops_endpoint_lookup(endpoint, "tenantid", "tenant_id")


def _devops_endpoint_subscription_id(endpoint: dict[str, object]) -> str | None:
    return _devops_endpoint_lookup(endpoint, "subscriptionid", "subscription_id")


def _devops_endpoint_lookup(endpoint: dict[str, object], *keys: str) -> str | None:
    collections: list[dict[str, object]] = []
    authorization = endpoint.get("authorization")
    if isinstance(authorization, dict):
        parameters = authorization.get("parameters")
        if isinstance(parameters, dict):
            collections.append(parameters)
    data = endpoint.get("data")
    if isinstance(data, dict):
        collections.append(data)

    lowered_keys = [key.lower() for key in keys]
    for collection in collections:
        lowered_collection = {str(key).lower(): value for key, value in collection.items()}
        for key in lowered_keys:
            value = lowered_collection.get(key)
            if value:
                return str(value)
    return None


def _devops_trigger_types(definition: dict[str, object]) -> list[str]:
    triggers = definition.get("triggers")
    if not isinstance(triggers, list):
        return []

    values: list[str] = []
    for trigger in triggers:
        if not isinstance(trigger, dict):
            continue
        trigger_type = trigger.get("triggerType") or trigger.get("type")
        if trigger_type:
            values.append(str(trigger_type))
    return _dedupe_strings(values)


def _devops_execution_modes(trigger_types: list[str]) -> list[str]:
    lowered = {value.lower() for value in trigger_types}
    modes: list[str] = []
    if "continuousintegration" in lowered:
        modes.append("auto-trigger")
    if "pullrequest" in lowered:
        modes.append("pr-trigger")
    if "schedule" in lowered:
        modes.append("schedule")
    if any("artifact" in value or "buildcompletion" in value for value in lowered):
        modes.append("artifact-trigger")
    if any("webhook" in value for value in lowered):
        modes.append("webhook-trigger")
    if not modes:
        modes.append("manual-only")
    return modes


def _devops_resolve_repository(
    *,
    repository_id: str | None,
    repository_name: str | None,
    repository_project_name: str | None,
    repositories_by_id: dict[str, dict[str, object]],
    repositories_by_name: dict[str, dict[str, object]],
) -> dict[str, object] | None:
    if repository_id:
        match = repositories_by_id.get(repository_id.strip().lower())
        if match is not None:
            return match
    for key in _devops_repository_lookup_keys(
        repository_name=repository_name,
        repository_project_name=repository_project_name,
    ):
        match = repositories_by_name.get(key)
        if match is not None:
            return match
    return None


def _devops_repository_host_type(repository_type: str | None) -> str | None:
    lowered = str(repository_type or "").strip().lower()
    if not lowered:
        return None
    if lowered == "tfsgit":
        return "azure-repos"
    if lowered == "github":
        return "github"
    if lowered == "githubenterprise":
        return "github-enterprise"
    if "bitbucket" in lowered:
        return "bitbucket"
    if lowered in {"git", "externalgit"}:
        return "external-git"
    if lowered == "tfvc":
        return "tfvc"
    return lowered


def _devops_source_visibility_state(
    *,
    repository_host_type: str | None,
    repository_name: str | None,
    catalog_repository: dict[str, object] | None,
) -> str | None:
    if not repository_name:
        return None
    if repository_host_type == "azure-repos":
        return "visible" if catalog_repository is not None else "inferred-only"
    if repository_host_type:
        return "external-reference"
    return "definition-reference"


def _devops_repo_ref(
    *,
    repository_host_type: str | None,
    repository_name: str | None,
    default_branch: str | None,
    repository_url: str | None,
) -> str | None:
    if repository_name:
        repo_ref = repository_name
        if default_branch:
            repo_ref = f"{repo_ref}@{default_branch}"
    elif repository_url:
        repo_ref = repository_url
    else:
        return None

    if repository_host_type:
        return f"{repository_host_type}:{repo_ref}"
    return repo_ref


def _devops_upstream_sources(
    *,
    organization: str,
    project_name: str,
    repository_host_type: str | None,
    repository_id: str | None,
    repository_name: str | None,
    default_branch: str | None,
    repository_url: str | None,
    execution_modes: list[str],
) -> list[str]:
    sources: list[str] = []
    repo_ref = _devops_repo_ref(
        repository_host_type=repository_host_type,
        repository_name=repository_name,
        default_branch=default_branch,
        repository_url=repository_url,
    )
    if repo_ref:
        sources.append(f"repo:{repo_ref}")
        if "pr-trigger" in execution_modes:
            sources.append(f"pull-request:{repo_ref}")
    if "schedule" in execution_modes:
        sources.append("schedule")
    if "artifact-trigger" in execution_modes:
        sources.append("artifact")
    if "webhook-trigger" in execution_modes:
        sources.append("webhook")
    if "manual-only" in execution_modes:
        sources.append("manual-run")
    return _dedupe_strings(sources)


def _devops_source_join_ids(
    *,
    organization: str,
    project_id: str | None,
    project_name: str | None,
    repository_id: str | None,
    repository_name: str | None,
    repository_project_name: str | None,
    repository_url: str | None,
    repository_host_type: str | None,
) -> list[str]:
    ids: list[str] = []
    if repository_host_type == "azure-repos" and project_id and repository_id:
        ids.append(
            "devops-repo://"
            f"{quote(organization, safe='')}/{quote(project_id, safe='')}/"
            f"{quote(repository_id, safe='')}"
        )
    if repository_url:
        ids.append(f"repo-url://{quote(repository_url, safe=':/@')}")
    if repository_name and repository_host_type:
        repo_ref_name = _devops_repository_display_name(
            repository_name=repository_name,
            repository_project_name=repository_project_name,
            current_project_name=project_name,
        ) or repository_name
        ids.append(
            f"repo-ref://{quote(repository_host_type, safe='')}/{quote(repo_ref_name, safe='')}"
        )
    return _dedupe_strings(ids)


def _devops_trusted_inputs(
    *,
    organization: str,
    project_id: str | None,
    project_name: str,
    definition: dict[str, object],
    repository_id: str | None,
    repository_name: str | None,
    repository_url: str | None,
    repository_host_type: str | None,
    repository_project_name: str | None,
    source_visibility_state: str | None,
    default_branch: str | None,
    execution_modes: list[str],
    repositories_by_id: dict[str, dict[str, object]],
    repositories_by_name: dict[str, dict[str, object]],
) -> list[dict[str, object]]:
    inputs: list[dict[str, object]] = []
    repo_ref = _devops_repo_ref(
        repository_host_type=repository_host_type,
        repository_name=_devops_repository_display_name(
            repository_name=repository_name,
            repository_project_name=repository_project_name,
            current_project_name=project_name,
        ),
        default_branch=default_branch,
        repository_url=repository_url,
    )
    if repo_ref:
        inputs.append(
            {
                "input_type": "repository",
                "ref": f"repository:{repo_ref}",
                "visibility_state": source_visibility_state,
                "surface_types": _dedupe_strings(
                    ["repo-content", "pull-request" if "pr-trigger" in execution_modes else None]
                ),
                "join_ids": _devops_source_join_ids(
                    organization=organization,
                    project_id=project_id,
                    project_name=project_name,
                    repository_id=repository_id,
                    repository_name=repository_name,
                    repository_project_name=repository_project_name,
                    repository_url=repository_url,
                    repository_host_type=repository_host_type,
                ),
            }
        )

    inputs.extend(
        _devops_definition_trusted_inputs(
            organization=organization,
            project_id=project_id,
            project_name=project_name,
            definition=definition,
            repositories_by_id=repositories_by_id,
            repositories_by_name=repositories_by_name,
        )
    )
    return _devops_merge_trusted_inputs(inputs)


def _devops_definition_trusted_inputs(
    *,
    organization: str,
    project_id: str | None,
    project_name: str,
    definition: dict[str, object],
    repositories_by_id: dict[str, dict[str, object]],
    repositories_by_name: dict[str, dict[str, object]],
) -> list[dict[str, object]]:
    inputs: list[dict[str, object]] = []
    repository_aliases: dict[str, dict[str, object]] = {}

    for path, node in _recursive_nodes(definition):
        if not isinstance(node, dict):
            continue
        path_tokens = set(_devops_path_tokens(path))

        if "resources" in path_tokens and "repositories" in path_tokens:
            repo_name = _string_value(node.get("name"))
            repo_url = _string_value(node.get("url"))
            repo_id = _string_value(node.get("id"))
            repo_project_name = _string_value(node.get("project")) or project_name
            repo_type = (
                _string_value(node.get("type"))
                or _string_value(node.get("repositoryType"))
                or _devops_repository_host_type_from_url(repo_url)
            )
            alias = _string_value(node.get("repository")) or _string_value(node.get("alias"))
            catalog_repository = _devops_resolve_repository(
                repository_id=repo_id,
                repository_name=repo_name or alias,
                repository_project_name=repo_project_name,
                repositories_by_id=repositories_by_id,
                repositories_by_name=repositories_by_name,
            )
            resolved_project_name = repo_project_name
            resolved_project_id = project_id
            if catalog_repository is not None:
                repo_id = str(catalog_repository.get("id") or repo_id or "") or None
                repo_name = str(catalog_repository.get("name") or repo_name or "") or None
                resolved_project_name = (
                    _devops_repository_project_name(catalog_repository)
                    or repo_project_name
                    or project_name
                )
                resolved_project_id = (
                    _devops_repository_project_id(catalog_repository)
                    or resolved_project_id
                )
                repo_url = (
                    str(
                        catalog_repository.get("webUrl")
                        or catalog_repository.get("url")
                        or catalog_repository.get("remoteUrl")
                        or repo_url
                        or ""
                    )
                    or None
                )

            host_type = _devops_repository_host_type(
                repo_type
            ) or _devops_repository_host_type_from_url(repo_url)
            visibility_state = _devops_visibility_state_for_value(
                _string_value(node.get("name")) or repo_url or alias,
                external_reference=host_type not in {None, "azure-repos"},
            )
            if host_type == "azure-repos":
                visibility_state = _devops_source_visibility_state(
                    repository_host_type=host_type,
                    repository_name=repo_name or alias,
                    catalog_repository=catalog_repository,
                )
            ref_value = _devops_repo_ref(
                repository_host_type=host_type,
                repository_name=_devops_repository_display_name(
                    repository_name=repo_name or alias,
                    repository_project_name=resolved_project_name,
                    current_project_name=project_name,
                ),
                default_branch=_string_value(node.get("ref")),
                repository_url=repo_url,
            )
            if ref_value:
                trusted_input = {
                    "input_type": "template-repository",
                    "ref": f"template-repository:{ref_value}",
                    "visibility_state": visibility_state,
                    "surface_types": ["template-repo"],
                    "join_ids": _devops_source_join_ids(
                        organization=organization,
                        project_id=resolved_project_id,
                        project_name=project_name,
                        repository_id=repo_id,
                        repository_name=repo_name or alias,
                        repository_project_name=resolved_project_name,
                        repository_url=repo_url,
                        repository_host_type=host_type,
                    ),
                }
                inputs.append(trusted_input)
                if alias:
                    repository_aliases[alias.lower()] = trusted_input

        if "resources" in path_tokens and "pipelines" in path_tokens:
            alias = _string_value(node.get("pipeline")) or _string_value(node.get("alias"))
            source_name = _string_value(node.get("source"))
            producer_project = _string_value(node.get("project")) or project_name
            artifact_name = _string_value(node.get("artifact")) or _string_value(
                node.get("artifactName")
            )
            if alias or source_name or artifact_name:
                ref = "pipeline-artifact:" + "/".join(
                    part
                    for part in (
                        producer_project,
                        source_name or alias,
                    )
                    if part
                )
                if artifact_name:
                    ref = f"{ref}#{artifact_name}"
                inputs.append(
                    {
                        "input_type": "pipeline-artifact",
                        "ref": ref,
                        "visibility_state": _devops_visibility_state_for_value(
                            source_name or alias or artifact_name
                        ),
                        "surface_types": ["pipeline-artifact"],
                        "join_ids": [
                            "devops-pipeline-artifact://"
                            f"{quote(organization, safe='')}/"
                            f"{quote(producer_project, safe='')}/"
                            f"{quote((source_name or alias or 'resource'), safe='')}"
                        ],
                    }
                )

    for path, node in _recursive_nodes(definition):
        if not isinstance(node, dict):
            continue
        path_tokens = set(_devops_path_tokens(path))

        if path_tokens & {"artifact", "download", "pipeline", "build"}:
            artifact_name = _devops_first_value_for_tokens(
                node,
                (
                    ("artifact", "name"),
                    ("artifact",),
                ),
            )
            artifact_source = _devops_first_value_for_tokens(
                node,
                (
                    ("pipeline",),
                    ("definition",),
                    ("build",),
                    ("source",),
                ),
            )
            artifact_project = _devops_first_value_for_tokens(
                node,
                (
                    ("project",),
                    ("project", "name"),
                ),
            )
            if artifact_name or artifact_source:
                ref = "pipeline-artifact:" + "/".join(
                    part
                    for part in (
                        artifact_project or project_name,
                        artifact_source or "current",
                    )
                    if part
                )
                if artifact_name:
                    ref = f"{ref}#{artifact_name}"
                inputs.append(
                    {
                        "input_type": "pipeline-artifact",
                        "ref": ref,
                        "visibility_state": _devops_visibility_state_for_value(
                            artifact_name or artifact_source
                        ),
                        "surface_types": ["pipeline-artifact"],
                        "join_ids": [
                            "devops-pipeline-artifact://"
                            f"{quote(organization, safe='')}/"
                            f"{quote((artifact_project or project_name), safe='')}/"
                            f"{quote((artifact_source or 'current'), safe='')}"
                        ],
                    }
                )

        secure_file = _devops_first_value_for_tokens(node, (("secure", "file"),))
        if secure_file:
            inputs.append(
                {
                    "input_type": "secure-file",
                    "ref": f"secure-file:{secure_file}",
                    "visibility_state": _devops_visibility_state_for_value(secure_file),
                    "surface_types": ["secure-file"],
                    "join_ids": [
                        "devops-secure-file://"
                        f"{quote(organization, safe='')}/"
                        f"{quote(project_name, safe='')}/"
                        f"{quote(secure_file, safe='')}"
                    ],
                }
            )

        feed_value = _devops_first_feed_value(node)
        if feed_value:
            inputs.append(_devops_package_feed_input(organization, project_name, feed_value))

        template_value = _devops_first_value_for_tokens(node, (("template",),))
        if template_value and "@" in template_value:
            alias = template_value.rsplit("@", 1)[-1].strip().lower()
            aliased_input = repository_aliases.get(alias)
            if aliased_input is not None:
                inputs.append(dict(aliased_input))
            else:
                inputs.append(
                    {
                        "input_type": "template-repository",
                        "ref": f"template-repository:{alias}",
                        "visibility_state": "inferred-only",
                        "surface_types": ["template-repo"],
                        "join_ids": [
                            "devops-template-repo://"
                            f"{quote(organization, safe='')}/"
                            f"{quote(project_name, safe='')}/"
                            f"{quote(alias, safe='')}"
                        ],
                    }
                )

        for key, value in node.items():
            if not isinstance(value, str):
                continue
            key_tokens = set(_devops_identifier_tokens(key))
            if _looks_like_http_url(value):
                if "repository" in path_tokens and "resources" not in path_tokens:
                    continue
                if _looks_like_repo_url(value) and ({"template", "repository"} & key_tokens):
                    host_type = _devops_repository_host_type_from_url(value)
                    inputs.append(
                        {
                            "input_type": "template-repository",
                            "ref": f"template-repository:{host_type}:{value}",
                            "visibility_state": "external-reference",
                            "surface_types": ["template-repo"],
                            "join_ids": [f"repo-url://{quote(value, safe=':/@')}"],
                        }
                    )
                elif {"url", "uri", "download", "script", "template"} & key_tokens:
                    inputs.append(
                        {
                            "input_type": "external-url",
                            "ref": f"external-url:{value}",
                            "visibility_state": "external-reference",
                            "surface_types": ["external-download"],
                            "join_ids": [f"url://{quote(value, safe=':/@')}"],
                        }
                    )

            if {"image", "container", "repository"} & key_tokens and _looks_like_image_ref(value):
                inputs.append(
                    {
                        "input_type": "registry-image",
                        "ref": f"registry-image:{value}",
                        "visibility_state": _devops_visibility_state_for_value(
                            value,
                            external_reference=True,
                        ),
                        "surface_types": ["registry-image"],
                        "join_ids": [f"image-ref://{quote(value, safe=':/@')}"],
                    }
                )

    return _devops_merge_trusted_inputs(inputs)


def _recursive_nodes(
    node: object,
    path: tuple[str, ...] = (),
) -> list[tuple[tuple[str, ...], object]]:
    values: list[tuple[tuple[str, ...], object]] = [(path, node)]
    if isinstance(node, dict):
        for key, value in node.items():
            values.extend(_recursive_nodes(value, path + (str(key),)))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            values.extend(_recursive_nodes(value, path + (f"[{index}]",)))
    return values


def _devops_identifier_tokens(value: object) -> list[str]:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(value))
    return [token for token in re.split(r"[^a-z0-9]+", text.lower()) if token]


def _devops_path_tokens(path: tuple[str, ...]) -> list[str]:
    return [token for part in path for token in _devops_identifier_tokens(part)]


def _devops_visibility_state_for_value(
    value: str | None,
    *,
    external_reference: bool = False,
) -> str | None:
    if not value:
        return None
    if _looks_like_expression(value):
        return "inferred-only"
    if external_reference:
        return "external-reference"
    return "visible"


def _looks_like_expression(value: str) -> bool:
    return "$(" in value or "${{" in value or "$[" in value


def _devops_repository_host_type_from_url(url: str | None) -> str | None:
    if not url:
        return None
    host = urlparse(url).netloc.lower()
    if "dev.azure.com" in host or "visualstudio.com" in host:
        return "azure-repos"
    if "github.com" in host:
        return "github"
    if "gitlab" in host:
        return "gitlab"
    if "bitbucket" in host:
        return "bitbucket"
    return "external-git" if host else None


def _looks_like_http_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _looks_like_repo_url(value: str) -> bool:
    lowered = value.lower()
    return lowered.endswith(".git") or any(
        marker in lowered for marker in ("github.com/", "gitlab", "/_git/", "bitbucket.org/")
    )


def _looks_like_image_ref(value: str) -> bool:
    if value.startswith("refs/") or _looks_like_http_url(value):
        return False
    return bool(
        re.match(
            r"^(?:[a-z0-9.-]+(?::\d+)?/)?[a-z0-9]+(?:[._/-][a-z0-9]+)*(?::[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})$",
            value.lower(),
        )
    )


def _devops_first_value_for_tokens(
    node: dict[str, object],
    token_groups: tuple[tuple[str, ...], ...],
) -> str | None:
    for key, value in node.items():
        if not isinstance(value, str):
            continue
        key_tokens = set(_devops_identifier_tokens(key))
        for token_group in token_groups:
            if set(token_group).issubset(key_tokens):
                return value.strip()
    return None


def _devops_first_feed_value(node: dict[str, object]) -> str | None:
    for key, value in node.items():
        if not isinstance(value, str):
            continue
        key_tokens = set(_devops_identifier_tokens(key))
        if "feed" in key_tokens or "/_packaging/" in value.lower():
            return value.strip()
    return None


def _devops_package_feed_input(
    organization: str,
    project_name: str,
    feed_value: str,
) -> dict[str, object]:
    visibility_state = _devops_visibility_state_for_value(feed_value)
    ref_value = feed_value
    join_ids: list[str] = []
    if _looks_like_http_url(feed_value):
        parsed = urlparse(feed_value)
        lowered_path = parsed.path.lower()
        if "/_packaging/" in lowered_path:
            feed_project_name, feed_name = _devops_feed_url_scope(
                organization=organization,
                feed_url=feed_value,
            )
            if feed_name:
                ref_value = (
                    f"{feed_project_name}/{feed_name}"
                    if feed_project_name
                    else feed_name
                )
        join_ids.append(f"feed-url://{quote(feed_value, safe=':/@')}")
        if (
            parsed.netloc
            and "dev.azure.com" not in parsed.netloc
            and "pkgs.dev.azure.com" not in parsed.netloc
        ):
            visibility_state = "external-reference"
    else:
        feed_project_name, feed_name = _devops_feed_ref_parts(
            feed_value,
            default_project_name=project_name,
        )
        ref_value = (
            f"{feed_project_name}/{feed_name}"
            if feed_project_name
            else (feed_name or feed_value)
        )
        if feed_name:
            join_ids.append(
                "devops-feed://"
                f"{quote(organization, safe='')}/"
                f"{quote((feed_project_name or ''), safe='')}/"
                f"{quote(feed_name, safe='')}"
            )

    return {
        "input_type": "package-feed",
        "ref": f"package-feed:{ref_value}",
        "visibility_state": visibility_state,
        "surface_types": ["feed-package"],
        "join_ids": join_ids,
    }


def _devops_access_state_rank(value: object) -> int:
    return {"write": 0, "use": 1, "read": 2, "exists-only": 3}.get(str(value or ""), 9)


def _devops_apply_permission_proof(
    trusted_input: dict[str, object],
    *,
    access_state: str | None,
    can_poison: bool | None,
    evidence_basis: str | None,
    permission_source: str | None,
    permission_detail: str | None,
) -> dict[str, object]:
    updated = dict(trusted_input)
    updated["current_operator_access_state"] = access_state
    updated["current_operator_can_poison"] = can_poison
    updated["trusted_input_evidence_basis"] = evidence_basis
    updated["trusted_input_permission_source"] = permission_source
    updated["trusted_input_permission_detail"] = permission_detail
    return updated


def _devops_default_permission_proof(trusted_input: dict[str, object]) -> tuple[str, str, str]:
    visibility_state = str(trusted_input.get("visibility_state") or "") or "visible"
    detail_map = {
        "visible": "visible reference only",
        "inferred-only": "expression-backed reference only",
        "external-reference": "external reference only",
        "definition-reference": "definition reference only",
    }
    return (
        "definition-reference",
        "pipeline-definition",
        detail_map.get(visibility_state, "reference only"),
    )


def _devops_apply_repository_permission_proof(
    trusted_input: dict[str, object],
    *,
    can_view: object,
    can_contribute: object,
    permission_source: str,
) -> dict[str, object]:
    if can_contribute is True:
        return _devops_apply_permission_proof(
            trusted_input,
            access_state="write",
            can_poison=True,
            evidence_basis="repository-permission",
            permission_source=permission_source,
            permission_detail="GenericContribute allowed",
        )
    if can_view is True:
        return _devops_apply_permission_proof(
            trusted_input,
            access_state="read",
            can_poison=False,
            evidence_basis="repository-permission",
            permission_source=permission_source,
            permission_detail="GenericRead allowed",
        )
    return trusted_input


def _devops_repo_project_and_id(join_ids: list[object]) -> tuple[str | None, str | None]:
    for join_id in join_ids:
        text = str(join_id or "")
        if not text.startswith("devops-repo://"):
            continue
        parts = [part for part in text.split("://", 1)[1].split("/") if part]
        if len(parts) >= 3:
            return parts[1], parts[2]
    return None, None


def _devops_feed_name_from_trusted_input(trusted_input: dict[str, object]) -> str | None:
    _project_name, feed_name = _devops_feed_scope_from_trusted_input(trusted_input)
    return feed_name


def _devops_feed_ref_parts(
    feed_value: str,
    *,
    default_project_name: str | None = None,
) -> tuple[str | None, str | None]:
    value = str(feed_value or "").strip()
    if not value:
        return default_project_name, None
    if "/" in value:
        project_name, feed_name = value.rsplit("/", 1)
        return project_name.strip() or None, feed_name.strip() or None
    return default_project_name, value


def _devops_feed_url_scope(
    *,
    organization: str,
    feed_url: str,
) -> tuple[str | None, str | None]:
    parsed = urlparse(feed_url)
    path_parts = [part for part in parsed.path.split("/") if part]
    if path_parts and path_parts[0].lower() == organization.lower():
        path_parts = path_parts[1:]
    if "_packaging" not in path_parts:
        return None, None
    index = path_parts.index("_packaging")
    project_name = path_parts[index - 1] if index >= 1 else None
    feed_name = path_parts[index + 1] if len(path_parts) > index + 1 else None
    return project_name or None, feed_name or None


def _devops_feed_scope_from_trusted_input(
    trusted_input: dict[str, object],
) -> tuple[str | None, str | None]:
    ref = str(trusted_input.get("ref") or "")
    if ref.startswith("package-feed:"):
        return _devops_feed_ref_parts(ref.split(":", 1)[1])
    for join_id in trusted_input.get("join_ids") or []:
        text = str(join_id or "")
        if not text.startswith("devops-feed://"):
            continue
        parts = text.split("://", 1)[1].split("/")
        if len(parts) >= 3:
            project_name = parts[1] or None
            feed_name = parts[2] or None
            return project_name, feed_name
    return None, None


def _devops_feed_permission_role(permission: dict[str, object]) -> str | None:
    candidates = [
        permission.get("role"),
        permission.get("roleName"),
        permission.get("displayName"),
    ]
    role = permission.get("role")
    if isinstance(role, dict):
        candidates.extend([role.get("name"), role.get("displayName")])
    for candidate in candidates:
        text = str(candidate or "").strip()
        if text:
            return text.lower()
    return None


def _devops_apply_feed_permission_proof(
    trusted_input: dict[str, object],
    *,
    permissions: list[dict[str, object]],
) -> dict[str, object]:
    best_role: str | None = None
    best_rank = 9
    for permission in permissions:
        role = _devops_feed_permission_role(permission)
        rank = {
            "administrator": 0,
            "contributor": 1,
            "collaborator": 2,
            "reader": 3,
        }.get(str(role or ""), 9)
        if rank < best_rank:
            best_role = role
            best_rank = rank

    if best_role in {"administrator", "contributor"}:
        return _devops_apply_permission_proof(
            trusted_input,
            access_state="write",
            can_poison=True,
            evidence_basis="feed-role",
            permission_source="azure-devops-artifacts-feed-permissions",
            permission_detail=f"role={best_role}",
        )
    if best_role in {"collaborator", "reader"}:
        return _devops_apply_permission_proof(
            trusted_input,
            access_state="read",
            can_poison=False,
            evidence_basis="feed-role",
            permission_source="azure-devops-artifacts-feed-permissions",
            permission_detail=f"role={best_role}",
        )
    return trusted_input


def _devops_secure_file_name_from_trusted_input(trusted_input: dict[str, object]) -> str | None:
    ref = str(trusted_input.get("ref") or "")
    if ref.startswith("secure-file:"):
        return ref.split(":", 1)[1]
    return None


def _devops_secure_file_role_name(role_assignment: dict[str, object]) -> str | None:
    role_name = role_assignment.get("roleName")
    if role_name:
        return str(role_name).strip().lower()
    role = role_assignment.get("role")
    if isinstance(role, dict):
        for key in ("name", "displayName"):
            value = role.get(key)
            if value:
                return str(value).strip().lower()
    for key in ("displayName", "name"):
        value = role_assignment.get(key)
        if value:
            return str(value).strip().lower()
    return None


def _devops_secure_file_assignment_matches_current_operator(
    role_assignment: dict[str, object],
    current_operator: dict[str, object] | None,
) -> bool:
    if not isinstance(current_operator, dict):
        return False

    profile_id = str(current_operator.get("profile_id") or "").lower()
    descriptors = {
        str(value).lower()
        for value in current_operator.get("subject_descriptors") or []
        if str(value or "").strip()
    }
    descriptor = str(current_operator.get("descriptor") or "").lower()
    if descriptor:
        descriptors.add(descriptor)

    candidates: list[str] = []
    for key in ("userId", "identityId", "descriptor", "identityDescriptor"):
        value = role_assignment.get(key)
        if value:
            candidates.append(str(value))
    identity = role_assignment.get("identity")
    if isinstance(identity, dict):
        for key in ("id", "descriptor", "subjectDescriptor"):
            value = identity.get(key)
            if value:
                candidates.append(str(value))

    lowered = {candidate.lower() for candidate in candidates if candidate}
    if profile_id and profile_id in lowered:
        return True
    return bool(descriptors & lowered)


def _devops_apply_secure_file_role_proof(
    trusted_input: dict[str, object],
    *,
    role_assignments: list[dict[str, object]],
    current_operator: dict[str, object] | None,
) -> dict[str, object]:
    best_role: str | None = None
    best_rank = 9
    for role_assignment in role_assignments:
        if not _devops_secure_file_assignment_matches_current_operator(
            role_assignment,
            current_operator,
        ):
            continue
        role_name = _devops_secure_file_role_name(role_assignment)
        rank = {
            "administrator": 0,
            "admin": 0,
            "user": 1,
            "creator": 2,
            "reader": 3,
        }.get(str(role_name or ""), 9)
        if rank < best_rank:
            best_role = role_name
            best_rank = rank

    if best_role in {"administrator", "admin"}:
        return _devops_apply_permission_proof(
            trusted_input,
            access_state="write",
            can_poison=True,
            evidence_basis="secure-file-role",
            permission_source="azure-devops-library-security-role",
            permission_detail=f"role={best_role}",
        )
    if best_role == "user":
        return _devops_apply_permission_proof(
            trusted_input,
            access_state="use",
            can_poison=False,
            evidence_basis="secure-file-role",
            permission_source="azure-devops-library-security-role",
            permission_detail="role=user",
        )
    if best_role in {"reader", "creator"}:
        return _devops_apply_permission_proof(
            trusted_input,
            access_state="exists-only",
            can_poison=False,
            evidence_basis="secure-file-role",
            permission_source="azure-devops-library-security-role",
            permission_detail=f"role={best_role}",
        )
    return trusted_input


def _devops_pipeline_lookup(
    pipelines: list[dict[str, object]],
) -> dict[tuple[str, str], dict[str, object]]:
    result: dict[tuple[str, str], dict[str, object]] = {}
    for pipeline in pipelines:
        project_name = str(pipeline.get("project_name") or "").strip().lower()
        pipeline_name = str(pipeline.get("name") or "").strip().lower()
        if project_name and pipeline_name:
            result[(project_name, pipeline_name)] = pipeline
        definition_id = str(pipeline.get("definition_id") or "").strip().lower()
        if project_name and definition_id:
            result[(project_name, definition_id)] = pipeline
    return result


def _devops_pipeline_artifact_ref_parts(ref: str) -> tuple[str | None, str | None, str | None]:
    if not ref.startswith("pipeline-artifact:"):
        return None, None, None
    path = ref.split(":", 1)[1]
    project_and_pipeline, _, artifact_name = path.partition("#")
    if "/" not in project_and_pipeline:
        return None, project_and_pipeline or None, artifact_name or None
    project_name, pipeline_name = project_and_pipeline.split("/", 1)
    return project_name or None, pipeline_name or None, artifact_name or None


def _devops_apply_artifact_producer_proof(
    trusted_input: dict[str, object],
    *,
    producer_pipeline: dict[str, object],
) -> dict[str, object]:
    producer_surfaces = [
        str(value)
        for value in (producer_pipeline.get("current_operator_injection_surface_types") or [])
        if value
    ]
    if (
        producer_pipeline.get("current_operator_can_edit") is True
        or "definition-edit" in producer_surfaces
    ):
        return _devops_apply_permission_proof(
            trusted_input,
            access_state="write",
            can_poison=True,
            evidence_basis="artifact-producer-definition-edit",
            permission_source="azure-devops-build-permissions",
            permission_detail="producer EditBuildDefinition allowed",
        )
    non_definition_surfaces = [
        value for value in producer_surfaces if value != "definition-edit"
    ]
    if non_definition_surfaces:
        return _devops_apply_permission_proof(
            trusted_input,
            access_state="write",
            can_poison=True,
            evidence_basis="artifact-producer-input-control",
            permission_source="azure-devops-build-permissions",
            permission_detail="producer poisonable via " + ",".join(non_definition_surfaces),
        )
    if producer_pipeline.get("current_operator_can_view_definition") is True:
        return _devops_apply_permission_proof(
            trusted_input,
            access_state="read",
            can_poison=False,
            evidence_basis="artifact-producer-visible",
            permission_source="azure-devops-build-permissions",
            permission_detail="producer definition visible",
        )
    return trusted_input


def _devops_enrich_artifact_trusted_inputs(
    *,
    pipeline: dict[str, object],
    trusted_inputs: list[dict[str, object]],
    pipelines_by_project_and_name: dict[tuple[str, str], dict[str, object]],
) -> list[dict[str, object]]:
    project_name = str(pipeline.get("project_name") or "")
    enriched: list[dict[str, object]] = []
    for trusted_input in trusted_inputs:
        item = dict(trusted_input)
        if str(item.get("input_type") or "") != "pipeline-artifact":
            enriched.append(item)
            continue
        ref = str(item.get("ref") or "")
        producer_project, producer_name, _artifact_name = _devops_pipeline_artifact_ref_parts(ref)
        if producer_name == "current":
            producer_pipeline = pipeline
        else:
            lookup_project = (producer_project or project_name).strip().lower()
            lookup_name = (producer_name or "").strip().lower()
            producer_pipeline = (
                pipelines_by_project_and_name.get((lookup_project, lookup_name))
                if lookup_project and lookup_name
                else None
            )
        if producer_pipeline is not None:
            item = _devops_apply_artifact_producer_proof(
                item,
                producer_pipeline=producer_pipeline,
            )
        enriched.append(item)
    return _devops_merge_trusted_inputs(enriched)


def _devops_merge_trusted_inputs(
    inputs: list[dict[str, object]],
) -> list[dict[str, object]]:
    merged: dict[tuple[str, str], dict[str, object]] = {}
    for item in inputs:
        input_type = str(item.get("input_type") or "")
        ref = str(item.get("ref") or "")
        if not input_type or not ref:
            continue
        key = (input_type, ref)
        existing = merged.get(key)
        if existing is None:
            merged[key] = {
                **item,
                "surface_types": [str(value) for value in item.get("surface_types") or [] if value],
                "join_ids": [str(value) for value in item.get("join_ids") or [] if value],
            }
            continue
        existing["surface_types"] = _dedupe_strings(
            [*existing.get("surface_types", []), *(item.get("surface_types") or [])]
        )
        existing["join_ids"] = _dedupe_strings(
            [*existing.get("join_ids", []), *(item.get("join_ids") or [])]
        )
        existing["visibility_state"] = _preferred_visibility_state(
            existing.get("visibility_state"),
            item.get("visibility_state"),
        )
        existing["current_operator_access_state"] = _preferred_access_state(
            existing.get("current_operator_access_state"),
            item.get("current_operator_access_state"),
        )
        if existing.get("current_operator_can_poison") is not True:
            if item.get("current_operator_can_poison") is True:
                existing["current_operator_can_poison"] = True
            elif existing.get("current_operator_can_poison") is None:
                existing["current_operator_can_poison"] = item.get("current_operator_can_poison")
        if _devops_should_replace_proof(existing, item):
            for field_name in (
                "trusted_input_evidence_basis",
                "trusted_input_permission_source",
                "trusted_input_permission_detail",
            ):
                existing[field_name] = item.get(field_name)
    return sorted(merged.values(), key=_trusted_input_sort_key)


def _preferred_visibility_state(left: object, right: object) -> str | None:
    order = {"visible": 0, "inferred-only": 1, "external-reference": 2}
    left_value = str(left) if left else None
    right_value = str(right) if right else None
    if left_value is None:
        return right_value
    if right_value is None:
        return left_value
    return left_value if order.get(left_value, 9) <= order.get(right_value, 9) else right_value


def _preferred_access_state(left: object, right: object) -> str | None:
    left_value = str(left) if left else None
    right_value = str(right) if right else None
    if left_value is None:
        return right_value
    if right_value is None:
        return left_value
    return (
        left_value
        if _devops_access_state_rank(left_value) <= _devops_access_state_rank(right_value)
        else right_value
    )


def _devops_should_replace_proof(existing: dict[str, object], item: dict[str, object]) -> bool:
    existing_rank = _devops_access_state_rank(existing.get("current_operator_access_state"))
    item_rank = _devops_access_state_rank(item.get("current_operator_access_state"))
    if item_rank < existing_rank:
        return True
    if item_rank > existing_rank:
        return False
    existing_poison = existing.get("current_operator_can_poison") is True
    item_poison = item.get("current_operator_can_poison") is True
    if item_poison and not existing_poison:
        return True
    if existing_poison and not item_poison:
        return False
    return any(
        item.get(field_name) and not existing.get(field_name)
        for field_name in (
            "trusted_input_evidence_basis",
            "trusted_input_permission_source",
            "trusted_input_permission_detail",
        )
    )


def _trusted_input_sort_key(item: dict[str, object]) -> tuple[int, int, int, str]:
    type_order = {
        "template-repository": 0,
        "package-feed": 1,
        "pipeline-artifact": 2,
        "secure-file": 3,
        "registry-image": 4,
        "external-url": 5,
        "repository": 6,
    }
    visibility_order = {"visible": 0, "inferred-only": 1, "external-reference": 2}
    poison = 0 if item.get("current_operator_can_poison") is True else 1
    visibility = visibility_order.get(str(item.get("visibility_state") or ""), 9)
    return (
        poison,
        type_order.get(str(item.get("input_type") or ""), 9),
        visibility,
        str(item.get("ref") or ""),
    )


def _devops_finalize_trusted_inputs(
    *,
    trusted_inputs: list[dict[str, object]],
    source_join_ids: list[str],
    current_operator_can_view_source: bool | None,
    current_operator_can_contribute_source: bool | None,
) -> list[dict[str, object]]:
    source_join_id_set = {str(value) for value in source_join_ids if value}
    finalized: list[dict[str, object]] = []
    for item in trusted_inputs:
        trusted_input = dict(item)
        access_state = str(trusted_input.get("current_operator_access_state") or "") or None
        can_poison = trusted_input.get("current_operator_can_poison")
        join_id_set = {str(value) for value in trusted_input.get("join_ids") or [] if value}
        if (
            trusted_input.get("input_type") in {"repository", "template-repository"}
            and join_id_set & source_join_id_set
        ):
            if current_operator_can_contribute_source is True:
                access_state = "write"
                can_poison = True
                trusted_input["trusted_input_evidence_basis"] = "repository-permission"
                trusted_input["trusted_input_permission_source"] = "azure-devops-git-permissions"
                trusted_input["trusted_input_permission_detail"] = "GenericContribute allowed"
            elif current_operator_can_view_source is True:
                access_state = "read"
                can_poison = False
                trusted_input["trusted_input_evidence_basis"] = "repository-permission"
                trusted_input["trusted_input_permission_source"] = "azure-devops-git-permissions"
                trusted_input["trusted_input_permission_detail"] = "GenericRead allowed"
            elif trusted_input.get("visibility_state"):
                access_state = "exists-only"
                can_poison = False
        elif access_state is None and trusted_input.get("visibility_state"):
            access_state = "exists-only"
            can_poison = False
        if access_state == "exists-only" and not trusted_input.get("trusted_input_evidence_basis"):
            basis, source, detail = _devops_default_permission_proof(trusted_input)
            trusted_input["trusted_input_evidence_basis"] = basis
            trusted_input["trusted_input_permission_source"] = source
            trusted_input["trusted_input_permission_detail"] = detail
        trusted_input["current_operator_access_state"] = access_state
        trusted_input["current_operator_can_poison"] = can_poison
        finalized.append(trusted_input)
    return _devops_merge_trusted_inputs(finalized)


def _devops_injection_surface_types(
    *,
    trusted_inputs: list[dict[str, object]],
) -> list[str]:
    return _dedupe_strings(
        [
            str(surface)
            for item in trusted_inputs
            for surface in (item.get("surface_types") or [])
            if surface
        ]
    )


def _devops_current_operator_injection_surfaces(
    *,
    trusted_inputs: list[dict[str, object]],
    current_operator_can_edit: object,
) -> list[str]:
    surfaces = [
        str(surface)
        for item in trusted_inputs
        if item.get("current_operator_can_poison") is True
        for surface in (item.get("surface_types") or [])
        if surface
    ]
    if bool(current_operator_can_edit):
        surfaces.append("definition-edit")
    return _dedupe_strings(surfaces)


def _devops_primary_trusted_input(
    trusted_inputs: list[dict[str, object]],
) -> dict[str, object] | None:
    if not trusted_inputs:
        return None
    return _devops_merge_trusted_inputs(list(trusted_inputs))[0]


def _devops_missing_execution_path(
    *,
    repository_name: str | None,
    execution_modes: list[str],
    current_operator_can_queue: bool | None = None,
    current_operator_can_edit: bool | None = None,
) -> bool:
    has_non_manual_execution = bool([mode for mode in execution_modes if mode != "manual-only"])
    return not bool(
        repository_name
        or has_non_manual_execution
        or current_operator_can_queue
        or current_operator_can_edit
    )


def _devops_trigger_join_ids(
    *,
    organization: str,
    project_name: str,
    definition_id: str,
    execution_modes: list[str],
    upstream_sources: list[str],
) -> list[str]:
    base = (
        f"devops-trigger://{quote(organization, safe='')}/"
        f"{quote(project_name, safe='')}/{quote(definition_id, safe='')}"
    )
    ids = [f"{base}/{quote(mode, safe='')}" for mode in execution_modes]
    ids.extend(f"devops-source://{quote(source, safe='')}" for source in upstream_sources)
    return _dedupe_strings(ids)


def _devops_target_clues(definition: dict[str, object]) -> list[str]:
    strings = [text.lower() for text in _recursive_strings(definition)]
    if not strings:
        return []

    patterns = {
        "AKS/Kubernetes": ("kubernetes", "kubectl", "helm", "aks"),
        "App Service": ("appservice", "app service", "azurewebapp", "webapp"),
        "Functions": ("functionapp", "function app", "azurefunctionapp"),
        "ARM/Bicep/Terraform": ("arm", "bicep", "terraform", "az deployment"),
        "ACR/Containers": ("containerregistry", "docker", "acr", "container image"),
    }

    clues: list[str] = []
    for clue, keywords in patterns.items():
        if any(keyword in text for keyword in keywords for text in strings):
            clues.append(clue)
    structured_clues = _devops_structured_target_clues(definition, broad_clues=clues)
    clues.extend(
        clue.split(":", 1)[0].strip() for clue in structured_clues if ":" in clue and clue
    )
    clues.extend(structured_clues)
    return _dedupe_strings(clues)


def _devops_structured_target_clues(
    definition: dict[str, object],
    *,
    broad_clues: list[str],
) -> list[str]:
    structured: list[str] = []
    lowered_broad_clues = {value.lower() for value in broad_clues}
    target_specs = (
        {
            "target_family": "app-services",
            "label": "App Service",
            "broad_clue": "app service",
            "named_groups": (
                ("azure", "web", "app", "name"),
                ("web", "app", "name"),
                ("app", "service", "name"),
            ),
            "fallback_named_groups": (("app", "name"),),
            "exact_groups": (
                ("azure", "web", "app"),
                ("web", "app"),
                ("app", "service"),
            ),
            "allow_host_or_url": True,
            "needs_arm_context": False,
        },
        {
            "target_family": "functions",
            "label": "Functions",
            "broad_clue": "functions",
            "named_groups": (
                ("azure", "function", "app", "name"),
                ("function", "app", "name"),
            ),
            "fallback_named_groups": (("function", "name"),),
            "exact_groups": (
                ("azure", "function", "app"),
                ("function", "app"),
                ("function",),
            ),
            "allow_host_or_url": True,
            "needs_arm_context": False,
        },
        {
            "target_family": "aks",
            "label": "AKS/Kubernetes",
            "broad_clue": "aks/kubernetes",
            "named_groups": (
                ("aks", "cluster", "name"),
                ("kubernetes", "cluster", "name"),
            ),
            "fallback_named_groups": (("cluster", "name"),),
            "exact_groups": (
                ("aks", "cluster"),
                ("kubernetes", "cluster"),
                ("kubernetes",),
            ),
            "allow_host_or_url": True,
            "needs_arm_context": False,
        },
        {
            "target_family": "arm-deployments",
            "label": "ARM/Bicep/Terraform",
            "broad_clue": "arm/bicep/terraform",
            "named_groups": (("deployment", "name"),),
            "fallback_named_groups": (),
            "exact_groups": (("deployment",),),
            "allow_host_or_url": False,
            "needs_arm_context": True,
        },
    )
    for path, node in _recursive_nodes(definition):
        if not isinstance(node, dict):
            continue
        node_tokens = {
            token for key in node for token in _devops_identifier_tokens(key)
        } | set(_devops_path_tokens(path))
        arm_context_present = _devops_node_has_arm_target_context(node_tokens)
        for spec in target_specs:
            broad_present = spec["broad_clue"] in lowered_broad_clues
            if spec["needs_arm_context"] and not (broad_present or arm_context_present):
                continue
            named_target = _devops_named_target_input(
                node,
                token_groups=spec["named_groups"],
            )
            if not named_target and broad_present and spec["fallback_named_groups"]:
                named_target = _devops_named_target_input(
                    node,
                    token_groups=spec["fallback_named_groups"],
                )
            if named_target:
                structured.append(f"{spec['label']}: {named_target}")
            exact_target = _devops_exact_target_input(
                node,
                target_family=spec["target_family"],
                node_tokens=node_tokens,
                token_groups=spec["exact_groups"],
                broad_clue_present=broad_present,
                allow_host_or_url=spec["allow_host_or_url"],
            )
            if exact_target:
                structured.append(f"{spec['label']}: {exact_target}")

    return structured


def _devops_node_has_arm_target_context(tokens: set[str]) -> bool:
    return bool(
        "arm" in tokens
        or "bicep" in tokens
        or "terraform" in tokens
        or ("resource" in tokens and "manager" in tokens)
    )


def _devops_named_target_input(
    node: dict[str, object],
    *,
    token_groups: tuple[tuple[str, ...], ...],
) -> str | None:
    for key, value in node.items():
        if not isinstance(value, str):
            continue
        cleaned_value = value.strip()
        if not cleaned_value or _looks_like_expression(cleaned_value):
            continue
        key_tokens = set(_devops_identifier_tokens(key))
        for token_group in token_groups:
            if set(token_group).issubset(key_tokens):
                return cleaned_value
    return None


def _devops_exact_target_input(
    node: dict[str, object],
    *,
    target_family: str,
    node_tokens: set[str],
    token_groups: tuple[tuple[str, ...], ...],
    broad_clue_present: bool,
    allow_host_or_url: bool,
) -> str | None:
    generic_exact_tokens = {
        "resourceid",
        "resource",
        "id",
        "url",
        "uri",
        "hostname",
        "host",
        "fqdn",
    }
    family_tokens = {token for group in token_groups for token in group}
    for key, value in node.items():
        if not isinstance(value, str):
            continue
        cleaned_value = value.strip()
        if not cleaned_value or _looks_like_expression(cleaned_value):
            continue
        if not looks_like_exact_target_value(
            cleaned_value,
            target_family=target_family,
            allow_host_or_url=allow_host_or_url,
        ):
            continue
        key_tokens = set(_devops_identifier_tokens(key))
        has_direct_context = any(set(group).issubset(key_tokens) for group in token_groups)
        has_generic_exact_key = bool(key_tokens & generic_exact_tokens)
        has_family_key_context = bool(key_tokens & family_tokens)
        has_node_context = any(set(group).issubset(node_tokens) for group in token_groups)
        if has_direct_context or (
            broad_clue_present
            and has_generic_exact_key
            and has_family_key_context
            and has_node_context
        ):
            return cleaned_value
    return None


def _devops_secret_support_types(
    *,
    secret_variable_names: list[str],
    key_vault_group_names: list[str],
    key_vault_names: list[str],
    variable_group_names: list[str],
) -> list[str]:
    types: list[str] = []
    if variable_group_names:
        types.append("variable-groups")
    if secret_variable_names:
        types.append("secret-variables")

    lowered_names = [value.lower() for value in secret_variable_names]
    if any("publish" in value and "profile" in value for value in lowered_names):
        types.append("publish-profiles")
    if any(token in value for value in lowered_names for token in ("sign", "pfx", "cert")):
        types.append("signing-keys")
    if any(
        token in value for value in lowered_names for token in ("acr", "registry", "docker", "helm")
    ):
        types.append("registry-creds")
    if any(
        token in value
        for value in lowered_names
        for token in ("deploy", "release", "slot", "swap", "webdeploy", "publish")
    ):
        types.append("deployment-creds")
    if key_vault_group_names or key_vault_names:
        types.append("keyvault-backed-inputs")
    return _dedupe_strings(types)


def _deployment_consequence_types(
    *,
    target_clues: list[str],
    execution_modes: list[str],
    secret_support_types: list[str],
    source_command: str,
) -> list[str]:
    consequences: list[str] = []
    clue_set = {value.lower() for value in target_clues}
    if clue_set & {"aks/kubernetes", "app service", "functions", "acr/containers"}:
        consequences.append("redeploy-workload")
    if "arm/bicep/terraform" in clue_set:
        consequences.append("modify-infra")
    if any(
        mode in execution_modes
        for mode in ("auto-trigger", "pr-trigger", "schedule", "webhook-trigger")
    ):
        consequences.append("run-recurring-execution")
    if any(mode in execution_modes for mode in ("auto-trigger", "pr-trigger", "schedule")):
        consequences.append("reintroduce-config")
    if secret_support_types:
        consequences.append("consume-secret-backed-deployment-material")
    if source_command == "automation" and not consequences:
        consequences.append("run-recurring-execution")
    return _dedupe_strings(consequences)


def _devops_risk_cues(
    *,
    trigger_types: list[str],
    azure_service_connection_names: list[str],
    secret_variable_count: int,
    key_vault_group_names: list[str],
    unresolved_group_count: int,
    unresolved_service_connection_count: int,
) -> list[str]:
    lowered_triggers = {value.lower() for value in trigger_types}
    cues: list[str] = []
    if lowered_triggers & {"continuousintegration", "schedule", "pullrequest"}:
        cues.append("auto-triggered")
    if azure_service_connection_names:
        cues.append("azure deployment connection")
    if len(azure_service_connection_names) > 1:
        cues.append("multiple azure connections")
    if secret_variable_count > 0:
        cues.append("secret-bearing variables")
    if key_vault_group_names:
        cues.append("key vault-backed variables")
    if unresolved_group_count or unresolved_service_connection_count:
        cues.append("partial-read")
    return cues


def _devops_operator_summary(
    *,
    definition_name: str,
    project_name: str,
    trusted_inputs: list[dict[str, object]],
    primary_injection_surface: str | None,
    primary_trusted_input_ref: str | None,
    trigger_types: list[str],
    execution_modes: list[str],
    injection_surface_types: list[str],
    azure_service_connection_names: list[str],
    variable_group_names: list[str],
    secret_variable_count: int,
    key_vault_group_names: list[str],
    key_vault_names: list[str],
    target_clues: list[str],
    partial_read_reasons: list[str],
    current_operator_can_queue: bool | None = None,
    current_operator_can_edit: bool | None = None,
    current_operator_can_contribute_source: bool | None = None,
    current_operator_injection_surface_types: list[str] | None = None,
    primary_trusted_input_type: str | None = None,
    primary_trusted_input_access_state: str | None = None,
) -> str:
    parts = [
        f"Build definition '{definition_name}' in project '{project_name}' "
        "exposes an Azure change path"
    ]

    source_clause = _devops_trusted_input_clause(trusted_inputs)
    if source_clause:
        parts.append(source_clause)

    trigger_phrase = _devops_trigger_phrase(trigger_types, execution_modes=execution_modes)
    if trigger_phrase:
        parts.append(trigger_phrase)

    injection_clause = _devops_injection_clause(
        injection_surface_types=injection_surface_types,
        current_operator_injection_surface_types=current_operator_injection_surface_types or [],
        current_operator_can_queue=current_operator_can_queue,
        current_operator_can_edit=current_operator_can_edit,
        current_operator_can_contribute_source=current_operator_can_contribute_source,
        primary_trusted_input_type=primary_trusted_input_type,
        primary_trusted_input_ref=primary_trusted_input_ref,
        primary_injection_surface=primary_injection_surface,
        primary_trusted_input_access_state=primary_trusted_input_access_state,
    )
    if injection_clause:
        parts.append(injection_clause)

    if azure_service_connection_names:
        parts.append(
            "uses Azure-facing service connection(s) " + ", ".join(azure_service_connection_names)
        )

    if variable_group_names:
        parts.append("references variable group(s) " + ", ".join(variable_group_names))

    if secret_variable_count > 0:
        parts.append(f"surfaces {secret_variable_count} secret-marked variable name(s)")

    if key_vault_group_names or key_vault_names:
        kv_targets = ", ".join(key_vault_names or key_vault_group_names)
        parts.append(f"pulls from Key Vault-backed variable support ({kv_targets})")

    if target_clues:
        parts.append("source clues ground likely Azure impact in " + ", ".join(target_clues))

    if partial_read_reasons:
        parts.append(
            "current credentials leave unresolved refs: " + "; ".join(partial_read_reasons)
        )
    else:
        parts.append(
            devops_next_review_hint(
                target_clues=target_clues,
                key_vault_names=key_vault_names,
                key_vault_group_names=key_vault_group_names,
                azure_service_connection_names=azure_service_connection_names,
                partial_read=False,
                current_operator_can_queue=current_operator_can_queue,
                current_operator_can_edit=current_operator_can_edit,
                current_operator_can_contribute_source=current_operator_can_contribute_source,
                current_operator_injection_surface_types=current_operator_injection_surface_types,
                primary_trusted_input_type=primary_trusted_input_type,
                primary_trusted_input_ref=primary_trusted_input_ref,
                primary_injection_surface=primary_injection_surface,
                primary_trusted_input_access_state=primary_trusted_input_access_state,
            ).rstrip(".")
        )

    if partial_read_reasons:
        parts.append(
            devops_next_review_hint(
                target_clues=target_clues,
                key_vault_names=key_vault_names,
                key_vault_group_names=key_vault_group_names,
                azure_service_connection_names=azure_service_connection_names,
                partial_read=True,
            ).rstrip(".")
        )

    return ". ".join(parts) + "."


def _devops_trusted_input_clause(trusted_inputs: list[dict[str, object]]) -> str | None:
    if not trusted_inputs:
        return None
    displays = [
        describe_trusted_input(
            input_type=str(item.get("input_type") or "") or None,
            ref=str(item.get("ref") or "") or None,
        )
        for item in trusted_inputs[:2]
    ]
    if len(trusted_inputs) > 2:
        displays.append(f"{len(trusted_inputs) - 2} additional trusted input(s)")
    return "trusted inputs include " + ", ".join(displays)


def _devops_source_clause(
    *,
    repository_host_type: str | None,
    source_visibility_state: str | None,
    repository_name: str | None,
    default_branch: str | None,
    repository_url: str | None,
) -> str | None:
    repo_ref = repository_name
    if repo_ref and default_branch:
        repo_ref = f"{repo_ref}@{default_branch}"
    if not repo_ref and repository_url:
        repo_ref = repository_url
    if not repo_ref:
        return None

    if repository_host_type == "azure-repos":
        if source_visibility_state == "visible":
            return f"source input points to visible Azure Repos repo {repo_ref}"
        if source_visibility_state == "inferred-only":
            return (
                f"source input points to Azure Repos repo {repo_ref}, but current scope only "
                "infers that source rather than reading it directly"
            )
    if repository_host_type:
        return f"source input points to {repository_host_type} repo {repo_ref}"
    return f"source input points to repo {repo_ref}"


def _devops_trigger_phrase(
    trigger_types: list[str],
    *,
    execution_modes: list[str],
) -> str | None:
    if execution_modes:
        if execution_modes == ["manual-only"]:
            return "execution currently looks manual-only"
        return "execution can start through " + ", ".join(execution_modes)
    lowered = {value.lower() for value in trigger_types}
    if "continuousintegration" in lowered:
        return "auto-triggers on source changes"
    if "schedule" in lowered:
        return "runs on a schedule"
    if "pullrequest" in lowered:
        return "includes pull-request trigger posture"
    if trigger_types:
        return "uses trigger types " + ", ".join(trigger_types)
    return None


def _devops_injection_clause(
    *,
    injection_surface_types: list[str],
    current_operator_injection_surface_types: list[str],
    current_operator_can_queue: bool | None,
    current_operator_can_edit: bool | None,
    current_operator_can_contribute_source: bool | None,
    primary_trusted_input_type: str | None = None,
    primary_trusted_input_ref: str | None = None,
    primary_injection_surface: str | None = None,
    primary_trusted_input_access_state: str | None = None,
) -> str | None:
    trusted_input = describe_trusted_input(
        input_type=primary_trusted_input_type,
        ref=primary_trusted_input_ref,
    )
    if primary_trusted_input_access_state == "write" and primary_injection_surface:
        return f"current credentials can poison {primary_injection_surface} through {trusted_input}"
    if current_operator_injection_surface_types:
        return "current credentials can inject through " + ", ".join(
            current_operator_injection_surface_types
        )
    if primary_trusted_input_access_state == "use":
        if primary_trusted_input_type == "secure-file":
            return (
                f"current credentials can use {trusted_input} in pipeline context, but Azure "
                "DevOps evidence here does not prove secure-file administration"
            )
    if primary_trusted_input_access_state == "read":
        if primary_trusted_input_type == "pipeline-artifact":
            return (
                f"current credentials can inspect the upstream producer behind {trusted_input}, "
                "but Azure DevOps evidence here does not prove producer-side control"
            )
        if primary_trusted_input_type == "secure-file":
            return (
                f"current credentials can use {trusted_input} in pipeline context, but Azure "
                "DevOps evidence here does not prove secure-file administration"
            )
        return (
            f"current credentials can read {trusted_input}, but not write it from Azure DevOps "
            "evidence here"
        )
    if primary_trusted_input_access_state == "exists-only":
        missing_proof = _devops_missing_trusted_input_proof(primary_trusted_input_type)
        if missing_proof:
            return (
                f"Azure DevOps evidence currently only proves that {trusted_input} is trusted "
                f"here; {missing_proof} remains unproven"
            )
        return f"Azure DevOps evidence currently only proves that {trusted_input} is trusted here"
    if current_operator_can_queue:
        return (
            "current credentials can queue it, but AzureFox has not yet proven an attacker-"
            "controlled injection point"
        )
    if current_operator_can_edit or current_operator_can_contribute_source:
        return (
            "current credentials can change part of the path, but AzureFox has not yet proven "
            "which trusted input becomes attacker-controlled"
        )
    if injection_surface_types:
        return "visible injection surfaces include " + ", ".join(injection_surface_types)
    return None


def _devops_missing_trusted_input_proof(input_type: str | None) -> str | None:
    return {
        "package-feed": "the current operator's feed role",
        "pipeline-artifact": "upstream producer control",
        "template-repository": "referenced repo read/write proof",
        "repository": "repo read/write proof",
        "secure-file": "secure-file use or admin proof",
    }.get(str(input_type or ""))


def _devops_partial_read_reasons(
    *,
    unresolved_group_ids: list[str],
    unresolved_endpoint_refs: list[str],
    unresolved_provider_endpoint_ids: list[str],
) -> list[str]:
    reasons: list[str] = []
    if unresolved_group_ids:
        reasons.append("unresolved variable group refs: " + ", ".join(unresolved_group_ids))
    if unresolved_endpoint_refs:
        reasons.append("unresolved service connection refs: " + ", ".join(unresolved_endpoint_refs))
    if unresolved_provider_endpoint_ids:
        reasons.append(
            "unresolved provider endpoint refs: " + ", ".join(unresolved_provider_endpoint_ids)
        )
    return reasons


def _recursive_strings(node: object) -> list[str]:
    values: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            values.append(str(key))
            values.extend(_recursive_strings(value))
    elif isinstance(node, list):
        for value in node:
            values.extend(_recursive_strings(value))
    elif isinstance(node, str):
        values.append(node)
    return values
