from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections import Counter
from pathlib import Path

from azurefox.auth.session import build_auth_session, decode_jwt_payload
from azurefox.clients.factory import build_clients
from azurefox.clients.graph import GraphClient
from azurefox.config import GlobalOptions
from azurefox.correlation.findings import build_keyvault_findings, build_storage_findings
from azurefox.errors import AzureFoxError, ErrorKind, classify_exception
from azurefox.models.common import Principal, RoleAssignment, ScopeRef


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
        return self._read("resource_trusts")

    def auth_policies(self) -> dict:
        return self._read("auth_policies")

    def managed_identities(self) -> dict:
        return self._read("managed_identities")

    def keyvault(self) -> dict:
        return self._read("keyvault")

    def storage(self) -> dict:
        return self._read("storage")

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
            item.get("id"): item
            for item in principals_data.get("principals", [])
            if item.get("id")
        }
        identities_by_principal: dict[str, list[dict]] = {}
        for identity in identities_data.get("identities", []):
            principal_id = identity.get("principal_id")
            if principal_id:
                identities_by_principal.setdefault(principal_id, []).append(identity)

        vm_by_id = {
            item.get("id"): item
            for item in vms_data.get("vm_assets", [])
            if item.get("id")
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

        principal_data = self.principals()
        candidate_sp_ids = sorted(
            {
                principal.get("id")
                for principal in principal_data.get("principals", [])
                if principal.get("id")
                and principal.get("principal_type") in {"ServicePrincipal", "ManagedIdentity"}
            }
        )

        service_principals: list[dict] = []
        for service_principal_id in candidate_sp_ids:
            try:
                service_principals.append(self.graph.get_service_principal(service_principal_id))
            except Exception as exc:
                issues.append(
                    _issue_from_exception(
                        f"role_trusts.service_principals[{service_principal_id}]",
                        exc,
                    )
                )

        service_principal_by_id = {
            item.get("id"): item for item in service_principals if item.get("id")
        }
        applications: list[dict] = []
        application_by_app_id: dict[str, dict] = {}

        for service_principal in service_principals:
            app_id = service_principal.get("appId")
            if not app_id or app_id in application_by_app_id:
                continue
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

            backing_sp = next(
                (
                    item
                    for item in service_principals
                    if item.get("appId") and item.get("appId") == application.get("appId")
                ),
                None,
            )

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
                resource = service_principal_by_id.get(assignment.get("resourceId"), {})
                resource_name = (
                    resource.get("displayName") or assignment.get("resourceId") or "unknown"
                )
                assignment_related_ids = [
                    item for item in [assignment.get("id"), assignment.get("resourceId")] if item
                ]
                trusts.append(
                    {
                        "trust_type": "app-to-service-principal",
                        "source_object_id": sp_id,
                        "source_name": service_principal.get("displayName"),
                        "source_type": "ServicePrincipal",
                        "target_object_id": assignment.get("resourceId") or "unknown",
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

        resource_trusts = [
            *_resource_trusts_from_storage(storage_data.get("storage_assets", [])),
            *_resource_trusts_from_keyvault(keyvault_data.get("key_vaults", [])),
        ]
        resource_trusts.sort(
            key=lambda item: (
                item.get("exposure") != "high",
                item.get("resource_type") or "",
                item.get("resource_name") or item.get("resource_id") or "",
                item.get("trust_type") or "",
            )
        )

        findings = [
            *build_storage_findings(storage_data.get("storage_assets", [])),
            *build_keyvault_findings(keyvault_data.get("key_vaults", [])),
        ]
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
                    "related_ids": [
                        item for item in [defaults.get("id")] if item
                    ],
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

                user_assigned = (
                    getattr(vm_identity, "user_assigned_identities", None) or {}
                )
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
            RoleAssignment.model_validate(a)
            for a in rbac_data.get("role_assignments", [])
        ]
        principal_ids = {
            item.get("principal_id")
            for item in identities.values()
            if item.get("principal_id")
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

                container_count = self._count_storage_children(
                    "blob_containers",
                    rg_name,
                    account_name,
                )
                share_count = self._count_storage_children("file_shares", rg_name, account_name)
                queue_count = self._count_storage_children("queue", rg_name, account_name)
                table_count = self._count_storage_children("table", rg_name, account_name)

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

        return {"storage_assets": assets, "issues": issues}

    def vms(self) -> dict:
        vm_assets: list[dict] = []
        issues: list[dict] = []

        try:
            for vm in self.clients.compute.virtual_machines.list_all():
                vm_id = getattr(vm, "id", "unknown")
                network_profile = getattr(vm, "network_profile", None)
                interfaces = getattr(network_profile, "network_interfaces", []) or []
                nic_ids = [n.id for n in interfaces if n and getattr(n, "id", None)]

                private_ips: list[str] = []
                public_ips: list[str] = []
                for nic_id in nic_ids:
                    nic_private, nic_public = self._resolve_nic_ips(nic_id)
                    private_ips.extend(nic_private)
                    public_ips.extend(nic_public)

                identity_ids = []
                vm_identity = getattr(vm, "identity", None)
                if vm_identity is not None:
                    if getattr(vm_identity, "principal_id", None):
                        identity_ids.append(f"{vm_id}/identities/system")
                    user_assigned = (
                        getattr(vm_identity, "user_assigned_identities", None) or {}
                    )
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
                    user_assigned = (
                        getattr(vmss_identity, "user_assigned_identities", None) or {}
                    )
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

    def _count_storage_children(self, op_name: str, rg_name: str | None, account_name: str) -> int:
        if not rg_name:
            return 0

        operation = getattr(self.clients.storage, op_name, None)
        if operation is None:
            return 0

        for method_name in ("list", "list_by_storage_account"):
            method = getattr(operation, method_name, None)
            if method is None:
                continue
            try:
                if method_name == "list":
                    return sum(1 for _ in method(rg_name, account_name))
                return sum(1 for _ in method(account_name))
            except Exception:
                return 0
        return 0

    def _resolve_nic_ips(self, nic_id: str) -> tuple[list[str], list[str]]:
        rg_name, nic_name = _resource_group_and_name(nic_id)
        if not rg_name or not nic_name:
            return [], []

        private_ips: list[str] = []
        public_ips: list[str] = []

        try:
            nic = self.clients.network.network_interfaces.get(rg_name, nic_name)
            for cfg in getattr(nic, "ip_configurations", None) or []:
                if getattr(cfg, "private_ip_address", None):
                    private_ips.append(str(cfg.private_ip_address))
                pub = getattr(cfg, "public_ip_address", None)
                pub_id = getattr(pub, "id", None)
                if pub_id:
                    pub_rg, pub_name = _resource_group_and_name(pub_id)
                    if pub_rg and pub_name:
                        pip = self.clients.network.public_ip_addresses.get(pub_rg, pub_name)
                        ip_addr = getattr(pip, "ip_address", None)
                        if ip_addr:
                            public_ips.append(str(ip_addr))
        except Exception:
            return private_ips, public_ips

        return private_ips, public_ips


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

    users = ((policy.get("conditions") or {}).get("users") or {})
    applications = ((policy.get("conditions") or {}).get("applications") or {})

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


def _string_value(value: object) -> str | None:
    if value is None:
        return None
    return str(getattr(value, "value", value))


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
            exposure = "high" if network_default_action == "allow" else "medium"
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
