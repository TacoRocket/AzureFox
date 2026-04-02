from __future__ import annotations

import json
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from azurefox.auth.session import GRAPH_SCOPE
from azurefox.errors import AzureFoxError, classify_exception

try:
    import certifi
except ImportError:  # pragma: no cover - dependency fallback
    certifi = None

GRAPH_ROOT = "https://graph.microsoft.com/v1.0"


@dataclass(slots=True)
class GraphClient:
    credential: object

    def list_applications(self) -> list[dict[str, Any]]:
        return self._list(
            "/applications",
            {
                "$select": "id,appId,displayName,signInAudience",
            },
        )

    def get_application(self, application_id: str) -> dict[str, Any]:
        return self._get(
            f"{GRAPH_ROOT}/applications/{application_id}"
            "?$select=id,appId,displayName,signInAudience"
        )

    def get_application_by_app_id(self, app_id: str) -> dict[str, Any] | None:
        items = self._list(
            "/applications",
            {
                "$filter": f"appId eq '{app_id}'",
                "$select": "id,appId,displayName,signInAudience",
            },
        )
        return items[0] if items else None

    def get_service_principal(self, service_principal_id: str) -> dict[str, Any]:
        return self._get(
            f"{GRAPH_ROOT}/servicePrincipals/{service_principal_id}"
            "?$select=id,appId,displayName,servicePrincipalType,appOwnerOrganizationId"
        )

    def list_service_principals(self) -> list[dict[str, Any]]:
        return self._list(
            "/servicePrincipals",
            {
                "$select": "id,appId,displayName,servicePrincipalType,appOwnerOrganizationId",
            },
        )

    def get_service_principals(self, service_principal_ids: list[str]) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for service_principal_id in service_principal_ids:
            items.append(self.get_service_principal(service_principal_id))
        return items

    def get_identity_security_defaults_policy(self) -> dict[str, Any]:
        return self._get(
            f"{GRAPH_ROOT}/policies/identitySecurityDefaultsEnforcementPolicy"
            "?$select=id,displayName,description,isEnabled"
        )

    def get_authorization_policy(self) -> dict[str, Any]:
        return self._get(
            f"{GRAPH_ROOT}/policies/authorizationPolicy"
            "?$select=id,displayName,description,allowInvitesFrom,"
            "allowUserConsentForRiskyApps,allowedToUseSSPR,"
            "allowedToSignUpEmailBasedSubscriptions,allowEmailVerifiedUsersToJoinOrganization,"
            "blockMsolPowerShell,defaultUserRolePermissions"
        )

    def list_conditional_access_policies(self) -> list[dict[str, Any]]:
        return self._list(
            "/identity/conditionalAccess/policies",
            {
                "$select": "id,displayName,state,conditions,grantControls,sessionControls",
            },
        )

    def list_application_federated_credentials(self, application_id: str) -> list[dict[str, Any]]:
        return self._list(
            f"/applications/{application_id}/federatedIdentityCredentials",
            {
                "$select": "id,name,issuer,subject,audiences",
            },
        )

    def list_application_owners(self, application_id: str) -> list[dict[str, Any]]:
        return self._list(
            f"/applications/{application_id}/owners",
            {
                "$select": "id,displayName,userPrincipalName,appId,servicePrincipalType",
            },
        )

    def list_service_principal_owners(self, service_principal_id: str) -> list[dict[str, Any]]:
        return self._list(
            f"/servicePrincipals/{service_principal_id}/owners",
            {
                "$select": "id,displayName,userPrincipalName,appId,servicePrincipalType",
            },
        )

    def list_oauth2_permission_grants(self, service_principal_id: str) -> list[dict[str, Any]]:
        return self._list(
            f"/servicePrincipals/{service_principal_id}/oauth2PermissionGrants",
            {
                "$select": "id,clientId,consentType,principalId,resourceId,scope",
            },
        )

    def list_app_role_assignments(self, service_principal_id: str) -> list[dict[str, Any]]:
        return self._list(
            f"/servicePrincipals/{service_principal_id}/appRoleAssignments",
            {
                "$select": "id,appRoleId,principalId,resourceId",
            },
        )

    def _list(
        self,
        path: str,
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        url = f"{GRAPH_ROOT}{path}"
        if params:
            url = f"{url}?{urlencode(params)}"

        items: list[dict[str, Any]] = []
        next_url: str | None = url
        while next_url:
            payload = self._get(next_url)
            values = payload.get("value", [])
            if isinstance(values, list):
                items.extend(item for item in values if isinstance(item, dict))
            next_url = payload.get("@odata.nextLink")
            if next_url is not None and not isinstance(next_url, str):
                next_url = None
        return items

    def _get(self, url: str) -> dict[str, Any]:
        token = self.credential.get_token(GRAPH_SCOPE).token
        request = Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
        )
        try:
            with urlopen(request, context=_graph_ssl_context(), timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            body = exc.read().decode("utf-8", errors="ignore")
            raise AzureFoxError(
                classify_exception(exc),
                f"Graph request failed for {url}: {exc.code} {exc.reason}",
                details={"body": body[:500]},
            ) from exc
        except URLError as exc:
            raise AzureFoxError(
                classify_exception(exc),
                f"Graph request failed for {url}: {exc.reason}",
            ) from exc


def _graph_ssl_context() -> ssl.SSLContext:
    if certifi is not None:
        return ssl.create_default_context(cafile=certifi.where())
    return ssl.create_default_context()
