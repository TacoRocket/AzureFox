from __future__ import annotations

import json
import ssl
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from azurefox.auth.session import GRAPH_SCOPE
from azurefox.errors import AzureFoxError, ErrorKind, classify_exception

try:
    import certifi
except ImportError:  # pragma: no cover - dependency fallback
    certifi = None

GRAPH_ROOT = "https://graph.microsoft.com/v1.0"
GRAPH_BATCH_MAX_REQUESTS = 20


@dataclass(slots=True)
class GraphBatchRequest:
    key: str
    path: str
    params: dict[str, str] | None = None


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

    def batch_list_objects_by_key(
        self,
        requests: list[GraphBatchRequest],
    ) -> tuple[dict[str, list[dict[str, Any]]], dict[str, AzureFoxError]]:
        partial: dict[str, list[dict[str, Any]]] = {}

        def _consume_list_body(
            request: GraphBatchRequest,
            body: dict[str, Any],
        ) -> tuple[bool, list[dict[str, Any]] | None]:
            values = body.get("value", [])
            if isinstance(values, list):
                partial.setdefault(request.key, []).extend(
                    item for item in values if isinstance(item, dict)
                )

            next_url = body.get("@odata.nextLink")
            if isinstance(next_url, str) and next_url:
                return False, None

            final_items = list(partial.get(request.key, []))
            partial.pop(request.key, None)
            return True, final_items

        return self._batch_collect_by_key(requests, _consume_list_body)

    def batch_get_objects_by_key(
        self,
        requests: list[GraphBatchRequest],
    ) -> tuple[dict[str, dict[str, Any]], dict[str, AzureFoxError]]:
        def _consume_get_body(
            _request: GraphBatchRequest,
            body: dict[str, Any],
        ) -> tuple[bool, dict[str, Any] | None]:
            return True, body

        return self._batch_collect_by_key(requests, _consume_get_body)

    def _batch_collect_by_key(
        self,
        requests: list[GraphBatchRequest],
        consume_body,
    ) -> tuple[dict[str, Any], dict[str, AzureFoxError]]:
        pending = list(requests)
        results: dict[str, Any] = {}
        errors: dict[str, AzureFoxError] = {}

        while pending:
            chunk = pending[:GRAPH_BATCH_MAX_REQUESTS]
            pending = pending[GRAPH_BATCH_MAX_REQUESTS:]

            bodies, body_errors = self._batch_execute(chunk)
            for request in chunk:
                if request.key in body_errors:
                    errors[request.key] = body_errors[request.key]
                    continue

                body = bodies.get(request.key)
                if body is None:
                    errors[request.key] = AzureFoxError(
                        ErrorKind.UNKNOWN,
                        f"Graph batch request missing response for {request.path}",
                    )
                    continue

                completed, final_value = consume_body(request, body)
                if not completed:
                    pending.append(
                        GraphBatchRequest(
                            key=request.key,
                            path=str(body["@odata.nextLink"]),
                        )
                    )
                    continue
                results[request.key] = final_value

        return results, errors

    def _list(
        self,
        path: str,
        params: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        url = self._build_url(path, params)

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

    def _build_url(self, path: str, params: dict[str, str] | None = None) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path

        url = f"{GRAPH_ROOT}{path}"
        if params:
            url = f"{url}?{urlencode(params)}"
        return url

    def _get(self, url: str) -> dict[str, Any]:
        return self._request_json("GET", url)

    def _post(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        return self._request_json("POST", url, payload=payload)

    def _request_json(
        self,
        method: str,
        url: str,
        *,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        token = self.credential.get_token(GRAPH_SCOPE).token
        data = None
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(
            url,
            data=data,
            headers=headers,
            method=method,
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

    def _batch_execute(
        self,
        requests: list[GraphBatchRequest],
    ) -> tuple[dict[str, dict[str, Any]], dict[str, AzureFoxError]]:
        if not requests:
            return {}, {}

        request_payload = {
            "requests": [
                {
                    "id": str(index),
                    "method": "GET",
                    "url": _graph_batch_url(self._build_url(request.path, request.params)),
                    "headers": {"Accept": "application/json"},
                }
                for index, request in enumerate(requests)
            ]
        }
        request_by_id = {str(index): request for index, request in enumerate(requests)}
        response_payload = self._post(f"{GRAPH_ROOT}/$batch", request_payload)

        results: dict[str, dict[str, Any]] = {}
        errors: dict[str, AzureFoxError] = {}
        responses = response_payload.get("responses", [])
        if not isinstance(responses, list):
            raise AzureFoxError(ErrorKind.UNKNOWN, "Graph batch response was not a list")

        for response in responses:
            if not isinstance(response, dict):
                continue
            response_id = response.get("id")
            if not isinstance(response_id, str):
                continue
            request = request_by_id.get(response_id)
            if request is None:
                continue

            status = response.get("status")
            body = response.get("body")
            if not isinstance(body, dict):
                body = {}
            if not isinstance(status, int):
                errors[request.key] = AzureFoxError(
                    ErrorKind.UNKNOWN,
                    f"Graph batch response missing status for {request.path}",
                )
                continue
            if status < 200 or status >= 300:
                errors[request.key] = _graph_batch_request_error(request.path, status, body)
                continue
            results[request.key] = body

        return results, errors


def _graph_batch_url(url: str) -> str:
    if url.startswith(GRAPH_ROOT):
        trimmed = url.removeprefix(GRAPH_ROOT)
        return trimmed or "/"
    return url


def _graph_batch_request_error(
    path: str,
    status: int,
    body: dict[str, Any],
) -> AzureFoxError:
    error_body = body.get("error")
    code = ""
    message = ""
    if isinstance(error_body, dict):
        raw_code = error_body.get("code")
        raw_message = error_body.get("message")
        if isinstance(raw_code, str):
            code = raw_code
        if isinstance(raw_message, str):
            message = raw_message

    pieces = [f"Graph batch request failed for {path}: status {status}"]
    if code:
        pieces.append(code)
    if message:
        pieces.append(message)
    formatted = " ".join(pieces)
    kind = _graph_batch_error_kind(status=status, code=code, message=message)
    return AzureFoxError(
        kind,
        formatted,
        details={"body": json.dumps(body)[:500]},
    )


def _graph_batch_error_kind(*, status: int, code: str, message: str) -> ErrorKind:
    if status == 401:
        return ErrorKind.AUTH_FAILURE
    if status == 403:
        return ErrorKind.PERMISSION_DENIED
    if status == 429:
        return ErrorKind.THROTTLING
    return classify_exception(Exception(" ".join(part for part in (code, message) if part)))


def _graph_ssl_context() -> ssl.SSLContext:
    if certifi is not None:
        return ssl.create_default_context(cafile=certifi.where())
    return ssl.create_default_context()
