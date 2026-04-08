from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass

from azurefox.auth.modes import (
    AZURE_CLI_AUTH_MODE,
    AZURE_CLI_MANAGED_IDENTITY_AUTH_MODE,
    AZURE_CLI_SERVICE_PRINCIPAL_AUTH_MODE,
    AZURE_CLI_USER_AUTH_MODE,
    ENVIRONMENT_AUTH_MODE,
    ENVIRONMENT_CLIENT_CERTIFICATE_AUTH_MODE,
    ENVIRONMENT_CLIENT_SECRET_AUTH_MODE,
)
from azurefox.errors import AzureFoxError, ErrorKind

MANAGEMENT_SCOPE = "https://management.azure.com/.default"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
DEVOPS_SCOPE = "499b84ac-1321-427f-aa17-267ca6975798/.default"


@dataclass(slots=True)
class AuthSession:
    credential: object
    token_source: str
    auth_mode: str
    access_token: str
    tenant_id: str | None


def build_auth_session(tenant_id: str | None) -> AuthSession:
    try:
        from azure.core.exceptions import ClientAuthenticationError
        from azure.identity import (
            AzureCliCredential,
            CredentialUnavailableError,
            EnvironmentCredential,
        )
    except ImportError as exc:  # pragma: no cover - dependency surface
        raise AzureFoxError(
            ErrorKind.DEPENDENCY_MISSING,
            (
                "Missing Azure dependencies. Install AzureFox with its default dependencies. "
                "From a local checkout, run: pip install -e ."
            ),
        ) from exc

    hint = (
        "Authenticate with one of: az login; az login --service-principal; "
        "az login --identity; or set AZURE_TENANT_ID/AZURE_CLIENT_ID with either "
        "AZURE_CLIENT_SECRET or AZURE_CLIENT_CERTIFICATE_PATH."
    )
    cli_credential = AzureCliCredential(tenant_id=tenant_id)
    try:
        token = cli_credential.get_token(MANAGEMENT_SCOPE)
        claims = decode_jwt_payload(token.token)
        return AuthSession(
            credential=cli_credential,
            token_source="azure_cli",
            auth_mode=_classify_azure_cli_auth_mode(claims),
            access_token=token.token,
            tenant_id=claims.get("tid", tenant_id),
        )
    except CredentialUnavailableError as exc:
        cli_error = exc
    except ClientAuthenticationError as exc:
        raise AzureFoxError(
            ErrorKind.AUTH_FAILURE,
            "Azure CLI authentication failed.",
            details={"hint": hint, "azure_cli_error": str(exc)},
        ) from exc
    except Exception as exc:
        raise AzureFoxError(
            ErrorKind.AUTH_FAILURE,
            "Azure CLI authentication failed unexpectedly.",
            details={"hint": hint, "azure_cli_error": str(exc)},
        ) from exc

    env_credential = EnvironmentCredential()
    env_auth_mode = _classify_environment_auth_mode()
    try:
        token = env_credential.get_token(MANAGEMENT_SCOPE)
        claims = decode_jwt_payload(token.token)
        return AuthSession(
            credential=env_credential,
            token_source="environment",
            auth_mode=env_auth_mode,
            access_token=token.token,
            tenant_id=claims.get("tid", tenant_id),
        )
    except Exception as exc:
        details = {
            "hint": hint,
            "azure_cli_error": str(cli_error),
            "environment_error": str(exc),
        }
        raise AzureFoxError(
            ErrorKind.AUTH_FAILURE,
            "Unable to authenticate with Azure CLI or environment credential.",
            details=details,
        ) from exc


def _classify_azure_cli_auth_mode(claims: dict[str, str]) -> str:
    if claims.get("xms_mirid"):
        return AZURE_CLI_MANAGED_IDENTITY_AUTH_MODE
    if _claims_look_like_user(claims):
        return AZURE_CLI_USER_AUTH_MODE
    if claims.get("idtyp", "").lower() == "app" or claims.get("appid"):
        return AZURE_CLI_SERVICE_PRINCIPAL_AUTH_MODE
    return AZURE_CLI_AUTH_MODE


def _classify_environment_auth_mode() -> str:
    if all(os.environ.get(name) for name in _CLIENT_SECRET_ENV_VARS):
        return ENVIRONMENT_CLIENT_SECRET_AUTH_MODE
    if all(os.environ.get(name) for name in _CLIENT_CERTIFICATE_ENV_VARS):
        return ENVIRONMENT_CLIENT_CERTIFICATE_AUTH_MODE
    return ENVIRONMENT_AUTH_MODE


def _claims_look_like_user(claims: dict[str, str]) -> bool:
    if claims.get("idtyp", "").lower() == "app":
        return False
    return any(
        claims.get(key) for key in ("upn", "preferred_username", "unique_name", "scp")
    ) or bool(claims.get("oid") and not claims.get("appid"))


def decode_jwt_payload(token: str) -> dict[str, str]:
    parts = token.split(".")
    if len(parts) < 2:
        return {}

    payload = parts[1]
    payload += "=" * (-len(payload) % 4)

    try:
        raw = base64.urlsafe_b64decode(payload.encode("utf-8"))
        data = json.loads(raw.decode("utf-8"))
    except Exception:
        return {}

    return {str(k): str(v) for k, v in data.items()}


_CLIENT_SECRET_ENV_VARS = (
    "AZURE_TENANT_ID",
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
)
_CLIENT_CERTIFICATE_ENV_VARS = (
    "AZURE_TENANT_ID",
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_CERTIFICATE_PATH",
)
