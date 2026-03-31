from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from azurefox.errors import AzureFoxError, ErrorKind

MANAGEMENT_SCOPE = "https://management.azure.com/.default"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"


@dataclass(slots=True)
class AuthSession:
    credential: object
    token_source: str
    access_token: str
    tenant_id: str | None


def build_auth_session(tenant_id: str | None) -> AuthSession:
    try:
        from azure.identity import AzureCliCredential, EnvironmentCredential
    except ImportError as exc:  # pragma: no cover - dependency surface
        raise AzureFoxError(
            ErrorKind.DEPENDENCY_MISSING,
            "Missing Azure dependencies. Install with: pip install -e '.[azure]'",
        ) from exc

    cli_credential = AzureCliCredential(tenant_id=tenant_id)
    try:
        token = cli_credential.get_token(MANAGEMENT_SCOPE)
        claims = decode_jwt_payload(token.token)
        return AuthSession(
            credential=cli_credential,
            token_source="azure_cli",
            access_token=token.token,
            tenant_id=claims.get("tid", tenant_id),
        )
    except Exception:
        pass

    env_credential = EnvironmentCredential()
    try:
        token = env_credential.get_token(MANAGEMENT_SCOPE)
        claims = decode_jwt_payload(token.token)
        return AuthSession(
            credential=env_credential,
            token_source="environment",
            access_token=token.token,
            tenant_id=claims.get("tid", tenant_id),
        )
    except Exception as exc:
        raise AzureFoxError(
            ErrorKind.AUTH_FAILURE,
            "Unable to authenticate with Azure CLI or environment credential.",
            details={
                "hint": (
                    "Run az login or set AZURE_TENANT_ID/"
                    "AZURE_CLIENT_ID/AZURE_CLIENT_SECRET."
                )
            },
        ) from exc


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
