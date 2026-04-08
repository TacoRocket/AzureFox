from __future__ import annotations

AZURE_CLI_AUTH_MODE = "azure_cli"
AZURE_CLI_USER_AUTH_MODE = "azure_cli_user"
AZURE_CLI_SERVICE_PRINCIPAL_AUTH_MODE = "azure_cli_service_principal"
AZURE_CLI_MANAGED_IDENTITY_AUTH_MODE = "azure_cli_managed_identity"

ENVIRONMENT_AUTH_MODE = "environment"
ENVIRONMENT_CLIENT_SECRET_AUTH_MODE = "environment_client_secret"
ENVIRONMENT_CLIENT_CERTIFICATE_AUTH_MODE = "environment_client_certificate"

FIXTURE_AUTH_MODE = "fixture"

AZURE_CLI_AUTH_MODES = frozenset(
    {
        AZURE_CLI_AUTH_MODE,
        AZURE_CLI_USER_AUTH_MODE,
        AZURE_CLI_SERVICE_PRINCIPAL_AUTH_MODE,
        AZURE_CLI_MANAGED_IDENTITY_AUTH_MODE,
    }
)

ENVIRONMENT_AUTH_MODES = frozenset(
    {
        ENVIRONMENT_AUTH_MODE,
        ENVIRONMENT_CLIENT_SECRET_AUTH_MODE,
        ENVIRONMENT_CLIENT_CERTIFICATE_AUTH_MODE,
    }
)

AUTH_MODE_LABELS = {
    AZURE_CLI_AUTH_MODE: "Azure CLI",
    AZURE_CLI_USER_AUTH_MODE: "Azure CLI user",
    AZURE_CLI_SERVICE_PRINCIPAL_AUTH_MODE: "Azure CLI service principal",
    AZURE_CLI_MANAGED_IDENTITY_AUTH_MODE: "Azure CLI managed identity",
    ENVIRONMENT_AUTH_MODE: "Environment credential",
    ENVIRONMENT_CLIENT_SECRET_AUTH_MODE: "Environment client secret",
    ENVIRONMENT_CLIENT_CERTIFICATE_AUTH_MODE: "Environment client certificate",
    FIXTURE_AUTH_MODE: "Fixture",
}


def auth_mode_label(value: object) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        return "unknown"
    return AUTH_MODE_LABELS.get(normalized, normalized.replace("_", " "))
