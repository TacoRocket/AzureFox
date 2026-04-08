from __future__ import annotations

import base64
import json
import sys
from types import ModuleType

import pytest
from azure.core.exceptions import ClientAuthenticationError

from azurefox.auth.session import build_auth_session
from azurefox.errors import AzureFoxError, ErrorKind


def _token_with_claims(**claims: str) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode("utf-8").rstrip("=")
    payload = base64.urlsafe_b64encode(
        json.dumps(claims).encode("utf-8")
    ).decode("utf-8").rstrip("=")
    return f"{header}.{payload}.sig"


def _credential_cls(*, token: str | None = None, error: Exception | None = None):
    class FakeCredential:
        def __init__(self, *args, **kwargs) -> None:
            self.args = args
            self.kwargs = kwargs

        def get_token(self, scope: str):
            if error is not None:
                raise error
            if token is None:
                raise AssertionError("fake credential missing token")
            return type("Token", (), {"token": token})()

    return FakeCredential


def _install_fake_identity_module(
    monkeypatch,
    *,
    cli_token: str | None = None,
    cli_unavailable: bool = False,
    cli_error: Exception | None = None,
    env_token: str | None = None,
    env_error: Exception | None = None,
) -> None:
    module = ModuleType("azure.identity")

    class FakeCredentialUnavailableError(Exception):
        pass

    module.CredentialUnavailableError = FakeCredentialUnavailableError
    module.AzureCliCredential = _credential_cls(
        token=cli_token,
        error=FakeCredentialUnavailableError("cli unavailable") if cli_unavailable else cli_error,
    )
    module.EnvironmentCredential = _credential_cls(token=env_token, error=env_error)
    monkeypatch.setitem(sys.modules, "azure.identity", module)


def _assert_session(session, *, token_source: str, auth_mode: str, tenant_id: str) -> None:
    assert session.token_source == token_source
    assert session.auth_mode == auth_mode
    assert session.tenant_id == tenant_id


def test_build_auth_session_falls_back_when_cli_is_unavailable(monkeypatch) -> None:
    _install_fake_identity_module(
        monkeypatch,
        cli_unavailable=True,
        env_token=_token_with_claims(
            tid="env-tenant",
            idtyp="app",
            appid="env-client-id",
        ),
    )
    monkeypatch.setenv("AZURE_TENANT_ID", "env-tenant")
    monkeypatch.setenv("AZURE_CLIENT_ID", "env-client-id")
    monkeypatch.setenv("AZURE_CLIENT_SECRET", "env-secret")

    session = build_auth_session("requested-tenant")

    _assert_session(
        session,
        token_source="environment",
        auth_mode="environment_client_secret",
        tenant_id="env-tenant",
    )


def test_build_auth_session_does_not_hide_cli_auth_failure(monkeypatch) -> None:
    calls = {"env": 0}

    class FakeEnvironmentCredential:
        def get_token(self, scope: str):
            calls["env"] += 1
            return type(
                "Token",
                (),
                {"token": _token_with_claims(tid="env-tenant", idtyp="app", appid="env-client-id")},
            )()

    module = ModuleType("azure.identity")

    class FakeCredentialUnavailableError(Exception):
        pass

    class FakeAzureCliCredential:
        def __init__(self, tenant_id=None) -> None:
            self.tenant_id = tenant_id

        def get_token(self, scope: str):
            raise ClientAuthenticationError("expired az login")

    module.CredentialUnavailableError = FakeCredentialUnavailableError
    module.AzureCliCredential = FakeAzureCliCredential
    module.EnvironmentCredential = FakeEnvironmentCredential
    monkeypatch.setitem(sys.modules, "azure.identity", module)

    with pytest.raises(AzureFoxError) as exc_info:
        build_auth_session("requested-tenant")

    assert exc_info.value.kind == ErrorKind.AUTH_FAILURE
    assert "Azure CLI authentication failed" in str(exc_info.value)
    assert exc_info.value.details["azure_cli_error"] == "expired az login"
    assert calls["env"] == 0


@pytest.mark.parametrize(
    ("claims", "expected_auth_mode"),
    [
        (
            {
                "oid": "user-oid",
                "appid": "azure-cli-client",
                "preferred_username": "analyst@contoso.com",
                "scp": "user_impersonation",
                "name": "Analyst User",
            },
            "azure_cli_user",
        ),
        (
            {
                "oid": "sp-object-id",
                "appid": "sp-client-id",
                "idtyp": "app",
                "name": "build-sp",
            },
            "azure_cli_service_principal",
        ),
        (
            {
                "oid": "mi-object-id",
                "appid": "mi-client-id",
                "idtyp": "app",
                "xms_mirid": (
                    "/subscriptions/sub/resourceGroups/rg/providers/"
                    "Microsoft.ManagedIdentity/userAssignedIdentities/ua-ops"
                ),
            },
            "azure_cli_managed_identity",
        ),
    ],
)
def test_build_auth_session_classifies_cli_auth_modes(
    monkeypatch,
    claims: dict[str, str],
    expected_auth_mode: str,
) -> None:
    _install_fake_identity_module(
        monkeypatch,
        cli_token=_token_with_claims(tid="cli-tenant", **claims),
        env_error=AssertionError("environment fallback should not run"),
    )

    session = build_auth_session("requested-tenant")

    _assert_session(
        session,
        token_source="azure_cli",
        auth_mode=expected_auth_mode,
        tenant_id="cli-tenant",
    )


@pytest.mark.parametrize(
    ("env_vars", "expected_auth_mode"),
    [
        ({"AZURE_CLIENT_SECRET": "env-secret"}, "environment_client_secret"),
        (
            {"AZURE_CLIENT_CERTIFICATE_PATH": "/tmp/fake-cert.pem"},
            "environment_client_certificate",
        ),
    ],
)
def test_build_auth_session_classifies_environment_auth_modes(
    monkeypatch,
    env_vars: dict[str, str],
    expected_auth_mode: str,
) -> None:
    _install_fake_identity_module(
        monkeypatch,
        cli_unavailable=True,
        env_token=_token_with_claims(tid="env-tenant", idtyp="app", appid="env-client-id"),
    )
    monkeypatch.setenv("AZURE_TENANT_ID", "env-tenant")
    monkeypatch.setenv("AZURE_CLIENT_ID", "env-client-id")
    for env_var_name, env_var_value in env_vars.items():
        monkeypatch.setenv(env_var_name, env_var_value)

    session = build_auth_session("requested-tenant")

    _assert_session(
        session,
        token_source="environment",
        auth_mode=expected_auth_mode,
        tenant_id="env-tenant",
    )
