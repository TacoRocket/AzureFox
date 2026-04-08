from __future__ import annotations

import base64
import json
import sys
from types import ModuleType

import pytest
from azure.core.exceptions import ClientAuthenticationError

from azurefox.auth.session import build_auth_session
from azurefox.errors import AzureFoxError, ErrorKind


def _token_for_tenant(tenant_id: str) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode("utf-8").rstrip("=")
    payload = base64.urlsafe_b64encode(
        json.dumps({"tid": tenant_id}).encode("utf-8")
    ).decode("utf-8").rstrip("=")
    return f"{header}.{payload}.sig"


def _install_fake_identity_module(monkeypatch, *, cli_credential_cls, env_credential_cls) -> None:
    module = ModuleType("azure.identity")

    class FakeCredentialUnavailableError(Exception):
        pass

    module.AzureCliCredential = cli_credential_cls
    module.EnvironmentCredential = env_credential_cls
    module.CredentialUnavailableError = FakeCredentialUnavailableError
    monkeypatch.setitem(sys.modules, "azure.identity", module)


def test_build_auth_session_falls_back_when_cli_is_unavailable(monkeypatch) -> None:
    class FakeAzureCliCredential:
        def __init__(self, tenant_id=None) -> None:
            self.tenant_id = tenant_id

        def get_token(self, scope: str):
            raise sys.modules["azure.identity"].CredentialUnavailableError("cli unavailable")

    class FakeEnvironmentCredential:
        def get_token(self, scope: str):
            return type("Token", (), {"token": _token_for_tenant("env-tenant")})()

    _install_fake_identity_module(
        monkeypatch,
        cli_credential_cls=FakeAzureCliCredential,
        env_credential_cls=FakeEnvironmentCredential,
    )

    session = build_auth_session("requested-tenant")

    assert session.token_source == "environment"
    assert session.tenant_id == "env-tenant"


def test_build_auth_session_does_not_hide_cli_auth_failure(monkeypatch) -> None:
    calls = {"env": 0}

    class FakeAzureCliCredential:
        def __init__(self, tenant_id=None) -> None:
            self.tenant_id = tenant_id

        def get_token(self, scope: str):
            raise ClientAuthenticationError("expired az login")

    class FakeEnvironmentCredential:
        def get_token(self, scope: str):
            calls["env"] += 1
            return type("Token", (), {"token": _token_for_tenant("env-tenant")})()

    _install_fake_identity_module(
        monkeypatch,
        cli_credential_cls=FakeAzureCliCredential,
        env_credential_cls=FakeEnvironmentCredential,
    )

    with pytest.raises(AzureFoxError) as exc_info:
        build_auth_session("requested-tenant")

    assert exc_info.value.kind == ErrorKind.AUTH_FAILURE
    assert "Azure CLI authentication failed" in str(exc_info.value)
    assert exc_info.value.details["azure_cli_error"] == "expired az login"
    assert calls["env"] == 0
