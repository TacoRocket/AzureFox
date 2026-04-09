from __future__ import annotations

from azurefox.chains.credential_path import (
    CREDENTIAL_PATH_HANDLERS,
    collect_credential_path_records,
)
from azurefox.collectors.commands import (
    collect_databases,
    collect_env_vars,
    collect_keyvault,
    collect_storage,
    collect_tokens_credentials,
)


def test_credential_path_handler_registry_names() -> None:
    assert [handler.name for handler in CREDENTIAL_PATH_HANDLERS] == [
        "keyvault",
        "database",
        "storage",
    ]


def test_collect_credential_path_records_from_registered_handlers(
    fixture_provider,
    options,
) -> None:
    loaded = {
        "env-vars": collect_env_vars(fixture_provider, options),
        "tokens-credentials": collect_tokens_credentials(fixture_provider, options),
        "databases": collect_databases(fixture_provider, options),
        "storage": collect_storage(fixture_provider, options),
        "keyvault": collect_keyvault(fixture_provider, options),
    }

    paths, issues = collect_credential_path_records(
        fixture_provider,
        "credential-path",
        loaded,
    )

    assert not issues
    assert len(paths) == 3
    assert {(item.setting_name, item.target_service) for item in paths} == {
        ("PAYMENT_API_KEY", "keyvault"),
        ("DB_PASSWORD", "database"),
        ("AzureWebJobsStorage", "storage"),
    }
    keyvault_path = next(item for item in paths if item.target_service == "keyvault")
    assert keyvault_path.target_names == ["kvlabopen01"]
    assert keyvault_path.confidence_boundary == "Your current identity can read this secret."
