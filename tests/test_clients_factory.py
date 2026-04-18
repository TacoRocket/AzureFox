from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace

from azurefox.clients.factory import build_clients


def _install_module(monkeypatch, name: str, *, is_package: bool = False, **attrs) -> ModuleType:
    module = ModuleType(name)
    if is_package:
        module.__path__ = []
    for attr_name, attr_value in attrs.items():
        setattr(module, attr_name, attr_value)
    monkeypatch.setitem(sys.modules, name, module)
    return module


def _management_client_class(name: str):
    class FakeManagementClient:
        def __init__(self, credential: object, subscription_id: str) -> None:
            self.credential = credential
            self.subscription_id = subscription_id

    FakeManagementClient.__name__ = name
    return FakeManagementClient


def _install_fake_management_modules(
    monkeypatch,
    *,
    subscription_client_on_resource: bool,
    subscription_client_on_split_module: bool,
) -> None:
    _install_module(monkeypatch, "azure", is_package=True)
    _install_module(monkeypatch, "azure.mgmt", is_package=True)

    subscriptions = [
        SimpleNamespace(subscription_id="sub-a", display_name="Alpha", state="Enabled"),
        SimpleNamespace(subscription_id="sub-b", display_name="Beta", state="Warned"),
    ]

    class FakeSubscriptionClient:
        def __init__(self, credential: object) -> None:
            self.credential = credential
            self.subscriptions = SimpleNamespace(list=lambda: list(subscriptions))

    client_modules = {
        "azure.mgmt.apimanagement": ("ApiManagementClient",),
        "azure.mgmt.authorization": ("AuthorizationManagementClient",),
        "azure.mgmt.automation": ("AutomationClient",),
        "azure.mgmt.compute": ("ComputeManagementClient",),
        "azure.mgmt.containerregistry": ("ContainerRegistryManagementClient",),
        "azure.mgmt.containerservice": ("ContainerServiceClient",),
        "azure.mgmt.keyvault": ("KeyVaultManagementClient",),
        "azure.mgmt.mysqlflexibleservers": ("MySQLManagementClient",),
        "azure.mgmt.network": ("NetworkManagementClient",),
        "azure.mgmt.postgresqlflexibleservers": ("PostgreSQLManagementClient",),
        "azure.mgmt.resource.deployments": ("DeploymentsMgmtClient",),
        "azure.mgmt.sql": ("SqlManagementClient",),
        "azure.mgmt.storage": ("StorageManagementClient",),
        "azure.mgmt.web": ("WebSiteManagementClient",),
    }
    for module_name, class_names in client_modules.items():
        _install_module(
            monkeypatch,
            module_name,
            **{class_name: _management_client_class(class_name) for class_name in class_names},
        )

    resource_attrs = {
        "ResourceManagementClient": _management_client_class("ResourceManagementClient"),
    }
    if subscription_client_on_resource:
        resource_attrs["SubscriptionClient"] = FakeSubscriptionClient
    _install_module(monkeypatch, "azure.mgmt.resource", is_package=True, **resource_attrs)

    if subscription_client_on_split_module:
        _install_module(
            monkeypatch,
            "azure.mgmt.resource.subscriptions",
            SubscriptionClient=FakeSubscriptionClient,
        )


def test_build_clients_supports_split_subscription_package(monkeypatch) -> None:
    _install_fake_management_modules(
        monkeypatch,
        subscription_client_on_resource=False,
        subscription_client_on_split_module=True,
    )

    session = SimpleNamespace(credential=object())

    clients = build_clients(session, "sub-b")

    assert clients.subscription_id == "sub-b"
    assert clients.subscription.display_name == "Beta"
    assert clients.resource.subscription_id == "sub-b"
    assert clients.resource_deployments.subscription_id == "sub-b"
