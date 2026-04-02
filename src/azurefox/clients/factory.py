from __future__ import annotations

from dataclasses import dataclass

from azurefox.auth.session import AuthSession
from azurefox.errors import AzureFoxError, ErrorKind
from azurefox.models.common import SubscriptionRef


@dataclass(slots=True)
class AzureClients:
    subscription_id: str
    subscription: SubscriptionRef
    resource: object
    authorization: object
    web: object
    containerservice: object
    api_management: object
    keyvault: object
    storage: object
    compute: object
    network: object


def build_clients(session: AuthSession, requested_subscription: str | None) -> AzureClients:
    try:
        from azure.mgmt.apimanagement import ApiManagementClient
        from azure.mgmt.authorization import AuthorizationManagementClient
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.containerservice import ContainerServiceClient
        from azure.mgmt.keyvault import KeyVaultManagementClient
        from azure.mgmt.network import NetworkManagementClient
        from azure.mgmt.resource import ResourceManagementClient, SubscriptionClient
        from azure.mgmt.storage import StorageManagementClient
        from azure.mgmt.web import WebSiteManagementClient
    except ImportError as exc:  # pragma: no cover - dependency surface
        raise AzureFoxError(
            ErrorKind.DEPENDENCY_MISSING,
            "Missing Azure management SDK dependencies. Install with: pip install -e '.[azure]'",
        ) from exc

    sub_client = SubscriptionClient(session.credential)

    subscription = None
    if requested_subscription:
        for sub in sub_client.subscriptions.list():
            if getattr(sub, "subscription_id", None) == requested_subscription:
                subscription = sub
                break
        if subscription is None:
            raise AzureFoxError(
                ErrorKind.AUTH_FAILURE,
                (
                    "Requested subscription "
                    f"'{requested_subscription}' not visible to current credential."
                ),
            )
    else:
        subscription = next(iter(sub_client.subscriptions.list()), None)

    if subscription is None:
        raise AzureFoxError(
            ErrorKind.AUTH_FAILURE,
            "No subscriptions found for current credential.",
        )

    subscription_id = str(subscription.subscription_id)
    subscription_ref = SubscriptionRef(
        id=subscription_id,
        display_name=getattr(subscription, "display_name", None),
        state=getattr(subscription, "state", None),
    )

    return AzureClients(
        subscription_id=subscription_id,
        subscription=subscription_ref,
        resource=ResourceManagementClient(session.credential, subscription_id),
        authorization=AuthorizationManagementClient(session.credential, subscription_id),
        web=WebSiteManagementClient(session.credential, subscription_id),
        containerservice=ContainerServiceClient(session.credential, subscription_id),
        api_management=ApiManagementClient(session.credential, subscription_id),
        keyvault=KeyVaultManagementClient(session.credential, subscription_id),
        storage=StorageManagementClient(session.credential, subscription_id),
        compute=ComputeManagementClient(session.credential, subscription_id),
        network=NetworkManagementClient(session.credential, subscription_id),
    )
