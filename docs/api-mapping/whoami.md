# whoami API Mapping

## Primary APIs

- `azure.identity.AzureCliCredential.get_token`
- `azure.identity.EnvironmentCredential.get_token`
- JWT claim extraction from access token payload
- `azure.mgmt.resource.SubscriptionClient.subscriptions.list`

## Correlation / Joins

- Token claims (`tid`, `oid`, `appid`) joined with selected subscription context.

## Assumptions

- Unverified JWT claim parsing is used for identity metadata only.
- Subscription scope is treated as effective base scope in Milestone 1.

## Blind Spots

- No Microsoft Graph lookup for friendly principal metadata in Milestone 1.
