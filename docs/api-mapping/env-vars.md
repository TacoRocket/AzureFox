# env-vars API Mapping

## Slice Goal

Surface management-plane workload environment-variable metadata that reveals plain-text secret
storage, high-signal config names, and Key Vault-backed settings.

This first version answers:
"Which App Service and Function App settings expose sensitive-looking plain-text config or Key
Vault-backed configuration paths worth operator review?"

## Initial Scope

- App Service application settings
- Function App application settings
- Setting names, workload identity, value classification, and Key Vault reference targets

## Explicit Non-Goals For V1

- Container Apps, AKS, VM guest environment, or App Configuration service coverage
- Slot-specific settings
- Raw runtime secret extraction beyond what the management-plane app settings API returns
- Full app-services or functions workload enumeration beyond app-setting metadata

## Primary APIs

- `azure.mgmt.web.WebSiteManagementClient.web_apps.list`
- `azure.mgmt.web.WebSiteManagementClient.web_apps.list_application_settings`

## Correlation / Joins

- Normalize app-setting metadata into operator-first rows
- Classify settings as plain text, Key Vault reference, or empty
- Generate findings for sensitive-looking plain-text settings and Key Vault-backed settings

## Blind Spots

- V1 does not cover deployment slots or non-App-Service workload config stores
- Setting names can be suggestive without proving the value is truly secret material
- Key Vault references show config trust paths but do not prove data-plane secret readability
