# AzureFox Roadmap

This document is the public-facing high-level roadmap for AzureFox.
Detailed planning, handoff notes, and internal implementation guidance are maintained outside the repo.

## Product Direction

AzureFox should provide:

- operator-first UX with flat commands, `all-checks`, and CloudFox-like output
- trustworthy output with deterministic JSON and explainable findings
- Azure-native depth through ARM, Graph, and service API correlation
- operational maturity through partial-permission tolerance and reusable command orchestration
- modern relevance through AI coverage and ATT&CK-driven Azure-only paths

## Phase 1: Identity and Privilege

- `principals`
- `permissions`
- `privesc`
- `role-trusts`
- `auth-policies`

## Phase 2: Secrets, Config, and Resource Trust

- `keyvault`
- `resource-trusts`
- `arm-deployments`
- `env-vars`
- `tokens-credentials`
- `storage` depth

## Phase 3: Compute, Apps, Endpoints, and Network

- `endpoints`
- `network-effective`
- `network-ports`
- `nics`
- `workloads`
- `app-services`
- `functions`
- `api-mgmt`
- `aks`
- `acr`
- `databases`
- `dns`

Grounded Phase 3 follow-on depth is intentionally parked separately in external planning notes so
the current shipped boundary stays clear:

- `api-mgmt-depth`
- `aks-depth`
- `acr-depth`
- `databases-relational-depth`
- `dns-depth`

## Phase 4: Azure-Only Coverage

- `cross-tenant`
- `lighthouse`
- `automation`
- `devops`
- `snapshots-disks`

Later revisit items such as `public-ips` and `load-balancers` are intentionally parked outside the
initial Phase 4 list until they show clearer analyst-decision value.

## Phase 5: AI Track

- `openai`
- `ai-foundry`
- `aml`

## Notes

- CloudFox remains an inspiration for operator workflow and output style, but AzureFox should stay Azure-native in command design and findings language.
- Detailed slice planning, help-surface requirements, and reference material live outside the public repo docs.
