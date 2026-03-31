# AzureFox Roadmap

## Pre-Work Gate

Before new command implementation resumes:

- complete the external assumptions review in `~/Documents/AzureFox-Assumptions.md`
- keep the external handoff file current in `~/Documents/AzureFox-Lab-Reference.md`
- classify CloudFox parity gaps in `docs/cloudfox-compatibility-ledger.md`

## First-Class Recon Tool Standard

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

## Phase 4: Azure-Only Coverage

- `cross-tenant`
- `lighthouse`
- `automation`
- `devops`
- `snapshots-disks`

## Phase 5: AI Track

- `openai`
- `ai-foundry`
- `aml`
