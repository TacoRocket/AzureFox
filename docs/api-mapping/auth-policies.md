# auth-policies Slice Proposal

## Slice Goal

Surface tenant auth controls that materially affect sign-in enforcement, guest invitation,
application registration, and consent posture.

This slice is intended to answer:
"Which tenant auth settings change how identities authenticate, register apps, invite guests, or
gain consented access?"

## CloudFox Mapping

- CloudFox-style operator framing: operator-first auth-control posture triage.
- AzureFox mapping: Azure-native tenant auth-policy review surface.
- Coverage note: this is Azure-specific and does not attempt a 1:1 AWS or GCP command analogue.

## Initial Scope

- Security defaults status
- Authorization policy settings that change guest invitations, app registration, and user consent
- Conditional Access policy inventory with state, core controls, and coarse scope signals

## Explicit Non-Goals For V1

- Full Conditional Access rule simulation
- Sign-in log correlation
- PIM, authentication methods policy, or registration-campaign modeling
- Claims that a permissive policy is actively abused

## Primary APIs

- Microsoft Graph `GET /policies/identitySecurityDefaultsEnforcementPolicy`
- Microsoft Graph `GET /policies/authorizationPolicy`
- Microsoft Graph `GET /identity/conditionalAccess/policies`

## Correlation / Joins

- Summarize authorization policy settings into operator-relevant control flags
- Summarize Conditional Access scope and grant controls without pretending to fully simulate policy
- Generate findings only for explicit permissive or missing baseline signals

## Output Shape

Suggested fields:

- `policy_type`
- `name`
- `state`
- `scope`
- `controls`
- `summary`
- `related_ids`

## Validation Plan

- Add fixtures for disabled security defaults, permissive authorization policy, and report-only or
  disabled Conditional Access policies
- Add live-smoke validation against a tenant with whatever policy-read access is available
- Keep partial-permission issues explicit rather than silently omitting unreadable policy surfaces

## Lab-Only Follow-Up

The sister lab repo should validate conditions AzureFox cannot prove from read-only policy metadata
alone. That follow-up should sharpen AzureFox output later, not replace careful command design now.

The lab is the right place to verify:

- whether Conditional Access policies actually produce the expected enforcement outcome in live
  sign-in scenarios
- whether permissive consent or app-registration settings can be exercised into meaningful trust
  paths in the deployed infrastructure
- whether missing live policy combinations reveal blind spots in AzureFox summaries or findings

AzureFox should not infer enforcement success, bypassability, or exploitability from policy
metadata alone.
