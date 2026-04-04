# role-trusts Slice Proposal

## Slice Goal

Surface high-signal Azure identity trust edges that can create reusable pivot paths between
applications, service principals, workloads, and federated or ownership-backed access.

This slice is intended to answer:
"Which Azure app and service-principal relationships create trust paths worth immediate abuse
review?"

## CloudFox Mapping

- CloudFox-style operator framing: trust-relationship triage for immediate abuse review.
- AzureFox mapping: Azure-native analogue to `role-trusts` / `identity-federation`.
- Coverage note: covered differently in Azure because the key trust edges are app registrations,
  service principals, federated identity credentials, app ownership, and app-role assignment
  relationships
  rather than AWS-style role assumption semantics.

## Initial Scope

- Federated identity credential trusts
- Application ownership edges
- Service principal ownership edges where exposed by the selected Graph path
- App-role assignment / application-permission style trust relationships
- High-value service principals linked to broadly trusted or privileged app objects

## Command Boundary

- Add one user-facing command: `azurefox role-trusts`
- Model trust families as row types inside the command rather than as separate CLI commands
- Keep broad Entra relationship dumping out of this command so `role-trusts` stays signal-first
- Revisit a future `entra-graph` or `directory-graph` command separately if coverage-first output
  becomes valuable

## Explicit Non-Goals For V1

- Full Entra relationship graph coverage
- Cross-tenant trust and B2B/B2C edge cases
- PIM or eligible-role modeling
- Full OAuth abuse-path simulation
- Delegated or admin consent-grant coverage
- Proof of exploitability or compromise

## Primary APIs

- Microsoft Graph application queries for app registrations
- Microsoft Graph service principal queries
- Microsoft Graph federated identity credential queries where supported
- Microsoft Graph ownership and app-role assignment queries

## Correlation / Joins

- Join app registrations to backing service principals
- Join ownership relationships to app or service-principal objects
- Join federated credentials to trusted external issuers and subjects
- Join app-role assignments to the target service principal and exposed application surface
- Flag trust edges that touch privileged or high-value identities as findings candidates

## Output Shape

The first version should keep the contract small and explicit. Each row should distinguish
confirmed relationships from investigative leads.

Suggested fields:

- `trust_type`
- `source_object_id`
- `source_name`
- `source_type`
- `target_object_id`
- `target_name`
- `target_type`
- `evidence_type`
- `confidence`
- `summary`
- `related_ids`

## Sample Output

```json
{
  "trusts": [
    {
      "trust_type": "federated-credential",
      "source_object_id": "11111111-1111-1111-1111-111111111111",
      "source_name": "build-app",
      "source_type": "Application",
      "target_object_id": "22222222-2222-2222-2222-222222222222",
      "target_name": "build-sp",
      "target_type": "ServicePrincipal",
      "evidence_type": "graph-federated-credential",
      "confidence": "confirmed",
      "summary": "Application 'build-app' trusts an external federated identity subject that can mint tokens for service principal 'build-sp'.",
      "related_ids": [
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222"
      ]
    },
    {
      "trust_type": "app-to-service-principal",
      "source_object_id": "33333333-3333-3333-3333-333333333333",
      "source_name": "reporting-app",
      "source_type": "ServicePrincipal",
      "target_object_id": "00000003-0000-0000-c000-000000000000",
      "target_name": "Microsoft Graph",
      "target_type": "ServicePrincipal",
      "evidence_type": "graph-app-role-assignment",
      "confidence": "confirmed",
      "summary": "Service principal 'reporting-app' holds an application permission or app-role assignment worth reviewing for reusable directory data exposure.",
      "related_ids": [
        "33333333-3333-3333-3333-333333333333",
        "00000003-0000-0000-c000-000000000000"
      ]
    }
  ]
}
```

## Assumptions

- This command is a trust-edge triage surface, not a full Entra graph dump.
- Graph-backed collection should enumerate readable app and service-principal trust edges directly
  rather than relying only on identities already surfaced by other commands.
- Confidence labels must separate confirmed relationships from investigative leads.
- Wording should stay narrower than the breadth implied by the command name.

## Validation Plan

- Add fixtures for app registrations, service principals, federated identity credentials, and at
  least one app-role assignment relationship
- Add golden output coverage for ownership, federated, and app-role rows
- Add real-tenant validation notes before claiming strong confidence in trust-heavy findings

## Lab-Only Follow-Up

The sister lab repo should validate conditions that AzureFox cannot prove from read-only control
plane and directory metadata alone. That follow-up is intended to catch real-world mismatches, not
to excuse weak command design here.

The lab is the right place to verify:

- whether a federated credential is actually usable from a live issuer/subject combination
- whether ownership edges can be exercised into meaningful app or service-principal changes under
  current tenant policy
- whether trust paths remain visible and valid after the required infrastructure is deployed
- whether AzureFox is missing trust edges that only become obvious once the lab infrastructure and
  validator assertions exist

AzureFox should not infer any of the above without evidence in its own output. If the lab later
shows a trust path is exploitable or missing, feed that back into AzureFox as a concrete output,
correlation, or known-gap update.

## Blind Spots

- Tenant-boundary trust may remain incomplete in V1
- Some ownership and app-role paths may require permissions not always granted to read-only
  operator identities
- Graph relationship breadth can easily outgrow the signal budget if not curated aggressively
