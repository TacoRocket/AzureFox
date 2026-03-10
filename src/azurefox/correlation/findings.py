from __future__ import annotations

from azurefox.models.common import (
    Finding,
    ManagedIdentity,
    RoleAssignment,
    StorageAsset,
    VmAsset,
)


def build_identity_findings(identities_raw: list[dict], assignments_raw: list[dict]) -> list[dict]:
    identities = [ManagedIdentity.model_validate(item) for item in identities_raw]
    assignments = [RoleAssignment.model_validate(item) for item in assignments_raw]

    findings: list[Finding] = []
    by_principal: dict[str, list[RoleAssignment]] = {}
    for assignment in assignments:
        by_principal.setdefault(assignment.principal_id, []).append(assignment)

    for identity in identities:
        if not identity.principal_id:
            continue

        roles = by_principal.get(identity.principal_id, [])
        privileged = [
            r
            for r in roles
            if (r.role_name or "").lower()
            in {"owner", "contributor", "user access administrator"}
        ]
        if privileged:
            findings.append(
                Finding(
                    id=f"identity-privileged-{identity.id}",
                    severity="high",
                    title="Managed identity has elevated role assignment",
                    description=(
                        f"Identity '{identity.name}' is assigned one or more high-impact roles "
                        f"({', '.join(sorted({r.role_name or 'Unknown' for r in privileged}))})."
                    ),
                    related_ids=[identity.id] + [r.id for r in privileged],
                )
            )

    return [f.model_dump() for f in findings]


def build_storage_findings(storage_raw: list[dict]) -> list[dict]:
    assets = [StorageAsset.model_validate(item) for item in storage_raw]
    findings: list[Finding] = []

    for asset in assets:
        if asset.public_access:
            findings.append(
                Finding(
                    id=f"storage-public-{asset.id}",
                    severity="high",
                    title="Storage account allows public blob access",
                    description=(
                        f"Storage account '{asset.name}' has blob public access enabled. "
                        "Validate anonymous access and exposed data paths."
                    ),
                    related_ids=[asset.id],
                )
            )

        if asset.network_default_action and asset.network_default_action.lower() == "allow":
            findings.append(
                Finding(
                    id=f"storage-firewall-open-{asset.id}",
                    severity="medium",
                    title="Storage account network default action is Allow",
                    description=(
                        f"Storage account '{asset.name}' default firewall action is Allow. "
                        "Review allowed network sources and private endpoint posture."
                    ),
                    related_ids=[asset.id],
                )
            )

    return [f.model_dump() for f in findings]


def build_vm_findings(vms_raw: list[dict]) -> list[dict]:
    vms = [VmAsset.model_validate(item) for item in vms_raw]
    findings: list[Finding] = []

    for vm in vms:
        if vm.public_ips and vm.identity_ids:
            findings.append(
                Finding(
                    id=f"vm-public-identity-{vm.id}",
                    severity="medium",
                    title="Public workload with attached identity",
                    description=(
                        f"Workload '{vm.name}' has public IP exposure and one or "
                        "more managed identities. "
                        "Validate identity privileges and ingress hardening."
                    ),
                    related_ids=[vm.id, *vm.identity_ids],
                )
            )

    return [f.model_dump() for f in findings]
