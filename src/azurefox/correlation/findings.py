from __future__ import annotations

import re

from azurefox.models.common import (
    ArmDeploymentSummary,
    AuthPolicySummary,
    EnvVarSummary,
    Finding,
    KeyVaultAsset,
    ManagedIdentity,
    RoleAssignment,
    StorageAsset,
    TokenCredentialSurfaceSummary,
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
            if (r.role_name or "").lower() in {"owner", "contributor", "user access administrator"}
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


def build_keyvault_findings(key_vaults_raw: list[dict]) -> list[dict]:
    key_vaults = [KeyVaultAsset.model_validate(item) for item in key_vaults_raw]
    findings: list[Finding] = []

    for vault in key_vaults:
        public_network_access = (vault.public_network_access or "").lower()
        network_default_action = (vault.network_default_action or "").lower()
        implicit_open_acl = public_network_access == "enabled" and not network_default_action

        if public_network_access == "enabled":
            if (
                network_default_action == "allow" or implicit_open_acl
            ) and not vault.private_endpoint_enabled:
                findings.append(
                    Finding(
                        id=f"keyvault-public-network-open-{vault.id}",
                        severity="high",
                        title="Key Vault is broadly reachable on the public network",
                        description=(
                            (
                                f"Key Vault '{vault.name}' has public network access enabled, "
                                "Azure omitted the network ACL object, and no private endpoint "
                                "is visible. Azure can return that shape for a fully open vault. "
                                "Review whether that secret-management surface is intentionally "
                                "internet reachable."
                            )
                            if implicit_open_acl
                            else (
                                f"Key Vault '{vault.name}' has public network access enabled, "
                                "default network action Allow, and no private endpoint visible. "
                                "Review whether that secret-management surface is intentionally "
                                "internet reachable."
                            )
                        ),
                        related_ids=[vault.id],
                    )
                )
            elif not vault.private_endpoint_enabled:
                findings.append(
                    Finding(
                        id=f"keyvault-public-network-enabled-{vault.id}",
                        severity="medium",
                        title="Key Vault remains reachable through a public network path",
                        description=(
                            f"Key Vault '{vault.name}' keeps public network access enabled with "
                            f"default network action '{vault.network_default_action or 'unknown'}' "
                            "and no private endpoint visible. Review whether that public path is "
                            "still intended."
                        ),
                        related_ids=[vault.id],
                    )
                )
            else:
                findings.append(
                    Finding(
                        id=f"keyvault-public-network-with-private-endpoint-{vault.id}",
                        severity="low",
                        title="Key Vault keeps a public network path alongside Private Link",
                        description=(
                            f"Key Vault '{vault.name}' has public network access enabled while a "
                            "private endpoint is also present. Validate whether the public path is "
                            "still required."
                        ),
                        related_ids=[vault.id],
                    )
                )

        if not vault.purge_protection_enabled:
            findings.append(
                Finding(
                    id=f"keyvault-purge-protection-disabled-{vault.id}",
                    severity="medium",
                    title="Key Vault purge protection is disabled",
                    description=(
                        f"Key Vault '{vault.name}' does not have purge protection enabled. "
                        "Validate whether destructive recovery protections are intentionally "
                        "absent."
                    ),
                    related_ids=[vault.id],
                )
            )

    return [f.model_dump() for f in findings]


def build_arm_deployment_findings(deployments_raw: list[dict]) -> list[dict]:
    deployments = [ArmDeploymentSummary.model_validate(item) for item in deployments_raw]
    findings: list[Finding] = []

    for deployment in deployments:
        state = (deployment.provisioning_state or "").lower()

        if state in {"failed", "canceled"}:
            findings.append(
                Finding(
                    id=f"arm-deployment-failed-{deployment.id}",
                    severity="medium",
                    title="Deployment did not complete successfully",
                    description=(
                        f"Deployment '{deployment.name}' ended in state "
                        f"'{deployment.provisioning_state or 'unknown'}'. Review the deployment "
                        "history for leaked config context, partial resource creation, or "
                        "operator troubleshooting artifacts."
                    ),
                    related_ids=[deployment.id],
                )
            )

        if deployment.outputs_count > 0:
            findings.append(
                Finding(
                    id=f"arm-deployment-outputs-{deployment.id}",
                    severity="medium",
                    title="Deployment exposes output values",
                    description=(
                        f"Deployment '{deployment.name}' includes {deployment.outputs_count} "
                        "recorded output values. Validate whether any outputs reveal useful "
                        "endpoints, identifiers, or sensitive configuration."
                    ),
                    related_ids=[deployment.id],
                )
            )

        if deployment.template_link or deployment.parameters_link:
            findings.append(
                Finding(
                    id=f"arm-deployment-remote-link-{deployment.id}",
                    severity="low",
                    title="Deployment references linked template content",
                    description=(
                        f"Deployment '{deployment.name}' uses linked template or parameter "
                        "content. Review those linked artifacts for exposed configuration, trust "
                        "assumptions, or reusable infrastructure patterns."
                    ),
                    related_ids=[deployment.id],
                )
            )

    return [f.model_dump() for f in findings]


def build_env_var_findings(env_vars_raw: list[dict]) -> list[dict]:
    env_vars = [EnvVarSummary.model_validate(item) for item in env_vars_raw]
    findings: list[Finding] = []

    for env_var in env_vars:
        if env_var.looks_sensitive and env_var.value_type == "plain-text":
            findings.append(
                Finding(
                    id=f"env-var-plain-sensitive-{env_var.asset_id}-{env_var.setting_name}",
                    severity="medium",
                    title="Sensitive-looking app setting is stored in plain text",
                    description=(
                        f"{env_var.asset_kind} '{env_var.asset_name}' stores setting "
                        f"'{env_var.setting_name}' as plain-text management-plane config."
                    ),
                    related_ids=[env_var.asset_id],
                )
            )

        if env_var.value_type == "keyvault-ref":
            findings.append(
                Finding(
                    id=f"env-var-keyvault-ref-{env_var.asset_id}-{env_var.setting_name}",
                    severity="low",
                    title="App setting references Key Vault",
                    description=(
                        f"{env_var.asset_kind} '{env_var.asset_name}' maps setting "
                        f"'{env_var.setting_name}' to Key Vault-backed configuration"
                        f"{f' ({env_var.reference_target})' if env_var.reference_target else ''}."
                    ),
                    related_ids=[env_var.asset_id],
                )
            )

    return [f.model_dump() for f in findings]


def build_tokens_credentials_findings(surfaces_raw: list[dict]) -> list[dict]:
    surfaces = [TokenCredentialSurfaceSummary.model_validate(item) for item in surfaces_raw]
    findings: list[Finding] = []

    for surface in surfaces:
        finding_id_suffix = _tokens_credentials_finding_suffix(surface)

        if surface.surface_type == "plain-text-secret":
            findings.append(
                Finding(
                    id=f"tokens-credentials-plain-text-{finding_id_suffix}",
                    severity="high",
                    title="Credential-like value is exposed in plain-text app settings",
                    description=surface.summary,
                    related_ids=surface.related_ids,
                )
            )
            continue

        if surface.surface_type == "keyvault-reference":
            findings.append(
                Finding(
                    id=f"tokens-credentials-keyvault-ref-{finding_id_suffix}",
                    severity="low",
                    title="Workload setting depends on Key Vault-backed secret retrieval",
                    description=surface.summary,
                    related_ids=surface.related_ids,
                )
            )
            continue

        if surface.surface_type == "managed-identity-token":
            severity = "high" if surface.priority == "high" else "medium"
            title = (
                "Publicly reachable workload can mint tokens with managed identity"
                if surface.priority == "high"
                else "Workload can mint tokens with managed identity"
            )
            findings.append(
                Finding(
                    id=f"tokens-credentials-managed-identity-{finding_id_suffix}",
                    severity=severity,
                    title=title,
                    description=surface.summary,
                    related_ids=surface.related_ids,
                )
            )
            continue

        if surface.surface_type == "deployment-output":
            findings.append(
                Finding(
                    id=f"tokens-credentials-deployment-output-{finding_id_suffix}",
                    severity="medium",
                    title="Deployment history records output values",
                    description=surface.summary,
                    related_ids=surface.related_ids,
                )
            )
            continue

        if surface.surface_type == "linked-deployment-content":
            findings.append(
                Finding(
                    id=f"tokens-credentials-linked-content-{finding_id_suffix}",
                    severity="low",
                    title="Deployment history references remote template or parameter content",
                    description=surface.summary,
                    related_ids=surface.related_ids,
                )
            )

    return [f.model_dump() for f in findings]


def _tokens_credentials_finding_suffix(surface: TokenCredentialSurfaceSummary) -> str:
    parts = [
        surface.asset_id or surface.asset_name,
        surface.access_path,
        _finding_slug(surface.operator_signal),
    ]
    return "-".join(part for part in parts if part)


def _finding_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "surface"


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


def build_auth_policy_findings(
    policies_raw: list[dict],
    issues_raw: list[dict] | None = None,
) -> list[dict]:
    policies = [AuthPolicySummary.model_validate(item) for item in policies_raw]
    findings: list[Finding] = []
    issues = issues_raw or []

    security_defaults = next(
        (policy for policy in policies if policy.policy_type == "security-defaults"),
        None,
    )
    authorization_policy = next(
        (policy for policy in policies if policy.policy_type == "authorization-policy"),
        None,
    )
    conditional_access = [
        policy for policy in policies if policy.policy_type == "conditional-access"
    ]
    conditional_access_unreadable = any(
        (issue.get("context") or {}).get("collector") == "auth_policies.conditional_access"
        for issue in issues
        if isinstance(issue, dict)
    )

    if security_defaults and security_defaults.state == "disabled":
        findings.append(
            Finding(
                id="auth-policy-security-defaults-disabled",
                severity="medium",
                title="Security defaults are disabled",
                description=(
                    "Tenant-wide security defaults are disabled. Review whether Conditional "
                    "Access policies provide equivalent baseline MFA and legacy-auth controls."
                ),
                related_ids=security_defaults.related_ids,
            )
        )

    if authorization_policy:
        controls = set(authorization_policy.controls)

        if "users-can-register-apps" in controls:
            findings.append(
                Finding(
                    id="auth-policy-users-can-register-apps",
                    severity="medium",
                    title="Users can register applications",
                    description=(
                        "Default user permissions allow application registration. Review whether "
                        "that app-creation surface is expected for this tenant."
                    ),
                    related_ids=authorization_policy.related_ids,
                )
            )

        if "guest-invites:everyone" in controls:
            findings.append(
                Finding(
                    id="auth-policy-guest-invites-everyone",
                    severity="medium",
                    title="Guest invitations are broadly allowed",
                    description=(
                        "The authorization policy allows guest invitations from everyone in the "
                        "tenant. Validate whether that guest-invite surface is intentional."
                    ),
                    related_ids=authorization_policy.related_ids,
                )
            )

        if "risky-app-consent:enabled" in controls:
            findings.append(
                Finding(
                    id="auth-policy-risky-app-consent-enabled",
                    severity="high",
                    title="Risky app consent is enabled",
                    description=(
                        "Authorization policy allows user consent for risky apps. Review whether "
                        "that consent posture is expected for this tenant."
                    ),
                    related_ids=authorization_policy.related_ids,
                )
            )
        elif "user-consent:self-service" in controls:
            findings.append(
                Finding(
                    id="auth-policy-user-consent-enabled",
                    severity="medium",
                    title="User consent is available to default users",
                    description=(
                        "Default user permissions include self-service permission-grant policy "
                        "assignment. Review which delegated or application access paths "
                        "that enables."
                    ),
                    related_ids=authorization_policy.related_ids,
                )
            )

    enabled_ca = [policy for policy in conditional_access if policy.state == "enabled"]
    if (
        security_defaults
        and security_defaults.state == "disabled"
        and not enabled_ca
        and not conditional_access_unreadable
    ):
        findings.append(
            Finding(
                id="auth-policy-no-active-enforcement-visible",
                severity="medium",
                title="No active auth enforcement visible",
                description=(
                    "Security defaults are disabled and no enabled Conditional Access policies are "
                    "visible from the current read path. Validate whether stronger auth controls "
                    "exist outside the currently readable policy surface."
                ),
                related_ids=security_defaults.related_ids,
            )
        )

    return [finding.model_dump() for finding in findings]
