from __future__ import annotations

from dataclasses import dataclass

from azurefox.registry import SECTION_NAMES, get_command_specs


@dataclass(frozen=True, slots=True)
class AttackLead:
    tactic: str
    technique: str


@dataclass(frozen=True, slots=True)
class CommandHelpTopic:
    name: str
    section: str
    summary: str
    offensive_question: str
    cloudfox_frame: str
    output_highlights: tuple[str, ...]
    attack_leads: tuple[AttackLead, ...]
    example: str


@dataclass(frozen=True, slots=True)
class SectionHelpTopic:
    name: str
    summary: str
    operator_goal: str
    attack_lenses: tuple[AttackLead, ...]


COMMAND_HELP: dict[str, CommandHelpTopic] = {
    "whoami": CommandHelpTopic(
        name="whoami",
        section="identity",
        summary="Confirm the caller identity, token context, and active subscription scope.",
        offensive_question=(
            "Who am I in this tenant and what subscription scope am I "
            "operating in right now?"
        ),
        cloudfox_frame="CloudFox-style caller-context check before deeper cloud enumeration.",
        output_highlights=("principal", "subscription", "effective_scopes", "token_source"),
        attack_leads=(
            AttackLead("Discovery", "Cloud Account"),
            AttackLead("Initial Access", "Valid Accounts: Cloud Accounts"),
        ),
        example="azurefox whoami --output table",
    ),
    "inventory": CommandHelpTopic(
        name="inventory",
        section="core",
        summary="Summarize the visible Azure resource footprint for fast scoping.",
        offensive_question=(
            "What cloud infrastructure and service surface is visible in "
            "this subscription?"
        ),
        cloudfox_frame="Azure analogue to CloudFox inventory-first situational awareness.",
        output_highlights=("resource_group_count", "resource_count", "top_resource_types"),
        attack_leads=(
            AttackLead("Discovery", "Cloud Infrastructure Discovery"),
            AttackLead("Discovery", "Cloud Service Discovery"),
        ),
        example="azurefox inventory --output table",
    ),
    "rbac": CommandHelpTopic(
        name="rbac",
        section="identity",
        summary="Enumerate raw RBAC assignments across the current subscription scope.",
        offensive_question="Which principals have role assignments here, and at what scopes?",
        cloudfox_frame="Closest AzureFox equivalent to a raw cloud permission-assignment dump.",
        output_highlights=("role_assignments", "principals", "scopes"),
        attack_leads=(
            AttackLead("Discovery", "Permission Groups Discovery: Cloud Groups"),
            AttackLead("Persistence", "Account Manipulation: Additional Cloud Roles"),
            AttackLead("Privilege Escalation", "Account Manipulation: Additional Cloud Roles"),
        ),
        example="azurefox rbac --output json",
    ),
    "principals": CommandHelpTopic(
        name="principals",
        section="identity",
        summary=(
            "Build a principal census from RBAC, caller context, and "
            "managed identity attachments."
        ),
        offensive_question=(
            "Which principals matter in this subscription, and how are "
            "they connected to roles and identities?"
        ),
        cloudfox_frame=(
            "Azure analogue to a CloudFox principal inventory with "
            "Azure-native identity edges."
        ),
        output_highlights=("display_name", "principal_type", "role_names", "identity_names"),
        attack_leads=(
            AttackLead("Discovery", "Cloud Account"),
            AttackLead("Discovery", "Permission Groups Discovery: Cloud Groups"),
        ),
        example="azurefox principals --output table",
    ),
    "permissions": CommandHelpTopic(
        name="permissions",
        section="identity",
        summary="Triage which visible principals hold high-impact RBAC roles.",
        offensive_question=(
            "Which principals are privileged here, how broad is that "
            "access, and is the current identity one of them?"
        ),
        cloudfox_frame=(
            "Azure analogue to a fast CloudFox permissions triage view "
            "rather than full effective-permissions proof."
        ),
        output_highlights=(
            "high_impact_roles",
            "assignment_count",
            "privileged",
            "current_identity",
        ),
        attack_leads=(
            AttackLead("Discovery", "Permission Groups Discovery: Cloud Groups"),
            AttackLead("Persistence", "Account Manipulation: Additional Cloud Roles"),
            AttackLead("Privilege Escalation", "Account Manipulation: Additional Cloud Roles"),
            AttackLead(
                "Privilege Escalation",
                "Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access",
            ),
        ),
        example="azurefox permissions --output table",
    ),
    "privesc": CommandHelpTopic(
        name="privesc",
        section="identity",
        summary="Surface likely Azure privilege-escalation and role-abuse paths first.",
        offensive_question=(
            "Which Azure identity paths look most likely to produce privileged "
            "control if an operator or attacker can act on them?"
        ),
        cloudfox_frame=(
            "Azure analogue to CloudFox privesc/cape triage, with emphasis on "
            "RBAC abuse and workload identity pivots."
        ),
        output_highlights=(
            "path_type",
            "asset",
            "impact_roles",
            "severity",
            "current_identity",
        ),
        attack_leads=(
            AttackLead("Privilege Escalation", "Account Manipulation: Additional Cloud Roles"),
            AttackLead(
                "Privilege Escalation",
                "Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access",
            ),
            AttackLead("Credential Access", "Cloud Instance Metadata API"),
            AttackLead(
                "Credential Access",
                "Use Alternate Authentication Material: Application Access Token",
            ),
        ),
        example="azurefox privesc --output table",
    ),
    "role-trusts": CommandHelpTopic(
        name="role-trusts",
        section="identity",
        summary="Triage Azure app and service-principal trust edges worth abuse review.",
        offensive_question=(
            "Which Azure app, service-principal, ownership, and federated relationships create "
            "trust paths I should review first?"
        ),
        cloudfox_frame=(
            "Azure-native analogue to trust-relationship triage, centered on app "
            "registrations, service principals, federated credentials, ownership, and "
            "app-role assignment metadata."
        ),
        output_highlights=(
            "trust_type",
            "source_name",
            "target_name",
            "confidence",
            "evidence_type",
        ),
        attack_leads=(
            AttackLead("Initial Access", "Trusted Relationship"),
            AttackLead(
                "Credential Access",
                "Use Alternate Authentication Material: Application Access Token",
            ),
            AttackLead("Privilege Escalation", "Account Manipulation: Additional Cloud Roles"),
        ),
        example="azurefox role-trusts --output table",
    ),
    "auth-policies": CommandHelpTopic(
        name="auth-policies",
        section="identity",
        summary="Review tenant auth controls that affect sign-in, consent, and identity hardening.",
        offensive_question=(
            "Which tenant auth settings materially change how identities authenticate, "
            "register apps, invite guests, or bypass stronger sign-in controls?"
        ),
        cloudfox_frame=(
            "Azure-native auth-control triage for tenant-wide identity policy surfaces "
            "such as security defaults, authorization policy, and Conditional Access."
        ),
        output_highlights=(
            "policy_type",
            "state",
            "controls",
            "summary",
            "findings",
        ),
        attack_leads=(
            AttackLead("Defense Evasion", "Modify Authentication Process"),
            AttackLead("Initial Access", "Valid Accounts: Cloud Accounts"),
            AttackLead(
                "Credential Access",
                "Use Alternate Authentication Material: Application Access Token",
            ),
        ),
        example="azurefox auth-policies --output table",
    ),
    "managed-identities": CommandHelpTopic(
        name="managed-identities",
        section="identity",
        summary="Enumerate managed identities, their attachments, and privileged findings.",
        offensive_question=(
            "Which workloads carry managed identities, and do any of "
            "those identities already hold dangerous roles?"
        ),
        cloudfox_frame="Azure-native identity-abuse lens centered on workload-attached identities.",
        output_highlights=("identities", "attached_to", "role_assignments", "findings"),
        attack_leads=(
            AttackLead("Credential Access", "Cloud Instance Metadata API"),
            AttackLead(
                "Credential Access",
                "Use Alternate Authentication Material: Application Access Token",
            ),
            AttackLead("Privilege Escalation", "Account Manipulation: Additional Cloud Roles"),
        ),
        example="azurefox managed-identities --output table",
    ),
    "keyvault": CommandHelpTopic(
        name="keyvault",
        section="secrets",
        summary="Enumerate Key Vault assets and flag secret-management exposure or recovery risk.",
        offensive_question=(
            "Which Key Vaults are exposed, weakly protected, or worth deeper secret-access "
            "review first?"
        ),
        cloudfox_frame=(
            "Azure-native secret-management surface triage using management-plane "
            "Key Vault metadata."
        ),
        output_highlights=(
            "public_network_access",
            "network_default_action",
            "purge_protection_enabled",
            "enable_rbac_authorization",
            "findings",
        ),
        attack_leads=(
            AttackLead("Discovery", "Cloud Service Discovery"),
            AttackLead("Collection", "Data from Information Repositories"),
            AttackLead(
                "Credential Access",
                "Steal or Forge Authentication Certificates",
            ),
        ),
        example="azurefox keyvault --output table",
    ),
    "resource-trusts": CommandHelpTopic(
        name="resource-trusts",
        section="resource",
        summary=(
            "Correlate Storage and Key Vault trust surfaces into operator-first "
            "resource paths."
        ),
        offensive_question=(
            "Which resources still trust public network paths, and which ones are constrained to "
            "private-link style access?"
        ),
        cloudfox_frame=(
            "Azure-native resource trust review centered on management-plane network posture and "
            "private endpoint surfaces."
        ),
        output_highlights=(
            "resource_type",
            "trust_type",
            "target",
            "exposure",
            "summary",
        ),
        attack_leads=(
            AttackLead("Discovery", "Cloud Service Discovery"),
            AttackLead("Initial Access", "Exploit Public-Facing Application"),
            AttackLead("Collection", "Data from Cloud Storage"),
        ),
        example="azurefox resource-trusts --output table",
    ),
    "storage": CommandHelpTopic(
        name="storage",
        section="storage",
        summary="Identify storage accounts with public exposure or weak network posture.",
        offensive_question=(
            "Which storage assets are likely exposed, and where should I "
            "look for accessible data next?"
        ),
        cloudfox_frame=(
            "CloudFox-style storage triage with Azure "
            "storage-specific exposure signals."
        ),
        output_highlights=(
            "public_access",
            "network_default_action",
            "private_endpoint_enabled",
            "findings",
        ),
        attack_leads=(
            AttackLead("Discovery", "Cloud Storage Object Discovery"),
            AttackLead("Collection", "Data from Cloud Storage"),
        ),
        example="azurefox storage --output table",
    ),
    "vms": CommandHelpTopic(
        name="vms",
        section="compute",
        summary="Summarize virtual machines and scale sets with network and identity context.",
        offensive_question=(
            "Which compute assets are reachable, and which of them "
            "expose useful identity or ingress paths?"
        ),
        cloudfox_frame="Azure compute census with the operator-first feel of CloudFox host triage.",
        output_highlights=("public_ips", "private_ips", "identity_ids", "nic_ids"),
        attack_leads=(
            AttackLead("Discovery", "Cloud Infrastructure Discovery"),
            AttackLead("Lateral Movement", "Remote Services: Direct Cloud VM Connections"),
        ),
        example="azurefox vms --output table",
    ),
    "all-checks": CommandHelpTopic(
        name="all-checks",
        section="orchestration",
        summary="Run the implemented AzureFox commands in a stable operator-first sequence.",
        offensive_question=(
            "What is the fastest broad sweep I can run right now for "
            "this tenant or section?"
        ),
        cloudfox_frame="Direct AzureFox analogue to a CloudFox grouped recon pass.",
        output_highlights=("results", "run-summary.json", "section filtering"),
        attack_leads=(
            AttackLead("Discovery", "Cloud Account"),
            AttackLead("Discovery", "Cloud Infrastructure Discovery"),
            AttackLead("Discovery", "Permission Groups Discovery: Cloud Groups"),
        ),
        example="azurefox all-checks --section identity",
    ),
}


SECTION_HELP: dict[str, SectionHelpTopic] = {
    "identity": SectionHelpTopic(
        name="identity",
        summary=(
            "Identity and privilege context for Azure principals, roles, "
            "and workload identities."
        ),
        operator_goal=(
            "Find who matters, who is privileged, and which identity "
            "paths are worth deeper abuse analysis."
        ),
        attack_lenses=(
            AttackLead("Discovery", "Cloud Account"),
            AttackLead("Discovery", "Permission Groups Discovery: Cloud Groups"),
            AttackLead("Persistence", "Account Manipulation: Additional Cloud Roles"),
            AttackLead("Privilege Escalation", "Account Manipulation: Additional Cloud Roles"),
        ),
    ),
    "core": SectionHelpTopic(
        name="core",
        summary="Tenant-wide situational awareness primitives that anchor the rest of the recon.",
        operator_goal="Establish account context and visible resource surface quickly.",
        attack_lenses=(
            AttackLead("Discovery", "Cloud Infrastructure Discovery"),
            AttackLead("Discovery", "Cloud Service Discovery"),
        ),
    ),
    "storage": SectionHelpTopic(
        name="storage",
        summary="Storage exposure, discovery, and collection-oriented posture checks.",
        operator_goal="Spot accessible storage paths and prioritize the best data-hunting targets.",
        attack_lenses=(
            AttackLead("Discovery", "Cloud Storage Object Discovery"),
            AttackLead("Collection", "Data from Cloud Storage"),
        ),
    ),
    "secrets": SectionHelpTopic(
        name="secrets",
        summary="Secret-store exposure and recovery-control posture for Azure secret services.",
        operator_goal=(
            "Find exposed or weakly protected secret-management surfaces worth deeper follow-up."
        ),
        attack_lenses=(
            AttackLead("Discovery", "Cloud Service Discovery"),
            AttackLead("Collection", "Data from Information Repositories"),
            AttackLead(
                "Credential Access",
                "Steal or Forge Authentication Certificates",
            ),
        ),
    ),
    "resource": SectionHelpTopic(
        name="resource",
        summary=(
            "Resource-level trust surfaces such as public network reachability "
            "and private-link paths."
        ),
        operator_goal=(
            "Find which resources still trust broad network paths and which ones are constrained "
            "to narrower trust boundaries."
        ),
        attack_lenses=(
            AttackLead("Discovery", "Cloud Service Discovery"),
            AttackLead("Initial Access", "Exploit Public-Facing Application"),
            AttackLead("Collection", "Data from Cloud Storage"),
        ),
    ),
    "compute": SectionHelpTopic(
        name="compute",
        summary="Compute reachability, workload identity context, and host-oriented pivot leads.",
        operator_goal=(
            "Find reachable workloads and identity-bearing hosts worth "
            "deeper access review."
        ),
        attack_lenses=(
            AttackLead("Discovery", "Cloud Infrastructure Discovery"),
            AttackLead("Lateral Movement", "Remote Services: Direct Cloud VM Connections"),
        ),
    ),
    "network": SectionHelpTopic(
        name="network",
        summary="Reserved for future network-centric AzureFox coverage.",
        operator_goal=(
            "Support ingress, pathing, and service exposure analysis as "
            "the network slice lands."
        ),
        attack_lenses=(AttackLead("Discovery", "Network Service Discovery"),),
    ),
    "azure-only": SectionHelpTopic(
        name="azure-only",
        summary="Reserved for Azure-native trust and control-plane abuse paths.",
        operator_goal=(
            "Highlight Azure-specific surfaces that do not map cleanly "
            "to AWS or GCP workflows."
        ),
        attack_lenses=(
            AttackLead("Initial Access", "Trusted Relationship"),
            AttackLead("Privilege Escalation", "Account Manipulation: Additional Cloud Roles"),
        ),
    ),
    "ai": SectionHelpTopic(
        name="ai",
        summary="Reserved for Azure AI control-plane and data-plane coverage.",
        operator_goal=(
            "Help operators reason about AI-specific discovery and misuse "
            "paths in Azure-native services."
        ),
        attack_lenses=(
            AttackLead("Discovery", "Cloud Service Discovery"),
            AttackLead(
                "Credential Access",
                "Use Alternate Authentication Material: Application Access Token",
            ),
        ),
    ),
}


def render_help(topic: str | None = None) -> str:
    if topic is None:
        return _render_root_help()

    if topic in COMMAND_HELP:
        return _render_command_help(COMMAND_HELP[topic])

    if topic in SECTION_HELP:
        return _render_section_help(SECTION_HELP[topic])

    available_topics = sorted(set(COMMAND_HELP) | set(SECTION_HELP))
    available = ", ".join(available_topics)
    raise ValueError(f"Unknown help topic '{topic}'. Available topics: {available}")


def _render_root_help() -> str:
    lines = [
        "AzureFox Help",
        "",
        "Operator-first Azure situational awareness with flat commands and scoped help.",
        "",
        "Usage:",
        "  azurefox help",
        "  azurefox help <section>",
        "  azurefox help <command>",
        "  azurefox -h <section>",
        "  azurefox -h <command>",
        "",
        "Sections:",
    ]

    for section in SECTION_NAMES:
        topic = SECTION_HELP.get(section)
        summary = topic.summary if topic else "Reserved for future coverage."
        lines.append(f"  {section}: {summary}")

    lines.extend(["", "Commands:"])
    for spec in get_command_specs():
        summary = COMMAND_HELP[spec.name].summary
        lines.append(f"  {spec.name}: {summary}")

    lines.extend(
        [
            "",
            "Notes:",
            "  - Command help includes ATT&CK cloud leads to guide investigation.",
            "  - ATT&CK references are investigative context, not proof that a technique occurred.",
        ]
    )
    return "\n".join(lines)


def _render_section_help(topic: SectionHelpTopic) -> str:
    commands = [spec.name for spec in get_command_specs(topic.name)]
    lines = [
        f"AzureFox Help :: {topic.name}",
        "",
        topic.summary,
        "",
        f"Operator goal: {topic.operator_goal}",
        "",
        "Implemented commands:",
    ]

    if commands:
        for command in commands:
            lines.append(f"  {command}: {COMMAND_HELP[command].summary}")
    else:
        lines.append("  none yet")

    lines.extend(
        [
            "",
            "ATT&CK cloud lenses:",
            *_render_attack_leads(topic.attack_lenses),
            "",
            "Examples:",
            f"  azurefox all-checks --section {topic.name}",
            f"  azurefox help {topic.name}",
        ]
    )
    return "\n".join(lines)


def _render_command_help(topic: CommandHelpTopic) -> str:
    lines = [
        f"AzureFox Help :: {topic.name}",
        "",
        topic.summary,
        "",
        f"Section: {topic.section}",
        f"Offensive question: {topic.offensive_question}",
        f"CloudFox frame: {topic.cloudfox_frame}",
        "",
        "Output highlights:",
    ]
    for item in topic.output_highlights:
        lines.append(f"  {item}")

    lines.extend(
        [
            "",
            "ATT&CK cloud leads:",
            *_render_attack_leads(topic.attack_leads),
            "",
            "Example:",
            f"  {topic.example}",
            "",
            "Note: ATT&CK references are leads to investigate, not proof of observed behavior.",
        ]
    )
    return "\n".join(lines)


def _render_attack_leads(leads: tuple[AttackLead, ...]) -> list[str]:
    return [f"  {lead.tactic}: {lead.technique}" for lead in leads]
