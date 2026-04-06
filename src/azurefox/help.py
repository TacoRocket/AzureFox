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
    implemented: bool = True
    deprecated: bool = False
    deprecation_note: str | None = None


@dataclass(frozen=True, slots=True)
class SectionHelpTopic:
    name: str
    summary: str
    operator_goal: str
    attack_lenses: tuple[AttackLead, ...]
    deprecation_note: str | None = None


COMMAND_HELP: dict[str, CommandHelpTopic] = {
    "whoami": CommandHelpTopic(
        name="whoami",
        section="identity",
        summary="Confirm the caller identity, token context, and active subscription scope.",
        offensive_question=(
            "Who am I in this tenant and what subscription scope am I operating in right now?"
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
            "What cloud infrastructure and service surface is visible in this subscription?"
        ),
        cloudfox_frame="Azure analogue to CloudFox inventory-first recon.",
        output_highlights=("resource_group_count", "resource_count", "top_resource_types"),
        attack_leads=(
            AttackLead("Discovery", "Cloud Infrastructure Discovery"),
            AttackLead("Discovery", "Cloud Service Discovery"),
        ),
        example="azurefox inventory --output table",
    ),
    "automation": CommandHelpTopic(
        name="automation",
        section="resource",
        summary=(
            "Summarize Azure Automation account identity, runbook, schedule, webhook, "
            "Hybrid Worker, and secure-asset posture."
        ),
        offensive_question=(
            "Which Azure Automation accounts create the strongest execution, persistence, "
            "or cross-boundary control paths for operator follow-up?"
        ),
        cloudfox_frame=(
            "Azure-native automation-account triage that stays at management-plane posture: "
            "managed identity, published runbooks, schedules, webhooks, Hybrid Runbook Worker "
            "presence, and secure-asset counts before any runbook-content or secret-value access."
        ),
        output_highlights=(
            "identity_type",
            "published_runbook_count",
            "schedule_count",
            "job_schedule_count",
            "webhook_count",
            "hybrid_worker_group_count",
            "credential_count",
            "encrypted_variable_count",
        ),
        attack_leads=(
            AttackLead("Execution", "Command and Scripting Interpreter"),
            AttackLead("Persistence", "Scheduled Task/Job"),
            AttackLead("Discovery", "Cloud Service Discovery"),
        ),
        example="azurefox automation --output table",
    ),
    "devops": CommandHelpTopic(
        name="devops",
        section="resource",
        summary=(
            "Surface Azure DevOps build definitions that already look like named Azure change "
            "paths and point to the next Azure review."
        ),
        offensive_question=(
            "Which Azure DevOps build definitions combine Azure-facing service connections, "
            "secret-bearing variable support, trigger posture, and the clearest next Azure "
            "follow-up that deserve operator review first?"
        ),
        cloudfox_frame=(
            "Azure-native deployment-path triage rather than generic DevOps inventory: named "
            "build definitions, Azure-facing service connections, safe secret-bearing variable "
            "metadata, Key Vault-backed group cues, trigger posture, and concise next-review "
            "hints without collecting secret values, repo content, or pipeline logs."
        ),
        output_highlights=(
            "project_name",
            "repository_name",
            "trigger_types",
            "azure_service_connection_names",
            "azure_service_connection_auth_schemes",
            "variable_group_names",
            "secret_variable_count",
            "secret_variable_names",
            "key_vault_group_names",
            "target_clues",
            "risk_cues",
        ),
        attack_leads=(
            AttackLead("Discovery", "Cloud Service Discovery"),
            AttackLead("Persistence", "Server Software Component"),
            AttackLead("Credential Access", "Unsecured Credentials"),
        ),
        example="azurefox --devops-organization contoso devops --output table",
    ),
    "app-services": CommandHelpTopic(
        name="app-services",
        section="compute",
        summary=(
            "Review App Service runtime, hostname, identity, and ingress cues that change "
            "follow-on paths."
        ),
        offensive_question=(
            "Which App Service apps expose the strongest runtime, identity, and ingress cues "
            "for operator follow-up?"
        ),
        cloudfox_frame=(
            "Azure-native App Service review that goes deeper than workload census by surfacing "
            "runtime stack, hostname, identity, and basic ingress and runtime exposure cues "
            "without duplicating app-setting or function-specific analysis."
        ),
        output_highlights=(
            "default_hostname",
            "runtime_stack",
            "workload_identity_type",
            "public_network_access",
            "https_only",
            "ftps_state",
        ),
        attack_leads=(
            AttackLead("Discovery", "Cloud Service Discovery"),
            AttackLead("Discovery", "Network Service Discovery"),
            AttackLead("Initial Access", "Exploit Public-Facing Application"),
        ),
        example="azurefox app-services --output table",
    ),
    "acr": CommandHelpTopic(
        name="acr",
        section="resource",
        summary=(
            "Summarize Azure Container Registry (ACR) login, auth, network, webhook, "
            "replication, and trust cues."
        ),
        offensive_question=(
            "Which container registries expose the strongest login, auth, network, "
            "automation, and trust cues for operator follow-up?"
        ),
        cloudfox_frame=(
            "Azure-native container registry census that stays at management-plane posture: "
            "login visibility, broad auth switches, network boundary signals, and a narrow "
            "amount of webhook, replication, and trust depth before any repository-content or "
            "data-plane analysis."
        ),
        output_highlights=(
            "login_server",
            "public_network_access",
            "network_rule_default_action",
            "admin_user_enabled",
            "anonymous_pull_enabled",
            "webhook_count",
            "enabled_webhook_count",
            "replication_count",
            "retention_policy_status",
            "trust_policy_status",
        ),
        attack_leads=(
            AttackLead("Discovery", "Cloud Service Discovery"),
            AttackLead("Discovery", "Container and Resource Discovery"),
            AttackLead("Collection", "Data from Information Repositories"),
        ),
        example="azurefox acr --output table",
    ),
    "databases": CommandHelpTopic(
        name="databases",
        section="resource",
        summary=(
            "Summarize Azure SQL, PostgreSQL Flexible, and MySQL Flexible server endpoint, "
            "network posture, identity context, and visible user-database inventory."
        ),
        offensive_question=(
            "Which relational database servers expose the most interesting endpoint, network "
            "posture, and visible database inventory for operator follow-up?"
        ),
        cloudfox_frame=(
            "Azure-native relational database census across Azure SQL, PostgreSQL Flexible, and "
            "MySQL Flexible management-plane posture: endpoint visibility, public network stance, "
            "managed identity context, and visible database inventory before any data-plane "
            "analysis."
        ),
        output_highlights=(
            "engine",
            "fully_qualified_domain_name",
            "public_network_access",
            "minimal_tls_version",
            "high_availability_mode",
            "database_count",
            "user_database_names",
        ),
        attack_leads=(
            AttackLead("Discovery", "Cloud Service Discovery"),
            AttackLead("Collection", "Data from Information Repositories"),
            AttackLead("Initial Access", "Exploit Public-Facing Application"),
        ),
        example="azurefox databases --output table",
    ),
    "dns": CommandHelpTopic(
        name="dns",
        section="network",
        summary=(
            "Summarize public and private Domain Name System (DNS) zone inventory and "
            "namespace boundaries."
        ),
        offensive_question=(
            "Which DNS zones reveal public delegation or private VNet-linked namespace context "
            "worth operator follow-up first?"
        ),
        cloudfox_frame=(
            "Azure-native DNS census that stays at management-plane zone metadata: public "
            "delegation clues, private VNet-link counts, and visible record-set totals before "
            "deeper record-content or resolution analysis."
        ),
        output_highlights=(
            "zone_kind",
            "record_set_count",
            "name_servers",
            "linked_virtual_network_count",
            "registration_virtual_network_count",
            "private_endpoint_reference_count",
        ),
        attack_leads=(
            AttackLead("Discovery", "Cloud Service Discovery"),
            AttackLead("Discovery", "Network Service Discovery"),
            AttackLead("Collection", "Data from Information Repositories"),
        ),
        example="azurefox dns --output table",
    ),
    "application-gateway": CommandHelpTopic(
        name="application-gateway",
        section="network",
        summary=(
            "Summarize Azure Application Gateway shared-ingress posture, routing breadth, "
            "and visible Web Application Firewall (WAF) coverage."
        ),
        offensive_question=(
            "Which Application Gateways are the shared public front doors for several "
            "backend paths, and which look weak enough to review first?"
        ),
        cloudfox_frame=(
            "Azure-native ingress-tier triage: frontend exposure, listener and routing "
            "breadth, backend-pool depth, and visible WAF posture without collecting "
            "request content, certificates, or backend app data."
        ),
        output_highlights=(
            "public_frontend_count",
            "listener_count",
            "request_routing_rule_count",
            "backend_target_count",
            "waf_mode",
            "firewall_policy_id",
        ),
        attack_leads=(
            AttackLead("Discovery", "Cloud Service Discovery"),
            AttackLead("Discovery", "Network Service Discovery"),
            AttackLead("Initial Access", "Exploit Public-Facing Application"),
        ),
        example="azurefox application-gateway --output table",
    ),
    "functions": CommandHelpTopic(
        name="functions",
        section="compute",
        summary=(
            "Deepen Function App runtime, storage binding, identity, and deployment-posture "
            "visibility."
        ),
        offensive_question=(
            "Which Function Apps expose the most interesting runtime, identity, storage, and "
            "ingress posture for operator follow-up?"
        ),
        cloudfox_frame=(
            "Azure-native Function App review that goes deeper than workload census by surfacing "
            "Functions runtime, storage binding, package-deployment signals, hostname, and "
            "identity posture without duplicating raw app-setting output."
        ),
        output_highlights=(
            "default_hostname",
            "runtime_stack",
            "functions_extension_version",
            "azure_webjobs_storage_value_type",
            "run_from_package",
            "key_vault_reference_count",
        ),
        attack_leads=(
            AttackLead("Discovery", "Cloud Service Discovery"),
            AttackLead("Discovery", "Network Service Discovery"),
            AttackLead("Execution", "Serverless Execution"),
        ),
        example="azurefox functions --output table",
    ),
    "aks": CommandHelpTopic(
        name="aks",
        section="compute",
        summary=(
            "Summarize Azure Kubernetes Service (AKS) cluster endpoint, identity, auth posture, "
            "and Azure-native depth cues."
        ),
        offensive_question=(
            "Which AKS clusters expose the most interesting control-plane endpoint, identity, "
            "federation, addon, and Azure-side posture for operator follow-up?"
        ),
        cloudfox_frame=(
            "Azure-native AKS census that stays at management-plane cluster posture: API endpoint "
            "visibility, identity context, auth controls, and a small amount of Azure-native "
            "federation and addon posture before deeper Kubernetes analysis."
        ),
        output_highlights=(
            "kubernetes_version",
            "fqdn",
            "private_cluster_enabled",
            "cluster_identity_type",
            "azure_rbac_enabled",
            "network_plugin",
            "oidc_issuer_enabled",
            "workload_identity_enabled",
            "addon_names",
            "web_app_routing_enabled",
        ),
        attack_leads=(
            AttackLead("Discovery", "Cloud Service Discovery"),
            AttackLead("Discovery", "Network Service Discovery"),
            AttackLead("Discovery", "Container and Resource Discovery"),
        ),
        example="azurefox aks --output table",
    ),
    "api-mgmt": CommandHelpTopic(
        name="api-mgmt",
        section="resource",
        summary=(
            "Summarize Application Programming Interface (API) Management gateway, hostname, "
            "identity, and narrow service-depth posture."
        ),
        offensive_question=(
            "Which API Management services expose the most interesting gateway, subscription, "
            "backend, and secret posture for operator follow-up?"
        ),
        cloudfox_frame=(
            "Azure-native API Management census that surfaces gateway hostnames, identity "
            "context, service inventory, and a small amount of deeper subscription, backend, "
            "and named-value posture without turning into a raw APIM dump."
        ),
        output_highlights=(
            "gateway_hostnames",
            "public_network_access",
            "virtual_network_type",
            "api_count",
            "named_value_count",
            "api_subscription_required_count",
            "subscription_count",
            "active_subscription_count",
            "named_value_secret_count",
            "named_value_key_vault_count",
            "backend_hostnames",
        ),
        attack_leads=(
            AttackLead("Discovery", "Cloud Service Discovery"),
            AttackLead("Initial Access", "Exploit Public-Facing Application"),
            AttackLead("Collection", "Data from Information Repositories"),
        ),
        example="azurefox api-mgmt --output table",
    ),
    "arm-deployments": CommandHelpTopic(
        name="arm-deployments",
        section="config",
        summary=(
            "Review ARM deployment history for output exposure, linked content, and failed runs."
        ),
        offensive_question=(
            "Which ARM deployments reveal useful config context, linked templates, or output "
            "values worth operator review?"
        ),
        cloudfox_frame=(
            "Azure-native deployment-history triage focused on management-plane config exposure."
        ),
        output_highlights=(
            "scope_type",
            "provisioning_state",
            "outputs_count",
            "template_link",
            "summary",
        ),
        attack_leads=(
            AttackLead("Discovery", "Cloud Service Discovery"),
            AttackLead("Collection", "Data from Information Repositories"),
            AttackLead("Credential Access", "Unsecured Credentials"),
        ),
        example="azurefox arm-deployments --output table",
    ),
    "endpoints": CommandHelpTopic(
        name="endpoints",
        section="network",
        summary=(
            "Correlate public IPs and Azure-managed hostnames into an operator-first "
            "ingress triage view."
        ),
        offensive_question=(
            "Which IPs or hostnames should I triage first, and which assets do those ingress "
            "paths belong to?"
        ),
        cloudfox_frame=(
            "Azure-native reachable-surface census that joins VM public IPs with Azure-managed "
            "web workload hostnames before deeper port or service analysis."
        ),
        output_highlights=(
            "endpoint",
            "source_asset_name",
            "exposure_family",
            "ingress_path",
            "summary",
        ),
        attack_leads=(
            AttackLead("Discovery", "Network Service Discovery"),
            AttackLead("Initial Access", "Exploit Public-Facing Application"),
            AttackLead("Lateral Movement", "Remote Services: Direct Cloud VM Connections"),
        ),
        example="azurefox endpoints --output table",
    ),
    "network-effective": CommandHelpTopic(
        name="network-effective",
        section="network",
        summary=(
            "Summarize likely public-IP reachability by combining endpoint and NSG evidence."
        ),
        offensive_question=(
            "Which public-IP-backed assets look most worth investigating first once I combine "
            "visible endpoint and inbound-rule evidence?"
        ),
        cloudfox_frame=(
            "Azure-native reachability triage that stays cautious: it combines visible endpoint "
            "and NSG evidence to help prioritize follow-up, not to prove full effective exposure."
        ),
        output_highlights=(
            "effective_exposure",
            "internet_exposed_ports",
            "constrained_ports",
            "observed_paths",
        ),
        attack_leads=(
            AttackLead("Discovery", "Network Service Discovery"),
            AttackLead("Initial Access", "Exploit Public-Facing Application"),
            AttackLead("Lateral Movement", "Remote Services: Direct Cloud VM Connections"),
        ),
        example="azurefox network-effective --output table",
    ),
    "network-ports": CommandHelpTopic(
        name="network-ports",
        section="network",
        summary="Summarize likely inbound port exposure for NIC-backed public endpoints.",
        offensive_question=(
            "Which visible public endpoints also have NSG evidence that suggests inbound port "
            "reachability, and where does that allow appear to come from?"
        ),
        cloudfox_frame=(
            "Azure-native ingress triage that joins public endpoint evidence with visible NIC "
            "and subnet NSG allow rules, without claiming full effective reachability proof."
        ),
        output_highlights=(
            "asset_name",
            "endpoint",
            "protocol",
            "port",
            "allow_source_summary",
            "exposure_confidence",
        ),
        attack_leads=(
            AttackLead("Discovery", "Network Service Discovery"),
            AttackLead("Initial Access", "Exploit Public-Facing Application"),
            AttackLead("Lateral Movement", "Remote Services: Direct Cloud VM Connections"),
        ),
        example="azurefox network-ports --output table",
    ),
    "env-vars": CommandHelpTopic(
        name="env-vars",
        section="config",
        summary=(
            "Review App Service and Function App settings for plain-text secrets and Key Vault "
            "references, with clearer next-step follow-up."
        ),
        offensive_question=(
            "Which workload app settings expose plain-text secrets, high-signal config names, "
            "or Key Vault-backed configuration paths worth review first, and what command "
            "should I pivot to next?"
        ),
        cloudfox_frame=(
            "Azure-native config triage focused on workload environment variables exposed through "
            "management-plane app settings with concise hints toward credential, Key Vault, or "
            "identity follow-up."
        ),
        output_highlights=(
            "asset_kind",
            "workload_identity_type",
            "setting_name",
            "value_type",
            "looks_sensitive",
            "reference_target",
            "key_vault_reference_identity",
        ),
        attack_leads=(
            AttackLead("Credential Access", "Unsecured Credentials"),
            AttackLead("Discovery", "Cloud Service Discovery"),
            AttackLead("Collection", "Data from Information Repositories"),
        ),
        example="azurefox env-vars --output table",
    ),
    "tokens-credentials": CommandHelpTopic(
        name="tokens-credentials",
        section="secrets",
        summary=(
            "Correlate readable token and credential surfaces across workloads, app settings, "
            "and deployment history with clearer next-step follow-up."
        ),
        offensive_question=(
            "Which workloads can mint tokens or expose credential-bearing metadata paths worth "
            "operator follow-up first, and what should I pivot to next?"
        ),
        cloudfox_frame=(
            "Azure-native credential leverage review that combines workload identity, readable "
            "app settings, and deployment-history clues into one operator-first surface while "
            "still pointing to the next honest follow-up."
        ),
        output_highlights=(
            "surface_type",
            "access_path",
            "priority",
            "operator_signal",
            "findings",
        ),
        attack_leads=(
            AttackLead("Credential Access", "Cloud Instance Metadata API"),
            AttackLead(
                "Credential Access",
                "Use Alternate Authentication Material: Application Access Token",
            ),
            AttackLead("Credential Access", "Unsecured Credentials"),
            AttackLead("Collection", "Data from Information Repositories"),
        ),
        example="azurefox tokens-credentials --output table",
    ),
    "rbac": CommandHelpTopic(
        name="rbac",
        section="identity",
        summary=(
            "Enumerate raw Role-Based Access Control (RBAC) assignments across the current "
            "subscription scope."
        ),
        offensive_question="Which principals have role assignments here, and at what scopes?",
        cloudfox_frame=(
            "Closest AzureFox equivalent to a raw cloud permission-assignment dump for Azure "
            "Role-Based Access Control (RBAC)."
        ),
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
            "Map principals visible through RBAC, caller context, and managed identity "
            "attachments."
        ),
        offensive_question=(
            "Which principals matter in this subscription, and how are "
            "they connected to roles and identities?"
        ),
        cloudfox_frame=(
            "Azure analogue to a CloudFox principal inventory with Azure-native identity edges."
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
            "scope_count",
            "operator_signal",
            "next_review",
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
            "Azure-native trust-edge triage across readable app registrations, service "
            "principals, federated credentials, ownership, and app-role assignments rather "
            "than delegated or admin consent grants. Fast mode is the default; full mode is "
            "the explicit slower tenant-wide application sweep that performs per-application "
            "owner and federated credential lookups."
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
        example="azurefox role-trusts --mode full --output table",
    ),
    "lighthouse": CommandHelpTopic(
        name="lighthouse",
        section="identity",
        summary=(
            "Review Azure Lighthouse delegated management scope, outside-tenant access shape, "
            "and stronger standing or eligible role cues."
        ),
        offensive_question=(
            "Which subscriptions or resource groups are delegated to another tenant through "
            "Azure Lighthouse, and which delegations deserve review first?"
        ),
        cloudfox_frame=(
            "Azure-native delegated resource management triage that keeps Azure Lighthouse "
            "separate from local RBAC and identity trust-edge review."
        ),
        output_highlights=(
            "scope_type",
            "managed_by_tenant_name",
            "strongest_role_name",
            "authorization_count",
            "eligible_authorization_count",
            "provisioning_state",
        ),
        attack_leads=(
            AttackLead("Discovery", "Cloud Service Discovery"),
            AttackLead("Initial Access", "Trusted Relationship"),
            AttackLead("Privilege Escalation", "Temporary Elevated Cloud Access"),
        ),
        example="azurefox lighthouse --output table",
    ),
    "cross-tenant": CommandHelpTopic(
        name="cross-tenant",
        section="identity",
        summary=(
            "Correlate outside-tenant trust, delegated management, and policy cues worth review "
            "first."
        ),
        offensive_question=(
            "Which visible outside-tenant relationships most change who can operate here or how an "
            "attacker could pivot into or across this environment?"
        ),
        cloudfox_frame=(
            "Azure-native cross-tenant trust triage that joins delegated management, external "
            "service-principal ownership, and tenant policy cues into one operator-first view."
        ),
        output_highlights=(
            "signal_type",
            "tenant_name",
            "scope",
            "posture",
            "attack_path",
            "priority",
            "summary",
        ),
        attack_leads=(
            AttackLead("Discovery", "Cloud Infrastructure Discovery"),
            AttackLead("Persistence", "External Remote Services"),
            AttackLead("Privilege Escalation", "Additional Cloud Roles"),
        ),
        example="azurefox cross-tenant --output table",
    ),
    "auth-policies": CommandHelpTopic(
        name="auth-policies",
        section="identity",
        summary=(
            "Surface tenant auth controls that widen guest, consent, app-creation, or sign-in "
            "abuse paths."
        ),
        offensive_question=(
            "Which tenant auth controls widen guest entry, app creation, consent abuse, "
            "or sign-in bypass opportunities from an existing foothold?"
        ),
        cloudfox_frame=(
            "Azure-native auth-control triage for tenant-wide identity policy surfaces "
            "such as security defaults, authorization policy, and Conditional Access. "
            "Unreadable policy surfaces stay explicit instead of being treated as a negative state."
        ),
        output_highlights=(
            "policy_type",
            "state",
            "controls",
            "summary",
            "findings",
            "issues",
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
        summary=(
            "Map workload-linked managed identities, their attachments, and visible "
            "privilege cues."
        ),
        offensive_question=(
            "Which workloads carry managed identities, and which of those identities show the "
            "strongest visible Azure-control cues?"
        ),
        cloudfox_frame="Azure-native identity-abuse lens centered on workload-attached identities.",
        output_highlights=("identity_type", "attached_to", "operator_signal", "next_review"),
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
        summary=(
            "Enumerate Key Vault assets and flag exposure, access-model weakness, or "
            "destructive leverage cues."
        ),
        offensive_question=(
            "Which Key Vaults are exposed, weakly protected, or most likely to change the "
            "attack path first?"
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
            "Correlate Storage and Key Vault trust surfaces into operator-first resource paths."
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
            "CloudFox-style storage triage with Azure storage-specific exposure, auth, and "
            "transport posture signals."
        ),
        output_highlights=(
            "public_access",
            "public_network_access",
            "network_default_action",
            "allow_shared_key_access",
            "minimum_tls_version",
            "https_traffic_only_enabled",
            "private_endpoint_enabled",
            "is_hns_enabled",
        ),
        attack_leads=(
            AttackLead("Discovery", "Cloud Storage Object Discovery"),
            AttackLead("Collection", "Data from Cloud Storage"),
        ),
        example="azurefox storage --output table",
    ),
    "snapshots-disks": CommandHelpTopic(
        name="snapshots-disks",
        section="compute",
        summary=(
            "Prioritize managed disks and snapshots that look easiest to review or copy offline."
        ),
        offensive_question=(
            "Which visible disks or snapshots should I review first because attachment state, "
            "sharing/export posture, or encryption context make them the highest-value targets?"
        ),
        cloudfox_frame=(
            "Azure-native disk and snapshot triage that keeps one operator-first row per "
            "disk-backed asset and sorts the highest-value offline-copy targets first."
        ),
        output_highlights=(
            "asset_kind",
            "attachment_state",
            "source_resource_name",
            "network_access_policy",
            "public_network_access",
            "max_shares",
            "disk_encryption_set_id",
            "summary",
        ),
        attack_leads=(
            AttackLead("Discovery", "Cloud Infrastructure Discovery"),
            AttackLead("Collection", "Data from Information Repositories"),
            AttackLead("Impact", "Data Destruction"),
        ),
        example="azurefox snapshots-disks --output table",
    ),
    "nics": CommandHelpTopic(
        name="nics",
        section="network",
        summary=(
            "Enumerate network interfaces (NICs) with attachment, IP, subnet, and NSG context."
        ),
        offensive_question=(
            "Which NICs anchor workload network placement, public IP references, and basic "
            "security-boundary context worth operator review first?"
        ),
        cloudfox_frame=(
            "Azure-native network-interface census that stays close to workload attachment and "
            "reachability context before deeper endpoint or port analysis."
        ),
        output_highlights=(
            "attached_asset_name",
            "private_ips",
            "public_ip_ids",
            "subnet_ids",
            "network_security_group_id",
        ),
        attack_leads=(
            AttackLead("Discovery", "Network Service Discovery"),
            AttackLead("Discovery", "Cloud Infrastructure Discovery"),
            AttackLead("Lateral Movement", "Remote Services: Direct Cloud VM Connections"),
        ),
        example="azurefox nics --output table",
    ),
    "workloads": CommandHelpTopic(
        name="workloads",
        section="compute",
        summary=(
            "Build a joined workload census across compute, web apps, identities, and endpoints."
        ),
        offensive_question=(
            "Which workloads are worth operator follow-up first once I join identity-bearing "
            "assets with their visible endpoint paths?"
        ),
        cloudfox_frame=(
            "Azure-native workload census that joins compute assets and web workloads with "
            "visible endpoint paths and managed identity context before deeper service-specific "
            "review."
        ),
        output_highlights=(
            "asset_kind",
            "identity_type",
            "endpoints",
            "ingress_paths",
            "summary",
        ),
        attack_leads=(
            AttackLead("Discovery", "Cloud Infrastructure Discovery"),
            AttackLead("Discovery", "Network Service Discovery"),
            AttackLead("Initial Access", "Exploit Public-Facing Application"),
            AttackLead("Lateral Movement", "Remote Services: Direct Cloud VM Connections"),
        ),
        example="azurefox workloads --output table",
    ),
    "vmss": CommandHelpTopic(
        name="vmss",
        section="compute",
        summary=(
            "Review Virtual Machine Scale Sets (VMSS) for identity, rollout, and frontend "
            "network posture."
        ),
        offensive_question=(
            "Which scale sets look most worth follow-up once I combine identity, fleet size, "
            "and visible frontend network cues?"
        ),
        cloudfox_frame=(
            "Azure-native scale-set triage that keeps VMSS posture first-class instead of "
            "burying it inside the broader compute census."
        ),
        output_highlights=(
            "sku_name",
            "instance_count",
            "orchestration_mode",
            "upgrade_mode",
            "public_ip_configuration_count",
            "subnet_ids",
        ),
        attack_leads=(
            AttackLead("Discovery", "Cloud Infrastructure Discovery"),
            AttackLead("Discovery", "Network Service Discovery"),
            AttackLead(
                "Credential Access",
                "Use Alternate Authentication Material: Application Access Token",
            ),
        ),
        example="azurefox vmss --output table",
    ),
    "vms": CommandHelpTopic(
        name="vms",
        section="compute",
        summary=("Summarize virtual machines (VMs) with network and identity context."),
        offensive_question=(
            "Which virtual machines are reachable, and which of them "
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
        summary=(
            "Deprecated broad recon sweep. Runs the implemented AzureFox commands in a stable "
            "broad sequence while narrower chains are still being wired in."
        ),
        offensive_question=(
            "What is the cleanest broad sweep I can run right now for this tenant or section "
            "when I want grouped results and can wait on a longer pass?"
        ),
        cloudfox_frame=(
            "Legacy AzureFox analogue to a CloudFox grouped recon pass. Planned chains are the "
            "replacement direction for narrower, higher-value grouped execution."
        ),
        output_highlights=("results", "run-summary.json", "section filtering"),
        attack_leads=(
            AttackLead("Discovery", "Cloud Account"),
            AttackLead("Discovery", "Cloud Infrastructure Discovery"),
            AttackLead("Discovery", "Permission Groups Discovery: Cloud Groups"),
        ),
        example="azurefox all-checks --section identity",
        deprecated=True,
        deprecation_note=(
            "Broad all-checks sweeps and section-filtered variants are being replaced by chains. "
            "Prefer flat commands directly for narrower runs until grouped chain families land."
        ),
    ),
    "chains": CommandHelpTopic(
        name="chains",
        section="orchestration",
        summary=(
            "Grouped family runner for higher-value preset paths, with credential-path "
            "available first."
        ),
        offensive_question=(
            "Which grouped Azure path should I run end to end when I want the value-added "
            "family answer instead of every underlying command on its own?"
        ),
        cloudfox_frame=(
            "AzureFox orchestration layer for targeted grouped runs that are meant to replace "
            "broad all-checks section sweeps with narrower, operator-first presets. Current "
            "state: credential-path is exposed now with conservative extraction-first joins; "
            "deployment-path and workload-identity-path remain planned."
        ),
        output_highlights=(
            "family selectors",
            "backing_commands",
            "target_resolution",
            "priority",
            "target_names",
            "target_visibility_issue",
            "next_review",
        ),
        attack_leads=(
            AttackLead("Discovery", "Cloud Service Discovery"),
            AttackLead("Credential Access", "Unsecured Credentials"),
            AttackLead("Persistence", "Server Software Component"),
        ),
        example="azurefox chains credential-path --output table",
    ),
}


SECTION_HELP: dict[str, SectionHelpTopic] = {
    "identity": SectionHelpTopic(
        name="identity",
        summary=(
            "Identity and privilege context for Azure principals, roles, and workload identities."
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
        deprecation_note=(
            "The broad `all-checks --section identity` sweep is deprecated and will be replaced by "
            "chains plus flat commands. Use the listed commands directly for now."
        ),
    ),
    "core": SectionHelpTopic(
        name="core",
        summary="Tenant-wide recon primitives that anchor the rest of the command set.",
        operator_goal="Establish account context and visible resource surface quickly.",
        attack_lenses=(
            AttackLead("Discovery", "Cloud Infrastructure Discovery"),
            AttackLead("Discovery", "Cloud Service Discovery"),
        ),
        deprecation_note=(
            "The broad `all-checks --section core` sweep is deprecated and will be replaced by "
            "chains plus flat commands. Use the listed commands directly for now."
        ),
    ),
    "config": SectionHelpTopic(
        name="config",
        summary=(
            "Deployment and workload configuration surfaces that expose useful operator context."
        ),
        operator_goal=(
            "Find deployment artifacts, workload settings, linked content, and surfaced outputs "
            "that reveal how the environment is wired together."
        ),
        attack_lenses=(
            AttackLead("Discovery", "Cloud Service Discovery"),
            AttackLead("Collection", "Data from Information Repositories"),
            AttackLead("Credential Access", "Unsecured Credentials"),
        ),
        deprecation_note=(
            "The broad `all-checks --section config` sweep is deprecated and will be replaced by "
            "chains plus flat commands. Use the listed commands directly for now."
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
        deprecation_note=(
            "The broad `all-checks --section storage` sweep is deprecated and will be replaced by "
            "chains plus flat commands. Use the listed commands directly for now."
        ),
    ),
    "secrets": SectionHelpTopic(
        name="secrets",
        summary=(
            "Secret, token, and credential surfaces that matter during Azure operator follow-up."
        ),
        operator_goal=(
            "Find secret-management surfaces, token minting paths, and credential-bearing "
            "metadata worth deeper follow-up."
        ),
        attack_lenses=(
            AttackLead("Discovery", "Cloud Service Discovery"),
            AttackLead("Collection", "Data from Information Repositories"),
            AttackLead("Credential Access", "Cloud Instance Metadata API"),
            AttackLead(
                "Credential Access",
                "Steal or Forge Authentication Certificates",
            ),
        ),
        deprecation_note=(
            "The broad `all-checks --section secrets` sweep is deprecated and will be replaced by "
            "chains plus flat commands. Use the listed commands directly for now."
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
        deprecation_note=(
            "The broad `all-checks --section resource` sweep is deprecated and will be replaced by "
            "chains plus flat commands. Use the listed commands directly for now."
        ),
    ),
    "compute": SectionHelpTopic(
        name="compute",
        summary="Compute reachability, workload identity context, and host-oriented pivot leads.",
        operator_goal=(
            "Find reachable workloads and identity-bearing hosts worth deeper access review."
        ),
        attack_lenses=(
            AttackLead("Discovery", "Cloud Infrastructure Discovery"),
            AttackLead("Lateral Movement", "Remote Services: Direct Cloud VM Connections"),
        ),
        deprecation_note=(
            "The broad `all-checks --section compute` sweep is deprecated and will be replaced by "
            "chains plus flat commands. Use the listed commands directly for now."
        ),
    ),
    "network": SectionHelpTopic(
        name="network",
        summary="Network attachment, namespace, and exposure context for Azure workloads.",
        operator_goal=(
            "Find the interfaces, namespaces, placements, and boundary references that shape "
            "ingress and lateral movement follow-up."
        ),
        attack_lenses=(
            AttackLead("Discovery", "Network Service Discovery"),
            AttackLead("Lateral Movement", "Remote Services: Direct Cloud VM Connections"),
        ),
        deprecation_note=(
            "The broad `all-checks --section network` sweep is deprecated and will be replaced by "
            "chains plus flat commands. Use the listed commands directly for now."
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
        deprecation_note=(
            "The broad `all-checks --section ai` sweep is deprecated and will be replaced by "
            "chains plus flat commands if AI coverage lands later."
        ),
    ),
}


def help_topic_names() -> set[str]:
    return set(COMMAND_HELP) | set(SECTION_HELP)


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
    command_names = [spec.name for spec in get_command_specs()]
    for name, topic in COMMAND_HELP.items():
        if topic.implemented and name not in command_names:
            command_names.append(name)
    planned_command_names = [name for name, topic in COMMAND_HELP.items() if not topic.implemented]

    lines = [
        "AzureFox Help",
        "",
        "Attack-path-focused Azure recon with flat commands and scoped help.",
        "",
        "Usage:",
        "  azurefox help",
        "  azurefox help <section>",
        "  azurefox help <command>",
        "  azurefox -h <section>",
        "  azurefox -h <command>",
        "  azurefox <command> --help",
        "",
        "Sections:",
    ]

    for section in SECTION_NAMES:
        topic = SECTION_HELP.get(section)
        summary = topic.summary if topic else "Reserved for future coverage."
        lines.append(f"  {section}: {summary}")

    lines.extend(["", "Commands:"])
    for name in command_names:
        summary = COMMAND_HELP[name].summary
        if COMMAND_HELP[name].deprecated:
            summary = f"{summary} [deprecated]"
        lines.append(f"  {name}: {summary}")

    if planned_command_names:
        lines.extend(["", "Planned grouped commands:"])
        for name in planned_command_names:
            summary = COMMAND_HELP[name].summary
            lines.append(f"  {name}: {summary}")

    lines.extend(
        [
            "",
            "Notes:",
            (
            "  - Shared flags such as --tenant, --subscription, --output, and --outdir "
            "work before or after the command."
        ),
        "  - Command help includes ATT&CK cloud leads to guide investigation.",
        (
            "  - Grouped command help stays visible even while additional chain families are "
            "still landing."
        ),
        "  - all-checks is deprecated and is being replaced by narrower chains plus flat commands.",
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
    ]

    if topic.deprecation_note:
        lines.extend(["", f"Deprecation: {topic.deprecation_note}"])

    lines.extend(["", "Implemented commands:"])

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
            "  # deprecated broad sweep",
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
        (
            "Status: planned grouped surface; public execution is not exposed yet."
            if not topic.implemented
            else (
                "Status: implemented command (deprecated)."
                if topic.deprecated
                else "Status: implemented command."
            )
        ),
        f"Section: {topic.section}",
        f"Offensive question: {topic.offensive_question}",
        f"CloudFox frame: {topic.cloudfox_frame}",
        "",
        "Output highlights:",
    ]
    for item in topic.output_highlights:
        lines.append(f"  {item}")

    if topic.deprecated and topic.deprecation_note:
        lines.extend(["", f"Deprecation: {topic.deprecation_note}"])

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
