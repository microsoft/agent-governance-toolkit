# agt-policies
# Jurisdiction Router — maps customer/transaction country to applicable policy packs
#
# Purpose:
#   A single source of truth for "which policies apply to this agent action?"
#   Integrations query this file first, then evaluate only the returned packs.
#   Eliminates unnecessary policy evaluations and makes multi-country agents safe.
#
# Two policy layers:
#   1. Universal agent safety controls — apply to ALL agents regardless of country
#      (prompt_injection, pii_leakage, tool_permissions, human_approval, model_routing)
#   2. Jurisdiction-specific regulatory packs — apply based on customer_country
#      (cbn, bvn_nin, ndpa, nfiu for NG; kdpa for KE; popia for ZA)
#
# Input schema expected:
#   {
#     "context": {
#       "customer_country":       "NG",          # ISO 3166-1 alpha-2 (primary)
#       "transaction_countries":  ["NG", "ZA"]   # optional — for cross-border transactions
#     }
#   }
#
# Callers query:
#   data.agt_policies.router.applicable_policies  → set of pack IDs
#   data.agt_policies.router.resolved_queries     → set of OPA query paths to evaluate
#   data.agt_policies.router.is_supported_jurisdiction
#   data.agt_policies.router.unsupported_jurisdiction_warning

package agt_policies.router

import rego.v1

# ── Universal agent safety packs ─────────────────────────────────
# These apply to ALL agent actions regardless of country.
universal_policies := {
	"prompt_injection",
	"pii_leakage",
	"tool_permissions",
	"human_approval",
	"model_routing",
}

# ── Jurisdiction → regulatory policy pack mapping ─────────────────
# Add new countries here. Each entry is: "ISO_CODE": {set of pack IDs}
# Pack IDs must match keys in policy_queries below.
jurisdiction_policies := {
	"NG": {"cbn", "bvn_nin", "ndpa", "nfiu"},
	"KE": {"kdpa"},
	"ZA": {"popia"},
	"UG": {"uganda_dppa"},
	"TZ": {"tanzania_pdpa"},
	"ET": {"ethiopia_pdp"},
	"IN": {"dpdp", "certin", "rbi", "sebi", "aadhaar"},
}

# ── Policy pack → OPA query path ─────────────────────────────────
# Authoritative mapping of pack ID → query path used by integrations.
policy_queries := {
	"cbn": "data.agt_policies_nigeria.cbn.decision",
	"bvn_nin": "data.agt_policies_nigeria.bvn_nin.decision",
	"ndpa": "data.agt_policies_nigeria.ndpa.decision",
	"nfiu": "data.agt_policies_nigeria.nfiu.decision",
	"kdpa": "data.agt_policies_africa.kdpa.decision",
	"popia": "data.agt_policies_africa.popia.decision",
	"uganda_dppa": "data.agt_policies_africa.uganda_dppa.decision",
	"tanzania_pdpa": "data.agt_policies_africa.tanzania_pdpa.decision",
	"ethiopia_pdp": "data.agt_policies_africa.ethiopia_pdp.decision",
	"dpdp": "data.agt_policies_india.dpdp.decision",
	"certin": "data.agt_policies_india.certin.decision",
	"rbi": "data.agt_policies_india.rbi.decision",
	"sebi": "data.agt_policies_india.sebi.decision",
	"aadhaar": "data.agt_policies_india.aadhaar.decision",
	"prompt_injection": "data.agt_policies_agent.prompt_injection.decision",
	"pii_leakage": "data.agt_policies_agent.pii_leakage.decision",
	"tool_permissions": "data.agt_policies_agent.tool_permissions.decision",
	"human_approval": "data.agt_policies_agent.human_approval.decision",
	"model_routing": "data.agt_policies_agent.model_routing.decision",
}

# ── applicable_policies ───────────────────────────────────────────

# Universal layer: always included for every agent action
applicable_policies contains policy if {
	some policy in universal_policies
}

# Jurisdiction layer: customer's primary country
applicable_policies contains policy if {
	some policy in jurisdiction_policies[input.context.customer_country]
}

# Multi-jurisdiction: transaction spans multiple countries
# Example: NG customer, data routed to ZA → NDPA + POPIA both apply
applicable_policies contains policy if {
	some country in input.context.transaction_countries
	some policy in jurisdiction_policies[country]
}

# ── resolved_queries ──────────────────────────────────────────────
# The OPA query paths the caller should run — ready to use directly.
# Example: opa eval -d policies/rego/ -i input.json "data.agt_policies.router.resolved_queries"
resolved_queries contains query if {
	some pack in applicable_policies
	query := policy_queries[pack]
}

# ── Jurisdiction support checks ───────────────────────────────────

is_supported_jurisdiction if {
	input.context.customer_country in object.keys(jurisdiction_policies)
}

unsupported_jurisdiction_warning := msg if {
	not is_supported_jurisdiction
	input.context.customer_country
	msg := sprintf(
		"No regulatory pack for jurisdiction '%v' — universal agent safety controls still apply.",
		[input.context.customer_country],
	)
}
