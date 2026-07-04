# agt-policies-uk - GB jurisdiction routing (OPA tests)
# Requires both uk-regulatory/rego and african-regulatory/rego on the OPA load path.
package agt_policies_uk.router_gb_test

import data.agt_policies.router as router
import rego.v1

gb_input := {"context": {"customer_country": "GB"}}

test_gb_is_supported_jurisdiction if {
	router.is_supported_jurisdiction with input as gb_input
}

test_gb_applicable_policies_include_uk_packs if {
	policies := router.applicable_policies with input as gb_input
	"uk_gdpr" in policies
	"ico_adm" in policies
	"fca_conduct" in policies
}

test_gb_applicable_policies_include_universal_controls if {
	policies := router.applicable_policies with input as gb_input
	"prompt_injection" in policies
	"pii_leakage" in policies
	"human_approval" in policies
}

test_gb_resolved_queries_include_uk_paths if {
	queries := router.resolved_queries with input as gb_input
	"data.agt_policies_uk.uk_gdpr.decision" in queries
	"data.agt_policies_uk.ico_adm.decision" in queries
	"data.agt_policies_uk.fca_conduct.decision" in queries
}

test_unsupported_jurisdiction_warning_absent_for_gb if {
	not router.unsupported_jurisdiction_warning with input as gb_input
}

test_unsupported_jurisdiction_warning_for_unknown_country if {
	msg := router.unsupported_jurisdiction_warning with input as {"context": {"customer_country": "XX"}}
	contains(msg, "No regulatory pack for jurisdiction 'XX'")
}
