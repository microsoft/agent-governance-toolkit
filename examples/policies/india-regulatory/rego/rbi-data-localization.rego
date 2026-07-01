# agt-policies-india - RBI Payment Localization / KYC / IT-Governance (Rego reference)
# Enforcing authority: Reserve Bank of India. Status: binding (FREE-AI advisory). NOT loaded at runtime. RE2.
#
# Input schema:
#   { "action": "store_payment_data_offshore",
#     "params": { "data_class": "payment_data", "storage_region": "US", "processed_abroad": true,
#                 "purge_within_hours": 72, "kyc_completed": false } }

package agt_policies_india.rbi

import rego.v1

_output_text := v if { is_string(input.output); v := input.output } else := ""

payment_classes := {"payment_data", "transaction_data", "card_data"}
onboarding_actions := {"onboard_customer", "open_account", "activate_customer"}
third_party_actions := {"route_to_third_party", "use_cloud_service", "invoke_external_ai"}

# 2018: payment system data stored only in India
deny contains msg if {
	input.params.data_class in payment_classes
	not input.params.storage_region == "IN"
	region := object.get(input.params, "storage_region", "unset")
	msg := sprintf("RBI 2018 (Storage of Payment System Data): payment data must be stored only in India, configured region: '%v'", [region])
}

# 2018: foreign-processed payment data purged and returned within 24h
deny contains msg if {
	input.params.data_class == "payment_data"
	input.params.processed_abroad == true
	input.params.purge_within_hours > 24
	msg := sprintf("RBI 2018: payment data processed abroad must be purged and returned to India within 24h, configured: %vh", [input.params.purge_within_hours])
}

# KYC MD 2016: KYC mandatory before onboarding
deny contains msg if {
	input.action in onboarding_actions
	not input.params.kyc_completed == true
	msg := "RBI Master Direction KYC 2016: customer due diligence (KYC) is mandatory before onboarding"
}

# Outsourcing/IT-Governance MDs 2023: third-party/cloud/AI data flows - escalate for due diligence
escalate contains msg if {
	input.action in third_party_actions
	msg := "RBI Master Directions Outsourcing of IT Services / IT Governance 2023: due diligence, audit rights, and data locality required for third-party/cloud/AI handling customer or payment data"
}

# FREE-AI 2025: ADVISORY only - audit, never deny
audit contains msg if {
	regex.match(`(?i)(ai|ml)\s+model.{0,30}(credit|loan|fraud|financial)\s+decision`, _output_text)
	msg := "ADVISORY (non-binding, RBI FREE-AI 2025): board-approved AI policy, AI incident reporting, and human oversight recommended for AI in financial services"
}

decision := "deny" if count(deny) > 0
decision := "escalate" if { count(deny) == 0; count(escalate) > 0 }
decision := "audit" if { count(deny) == 0; count(escalate) == 0; count(audit) > 0 }
decision := "allow" if { count(deny) == 0; count(escalate) == 0; count(audit) == 0 }
