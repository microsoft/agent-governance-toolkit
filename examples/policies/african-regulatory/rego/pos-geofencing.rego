# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt_policies_nigeria.pos_geofencing

import rego.v1

import data.agt_policies.acs

pos_actions := {
	"pos_transaction",
	"pos_payment",
	"pos_charge",
	"terminal_transaction",
	"tap_pay",
	"swipe_card",
}

registration_actions := {
	"update_terminal_location",
	"register_terminal",
	"reassign_terminal",
	"transfer_terminal",
	"deactivate_terminal",
	"activate_terminal",
}

deny contains msg if {
	input.action in pos_actions
	object.get(input.context, "location_verified", false) != true
	msg := "CBN POS Geo-Fencing: location must be verified before a POS action"
}

deny contains msg if {
	regex.match(`(?i)(terminal|pos).{0,60}(outside|beyond|not\s+in|mismatch|wrong).{0,40}(zone|region|location|registered\s+area|geo.?fence)`, input.output)
	msg := "CBN POS Geo-Fencing: terminal location does not match its registered zone"
}

deny contains msg if {
	regex.match(`(?i)(bypass.{0,30}(geo.?fence|location\s+check|geo.?zone)|disable.{0,30}(location\s+verification|geo.?compliance)|skip.{0,20}(location|geo)\s+(check|verify|validation))`, input.output)
	msg := "CBN POS Geo-Fencing: location verification cannot be bypassed"
}

escalate contains msg if {
	input.action in registration_actions
	msg := "CBN Agent Banking: terminal registration changes require human approval"
}

escalate contains msg if {
	regex.match(`(?i)(pos|terminal|point.of.sale).{0,60}(₦|NGN)\s*[3-9][0-9]{2},?[0-9]{3}`, input.output)
	msg := "CBN Agent Banking: high-value POS transaction requires human approval"
}

audit contains msg if {
	regex.match(`^(pos_|terminal_|merchant_).*`, input.action)
	msg := "CBN POS Audit: terminal action recorded"
}

decision := "deny" if count(deny) > 0

decision := "escalate" if {
	count(deny) == 0
	count(escalate) > 0
}

decision := "audit" if {
	count(deny) == 0
	count(escalate) == 0
	count(audit) > 0
}

decision := "allow" if {
	count(deny) == 0
	count(escalate) == 0
	count(audit) == 0
}

acs_input_result := result if {
	legacy := acs.legacy_input(input, "input")
	denials := deny with input as legacy
	escalations := escalate with input as legacy
	audits := audit with input as legacy
	result := acs.normalize(denials, escalations, audits)
}

acs_pre_tool_call_result := result if {
	legacy := acs.legacy_input(input, "pre_tool_call")
	denials := deny with input as legacy
	escalations := escalate with input as legacy
	audits := audit with input as legacy
	result := acs.normalize(denials, escalations, audits)
}

acs_output_result := result if {
	legacy := acs.legacy_input(input, "output")
	denials := deny with input as legacy
	escalations := escalate with input as legacy
	audits := audit with input as legacy
	result := acs.normalize(denials, escalations, audits)
}
