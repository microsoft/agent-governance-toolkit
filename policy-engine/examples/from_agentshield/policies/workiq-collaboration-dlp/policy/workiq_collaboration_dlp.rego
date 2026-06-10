# Ported from AgentShield examples/policies/workiq-collaboration-dlp.yaml
#
# Snapshot contract: ACS is stateless, so all AgentShield taint and delegate
# variables are supplied by the host on each evaluation. Expected fields are
# snapshot.document_sensitivity, document_audience, email_read_this_turn,
# email_source_domains, slack_channel_members, teams_channel_members,
# sink_covers_document_audience, and recent_send_count. Missing sensitive
# sink-side fields fail closed for matching DLP gates. The task_adherence LLM
# guard is represented by the declared task_adherence annotator.
package agent_control_specification.workiq_collaboration_dlp

import rego.v1

default verdict := {"decision": "allow"}
default input_verdict := {"decision": "allow"}
default pre_tool_call_verdict := {"decision": "allow"}
default post_tool_call_verdict := {"decision": "allow"}
default output_verdict := {"decision": "allow"}

verdict := input_verdict if input.intervention_point == "input"
verdict := pre_tool_call_verdict if input.intervention_point == "pre_tool_call"
verdict := post_tool_call_verdict if input.intervention_point == "post_tool_call"
verdict := output_verdict if input.intervention_point == "output"

snapshot := object.get(input, "snapshot", {})
args := object.get(object.get(input, "policy_target", {}), "value", {})
input_text := object.get(object.get(input.policy_target, "value", {}), "text", "")
doc_sensitivity := object.get(snapshot, "document_sensitivity", "public")
email_read := object.get(snapshot, "email_read_this_turn", false)
recent_send_count := object.get(snapshot, "recent_send_count", 0)
sink_covers_document_audience := object.get(snapshot, "sink_covers_document_audience", false)
email_source_domains := object.get(snapshot, "email_source_domains", [])
slack_members := object.get(snapshot, "slack_channel_members", [])
teams_members := object.get(snapshot, "teams_channel_members", [])

input_verdict := {
	"decision": "deny",
	"reason": "jailbreak_regex",
	"message": "Jailbreak attempt detected.",
} if {
	input.intervention_point == "input"
	regex.match(`(?i)ignore.*(?:previous|all|prior).*(?:instructions|rules|guidelines)`, input_text)
}

pre_tool_call_verdict := {
	"decision": "deny",
	"reason": "restricted_document_to_slack",
	"message": "Restricted documents must not be posted to Slack.",
} if {
	input.tool.name == "slack_post_message"
	sensitivity_rank(doc_sensitivity) >= sensitivity_rank("restricted")
} else := {
	"decision": "deny",
	"reason": "restricted_document_to_teams",
	"message": "Restricted documents must not be posted to Teams.",
} if {
	input.tool.name == "teams_post_message"
	sensitivity_rank(doc_sensitivity) >= sensitivity_rank("restricted")
} else := {
	"decision": "deny",
	"reason": "restricted_document_to_email",
	"message": "Restricted documents must not be emailed.",
} if {
	input.tool.name == "outlook_send_email"
	sensitivity_rank(doc_sensitivity) >= sensitivity_rank("restricted")
} else := {
	"decision": "deny",
	"reason": "slack_rate_limit_exceeded",
	"message": "Rate limit exceeded for this Slack channel.",
} if {
	input.tool.name == "slack_post_message"
	recent_send_count >= 3
} else := {
	"decision": "deny",
	"reason": "teams_rate_limit_exceeded",
	"message": "Rate limit exceeded for this Teams channel.",
} if {
	input.tool.name == "teams_post_message"
	recent_send_count >= 3
} else := {
	"decision": "deny",
	"reason": "email_rate_limit_exceeded",
	"message": "Rate limit exceeded for this email recipient.",
} if {
	input.tool.name == "outlook_send_email"
	recent_send_count >= 5
} else := {
	"decision": "deny",
	"reason": "unlisted_sensitive_tool",
	"message": "Unlisted tools may not operate on confidential or restricted data.",
} if {
	is_unlisted_tool
	sensitivity_rank(doc_sensitivity) >= sensitivity_rank("confidential")
} else := {
	"decision": "escalate",
	"reason": "slack_audience_not_superset",
	"message": "Slack channel members are not a superset of the source document's authorized audience.",
} if {
	input.tool.name == "slack_post_message"
	sensitivity_rank(doc_sensitivity) >= sensitivity_rank("confidential")
	not sink_covers_document_audience
} else := {
	"decision": "escalate",
	"reason": "teams_audience_not_superset",
	"message": "Teams channel members are not a superset of the source document's authorized audience.",
} if {
	input.tool.name == "teams_post_message"
	sensitivity_rank(doc_sensitivity) >= sensitivity_rank("confidential")
	not sink_covers_document_audience
} else := {
	"decision": "escalate",
	"reason": "email_audience_not_superset",
	"message": "Recipient list is not a superset of the source document's authorized audience.",
} if {
	input.tool.name == "outlook_send_email"
	sensitivity_rank(doc_sensitivity) >= sensitivity_rank("confidential")
	not sink_covers_document_audience
} else := {
	"decision": "escalate",
	"reason": "slack_cross_domain_send",
	"message": "Slack channel contains members outside the source email domains.",
} if {
	input.tool.name == "slack_post_message"
	email_read
	not slack_all_members_in_email_domain
} else := {
	"decision": "escalate",
	"reason": "teams_cross_domain_send",
	"message": "Teams channel contains members outside the source email domains.",
} if {
	input.tool.name == "teams_post_message"
	email_read
	not teams_all_members_in_email_domain
} else := {
	"decision": "escalate",
	"reason": "email_cross_domain_send",
	"message": "Email recipients include addresses outside the source email domains.",
} if {
	input.tool.name == "outlook_send_email"
	email_read
	not email_recipients_all_in_source_domain
} else := {
	"decision": "warn",
	"reason": "task_adherence",
	"message": "Proposed tool call deviates from the workplace copilot objective.",
} if {
	object.get(object.get(input, "annotations", {}), "task_adherence", {}).deviates == true
}

post_tool_call_verdict := {
	"decision": "transform",
	"reason": "pii_redact_tool_output",
	"message": "PII detected in tool result.",
	"transform": {"path": "$policy_target.value", "value": replace(text, pii, "[PII REDACTED]")},
} if {
	text := object.get(object.get(input.policy_target, "value", {}), "value", "")
	matches := regex.find_n(`\b(\d{3}-\d{2}-\d{4}|\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4})\b`, text, 1)
	count(matches) > 0
	pii := matches[0]
}

output_verdict := {
	"decision": "transform",
	"reason": "pii_redaction",
	"message": "PII detected in agent output.",
	"transform": {"path": "$policy_target.text", "value": replace(text, pii, "[REDACTED]")},
} if {
	text := object.get(object.get(input.policy_target, "value", {}), "text", "")
	matches := regex.find_n(`\b(\d{3}-\d{2}-\d{4}|\d{16}|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b`, text, 1)
	count(matches) > 0
	pii := matches[0]
}

sensitivity_rank(label) := rank if {
	ranks := {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}
	rank := object.get(ranks, label, 3)
}

is_unlisted_tool if not input.tool.name in {"workiq_get_document", "workiq_search_documents", "workiq_list_sites", "outlook_read_message", "outlook_search_inbox", "outlook_send_email", "slack_post_message", "slack_list_channels", "teams_post_message", "teams_list_channels"}

slack_all_members_in_email_domain if {
	is_array(slack_members)
	is_array(email_source_domains)
	count(email_source_domains) > 0
	not member_outside_domains(slack_members)
}

teams_all_members_in_email_domain if {
	is_array(teams_members)
	is_array(email_source_domains)
	count(email_source_domains) > 0
	not member_outside_domains(teams_members)
}

email_recipients_all_in_source_domain if {
	to := object.get(args, "to", [])
	is_array(to)
	is_array(email_source_domains)
	count(email_source_domains) > 0
	not recipient_outside_domains(to)
}

member_outside_domains(members) if {
	some m in members
	not address_in_domains(m)
}

recipient_outside_domains(recipients) if {
	some r in recipients
	not address_in_domains(r)
}

address_in_domains(address) if {
	some d in email_source_domains
	endswith(lower(address), concat("", ["@", lower(d)]))
}
