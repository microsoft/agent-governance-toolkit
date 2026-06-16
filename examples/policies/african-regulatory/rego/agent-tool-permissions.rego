package agt_policies_agent.tool_permissions

import rego.v1

# Tool Permission Controls
# Universal AI agent safety control — defines which tools an agent may call.
# Deployer configures allowed, denied, and restricted (require approval) lists.
#
# Regulatory alignment:
#   OWASP Agentic AI Top 10 — LLM08 Excessive Agency
#   NIST AI RMF — GOVERN 1.3, MANAGE 1.3
#   Microsoft AGT — Tool Use Safety pillar
#
# Config (override via data.config.tool_permissions.*):
#   allowed    — set of tool names; non-empty = allowlist mode (deny anything not listed)
#   denied     — set of tool names explicitly blocked regardless of allowed list
#   restricted — set of tool names requiring human approval before execution
#
# Logic:
#   denied list   → always deny
#   not in allowed (when allowed is non-empty) → deny
#   restricted list (and not denied) → escalate
#   everything else → allow

_default_restricted := {
	"delete_record",
	"bulk_delete",
	"drop_table",
	"truncate_table",
	"send_email",
	"send_sms",
	"send_bulk_email",
	"execute_code",
	"shell_exec",
	"file_write",
	"file_delete",
	"deploy",
	"modify_permissions",
	"grant_admin",
	"revoke_access",
}

_allowed_tools := s if {
	s := data.config.tool_permissions.allowed
} else := set()

_denied_tools := s if {
	s := data.config.tool_permissions.denied
} else := set()

_restricted_tools := s if {
	s := data.config.tool_permissions.restricted
} else := _default_restricted

# Allowlist mode is active when the allowed set is non-empty
_allowlist_active if {
	count(_allowed_tools) > 0
}

# ── Deny: explicitly blocked ──────────────────────────────────────────

deny contains msg if {
	input.action in _denied_tools
	msg := sprintf("Tool permission denied: '%v' is on the denied list — action blocked.", [input.action])
}

# ── Deny: not in allowlist (when allowlist mode is active) ────────────

deny contains msg if {
	_allowlist_active
	not input.action in _allowed_tools
	not input.action in _denied_tools
	msg := sprintf("Tool permission denied: '%v' is not in the allowed tools list.", [input.action])
}

# ── Escalate: restricted tool requires human approval ─────────────────

escalate contains msg if {
	input.action in _restricted_tools
	not input.action in _denied_tools
	msg := sprintf("Tool requires human approval: '%v' is a restricted tool — route to authorization queue.", [input.action])
}

# ── Decision: most restrictive wins ──────────────────────────────────

decision := "deny" if {
	count(deny) > 0
}

decision := "escalate" if {
	count(deny) == 0
	count(escalate) > 0
}

decision := "allow" if {
	count(deny) == 0
	count(escalate) == 0
}
