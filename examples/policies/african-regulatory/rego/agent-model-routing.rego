package agt_policies_agent.model_routing

import rego.v1

# Model Routing Controls
# Universal AI agent safety control — governs which AI models may process
# which types of tasks. Prevents sensitive workloads from being routed to
# unapproved, unverified, or insufficiently capable models.
# Deployer-configurable model lists and task type classifications.
#
# Regulatory alignment:
#   OWASP Agentic AI Top 10 — LLM03 Model Theft / LLM05 Supply Chain
#   NIST AI RMF — GOVERN 1.1, GOVERN 2.2
#   EU AI Act Art. 9 — risk management for high-risk AI
#   NDPA 2023 s.24 — appropriate technical measures for data processing
#
# Config (override via data.config.model_routing.*):
#   sensitive_task_types         — set of task_type values needing approved model
#   approved_sensitive_models    — models allowed on sensitive tasks
#   banned_models                — models blocked unconditionally
#   require_model_on_sensitive   — bool; if true, deny when no model specified for sensitive task

_default_sensitive_task_types := {
	"pii_processing",
	"financial_decision",
	"fraud_detection",
	"medical_advice",
	"legal_advice",
	"authentication",
	"credit_scoring",
	"kyc_review",
	"aml_screening",
}

_default_approved_sensitive_models := {
	"gpt-4o",
	"gpt-4-turbo",
	"claude-opus-4",
	"claude-opus-4-8",
	"claude-sonnet-4",
	"claude-sonnet-4-6",
	"gemini-ultra",
	"gemini-1.5-pro",
}

_default_banned_models := set()

_sensitive_task_types := s if {
	s := data.config.model_routing.sensitive_task_types
} else := _default_sensitive_task_types

_approved_sensitive_models := s if {
	s := data.config.model_routing.approved_sensitive_models
} else := _default_approved_sensitive_models

_banned_models := s if {
	s := data.config.model_routing.banned_models
} else := _default_banned_models

# ── Context helpers ───────────────────────────────────────────────────

_requested_model := v if {
	is_string(input.context.model)
	input.context.model != ""
	v := input.context.model
} else := ""

_task_type := v if {
	is_string(input.context.task_type)
	v := input.context.task_type
} else := "general"

# ── Helpers ───────────────────────────────────────────────────────────

_is_sensitive_task if {
	_task_type in _sensitive_task_types
}

_model_specified if {
	_requested_model != ""
}

_model_is_approved_for_sensitive if {
	_requested_model in _approved_sensitive_models
}

# ── Deny: banned model ────────────────────────────────────────────────

deny contains msg if {
	_requested_model in _banned_models
	msg := sprintf("Model routing denied: model '%v' is on the banned list.", [_requested_model])
}

# ── Deny: unapproved model on sensitive task ──────────────────────────

deny contains msg if {
	_is_sensitive_task
	_model_specified
	not _model_is_approved_for_sensitive
	not _requested_model in _banned_models
	msg := sprintf(
		"Model routing denied: model '%v' is not approved for sensitive task type '%v'.",
		[_requested_model, _task_type],
	)
}

# ── Escalate: sensitive task with no model specified ──────────────────

escalate contains msg if {
	_is_sensitive_task
	not _model_specified
	msg := sprintf(
		"Model routing: sensitive task type '%v' requires an explicitly approved model — none specified.",
		[_task_type],
	)
}

# ── Audit: sensitive task using approved model ────────────────────────

audit contains msg if {
	_is_sensitive_task
	_model_specified
	_model_is_approved_for_sensitive
	msg := sprintf(
		"Model routing audit: sensitive task '%v' processed by approved model '%v'.",
		[_task_type, _requested_model],
	)
}

# ── Decision: most restrictive wins ──────────────────────────────────

decision := "deny" if {
	count(deny) > 0
}

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
