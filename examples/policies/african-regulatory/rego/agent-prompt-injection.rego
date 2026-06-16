package agt_policies_agent.prompt_injection

import rego.v1

# Prompt Injection Prevention
# Universal AI agent safety control — deployer-configurable.
#
# Regulatory alignment:
#   OWASP Agentic AI Top 10 — LLM01 Prompt Injection
#   NIST AI RMF — GOVERN 1.2, MANAGE 2.2
#   NDPA 2023 s.24 — processors must implement appropriate technical safeguards
#
# Config (override via data.config.prompt_injection.*):
#   patterns        — set of strings; if any appears in user input → deny
#   structural_indicators — set of strings; structural injection markers → escalate

_default_patterns := {
	"ignore previous instructions",
	"ignore all previous",
	"disregard your instructions",
	"disregard all previous",
	"forget your instructions",
	"forget previous instructions",
	"you are now",
	"act as if you are",
	"act as though you",
	"pretend you are",
	"pretend to be",
	"new instructions:",
	"override your",
	"jailbreak",
	"bypass your",
	"ignore your guidelines",
	"ignore your rules",
	"your new purpose",
	"your real instructions",
}

_default_structural := {
	"[inst]",
	"<|system|>",
	"###system",
	"---system---",
	"<system>",
	"</system>",
	"[system prompt]",
	"{{system}}",
}

_injection_patterns := p if {
	p := data.config.prompt_injection.patterns
} else := _default_patterns

_structural_indicators := p if {
	p := data.config.prompt_injection.structural_indicators
} else := _default_structural

# User-controlled text fields most likely to carry injection payloads
_user_text_fields := {
	"prompt", "message", "user_input", "query",
	"text", "input", "content", "instruction",
}

_user_texts contains v if {
	some field in _user_text_fields
	v := input.params[field]
	is_string(v)
}

# ── Deny: confirmed injection pattern ─────────────────────────────────

_has_injection_pattern if {
	some text in _user_texts
	some pattern in _injection_patterns
	contains(lower(text), pattern)
}

deny contains msg if {
	_has_injection_pattern
	msg := "Prompt injection detected: input contains known injection pattern — action blocked."
}

# ── Escalate: structural injection indicator ──────────────────────────

_has_structural_indicator if {
	some text in _user_texts
	some indicator in _structural_indicators
	contains(lower(text), indicator)
}

escalate contains msg if {
	_has_structural_indicator
	not _has_injection_pattern
	msg := "Potential prompt injection: structural injection marker detected — route to review."
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
