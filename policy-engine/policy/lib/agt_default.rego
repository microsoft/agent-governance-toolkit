# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# AGT default policy. Hosts that do not author Rego of their own bind their
# manifest's `rego` policy to `data.agt.defaults.verdict`. The library
# imports every AGT stock helper and consults each one in priority order:
# IFC deny > confidence deny > budget deny > content_hash deny > egress
# deny > pattern deny > drift warn > allow. Configuration travels through
# the host-supplied `data.agt.defaults.config` document so a manifest only
# has to set thresholds, allowlists, and pattern lists in YAML without
# touching Rego. The M6 GovernancePolicy migration tool emits this exact
# binding for hosts coming from the legacy declarative policy.

package agt.defaults

import data.agt.approval
import data.agt.budgets
import data.agt.confidence
import data.agt.content_hash
import data.agt.drift
import data.agt.egress
import data.agt.ifc
import data.agt.patterns
import data.agt.redact
import rego.v1

# Host-supplied configuration lives at data.agt.defaults.config (loaded
# from a JSON or YAML data document or pushed by the SDK). Referencing
# it via the cfg helper avoids a self-recursive rule named `config` in
# this package.
cfg := value if {
	value := data.agt.defaults.config
	is_object(value)
} else := {}

# ---------------------------------------------------------------------------
# Per-class verdict shortcuts. Each is `undefined` (no verdict) when its
# configuration is absent or the rule it gates does not match.

ifc_verdict := value if {
	clearance := cfg.ifc.sink_clearance
	is_string(clearance)
	labels := ifc_labels
	value := ifc.verdict_propagating(clearance, labels)
}

ifc_labels := labels if {
	input.intervention_point == "output"
	labels := ifc.result_labels
} else := labels if {
	labels := ifc.source_labels
}

confidence_verdict := value if {
	threshold := cfg.confidence.min_score
	value := confidence.deny_if_low_confidence(threshold)
}

budgets_verdict := value if {
	thresholds := cfg.budgets
	is_object(thresholds)
	value := budgets.deny_if_budget_exceeded(thresholds)
}

content_hash_verdict := value if {
	cfg.content_hash.enforce == true
	value := content_hash.deny_if_mismatch
}

egress_verdict := value if {
	rules := cfg.egress
	is_object(rules)
	value := egress.deny_egress(rules)
}

pattern_verdict := value if {
	rules := cfg.patterns
	is_object(rules)
	pats := rules.patterns
	is_array(pats)
	text := pattern_text(rules)
	reason := pattern_reason(rules)
	value := patterns.deny_if_pattern(text, pats, reason)
}

pattern_text(rules) := value if {
	is_string(rules.text)
	value := rules.text
} else := value if {
	value := input.policy_target.value
	is_string(value)
} else := ""

pattern_reason(rules) := value if {
	is_string(rules.reason)
	value := rules.reason
} else := "pattern_blocked"

redact_verdict := value if {
	rules := cfg.redact
	is_object(rules)
	pats := rules.patterns
	is_array(pats)
	text := input.policy_target.value
	is_string(text)
	replacement := redact_replacement(rules)
	value := redact.redact_text(text, pats, replacement)
}

redact_replacement(rules) := value if {
	is_string(rules.replacement)
	value := rules.replacement
} else := redact.default_replacement

drift_verdict := value if {
	threshold := cfg.drift.warn_threshold
	value := drift.warn_if_drift(threshold)
}

approval_verdict := value if {
	required := cfg.approval.required
	required == true
	approvers := cfg.approval.approvers
	value := approval.escalate_if_approver_required(approvers)
}

# ---------------------------------------------------------------------------
# Final verdict. Highest-severity decision wins; transform short-circuits
# above warn but below deny, matching the AGT verdict severity (deny >
# escalate > transform > warn > allow). The order below encodes that
# ranking.

default verdict := {"decision": "allow"}

verdict := ifc_verdict if {
	ifc_verdict.decision == "deny"
}

else := confidence_verdict if {
	confidence_verdict.decision == "deny"
}

else := budgets_verdict if {
	budgets_verdict.decision == "deny"
}

else := content_hash_verdict if {
	content_hash_verdict.decision == "deny"
}

else := egress_verdict if {
	egress_verdict.decision == "deny"
}

else := pattern_verdict if {
	pattern_verdict.decision == "deny"
}

else := approval_verdict if {
	approval_verdict.decision == "escalate"
}

else := redact_verdict if {
	redact_verdict.decision == "transform"
}

else := drift_verdict if {
	drift_verdict.decision == "warn"
}

else := ifc_verdict if {
	ifc_verdict.decision == "allow"
	ifc_verdict.result_labels
}
