// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// AGT default Cedar policy. Cedar mirror of `policy/lib/agt_default.rego`.
// Hosts that do not author Cedar of their own bind their manifest's
// `cedar` policy to this file. The policy composes every other AGT stock
// Cedar gate (`budgets.cedar`, `patterns.cedar`, `content_hash.cedar`,
// `egress.cedar`, `ifc.cedar`, `confidence.cedar`, `drift.cedar`,
// `redact.cedar`, `approval.cedar`) and adds a baseline permit so the
// dispatcher returns allow on the green path. Cedar's explicit deny
// always wins over permit, so any forbid below takes precedence.
//
// The composed policy IDs are the deny reasons that surface on the AGT
// verdict per D3.3, matching the Rego library's verdict reasons.
//
// Tuning. The thresholds, allowlists, clearance closures, and content
// hashes are loaded as resource entity attributes through the policy
// `entities_path` (D3.1). The manifest author binds an entity store
// that maps the resource UIDs built by D3.2 (`Tool::"<name>"` or
// `PolicyTarget::"<kind>"`) to attribute records carrying the values.
// Attributes that are absent disable the corresponding gate, matching
// the Rego library's behaviour of treating missing config as "do not
// enforce".
//
// Cedar limit. The composer mirrors what each individual cedar gate
// can express. The Cedar mirrors of the Rego libraries are weaker than
// their Rego counterparts (no regex, no URL host extraction, no
// dynamic transform values, integer scoring only). Authors who hit a
// limit stay on the Rego library `data.agt.defaults` which composes
// the full strength Rego stack.

// ── budgets ──────────────────────────────────────────────────────────

@id("budget_tool_calls_exceeded")
forbid (
  principal,
  action,
  resource
) when {
  context has envelope &&
  context.envelope has budgets &&
  context.envelope.budgets has tool_call_count &&
  resource has max_tool_calls &&
  context.envelope.budgets.tool_call_count >= resource.max_tool_calls
};

@id("budget_tokens_exceeded")
forbid (
  principal,
  action,
  resource
) when {
  context has envelope &&
  context.envelope has budgets &&
  context.envelope.budgets has token_count &&
  resource has max_tokens &&
  context.envelope.budgets.token_count >= resource.max_tokens
};

// ── content_hash ─────────────────────────────────────────────────────

@id("tool_content_hash_mismatch")
forbid (
  principal,
  action,
  resource
) when {
  resource has content_hash &&
  context has tool_call &&
  context.tool_call has content_hash &&
  resource.content_hash != context.tool_call.content_hash
};

@id("tool_content_hash_mismatch_observed_missing")
forbid (
  principal,
  action,
  resource
) when {
  resource has content_hash &&
  context has tool_call &&
  !(context.tool_call has content_hash)
};

// ── egress ───────────────────────────────────────────────────────────

@id("egress_destination_not_allowed")
forbid (
  principal,
  action,
  resource
) when {
  resource has security_labels &&
  context has tool_call &&
  context.tool_call has args &&
  context.tool_call.args has host &&
  !(resource.security_labels.contains(context.tool_call.args.host))
};

@id("egress_destination_not_allowed_annotation")
forbid (
  principal,
  action,
  resource
) when {
  resource has security_labels &&
  context has annotations &&
  context.annotations has egress &&
  context.annotations.egress has destination &&
  !(resource.security_labels.contains(context.annotations.egress.destination))
};

// ── patterns ─────────────────────────────────────────────────────────

@id("pii_email_pattern_in_input")
forbid (
  principal,
  action,
  resource
) when {
  context has input &&
  context.input has body &&
  context.input.body like "*@*.*"
};

@id("pii_email_pattern_in_output")
forbid (
  principal,
  action,
  resource
) when {
  context has response &&
  context.response has content &&
  context.response.content like "*@*.*"
};

@id("pii_ssn_pattern_in_input")
forbid (
  principal,
  action,
  resource
) when {
  context has input &&
  context.input has body &&
  context.input.body like "*-*-*"
};

// ── confidence ───────────────────────────────────────────────────────

@id("confidence_below_threshold")
forbid (
  principal,
  action,
  resource
) when {
  resource has min_confidence &&
  context has annotations &&
  context.annotations has confidence &&
  context.annotations.confidence has score &&
  context.annotations.confidence.score < resource.min_confidence
};

// ── ifc ──────────────────────────────────────────────────────────────

@id("ifc_clearance_violation_input")
forbid (
  principal,
  action == Action::"input",
  resource
) when {
  resource has clearance_dominated_labels &&
  context has input &&
  context.input has ifc &&
  context.input.ifc has source_labels &&
  !(resource.clearance_dominated_labels.containsAll(context.input.ifc.source_labels))
};

@id("ifc_clearance_violation_output")
forbid (
  principal,
  action == Action::"output",
  resource
) when {
  resource has clearance_dominated_labels &&
  context has response &&
  context.response has ifc &&
  context.response.ifc has result_labels &&
  !(resource.clearance_dominated_labels.containsAll(context.response.ifc.result_labels))
};

// ── approval (escalate via advice) ───────────────────────────────────

@advice("{\"verdict\":\"escalate\",\"reason\":\"approval_required\"}")
@id("agt.approval.approver_required")
permit (
  principal,
  action,
  resource
) when {
  resource has approvers &&
  !(resource.approvers.isEmpty()) &&
  !(context has annotations &&
    context.annotations has approval &&
    context.annotations.approval has granted &&
    context.annotations.approval.granted == true)
};

@advice("{\"verdict\":\"escalate\",\"reason\":\"approval_required\"}")
@id("agt.approval.annotator_required")
permit (
  principal,
  action,
  resource
) when {
  context has annotations &&
  context.annotations has approval &&
  context.annotations.approval has required &&
  context.annotations.approval.required == true
};

// ── redact (transform via advice) ────────────────────────────────────

@advice("{\"verdict\":\"transform\",\"reason\":\"redaction_applied\",\"transform\":{\"path\":\"$policy_target.value\",\"value\":\"[REDACTED]\"}}")
@id("agt.redact.pii")
permit (
  principal,
  action,
  resource
) when {
  context has annotations &&
  context.annotations has pii_detected &&
  context.annotations.pii_detected == true
};

// ── drift (warn via advice) ──────────────────────────────────────────

@advice("{\"verdict\":\"warn\",\"reason\":\"drift_detected\"}")
@id("agt.drift.warn")
permit (
  principal,
  action,
  resource
) when {
  context has annotations &&
  context.annotations has drift_score &&
  resource has drift_threshold &&
  context.annotations.drift_score >= resource.drift_threshold
};

// ── baseline permit ──────────────────────────────────────────────────
//
// Cedar denies by default. This baseline permit allows any request that
// no forbid above matches. The advice channel is empty, so the
// dispatcher returns a plain allow verdict per D3.3.

@id("agt.defaults.allow")
permit (
  principal,
  action,
  resource
);
