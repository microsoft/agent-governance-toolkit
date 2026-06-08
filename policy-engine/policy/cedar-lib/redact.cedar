// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// AGT stock redaction transform, Cedar mirror of `policy/lib/redact.rego`.
// The Rego library performs in place regex substitution with
// `regex.replace` and surfaces the rewritten text in the AGT transform
// verdict per SPECIFICATION.md §14. Cedar annotations
// are static strings, so this Cedar mirror cannot compute the replacement
// from the snapshot. It only emits a fixed `transform` advice payload
// that wholesale replaces `$policy_target.value` with the literal
// `"[REDACTED]"`.
//
// Cedar limit. The Cedar mirror is single target single value only and
// produces only a wholesale replacement. The Rego library can apply a
// regex pattern substitution that preserves the surrounding text.
// Authors who need partial substitution or a computed replacement run
// an annotator that produces the rewritten text or stay on the Rego
// library `data.agt.redact`.
//
// Trigger. The policy fires when the host annotator places
// `context.annotations.pii_detected` and sets it to `true`. The annotator
// has classified the policy target as containing PII; the cedar advice
// then directs the cedar dispatcher to produce an AGT `transform`
// verdict per D3.3, and the runtime applies the wholesale replacement
// to the policy target before the action proceeds.
//
// This permit policy MUST be composed with at least one baseline
// permit, or it relies on Cedar's implicit deny when no PII annotation
// is present.

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
