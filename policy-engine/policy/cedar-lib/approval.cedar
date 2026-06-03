// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// AGT stock approval helpers, Cedar mirror of `policy/lib/approval.rego`.
// The Rego library produces `escalate` verdicts per
// SPECIFICATION.md §13.1. The host approval path
// (section 17.1) resolves them through the resolver declared in the
// `approval` manifest section (section D5). Cedar has no native
// `escalate` decision, so this library emits the AGT `escalate` verdict
// through the cedar advice channel per D3.3.
//
// Trigger. The policy fires when either the resource entity carries a
// non empty `approvers` attribute and the host has not yet annotated
// the policy input with an approval grant, or when the host annotator
// places `context.annotations.approval.required` and sets it to `true`.
// The first form lets the manifest declare a static approver list per
// resource. The second form lets a host annotator decide at runtime
// whether approval is required based on snapshot signals not visible to
// Cedar.
//
// Cedar limit. The cedar advice `reason` field is fixed in the
// `@advice` annotation and cannot reference snapshot values. Authors
// who need a per request escalation reason or message stay on the Rego
// library `data.agt.approval` which composes the reason string from
// the snapshot via `sprintf`.

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
