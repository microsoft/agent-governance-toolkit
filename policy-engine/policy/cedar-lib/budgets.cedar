// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// AGT stock budget gate, Cedar mirror of `policy/lib/budgets.rego`. Each
// `forbid` policy reads a host-tracked counter from
// `context.envelope.budgets.*` per AGT-SNAPSHOT-1.0.md section 1 and forbids
// the action when the counter reaches the threshold declared on the resource
// entity. The host loads thresholds via the Cedar policy's `entities_path`
// field (D3.1) on entities matching the resource UID built by D3.2.
//
// The Cedar `@id` annotation becomes the AGT deny reason because the cedar
// dispatcher returns `{decision: "deny", reason: <first policy id that
// contributed>}` per D3.3.
//
// Cedar limit. Cedar long values only cover integer budgets. The
// `elapsed_seconds` and `cost_usd` thresholds, which are floats in the AGT
// snapshot, are not modelled here. Authors who need float budget gates
// stay on the Rego library `agt.budgets.max_cost_exceeded` and
// `agt.budgets.timeout_exceeded`.

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
