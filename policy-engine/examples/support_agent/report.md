# ACS generator report: customer_support_guardrails

## Assumptions

### Annotators
- `input_risk` (classifier) expected labels/outputs: none declared
- `refund_risk` (classifier) expected labels/outputs: none declared
- `recipient_scope` (classifier) expected labels/outputs: none declared
- `pii_scan` (classifier) expected labels/outputs: none declared

### JSONPaths
- `input` policy_target `user_input` at `$.input`
- `pre_tool_call` policy_target `tool_args` at `$.tool_call.args`
  - tool name from `$.tool_call.name`
- `post_tool_call` policy_target `tool_result` at `$.tool_result`
  - tool name from `$.tool_call.name`
- `output` policy_target `assistant_output` at `$.output`

### Tools
- No tools emitted; none were both requested and present in the provided inventory.

## Not statically verified

- Classifier labels and scores match real annotator outputs.
- Policy intent fully captures the natural-language prompt.

## Warnings

- No tool inventory metadata was provided beyond tool names; rules are scoped only by declared tool names.
- Default allow behavior is implicit; no explicit catch-all allow rule is included.
- Requested tools missing from inventory and omitted: {'name': 'issue_refund'}, {'name': 'lookup_customer'}, {'name': 'send_email'}
- Tool-specific guardrails requested without inventory; manifest tools section omitted.
