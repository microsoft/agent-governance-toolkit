# ACS generator report: web_research_agent_guardrails

## Assumptions

### Annotators
- `input_risk` (classifier) expected labels/outputs: none declared
- `url_scope` (classifier) expected labels/outputs: none declared
- `content_size` (classifier) expected labels/outputs: none declared
- `secret_scan` (classifier) expected labels/outputs: none declared

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

- No explicit unconditional allow rule emitted per instruction; unspecified cases are intended to pass through by default.
- The runnable Node integration adds concrete `http_fetch` and `post_webhook` tool metadata and binds annotators to intervention points so the SDK can collect the classifier values the Rego policy reads.
- Redaction effects in the runnable policy include concrete spans for secrets found by the host-side classifier pattern so the ACS runtime can apply transforms.
