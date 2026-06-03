# ACS generator report: medical_records_assistant_guardrails

## Assumptions

### Annotators
- `input_risk` (classifier) expected labels/outputs: none declared
- `access_scope` (classifier) expected labels/outputs: none declared
- `phi_scan` (classifier) expected labels/outputs: none declared

### JSONPaths
- `input` policy_target `user_input` at `$.input`
- `pre_tool_call` policy_target `tool_args` at `$.tool_call.args`
  - tool name from `$.tool_call.name`
- `post_model_call` policy_target `model_response` at `$.model_response`
- `post_tool_call` policy_target `tool_result` at `$.tool_result`
  - tool name from `$.tool_call.name`
- `output` policy_target `assistant_output` at `$.output`

### Tools
- No tools emitted; none were both requested and present in the provided inventory.

## Not statically verified

- Classifier labels and scores match real annotator outputs.
- Policy intent fully captures the natural-language prompt.

## Warnings

- Default allow behavior is implicit; no unconditional allow rule emitted per instruction.
- No tool inventory metadata beyond tool names was provided.
- Requested tools missing from inventory and omitted: {'name': 'fetch_record'}, {'name': 'export_data'}
- Tool-specific guardrails requested without inventory; manifest tools section omitted.
