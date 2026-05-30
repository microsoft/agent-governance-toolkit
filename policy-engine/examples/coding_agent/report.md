# ACS generator report: software_engineering_assistant_guardrails

## Assumptions

### Annotators
- `input_risk` (classifier) expected labels/outputs: none declared
- `shell_command_risk` (classifier) expected labels/outputs: none declared
- `write_path_risk` (classifier) expected labels/outputs: none declared
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

- No tool inventory was provided; rules reference tool names from the natural-language requirements.
- Tool-specific guardrails requested without inventory; manifest tools section omitted.
