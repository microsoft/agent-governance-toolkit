---
description: Check text against AGT prompt-injection, context-poisoning, and MCP threat detectors.
argument-hint: [text]
allowed-tools: mcp__agt_governance__agt_policy_check_text
---

If `$ARGUMENTS` is empty, tell the user to pass text to inspect.

Otherwise, call `mcp__agt_governance__agt_policy_check_text` exactly once with:

```json
{"text":"$ARGUMENTS"}
```

Print the JSON result verbatim. Do not summarize or add commentary.
