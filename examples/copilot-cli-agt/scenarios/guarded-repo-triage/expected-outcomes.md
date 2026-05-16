# Expected Outcomes

## 1. `/agt status`

You should see:

- the active policy source
- the vendored or configured SDK source
- the prompt defense grade and minimum required grade
- the audit path and audit chain status

## 2. `prompts/prompt-injection.txt`

Expected behavior:

- AGT evaluates the prompt as `prompt.submit`
- the prompt is treated as suspicious
- the extension rewrites the prompt into a refusal/explanation flow instead of letting the original injection through
- an audit entry is written

## 3. `prompts/unsafe-bootstrap.txt`

Expected behavior:

- AGT evaluates the requested tool usage as `tool.powershell` or `tool.bash`
- command-pattern matching catches downloaded-script execution
- Copilot CLI receives a deny or review decision instead of silently proceeding
- an audit entry is written

## 4. `/agt check` against `tool-output/poisoned-web-content.txt`

Expected behavior:

- `ContextPoisoningDetector` finds prompt-injection style content
- `McpSecurityScanner` may also flag instruction-like patterns
- the returned JSON reports the findings and whether the content is suspicious

## 5. Advisory mode

If you flip the policy to advisory and reload:

- AGT should still detect issues
- but the extension should attach advisory context instead of hard-blocking where possible
