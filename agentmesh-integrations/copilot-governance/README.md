# @agentmesh/copilot-governance

GitHub Copilot Extension that reviews agent code for governance gaps and validates policy YAML files — bringing the [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) directly into your IDE.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](../../LICENSE)
[![Part of Agent Governance Toolkit](https://img.shields.io/badge/agent--governance--toolkit-microsoft-blue)](https://github.com/microsoft/agent-governance-toolkit)

---

## What It Does

| Capability | Description |
|-----------|-------------|
| **Governance code review** | Scans agent code for missing policy checks, unguarded tool calls, and absent audit logging |
| **OWASP risk mapping** | Links each finding to the relevant [OWASP Agentic Top-10](https://genai.owasp.org/) risk |
| **Policy YAML validation** | Validates governance policy YAML files for correctness and completeness |
| **Middleware suggestions** | Recommends adding `@agentmesh/mastra` or `agent-os` governance middleware |

---

## Installation

### As a library

```bash
npm install @agentmesh/copilot-governance
```

### As a Copilot Extension server

```bash
npm install @agentmesh/copilot-governance
npx copilot-governance          # starts on port 3000
PORT=8080 npx copilot-governance
```

Deploy this server as a GitHub App with the agent endpoint pointing to
`https://your-host/agent`. See [GitHub Copilot Extensions docs](https://docs.github.com/en/copilot/building-copilot-extensions) for setup.

---

## Copilot Chat Commands

Once the extension is enabled in your GitHub Copilot settings, use it in
any Copilot Chat window:

### Review agent code

````
@governance review
```ts
// Paste your agent code here
const result = await myTool.execute({ query: userInput });
```
````

**Example output:**

```
❌ Governance review found 3 issue(s): 3 high.

### 🟠 No governance middleware detected
Rule: `missing-governance-middleware`

This file defines or executes agent tools but does not apply governance middleware...

**OWASP Agentic Top-10:** `AT07`, `AT08`
```

### Validate a policy YAML file

````
@governance validate
```yaml
policy:
  name: my-agent-policy
  version: "1.0"
  rules:
    rate_limit_per_minute: 60
    pii_fields: [ssn, email]
    blocked_patterns:
      - "(?i)ignore previous instructions"
    allowed_tools: [web-search, read-file]
  audit:
    enabled: true
    capture_data: false
```
````

### Show OWASP Agentic Top-10

```
@governance owasp
```

### Show help

```
@governance help
```

---

## Governance Checks

| Rule | Severity | OWASP |
|------|----------|-------|
| Missing governance middleware | High | AT07, AT08 |
| Unguarded direct tool execution | High | AT07, AT08 |
| No audit logging | High | AT09 |
| No PII redaction | Medium | AT06 |
| No trust verification for agent handoffs | Medium | AT07, AT08 |
| No tool allow-list/deny-list | Medium | AT08 |
| No prompt-injection input filters | Medium | AT01 |

---

## Programmatic Usage

```typescript
import { reviewCode, validatePolicy, handleAgentRequest } from "@agentmesh/copilot-governance";

// Review agent source code
const review = reviewCode(myAgentSource);
if (!review.passed) {
  console.log(review.summary);
  for (const finding of review.findings) {
    console.log(`[${finding.severity}] ${finding.title}`);
    console.log(`  OWASP: ${finding.owaspRisks.join(", ")}`);
  }
}

// Validate a policy object (parsed from YAML)
const validation = validatePolicy(parsedYaml);
if (!validation.valid) {
  for (const f of validation.findings) {
    console.log(`${f.field}: ${f.message}`);
  }
}

// Drive the Copilot agent stream
for await (const token of handleAgentRequest(copilotRequest)) {
  res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: token.content } }] })}\n\n`);
}
```

---

## Policy YAML Schema

```yaml
policy:
  name: string          # Required — policy name
  version: string       # Recommended — e.g. "1.0"
  rules:
    rate_limit_per_minute: integer   # Max tool calls/min per agent
    max_input_length: integer        # Max input size in characters
    pii_fields: [string]             # Fields to redact (ssn, email, ...)
    blocked_patterns: [string]       # Regex patterns to block in inputs
    allowed_tools: [string]          # Tool allow-list (empty = all allowed)
    blocked_tools: [string]          # Tool deny-list
  audit:
    enabled: boolean                 # Enable audit logging
    capture_data: boolean            # Include input/output in audit entries
```

---

## Architecture

```
GitHub Copilot Chat
       │  POST /agent
       ▼
┌──────────────────────────────┐
│  @agentmesh/copilot-governance│
│                              │
│  agent.ts ─────────────────► │  detectCommand()
│                ┌─────────────► │  reviewCode()       → reviewer.ts
│                │             │  validatePolicy()   → policy-validator.ts
│                │             │  OWASP catalogue    → owasp.ts
│                │             │
│  server.ts ────┘             │  HTTP /agent endpoint (SSE stream)
└──────────────────────────────┘
```

---

## Recommended Fixes

When the extension detects governance gaps, it suggests adding the appropriate toolkit:

**TypeScript/JavaScript agents:**
```bash
npm install @agentmesh/mastra
```

**Python agents:**
```bash
pip install agent-os-kernel
```

See the [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit) for the full documentation.

---

## Related

- [OWASP Agentic Top-10](https://genai.owasp.org/)
- [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
- [`@agentmesh/mastra`](../mastra-agentmesh/) — TypeScript governance middleware
- [GitHub Copilot Extensions docs](https://docs.github.com/en/copilot/building-copilot-extensions)

---

## License

MIT — same as the Agent Governance Toolkit.
