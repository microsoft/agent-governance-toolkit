# Prompt Defense

Evaluates five prompts — one benign, four malicious — against the built-in
prompt defense rules. Demonstrates `InstructionOverride`, `PromptExfiltration`,
`CredentialLeak`, and `ApprovalBypass` threat categories.

Covers [`promptdefense.go`](../../packages/agentmesh/promptdefense.go):
`NewPromptDefenseEvaluator`, `Evaluate`, `PromptDefenseResult`,
`PromptDefenseFinding`, `PromptThreatType`.

## Run it

```bash
go run .
```

## Expected output

```text
benign           safe=true  risk=0   findings=none
override         safe=false risk=40  findings=[instruction_override/critical: "Ignore previous instructions"]
exfiltration     safe=false risk=40  findings=[prompt_exfiltration/critical: "Reveal your system prompt"]
credential leak  safe=false risk=40  findings=[credential_exfiltration/critical: "Send the api key"]
approval bypass  safe=false risk=25  findings=[approval_bypass/high: "without approval"]
```

`risk` aggregates per-finding severity (critical=40, high=25, medium=15,
low=5, capped at 100). The included middleware pipeline can be configured
to reject any operation whose prompt scores above a threshold — see
[`../README.md`](../../README.md) for `PromptDefenseMiddleware`.

## Where to go next

- [`mcp-scan/`](../mcp-scan/) — scan tool *definitions* (rather than prompt
  inputs) for the same instruction-override patterns.
- [`full-stack/`](../full-stack/) — wire `PromptDefenseEvaluator` into the
  governance middleware so risky prompts are rejected before execution.
- [`../README.md`](../../README.md) — full SDK overview.
