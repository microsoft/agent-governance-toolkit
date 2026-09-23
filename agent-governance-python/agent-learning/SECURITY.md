# Security

This package is part of the [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit).

Do not report security vulnerabilities through public GitHub issues. Follow the
[repository security policy](../../SECURITY.md) or Microsoft's guidance at
`https://aka.ms/SECURITY.md`.

## Integration defaults

- Policy evaluator failures are denied by default (`fail_closed=True`).
- Denied actions are captured without executing or persisting a tool result.
- Raw prompts, tool arguments, credentials, and backend responses are excluded
  from governance audit events and dashboard projections.
- Candidate policies remain inactive through validation and canary. Production
  persists signed state and approval audit before local activation; callback
  rejection restores the prior active policy.
- Production requires a configured audit sink and run-backed candidate storage;
  missing durable infrastructure prevents both activation and callback execution.
- Bayesian decision episodes never contribute behavior-policy propensities to
  REINFORCE updates.
- Decision certificates, policy candidates, and promotion receipts are bound by
  HMAC-SHA256. Durable or multi-process deployments must provide the same
  secret-backed `provenance_key` of at least 32 bytes to capture, learning, and
  promotion. The default key is ephemeral and process-local.

Agent Learning `0.8.0` does not redact `user_input`, `system_message`, or
`conversation_history` before episode storage. Minimize or redact those fields
before capture and protect the learning store with appropriate access,
encryption, and retention controls. HMAC provenance detects artifact mutation;
it does not isolate mutually untrusted code running in the same Python process.
