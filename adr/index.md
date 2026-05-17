# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for the Agent Governance Toolkit.

ADRs are short documents that capture important architectural decisions made during the project's development. They provide context for why decisions were made, making it easier for new contributors to understand the codebase and reducing re-litigation of settled questions.

## Process

1. Copy `0000-template.md` to `NNNN-title.md` (use the next sequential number).
2. Fill in the Status, Context, Decision, and Consequences sections.
3. Submit a PR with the ADR. Discussion happens in the PR review.
4. Once merged, the ADR status moves to **Accepted**.

To propose changing a previous decision, create a new ADR that references the original and update the original's status to **Superseded**.

## Records

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-ed25519-agent-identity.md) | Ed25519 for agent identity | Accepted |
| [0002](0002-yaml-policy-format.md) | YAML-based policy engine format | Accepted |
| [0003](0003-delegation-chain-design.md) | Cryptographic delegation chains | Accepted |
| [0004](0004-privilege-ring-execution.md) | Privilege ring execution model | Accepted |
