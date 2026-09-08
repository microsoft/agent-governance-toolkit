## Related Issue
<!-- Link the issue this PR resolves, e.g. Fixes #123 or Closes #456. -->

> **If no related issue is linked above, you must complete "Problem & Solution", "Impact on Your Work", and "Alternatives Considered" below.**

## Problem & Solution
<!-- Required if no related issue is linked above. Provide both: -->
<!-- Problem: what is broken, missing, or needed today? -->
<!-- Solution: what does this PR change to address it? -->

## Impact on Your Work
<!-- Required if no related issue is linked above. -->
<!-- How does this change impact your work and what are you trying to achieve? What pain point or blocker prompted it? -->

## Timeline
<!-- If this is time-sensitive, when do you need it merged by? Write "None" if there's no specific deadline. -->

## Alternatives Considered
<!-- Required if no related issue is linked above. -->
<!-- What other approaches did you evaluate, and why did you choose this one? Write "None" if this was the only viable approach. -->

## Type of Change
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update
- [ ] Maintenance (dependency updates, CI/CD, refactoring)
- [ ] Security fix

## Package(s) Affected
**Core & runtime:**
- [ ] agent-governance-toolkit-core
- [ ] agent-primitives
- [ ] agent-os
- [ ] agent-mesh
- [ ] agent-runtime
- [ ] agent-sre
- [ ] agent-compliance

**Governance & security:**
- [ ] agent-mcp-governance
- [ ] agent-rag-governance
- [ ] agent-sandbox
- [ ] agent-discovery
- [ ] agt-policies
- [ ] policy-engine

**Platform & tooling:**
- [ ] agent-hypervisor
- [ ] agent-lightning
- [ ] agent-marketplace
- [ ] agent-governance-toolkit-cli
- [ ] agent-governance-toolkit-integrations
- [ ] agent-governance-toolkit-protocols
- [ ] agentmesh-integrations (framework integrations)

**CLI plugins:**
- [ ] agent-governance CLI plugins (copilot-cli / claude-code / opencode / antigravity-cli)

**Shared / other:**
- [ ] schemas
- [ ] action (GitHub Action)
- [ ] examples
- [ ] docs / root

## Testing
<!-- Describe how you verified this change. -->

### Unit Testing
<!-- What unit tests did you add or update, and what do they cover? -->

### Manual Testing
<!-- What did you run by hand to verify this change (commands, environment, results)? -->
<!-- Write "N/A" if manual testing does not apply. -->

## Checklist
- [ ] I have linked a related issue above, or completed "Problem & Solution", "Impact on Your Work", and "Alternatives Considered"
- [ ] My code follows the project style guidelines (ruff check)
- [ ] I have added tests that prove my fix/feature works
- [ ] All new and existing tests pass (pytest)
- [ ] I have updated documentation as needed
- [ ] I have signed the [Microsoft CLA](https://cla.opensource.microsoft.com/)

## Attribution & Prior Art
<!-- REQUIRED for new features, integrations, or architectural patterns -->
- [ ] This contribution does not contain code copied or derived from other projects without attribution
- [ ] Any external projects that inspired this design are credited in code comments or documentation
- [ ] If this PR implements functionality similar to an existing open-source project, I have listed it below

**Prior art / related projects** (if any):
<!-- Example: "Sandboxing approach inspired by https://github.com/example/project (Apache-2.0)" -->
<!-- Leave blank if not applicable -->

## AI Assistance
<!-- See CONTRIBUTING.md "AI-Assisted Contributions" for full policy -->
- [ ] I can explain every meaningful change in this PR: what it does, why, and what tradeoffs were considered
- [ ] I have run tests and verification appropriate for this change
- [ ] No part of this PR was autonomously submitted by an AI agent without my review
- [ ] I have not used AI to generate review comments on others' PRs

If AI tools materially shaped this change, briefly note what was used:
<!-- Example: "GitHub Copilot for boilerplate, Codex for test generation — all output reviewed" -->
<!-- Leave blank if AI was not used or was only used for minor assistance -->

## IP, Patents, and Licensing
- [ ] This contribution does not implement patent-pending or patent-encumbered techniques
- [ ] This contribution does not require an NDA or licensing agreement to understand or use
- [ ] Any AI tools used have terms compatible with the MIT License
