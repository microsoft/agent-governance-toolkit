# Autonomous contribution policy

This document defines which automated agents and bots are authorized to
interact with the Agent Governance Toolkit repository, what behaviors are
permitted, and how to request authorization for new bots.

## Default policy

Autonomous contributions are **not accepted by default**. All contributions
must have a responsible human who directed the work and can explain and defend
it. See [CONTRIBUTING.md](../../CONTRIBUTING.md) for the full AI contribution
policy.

## Authorized bots

The following bots are authorized to operate in this repository. Each entry
lists the bot identity, permitted behaviors, and scope constraints.

### Dependabot

- **Identity**: `dependabot[bot]`
- **Permitted behaviors**: open PRs for dependency version bumps, security
  patches, and ecosystem updates
- **Scope**: `package.json`, `requirements*.txt`, `pyproject.toml`,
  `Cargo.toml`, `go.mod`, `*.csproj`, lock files
- **Human oversight**: maintainer review and approval required before merge
- **Configuration**: `.github/dependabot.yml`

### GitHub Actions bot

- **Identity**: `github-actions[bot]`
- **Permitted behaviors**: post CI status comments, apply labels via
  workflows, update PR metadata
- **Scope**: limited to workflow-defined actions
- **Human oversight**: workflows are reviewed via PR before deployment

### Microsoft CLA bot

- **Identity**: `microsoft-github-policy-service[bot]`
- **Permitted behaviors**: check CLA status, post CLA signing instructions
- **Scope**: CLA enforcement only
- **Human oversight**: none required (policy-driven)

### OpenSSF Scorecard

- **Identity**: `ossf-scorecard[bot]` / scheduled workflow
- **Permitted behaviors**: compute repository security scores, post results
- **Scope**: read-only analysis
- **Human oversight**: results reviewed by maintainers

### Copilot (coding agent)

- **Identity**: `copilot[bot]` / `Copilot`
- **Permitted behaviors**: open PRs assigned by maintainers via GitHub Issues
- **Scope**: changes directed by a maintainer-filed issue
- **Human oversight**: maintainer must review and approve before merge.
  The assigning maintainer is the responsible human for the contribution.
- **Configuration**: `.github/copilot-setup-steps.yml`

## Prohibited autonomous behaviors

The following behaviors are not authorized for any bot or agent unless
explicitly listed above:

- Opening pull requests without a human reviewing the specific changes
- Filing bug reports or feature requests without human verification
- Claiming issues (especially "good first issue") without human intent to
  follow through
- Posting unsolicited code review feedback on others' pull requests
- Responding in issue or discussion threads without human oversight
- Approving pull requests
- Merging pull requests without human authorization

## Requesting authorization for a new bot

To request authorization for a new automated agent:

1. Open a GitHub Discussion in the repository describing:
   - The bot identity (GitHub username or app name)
   - The specific behaviors it needs to perform
   - The scope of files or actions it will touch
   - The human oversight model (who reviews its output)
   - How it will be configured and controlled
2. A maintainer will review the request and, if approved, update this document
   via PR to add the bot to the authorized list.
3. Bots must not begin operating until the authorization PR is merged.

## Revoking authorization

Maintainers may revoke a bot's authorization at any time by removing its entry
from this document and disabling the corresponding GitHub App or workflow. Bots
that violate their permitted scope will be immediately disabled pending review.

## Relationship to AGENTS.md

The root [AGENTS.md](../../AGENTS.md) file documents how AI coding agents
should interact with the codebase (code conventions, testing requirements,
architecture guidance). This document governs which agents are authorized
and what repository-level actions they may take. Both documents apply.
