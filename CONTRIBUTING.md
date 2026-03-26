# Contributing

Thanks for contributing to Agent Governance Toolkit.

This repository is a multi-package workspace covering Python, TypeScript, .NET,
docs, examples, and deployment assets. The lowest-friction path is:

1. Fork the repository and create a feature branch from `main`.
2. Install the tooling needed for the package or docs area you are changing.
3. Run the repository pre-commit hooks before opening a pull request.
4. Run the most relevant tests or validation commands for your change.

## Install pre-commit hooks

```bash
pip install pre-commit
pre-commit install
```

The repository hook set currently runs:

- `ruff` linting for `packages/agent-runtime/src/agent_runtime`
- `ruff-format --check` for `packages/agent-runtime/src/agent_runtime`
- `mypy --ignore-missing-imports` for `packages/agent-runtime/src/agent_runtime`
- `detect-secrets`
- `check-yaml`
- `check-merge-conflict`
- `trailing-whitespace`
- `end-of-file-fixer`

`detect-secrets` uses the checked-in `.secrets.baseline` so existing fixtures,
examples, and snapshot data do not block routine contribution work while new
diffs are still scanned. `check-yaml` excludes Helm templates and policy
template directories that intentionally use multi-document files or templating
syntax outside plain YAML.

To run the full hook suite manually:

```bash
pre-commit run --all-files
```

## Suggested local validation

Pick the validation that matches your change:

- Docs-only changes: `pre-commit run --all-files`
- Agent Runtime Python changes:
  ```bash
  ruff check packages/agent-runtime/src/agent_runtime
  ruff format --check packages/agent-runtime/src/agent_runtime
  mypy --ignore-missing-imports packages/agent-runtime/src/agent_runtime
  ```
- Package-specific changes: run the checks documented in that package's own
  `README.md`, `AGENTS.md`, or local `CONTRIBUTING.md`

## Repository layout

- `packages/agent-os/` — policy engine, governance kernel, and core docs
- `packages/agent-mesh/` — trust, identity, and multi-agent infrastructure
- `packages/agent-runtime/` — execution supervision and isolation
- `packages/agent-sre/` — reliability and observability tooling
- `docs/` — repo-level deployment, proposal, and tutorial content
- `examples/` and `demo/` — runnable walkthroughs and demos

## Pull request checklist

- Keep the change scoped to one issue or problem statement.
- Update docs or examples when behavior or developer workflow changes.
- Include validation notes in the PR description.
- Prefer small, reviewable changes over wide cross-package refactors.
