# AGT Studio

AGT Studio is the canonical package for the Agent Governance Toolkit's unified
UI. Its Python distribution is `agent-governance-studio` (import
`agent_governance_studio`); its frontend is
`@microsoft/agent-governance-studio`. This scaffold establishes packaging and
validation only. See the [Studio execution tracker](https://github.com/microsoft/agent-governance-toolkit/issues/2729)
and [ADR 0028](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/adr/0028-agt-studio-unified-ui.md)
for the agreed scope.

From the repository root, with the Python build, pytest, and Ruff tools
installed and Node.js 20.19+ (or 22.12+):

```sh
python -m build agent-governance-studio
python -m pytest agent-governance-studio/tests -q
ruff check agent-governance-studio/src agent-governance-studio/tests --select E,F,W --ignore E501

npm ci --ignore-scripts --prefix agent-governance-studio/web
npm run lint --prefix agent-governance-studio/web
npm test --prefix agent-governance-studio/web
npm run build --prefix agent-governance-studio/web
```

The local sidecar, `agt ui` / `agt serve` launchers, transport, generated
client, SPA shell, and product UI are deliberately deferred to their respective
issues. This package does not register CLI commands or expose an Engine API.
