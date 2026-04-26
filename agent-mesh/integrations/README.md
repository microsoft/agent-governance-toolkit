# Integrations have moved!

All AgentMesh integrations now live in the dedicated ecosystem repo:

**https://github.com/microsoft/agent-governance-toolkit**

| Integration | Description |
|---|---|
| [dify](https://github.com/microsoft/agent-governance-toolkit/tree/master/dify) | Trust & identity middleware for Dify workflows |
| [dify-plugin](https://github.com/microsoft/agent-governance-toolkit/tree/master/dify-plugin) | Packaged Dify plugin with trust verification tools |
| [langchain-agentmesh](https://github.com/microsoft/agent-governance-toolkit/tree/master/langchain-agentmesh) | LangChain tools, callbacks, and trust integration |
| [moltbook](https://github.com/microsoft/agent-governance-toolkit/tree/master/moltbook) | AgentMesh skill for Moltbook agent registry |
| [nostr-wot](https://github.com/microsoft/agent-governance-toolkit/tree/master/nostr-wot) | Nostr Web of Trust provider (NIP-85) |

## Why?

AgentMesh core is a lean, zero-external-dependency library. Moving integrations to a separate repo means:

- **Core stays stable** — no risk of breaking changes from integration dependencies
- **Independent releases** — integrations ship on their own cadence
- **Clean installs** — users only install what they need (`pip install langchain-agentmesh`)
- **Community ownership** — contributors can own their integrations end-to-end

## Contributing New Integrations

See the [agentmesh-integrations contributing guide](https://github.com/microsoft/agent-governance-toolkit#contributing-a-new-integration).
