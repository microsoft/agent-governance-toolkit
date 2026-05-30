# Framework adapter matrix

Every SDK ships the same base enforcement surface: generic `input`/`output`, `pre_model_call`/`post_model_call`, `pre_tool_call`/`post_tool_call` wrappers, and the `escalate` approval seam. Any framework can be guarded through those primitives.

On top of the base, each SDK ships first-class adapters for the frameworks that exist in that language. A cell marked "n/a" means the framework has no first-party package for that language, so a dedicated adapter would have nothing to bind to. A cell marked "base" means the framework is guarded through the generic wrappers rather than a dedicated shape.

| Framework | Python | Node | .NET | Rust |
| --- | --- | --- | --- | --- |
| Generic model / tool / run | yes | yes | yes | yes |
| Approval / escalate seam | yes | yes | yes | yes |
| LangChain | yes | yes | n/a | n/a |
| OpenAI Agents SDK | yes | yes | base | n/a |
| OpenAI client | yes | base | base | yes |
| Anthropic | yes | yes | base | via Rig |
| AutoGen | yes | n/a | yes | n/a |
| Semantic Kernel | yes | n/a | yes | n/a |
| Microsoft Agent Framework | n/a | n/a | yes | n/a |
| CrewAI | yes | n/a | n/a | n/a |
| LiteLLM proxy | yes | n/a | n/a | n/a |
| MCP tool provider | yes | yes | yes | yes |
| GitHub Copilot permission hook | n/a | yes | n/a | n/a |
| OpenClaw | n/a | yes | n/a | n/a |
| Rig | n/a | n/a | n/a | yes |

## Notes

- **LangChain, CrewAI, LiteLLM** are Python ecosystems (LangChain also ships JavaScript). They have no first-party .NET or Rust packages, so those cells are "n/a" rather than gaps.
- **AutoGen and Semantic Kernel** are Python and .NET frameworks, so Node and Rust cells are "n/a".
- **Microsoft Agent Framework** is the unified .NET successor to Semantic Kernel and AutoGen. The .NET SDK ships `AgentControlAgentFrameworkFunctionMiddleware` (function-calling middleware) and `AgentControlAgentFrameworkRunMiddleware` (agent-run middleware), exposed through the `AgentControlFrameworkAdapters.AgentFramework*` factory methods. Like the other .NET adapters it is duck-typed against small SDK-owned interfaces, so the integrator binds Agent Framework's real middleware types without the SDK taking a third-party package dependency.
- **OpenAI and Anthropic on .NET** are guarded through `AgentControlDelegatingChatClient`, which wraps any `Microsoft.Extensions.AI` `IChatClient`. Both the official OpenAI and Anthropic .NET SDKs expose an `IChatClient`, so the generic chat-client shape covers them without the .NET SDK taking a third-party package dependency. This keeps the core .NET package dependency-free by design.
- **OpenAI client on Node** is guarded through `runModel` / `protectModel`; the dedicated Node adapters target the agent-style frameworks.
- **OpenAI and MCP on Rust** ship dedicated dependency-bearing crates: `integrations/openai` (`GuardedOpenAiToolExecutor` over real `async-openai`) and `integrations/mcp` (`GuardedMcpToolExecutor` / `GuardedMcpServer` over the official `rmcp` crate). The dependency-free SDK still offers generic `run_tool` / `ProtectedTool` for hosts that do not want those crates.
- **LangChain on Rust** has no official first-party crate — LangChain is a Python/JavaScript project, and the community `langchain-rust` port is an immature, heavy dependency (it drags in weak-copyleft and unmaintained transitive crates), so the project deliberately ships no dedicated Rust LangChain crate. This mirrors the Anthropic-Rust decision: Rust LangChain tools are guarded through the generic `run_tool` / `ProtectedTool` surface (or `integrations/rig`), keeping the workspace dependency posture lean and permissive.
- **Anthropic on Rust** has no official or stable first-party crate, so the project deliberately ships no dedicated Anthropic crate (a wrapper around an immature community crate would be a supply-chain liability). Anthropic-backed agents are guarded through `integrations/rig` — `rig-core` ships a first-class Anthropic provider, and `GuardedRigTool` guards its tools model-agnostically. This mirrors the .NET decision to guard OpenAI/Anthropic through the generic `IChatClient` rather than dedicated packages.
- **Rig** has a dedicated dependency-bearing crate at `integrations/rig` (`GuardedRigTool` implementing `rig::tool::ToolDyn`). The Rust SDK also ships a dependency-free `RigLikeTool` / `GuardedRigLikeTool` abstraction for hosts that do not want the `rig-core` dependency.

## Coverage parity

This matrix tracks parity with proven framework coverage. Where a dependency-bearing package exists (for example .NET Anthropic and OpenAI packages), this project either ships an equivalent or, where the generic surface already covers the integration idiomatically, documents the base-surface path instead of duplicating a package dependency.
