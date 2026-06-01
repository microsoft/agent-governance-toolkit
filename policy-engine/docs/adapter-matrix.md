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
- **.NET adapters ship in two layers.** The base `AgentControlSpecification` package is dependency-free (no NuGet references beyond the native runtime payload) and ships *duck-typed* conceptual shapes such as `AgentControlDelegatingChatClient`, `AgentControlSemanticKernelFunctionFilter`, `AgentControlAutoGenMiddleware`, and the `AgentControlFrameworkAdapters.AgentFramework*` middleware in `FrameworkAdapters.cs`. These bind a framework's types structurally without referencing its package. On top of that, companion packages (`AgentControlSpecification.AI`, `AgentControlSpecification.SemanticKernel`, `AgentControlSpecification.AutoGen`, `AgentControlSpecification.AgentFramework`) each take a single real framework dependency and guard the genuine types via `UseAgentControl(...)` / `AsGuarded(...)`, so a host restores only the framework packages it actually uses. This mirrors the Rust split between the dependency-free `RigLikeTool` surface and the dependency-bearing `integrations/rig` crate: the core stays dependency-free, while opt-in companion packages bear their framework dep.
- **Microsoft Agent Framework** is the unified .NET successor to Semantic Kernel and AutoGen. The dependency-free base package ships the duck-typed `AgentControlAgentFrameworkFunctionMiddleware` and `AgentControlAgentFrameworkRunMiddleware` shapes (via the `AgentControlFrameworkAdapters.AgentFramework*` factories), while the companion `AgentControlSpecification.AgentFramework` package takes a real `Microsoft.Agents.AI` dependency and guards genuine `AIAgent` instances with `UseAgentControl(...)` / `AsGuarded(...)`.
- **OpenAI and Anthropic on .NET** are guarded through the `Microsoft.Extensions.AI` `IChatClient` shape rather than per-vendor packages: both official SDKs expose an `IChatClient`, so one surface covers both. The dependency-free base package ships the duck-typed `AgentControlDelegatingChatClient` (`UseAgentControl(...)`), and the companion `AgentControlSpecification.AI` package takes a real `Microsoft.Extensions.AI` dependency to wrap concrete `IChatClient` instances. There is no dedicated OpenAI- or Anthropic-specific .NET package because the shared `IChatClient` abstraction already covers them idiomatically.
- **OpenAI client on Node** is guarded through `runModel` / `protectModel`; the dedicated Node adapters target the agent-style frameworks.
- **OpenAI and MCP on Rust** ship dedicated dependency-bearing crates: `agent_control_specification_openai` from `integrations/openai` (`GuardedOpenAiToolExecutor` over real `async-openai`) and `agent_control_specification_mcp` from `integrations/mcp` (`GuardedMcpToolExecutor` / `GuardedMcpServer` over the official `rmcp` crate). Artifact-only kits include matching `.crate` files when these integrations are part of the kit; extract them and patch `agent_control_specification` plus `agent_control_specification_core` to local paths. The dependency-free SDK still offers generic `run_tool` / `ProtectedTool` for hosts that do not want those crates.
- **LangChain on Rust** has no official first-party crate. LangChain is a Python/JavaScript project, and the community `langchain-rust` port is an immature, heavy dependency (it drags in weak-copyleft and unmaintained transitive crates), so the project deliberately ships no dedicated Rust LangChain crate. This mirrors the Anthropic-Rust decision: Rust LangChain tools are guarded through the generic `run_tool` / `ProtectedTool` surface (or `integrations/rig`), keeping the workspace dependency posture lean and permissive.
- **Anthropic on Rust** has no official or stable first-party crate, so the project deliberately ships no dedicated Anthropic crate (a wrapper around an immature community crate would be a supply-chain liability). Anthropic-backed agents are guarded through `integrations/rig`. `rig-core` ships a first-class Anthropic provider, and `GuardedRigTool` guards its tools model-agnostically. This mirrors the .NET decision to guard OpenAI/Anthropic through the shared `IChatClient` surface rather than dedicated per-vendor packages.
- **Rig** has a dedicated dependency-bearing crate at `integrations/rig` (`GuardedRigTool` implementing `rig::tool::ToolDyn`). Use `GuardedRigTool::with_ambient_snapshot` when policies need host context such as `snapshot.ifc.source_labels`. Use `GuardedRigTool::call_with_result` when the host needs post-tool ACS metadata such as `result_labels`; the plain `ToolDyn::call` trait returns only the Rig tool string. The Rust SDK also ships a dependency-free `RigLikeTool` / `GuardedRigLikeTool` abstraction for hosts that do not want the `rig-core` dependency.

## Coverage parity

This matrix tracks parity with proven framework coverage. Where a dependency-bearing package exists (for example .NET Anthropic and OpenAI packages), this project either ships an equivalent or, where the generic surface already covers the integration idiomatically, documents the base-surface path instead of duplicating a package dependency.
