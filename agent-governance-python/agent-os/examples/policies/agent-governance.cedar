// Agent Governance Cedar Policy — Example
// =========================================
//
// This policy demonstrates how to use Cedar with the Agent Governance
// Toolkit's GovernancePlugin for Google ADK agents.
//
// Usage:
//   from agent_os.integrations.google_adk_adapter import GoogleADKKernel
//   from google.adk import Runner
//
//   kernel = GoogleADKKernel.from_cedar(
//       policy_path="policies/agent-governance.cedar",
//       blocked_tools=["shell"],
//   )
//   runner = Runner(
//       agent=root_agent,
//       plugins=[kernel.as_plugin()],
//   )
//
// Cedar evaluates permit/forbid statements against a principal (agent),
// action (tool or model call), and resource.  The toolkit maps ADK
// lifecycle data to these triples automatically via _build_cedar_context().
//
// Default: deny-by-default. Only explicitly permitted actions are allowed.

// ── Read-only tools are always permitted ─────────────────────────
permit(
    principal,
    action == Action::"ReadData",
    resource
);

permit(
    principal,
    action == Action::"ListFiles",
    resource
);

permit(
    principal,
    action == Action::"SearchDocuments",
    resource
);

// ── Model calls are permitted (LLM invocations) ─────────────────
permit(
    principal,
    action == Action::"ModelCall",
    resource
);

// ── Dangerous tools are explicitly forbidden ─────────────────────
forbid(
    principal,
    action == Action::"DeleteFile",
    resource
);

forbid(
    principal,
    action == Action::"Shell",
    resource
);

forbid(
    principal,
    action == Action::"ExecCode",
    resource
);

forbid(
    principal,
    action == Action::"DropTable",
    resource
);

// ── Write tools require scoped permission ────────────────────────
// Uncomment and modify for your environment:
//
// permit(
//     principal == Agent::"finance-agent",
//     action == Action::"WriteData",
//     resource == Resource::"finance-db"
// );
//
// permit(
//     principal == Agent::"ops-agent",
//     action == Action::"SendEmail",
//     resource == Resource::"internal-smtp"
// );
