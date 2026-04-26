// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Help Content
 *
 * Tooltip text constants organized by panel. Each value is a short
 * plain-text string (1-2 sentences) suitable for hover tooltips.
 * No HTML or Markdown — render as-is inside Tooltip components.
 */

export const HELP = {
    slo: {
        availability:
            'Percentage of governance evaluations that succeeded without internal errors over the current SLO window.',
        availabilityTarget:
            'The minimum acceptable availability. Breaching this target consumes error budget.',
        latencyP99:
            '99th-percentile policy evaluation latency in milliseconds. Only 1% of calls are slower than this.',
        latencyTarget:
            'Maximum acceptable P99 latency. Exceeding the target counts against the latency error budget.',
        compliance:
            'Percentage of tool calls that passed policy evaluation without triggering a violation.',
        trust:
            'Mean trust score across all registered agents on a 0-1000 scale. Higher is better.',
        burnRate:
            'Rate of error budget consumption. 1.0 means the budget will exhaust exactly at window end. Above 1.0 is critical.',
        budgetAvailability:
            'Remaining availability error budget as a percentage. When this reaches 0%, the SLO is breached.',
        budgetLatency:
            'Remaining latency error budget as a percentage. Tracks how much latency headroom remains.',
    },
    topology: {
        graph:
            'Force-directed visualization of the agent mesh. Nodes are agents, edges are delegation chains.',
        trustTiers:
            'Agents grouped into concentric rings by trust score: high (751-1000), medium (501-750), low (0-500).',
        trust:
            'Mean governance trust score across all agents in the mesh (0-1000). Higher is better.',
        bridges:
            'Protocol adapters connecting this mesh to external systems. Green dot means connected.',
        agents:
            'Registered agents with their DID, trust score, and assigned execution ring.',
        delegations:
            'Directed trust relationships where one agent grants a specific capability to another.',
        chains:
            'Active delegation chains where one agent has granted capabilities to another.',
    },
    audit: {
        severity:
            'Event severity: info (normal), warning (policy flagged but allowed), critical (blocked or escalated).',
        search:
            'Filter audit entries by action type, agent DID, file path, or severity level.',
        totalToday:
            'Total number of governance events recorded since midnight UTC.',
        violations:
            'Count of events where policy evaluation returned DENY or BLOCK.',
        lastEvent:
            'Time elapsed since the most recent governance event was recorded.',
    },
    policy: {
        actions:
            'Policy result: ALLOW (permit), DENY (reject silently), AUDIT (permit and log), BLOCK (reject and alert).',
        deny:
            'DENY rules reject tool calls and return an error to the requesting agent.',
        block:
            'BLOCK rules silently prevent execution without notifying the agent.',
        audit:
            'AUDIT rules permit the action but log it for governance review.',
        allow:
            'ALLOW rules explicitly permit matching tool calls without restriction.',
        evaluations:
            'Number of times this rule was tested against a tool call today.',
        violations:
            'Number of times this rule triggered a DENY or BLOCK action today.',
        pattern:
            'Glob or regex pattern that this rule matches against tool call names or file paths.',
    },
    stats: {
        blocked:
            'Total tool calls rejected by policy this session. Includes both DENY and BLOCK actions.',
        blockedToday:
            'Tool calls rejected by policy enforcement since midnight UTC.',
        blockedThisWeek:
            'Tool calls rejected by policy enforcement in the current calendar week.',
        warnings:
            'Tool calls that matched an AUDIT rule. Permitted but logged for review.',
        cmvk:
            'Number of multi-model verification reviews triggered. Each review cross-checks output across models.',
        cmvkReviews:
            'Constitutional Multi-View Kernel reviews: multi-model code verification checks performed today.',
        totalLogs:
            'Total governance log entries across all severity levels for the current session.',
    },
    kernel: {
        agents:
            'Number of agents currently registered with the governance kernel.',
        activeAgents:
            'Agents currently executing tasks within the governance mesh.',
        violations:
            'Active policy violations that have not been resolved or acknowledged.',
        checkpoints:
            'Saga checkpoints recorded by the hypervisor for in-progress workflows.',
        uptime:
            'Time since the governance kernel was last initialized, formatted as hours and minutes.',
    },
    memory: {
        vfs:
            'Virtual filesystem provided by the Episodic Memory Kernel. Stores agent working memory.',
        directories:
            'Folders in the virtual filesystem. Each agent may have its own namespace.',
        files:
            'Individual memory entries stored by agents during execution. Content is read-only in this view.',
    },
    hub: {
        health:
            'Composite health indicator combining SLO availability, compliance, and trust into a single status.',
        alerts:
            'Recent critical events requiring attention: SLO breaches, blocked calls, or escalations.',
        activeAlerts:
            'Sum of policy violations and audit warnings requiring attention.',
        compliance:
            'Summary of policy compliance across all active rules and agents.',
        agents:
            'Total registered agents visible in the governance mesh.',
        tabs:
            'Switch between SLO, Topology, Audit, and Policy views within the Governance Hub.',
        sloTab:
            'Service Level Objectives: availability, latency, compliance, and trust metrics.',
        topologyTab:
            'Agent mesh visualization: force graph of agents, bridges, and delegation chains.',
        auditTab:
            'Governance audit log: filterable list of all policy evaluation events.',
        policiesTab:
            'Active policy rules grouped by action type with evaluation statistics.',
    },
    governanceHub: {
        health:
            'Composite health: green = all SLOs met, yellow = warnings, red = SLO breach or critical violations.',
        activeAlerts:
            'Sum of policy violations and audit warnings requiring attention.',
        compliance:
            'Overall policy compliance percentage across all active rules.',
        agents:
            'Total registered agents visible in the governance mesh.',
    },
} as const;

/** Type-safe panel key. */
export type HelpPanel = keyof typeof HELP;

/** Type-safe metric key within a panel. */
export type HelpKey<P extends HelpPanel> = keyof (typeof HELP)[P];
