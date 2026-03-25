// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Sidebar Hub Content Styles
 *
 * CSS for compact metrics, agent list, audit entries, and progress bars.
 */

/** Returns compact content CSS for sidebar metrics, agents, and audit. */
export function sidebarContentStyles(): string {
    return `
/* Compact Metric Rows */
.metric-compact {
    display: flex; justify-content: space-between; align-items: center;
    padding: var(--hub-spacing-xs) 0; font-size: 12px;
    border-bottom: 1px solid var(--vscode-panel-border);
}
.metric-compact:last-child { border-bottom: none; }
.metric-compact .label { color: var(--vscode-descriptionForeground); }
.metric-compact .value { font-weight: 600; font-variant-numeric: tabular-nums; }
.metric-compact .value.healthy { color: var(--vscode-charts-green); }
.metric-compact .value.warning { color: var(--vscode-charts-yellow); }
.metric-compact .value.critical { color: var(--vscode-charts-red); }

/* Section Headers */
.section-header {
    font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px;
    color: var(--vscode-descriptionForeground);
    margin: var(--hub-spacing-md) 0 var(--hub-spacing-sm);
    padding-bottom: var(--hub-spacing-xs);
    border-bottom: 1px solid var(--vscode-panel-border);
}
.section-header:first-child { margin-top: 0; }

/* Progress Bar */
.progress-bar {
    height: 4px; background: var(--vscode-progressBar-background);
    border-radius: 2px; overflow: hidden;
    margin-top: var(--hub-spacing-xs);
}
.progress-bar .fill { height: 100%; transition: width 0.3s; }
.progress-bar .fill.healthy { background: var(--vscode-charts-green); }
.progress-bar .fill.warning { background: var(--vscode-charts-yellow); }
.progress-bar .fill.critical { background: var(--vscode-charts-red); }

/* Agent List */
.agent-item {
    display: flex; align-items: center; gap: var(--hub-spacing-sm);
    padding: var(--hub-spacing-xs) 0; font-size: 11px;
}
.agent-item .tier-badge {
    font-size: 9px; padding: 1px 4px; border-radius: 2px;
    background: var(--vscode-badge-background); color: var(--vscode-badge-foreground);
}
.agent-item .name {
    flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.agent-item .status-indicator { width: 6px; height: 6px; border-radius: 50%; }
.agent-item .status-indicator.active { background: var(--vscode-charts-green); }
.agent-item .status-indicator.idle { background: var(--vscode-charts-yellow); }
.agent-item .status-indicator.offline { background: var(--vscode-charts-red); }

/* Audit Entries */
.audit-entry {
    padding: var(--hub-spacing-sm) 0;
    border-bottom: 1px solid var(--vscode-panel-border); font-size: 11px;
}
.audit-entry:last-child { border-bottom: none; }
.audit-entry .timestamp { color: var(--vscode-descriptionForeground); font-size: 10px; }
.audit-entry .type-badge {
    display: inline-block; font-size: 9px; padding: 1px 4px;
    border-radius: 2px; margin-left: var(--hub-spacing-xs);
}
.audit-entry .type-badge.violation {
    background: var(--vscode-inputValidation-errorBackground);
    color: var(--vscode-inputValidation-errorForeground);
}
.audit-entry .type-badge.warning {
    background: var(--vscode-inputValidation-warningBackground);
    color: var(--vscode-inputValidation-warningForeground);
}
.audit-entry .type-badge.info {
    background: var(--vscode-inputValidation-infoBackground);
    color: var(--vscode-inputValidation-infoForeground);
}
.audit-entry .file {
    margin-top: 2px; color: var(--vscode-textLink-foreground);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
    `;
}
