// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance Hub Audit Styles
 *
 * CSS for audit event list, filters, policy rules, and violations.
 */

/** Returns audit panel and policy panel CSS. */
export function auditStyles(): string {
    return `
        /* Audit Panel Styles */
        .audit-panel { padding: 0; }
        .audit-list { list-style: none; }

        .audit-item {
            display: flex;
            align-items: flex-start;
            gap: 12px;
            padding: 12px 16px;
            border-bottom: 1px solid var(--vscode-panel-border);
            transition: background 0.2s;
        }

        .audit-item:hover { background: var(--vscode-list-hoverBackground); }

        .audit-icon {
            width: 24px; height: 24px; border-radius: 50%;
            display: flex; align-items: center; justify-content: center;
            font-size: 12px; flex-shrink: 0;
        }

        .audit-icon.blocked {
            background: var(--vscode-inputValidation-errorBackground);
            color: var(--vscode-errorForeground);
        }
        .audit-icon.allowed {
            background: rgba(76, 175, 80, 0.2);
            color: var(--vscode-charts-green, #4caf50);
        }
        .audit-icon.warning {
            background: rgba(255, 152, 0, 0.2);
            color: var(--vscode-charts-yellow, #ff9800);
        }

        .audit-content { flex: 1; min-width: 0; }
        .audit-title { font-weight: 500; margin-bottom: 2px; }
        .audit-details { font-size: 11px; color: var(--vscode-descriptionForeground); }
        .audit-time { font-size: 10px; color: var(--vscode-descriptionForeground); flex-shrink: 0; }

        /* Audit Filter Styles */
        .audit-controls {
            display: flex; gap: 8px; padding: 12px;
            border-bottom: 1px solid var(--vscode-panel-border);
        }
        .audit-controls input {
            flex: 1;
            background: var(--vscode-input-background);
            border: 1px solid var(--vscode-input-border);
            color: var(--vscode-input-foreground);
            padding: 6px 10px;
            border-radius: 4px;
        }
        .audit-controls select {
            background: var(--vscode-dropdown-background);
            border: 1px solid var(--vscode-dropdown-border);
            color: var(--vscode-dropdown-foreground);
            padding: 6px;
            border-radius: 4px;
        }
        .audit-controls button {
            background: var(--vscode-button-secondaryBackground);
            border: none;
            color: var(--vscode-button-secondaryForeground);
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
        }
        .audit-controls button:hover {
            background: var(--vscode-button-secondaryHoverBackground);
        }

        /* Policy Panel Styles */
        .policies-panel { padding: 16px; }
        .policy-stats { display: flex; gap: 12px; margin-bottom: 20px; }
        .stat-card {
            flex: 1;
            background: var(--vscode-input-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 6px;
            padding: 12px;
            text-align: center;
        }
        .stat-card.alert { border-color: var(--vscode-errorForeground); }
        .stat-value { display: block; font-size: 24px; font-weight: 700; }
        .stat-label { font-size: 11px; color: var(--vscode-descriptionForeground); }

        .rules-list { display: flex; flex-direction: column; gap: 8px; }
        .policy-rule {
            background: var(--vscode-input-background);
            border: 1px solid var(--vscode-panel-border);
            border-radius: 6px;
            padding: 12px;
        }
        .policy-rule.disabled { opacity: 0.5; }
        .rule-header { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
        .rule-action {
            padding: 2px 6px; border-radius: 4px;
            font-size: 10px; font-weight: 600; text-transform: uppercase;
        }
        .action-allow { background: rgba(76, 175, 80, 0.2); color: var(--vscode-charts-green); }
        .action-deny { background: rgba(244, 67, 54, 0.2); color: var(--vscode-charts-red); }
        .action-audit { background: rgba(255, 193, 7, 0.2); color: var(--vscode-charts-yellow); }
        .action-block { background: rgba(244, 67, 54, 0.3); color: var(--vscode-errorForeground); }
        .rule-name { font-weight: 500; flex: 1; }
        .rule-scope { font-size: 10px; color: var(--vscode-descriptionForeground); }
        .rule-description { font-size: 12px; color: var(--vscode-descriptionForeground); margin-bottom: 8px; }
        .rule-stats { display: flex; gap: 16px; font-size: 11px; }
        .rule-stats .violations { color: var(--vscode-errorForeground); }

        .violations-list { margin-top: 8px; }
        .violation-item {
            display: flex; gap: 12px; padding: 8px;
            border-bottom: 1px solid var(--vscode-panel-border);
            font-size: 12px;
        }
        .violation-time { color: var(--vscode-descriptionForeground); }
        .violation-rule { font-weight: 500; }
        .violation-context { color: var(--vscode-descriptionForeground); flex: 1; }
    `;
}
