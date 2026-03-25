// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Governance Hub Layout Styles
 *
 * CSS for layout, header, tabs, footer, and content panels.
 */

/** Returns layout, header, tab bar, and footer CSS. */
export function layoutStyles(): string {
    return `
        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: var(--vscode-font-family);
            font-size: var(--vscode-font-size);
            color: var(--vscode-foreground);
            background: var(--vscode-editor-background);
            height: 100vh;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }

        /* Header */
        .hub-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 16px;
            background: var(--vscode-sideBar-background);
            border-bottom: 1px solid var(--vscode-panel-border);
            flex-shrink: 0;
        }

        .hub-title {
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 14px;
            font-weight: 600;
        }

        .hub-title .status-indicator {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--vscode-charts-green, #4caf50);
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.6; transform: scale(0.9); }
        }

        .hub-actions {
            display: flex;
            gap: 8px;
        }

        .hub-actions button {
            background: transparent;
            border: 1px solid var(--vscode-button-border, var(--vscode-panel-border));
            color: var(--vscode-foreground);
            padding: 4px 8px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 11px;
            display: flex;
            align-items: center;
            gap: 4px;
        }

        .hub-actions button:hover {
            background: var(--vscode-button-secondaryHoverBackground);
        }

        /* Tab bar */
        .tab-bar {
            display: flex;
            background: var(--vscode-sideBar-background);
            border-bottom: 1px solid var(--vscode-panel-border);
            flex-shrink: 0;
        }

        .tab {
            padding: 10px 16px;
            cursor: pointer;
            border: none;
            background: transparent;
            color: var(--vscode-foreground);
            font-size: 12px;
            font-weight: 500;
            position: relative;
            opacity: 0.7;
            transition: opacity 0.2s, background 0.2s;
        }

        .tab:hover {
            opacity: 1;
            background: var(--vscode-list-hoverBackground);
        }

        .tab.active { opacity: 1; }

        .tab.active::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: var(--vscode-focusBorder, var(--vscode-textLink-foreground));
        }

        .tab .badge {
            background: var(--vscode-badge-background);
            color: var(--vscode-badge-foreground);
            padding: 2px 6px;
            border-radius: 10px;
            font-size: 10px;
            margin-left: 6px;
        }

        .tab .badge.alert {
            background: var(--vscode-errorForeground);
            color: white;
        }

        /* Content panels */
        .tab-content {
            flex: 1;
            overflow: auto;
            display: none;
        }

        .tab-content.active { display: block; }

        /* Footer status */
        .hub-footer {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 16px;
            background: var(--vscode-sideBar-background);
            border-top: 1px solid var(--vscode-panel-border);
            font-size: 11px;
            color: var(--vscode-descriptionForeground);
            flex-shrink: 0;
        }

        .connection-status {
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .connection-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: var(--vscode-charts-green, #4caf50);
        }

        .connection-dot.disconnected {
            background: var(--vscode-charts-red, #f44336);
        }

        .empty-state {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            height: 200px;
            color: var(--vscode-descriptionForeground);
            text-align: center;
            padding: 20px;
        }

        .empty-state .icon {
            font-size: 32px;
            margin-bottom: 12px;
            opacity: 0.5;
        }
    `;
}
