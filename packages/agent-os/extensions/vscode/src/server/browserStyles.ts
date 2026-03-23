// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Browser Dashboard Styles
 *
 * CSS styles for the browser-based governance dashboard.
 */

/** Build the CSS styles for the browser dashboard. */
export function buildBrowserStyles(): string {
    return `
    :root {
        --bg-primary: #1e1e1e;
        --bg-secondary: #252526;
        --bg-tertiary: #2d2d30;
        --text-primary: #cccccc;
        --text-secondary: #9d9d9d;
        --accent-blue: #0078d4;
        --health-ok: #4ec9b0;
        --health-warn: #dcdcaa;
        --health-breach: #f14c4c;
        --border: #3c3c3c;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        background: var(--bg-primary);
        color: var(--text-primary);
        min-height: 100vh;
    }
    .container { display: flex; min-height: 100vh; }
    .sidebar {
        width: 220px;
        background: var(--bg-secondary);
        border-right: 1px solid var(--border);
        padding: 16px;
        flex-shrink: 0;
    }
    .sidebar.collapsed { width: 50px; }
    .sidebar.collapsed .nav-label { display: none; }
    .main { flex: 1; padding: 24px; overflow-y: auto; }
    .nav-item {
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 10px 12px;
        border-radius: 4px;
        cursor: pointer;
        color: var(--text-secondary);
        text-decoration: none;
        margin-bottom: 4px;
    }
    .nav-item:hover, .nav-item.active {
        background: var(--bg-tertiary);
        color: var(--text-primary);
    }
    .nav-icon { font-size: 18px; }
    .header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 24px;
    }
    .header h1 { font-size: 20px; font-weight: 500; }
    .status-indicator { display: flex; align-items: center; gap: 8px; }
    .status-dot {
        width: 10px;
        height: 10px;
        border-radius: 50%;
        background: var(--health-ok);
    }
    .status-dot.disconnected { background: var(--health-breach); }
    .tab-content { display: none; }
    .tab-content.active { display: block; }
    .card {
        background: var(--bg-secondary);
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 16px;
    }
    .card-title {
        font-size: 14px;
        color: var(--text-secondary);
        margin-bottom: 12px;
    }
    .metric-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 16px;
    }
    .metric { text-align: center; }
    .metric-value { font-size: 32px; font-weight: 600; }
    .metric-label {
        font-size: 12px;
        color: var(--text-secondary);
        margin-top: 4px;
    }
    .health-ok { color: var(--health-ok); }
    .health-warn { color: var(--health-warn); }
    .health-breach { color: var(--health-breach); }
    #topology-graph {
        width: 100%;
        height: 500px;
        background: var(--bg-tertiary);
        border-radius: 8px;
    }
    #topology-graph svg { width: 100%; height: 100%; }
    .node circle { cursor: pointer; }
    .link { stroke: var(--border); stroke-opacity: 0.6; }
    .node-label {
        font-size: 10px;
        fill: var(--text-secondary);
        pointer-events: none;
    }
    .audit-list { max-height: 400px; overflow-y: auto; }
    .audit-item {
        padding: 10px;
        border-bottom: 1px solid var(--border);
        display: flex;
        gap: 12px;
    }
    .audit-type { font-weight: 500; width: 80px; }
    .audit-time { color: var(--text-secondary); font-size: 12px; width: 100px; }
    .toggle-btn {
        background: none;
        border: none;
        color: var(--text-primary);
        cursor: pointer;
        font-size: 18px;
    }
    .chart-container { height: 120px; }`;
}
