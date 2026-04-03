// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Browser Dashboard Styles — Command Center Layout
 *
 * Fixed-viewport grid with 4 Microsoft-style themes.
 * Designed for maximum information density without scrolling.
 */

/** Build the CSS styles for the command center dashboard. */
export function buildBrowserStyles(): string {
    return `
    /* === Theme: Corporate Slate (default) === */
    :root, [data-theme="slate"] {
        --bg-primary: #1a1d23;
        --bg-panel: #21252b;
        --bg-card: #282c34;
        --bg-hover: #2c313a;
        --text-bright: #abb2bf;
        --text-primary: #9da5b4;
        --text-muted: #636d83;
        --accent: #61afef;
        --accent-dim: #4d8cc7;
        --success: #98c379;
        --warning: #e5c07b;
        --error: #e06c75;
        --border: #333842;
        --border-light: #3e4451;
        --radius: 8px;
        --gap: 6px;
        --header-h: 40px;
        --focus-ring: var(--accent);
    }

    /* === Theme: Midnight Blue — deep navy executive === */
    [data-theme="midnight"] {
        --bg-primary: #0b1120;
        --bg-panel: #111a2e;
        --bg-card: #162038;
        --bg-hover: #1b2844;
        --text-bright: #e2e8f0;
        --text-primary: #b8c5d6;
        --text-muted: #64748b;
        --accent: #3b82f6;
        --accent-dim: #2563eb;
        --success: #34d399;
        --warning: #fbbf24;
        --error: #f87171;
        --border: #1e3050;
        --border-light: #28406a;
        --focus-ring: #3b82f6;
    }

    /* === Theme: Onyx — ultra-dark premium === */
    [data-theme="onyx"] {
        --bg-primary: #050505;
        --bg-panel: #0c0c0c;
        --bg-card: #141414;
        --bg-hover: #1a1a1a;
        --text-bright: #f0f0f0;
        --text-primary: #a8a8a8;
        --text-muted: #5c5c5c;
        --accent: #a78bfa;
        --accent-dim: #8b5cf6;
        --success: #6ee7b7;
        --warning: #fcd34d;
        --error: #fca5a5;
        --border: #222222;
        --border-light: #2e2e2e;
        --focus-ring: #a78bfa;
    }

    /* === Theme: Azure Mist — soft blue light === */
    [data-theme="azure"] {
        --bg-primary: #f0f4f8;
        --bg-panel: #ffffff;
        --bg-card: #e8eef4;
        --bg-hover: #dce4ed;
        --text-bright: #0f172a;
        --text-primary: #334155;
        --text-muted: #64748b;
        --accent: #0284c7;
        --accent-dim: #0369a1;
        --success: #059669;
        --warning: #d97706;
        --error: #dc2626;
        --border: #cbd5e1;
        --border-light: #e2e8f0;
        --focus-ring: #0284c7;
    }

    /* === Theme: High Contrast Dark === */
    [data-theme="hc-dark"] {
        --bg-primary: #000000;
        --bg-panel: #000000;
        --bg-card: #0a0a0a;
        --bg-hover: #1a1a1a;
        --text-bright: #ffffff;
        --text-primary: #ffffff;
        --text-muted: #d0d0d0;
        --accent: #1aebff;
        --accent-dim: #00b7cc;
        --success: #3ff23f;
        --warning: #ffff00;
        --error: #ff0000;
        --border: #6fc3df;
        --border-light: #6fc3df;
        --focus-ring: #f38518;
    }

    /* === Theme: High Contrast Light === */
    [data-theme="hc-light"] {
        --bg-primary: #ffffff;
        --bg-panel: #ffffff;
        --bg-card: #f0f0f0;
        --bg-hover: #e0e0e0;
        --text-bright: #000000;
        --text-primary: #292929;
        --text-muted: #5a5a5a;
        --accent: #0f4a85;
        --accent-dim: #0b3a6b;
        --success: #0b7630;
        --warning: #7a6400;
        --error: #b5200d;
        --border: #000000;
        --border-light: #5a5a5a;
        --focus-ring: #0f4a85;
    }

    /* === Animations === */
    @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: none; } }
    @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }

    /* === Base reset === */
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
        font-family: 'Segoe UI Variable', 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
        background: var(--bg-primary);
        color: var(--text-primary);
        height: 100vh;
        overflow: hidden;
        font-size: 13px;
        -webkit-font-smoothing: antialiased;
        -moz-osx-font-smoothing: grayscale;
    }

    /* === Focus === */
    :focus-visible {
        outline: 2px solid var(--focus-ring);
        outline-offset: 1px;
    }
    button:focus-visible, select:focus-visible, textarea:focus-visible {
        outline: 2px solid var(--focus-ring);
        outline-offset: 1px;
    }

    /* === Top bar === */
    .topbar {
        height: var(--header-h);
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 0 16px;
        border-bottom: 1px solid var(--border);
        background: var(--bg-panel);
        flex-shrink: 0;
    }
    .topbar-left { display: flex; align-items: center; gap: 10px; }
    .topbar-brand {
        display: flex;
        align-items: center;
    }
    .topbar-title {
        font-size: 13px;
        font-weight: 600;
        color: var(--text-bright);
        letter-spacing: 0.4px;
    }
    .topbar-right { display: flex; align-items: center; gap: 8px; }
    .status-dot {
        width: 7px; height: 7px; border-radius: 50%;
        background: var(--success);
    }
    .status-dot:not(.disconnected) { animation: pulse 2s ease infinite; }
    .status-dot.disconnected { background: var(--error); animation: none; }
    .status-label { font-size: 11px; color: var(--text-muted); }
    .staleness { font-size: 10px; color: var(--text-muted); }
    .theme-selector {
        background: var(--bg-card);
        color: var(--text-primary);
        border: 1px solid var(--border);
        border-radius: 4px;
        padding: 3px 6px;
        font-size: 11px;
        font-family: inherit;
        cursor: pointer;
    }
    .theme-selector:hover { border-color: var(--accent); }
    .help-trigger {
        background: none; border: 1px solid var(--border);
        border-radius: 4px; width: 26px; height: 26px;
        cursor: pointer; font-size: 12px; color: var(--text-muted);
        display: flex; align-items: center; justify-content: center;
    }
    .help-trigger:hover { background: var(--bg-hover); color: var(--text-primary); }

    /* === Grid shell === */
    .grid-shell {
        display: grid;
        height: calc(100vh - var(--header-h));
        grid-template-columns: 1fr 1.6fr 1fr;
        grid-template-rows: auto 1fr;
        gap: var(--gap);
        padding: var(--gap);
        animation: fadeIn 0.3s ease;
    }

    /* === Panels === */
    .panel {
        background: var(--bg-panel);
        border: 1px solid var(--border);
        border-radius: var(--radius);
        display: flex;
        flex-direction: column;
        overflow: hidden;
        min-height: 0;
        box-shadow: 0 1px 3px rgba(0,0,0,0.15);
    }
    .panel-hdr {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 6px 10px;
        border-bottom: 1px solid var(--border);
        flex-shrink: 0;
    }
    .panel-title {
        font-size: 10px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.8px;
        color: var(--text-muted);
    }
    .panel-body {
        flex: 1;
        padding: 8px 10px;
        overflow-y: auto;
        min-height: 0;
    }
    .panel-body::-webkit-scrollbar { width: 4px; }
    .panel-body::-webkit-scrollbar-thumb { background: var(--border-light); border-radius: 2px; }
    .panel-body { scrollbar-width: thin; scrollbar-color: var(--border-light) transparent; }

    /* === Metric cards === */
    .metric-row {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: var(--gap);
    }
    .metric-card {
        background: var(--bg-card);
        border-radius: var(--radius);
        padding: 10px 12px;
        text-align: center;
        border-top: 2px solid var(--accent);
    }
    .metric-val {
        font-size: 26px;
        font-weight: 700;
        font-variant-numeric: tabular-nums;
        line-height: 1.2;
    }
    .metric-lbl {
        font-size: 9px;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-top: 2px;
    }
    .metric-trend {
        font-size: 9px;
        margin-left: 4px;
        font-variant-numeric: tabular-nums;
    }
    .c-ok { color: var(--success); }
    .c-warn { color: var(--warning); }
    .c-err { color: var(--error); }
    .c-accent { color: var(--accent); }
    .c-text { color: var(--text-bright); }

    /* === SLO banner (spans full width, row 1) === */
    .slo-banner {
        grid-column: 1 / -1;
        box-shadow: 0 2px 6px rgba(0,0,0,0.2);
    }

    /* === Topology (center column) === */
    .topology-panel { grid-column: 2; }
    #topology-svg { width: 100%; height: 100%; display: block; }
    .node circle { cursor: pointer; transition: r 0.2s; }
    .node circle:hover { r: 24; }
    .link { stroke: var(--border-light); stroke-opacity: 0.5; stroke-width: 1.5; }
    .node-label {
        font-size: 9px;
        fill: var(--text-muted);
        pointer-events: none;
        text-anchor: middle;
    }

    /* === Stat rows === */
    .stat-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 5px 0;
        border-bottom: 1px solid var(--border);
    }
    .stat-row:last-child { border-bottom: none; }
    .stat-label { color: var(--text-muted); font-size: 11px; }
    .stat-value { font-weight: 600; font-size: 13px; font-variant-numeric: tabular-nums; }

    /* === Policy table === */
    .policy-row {
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 4px 0;
        border-bottom: 1px solid var(--border);
        font-size: 11px;
    }
    .policy-row:last-child { border-bottom: none; }
    .action-badge {
        display: inline-block;
        padding: 2px 6px;
        border-radius: 3px;
        font-size: 9px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.3px;
    }
    .badge-deny { background: rgba(239,68,68,0.15); color: var(--error); }
    .badge-block { background: rgba(239,68,68,0.15); color: var(--error); }
    .badge-allow { background: rgba(34,197,94,0.15); color: var(--success); }
    .badge-audit { background: rgba(0,102,255,0.15); color: var(--accent); }

    /* === Audit list === */
    .audit-row {
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 4px 0;
        border-bottom: 1px solid var(--border);
        font-size: 11px;
    }
    .audit-row:last-child { border-bottom: none; }
    .sev-badge {
        display: inline-block;
        padding: 1px 5px;
        border-radius: 3px;
        font-size: 8px;
        font-weight: 700;
        text-transform: uppercase;
    }
    .sev-critical { background: rgba(239,68,68,0.15); color: var(--error); }
    .sev-warning { background: rgba(234,179,8,0.15); color: var(--warning); }
    .sev-info { background: rgba(0,102,255,0.1); color: var(--text-muted); }
    .audit-action { font-weight: 500; color: var(--text-bright); min-width: 60px; }
    .audit-time { color: var(--text-muted); font-size: 10px; margin-left: auto; white-space: nowrap; }
    .audit-detail { color: var(--text-muted); font-size: 10px; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

    /* === Kernel agents === */
    .agent-row {
        display: flex; align-items: center; gap: 6px;
        padding: 3px 0; border-bottom: 1px solid var(--border); font-size: 11px;
    }
    .agent-row:last-child { border-bottom: none; }
    .agent-dot { width: 6px; height: 6px; border-radius: 50%; }
    .agent-dot.running { background: var(--success); }
    .agent-dot.paused { background: var(--warning); }
    .agent-dot.stopped, .agent-dot.error { background: var(--error); }
    .agent-name { font-weight: 500; color: var(--text-bright); }
    .agent-id { font-family: monospace; color: var(--text-muted); font-size: 10px; }
    .agent-meta { color: var(--text-muted); font-size: 10px; margin-left: auto; }

    /* === VFS tree === */
    .vfs-node {
        display: flex; align-items: center; gap: 4px;
        padding: 2px 0; font-size: 11px; font-family: monospace;
        color: var(--text-primary); cursor: default;
    }
    .vfs-icon { color: var(--text-muted); font-size: 10px; width: 12px; text-align: center; }

    /* === Help panel === */
    .help-panel {
        position: fixed; top: 0; right: 0; bottom: 0; width: 360px;
        background: var(--bg-primary); border-left: 1px solid var(--border);
        z-index: 200; transform: translateX(100%); transition: transform 0.15s ease;
        display: flex; flex-direction: column;
    }
    .help-panel.visible { transform: translateX(0); }
    .help-header {
        display: flex; justify-content: space-between; align-items: center;
        padding: 10px 14px; border-bottom: 1px solid var(--border);
    }
    .help-header h2 { font-size: 13px; color: var(--text-bright); }
    .help-close-btn {
        background: none; border: none; font-size: 16px;
        cursor: pointer; color: var(--text-primary); padding: 2px 6px;
    }
    .help-search {
        margin: 8px 14px; padding: 5px 8px;
        background: var(--bg-card); border: 1px solid var(--border);
        border-radius: 4px; color: var(--text-primary); font-size: 11px;
    }
    .help-body {
        flex: 1; overflow-y: auto; padding: 14px;
        font-size: 11px; line-height: 1.6;
    }
    .help-body h2 { font-size: 12px; margin: 14px 0 6px; color: var(--text-bright); }
    .help-body p { margin: 0 0 6px; }
    .help-body strong { color: var(--text-bright); }
    .help-body table { width: 100%; border-collapse: collapse; margin: 6px 0; }
    .help-body td, .help-body th {
        padding: 4px 6px; border-bottom: 1px solid var(--border);
        text-align: left; font-size: 10px;
    }
    .help-body th { color: var(--text-bright); }

    /* === Inline tab strip === */
    .tab-strip {
        display: flex; gap: 0;
        border-bottom: 1px solid var(--border);
        flex-shrink: 0;
    }
    .tab-btn {
        flex: 1;
        padding: 6px 0;
        background: none;
        border: none;
        border-bottom: 2px solid transparent;
        cursor: pointer;
        font-size: 10px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.6px;
        color: var(--text-muted);
        transition: color 0.15s, border-color 0.15s, background 0.15s;
    }
    .tab-btn:hover { color: var(--text-primary); background: var(--bg-hover); }
    .tab-btn.active {
        color: var(--accent);
        border-bottom-color: var(--accent);
        background: var(--bg-card);
    }
    .tab-pane { display: none; flex: 1; overflow-y: auto; min-height: 0; }
    .tab-pane.active { display: flex; flex-direction: column; }

    /* === Compound panels (panels with tabs) === */
    .compound-panel { display: flex; flex-direction: column; }

    /* === Policy Editor === */
    .pe-toolbar {
        display: flex; align-items: center; gap: 6px;
        padding: 6px 10px;
        border-bottom: 1px solid var(--border);
        flex-shrink: 0;
        flex-wrap: wrap;
    }
    .pe-toolbar select, .pe-toolbar button {
        font-size: 11px; font-family: inherit;
        padding: 3px 8px; border-radius: 4px;
        cursor: pointer;
    }
    .pe-toolbar select {
        background: var(--bg-card); color: var(--text-primary);
        border: 1px solid var(--border);
    }
    .pe-toolbar button {
        background: var(--accent); color: #fff;
        border: none; font-weight: 600;
    }
    .pe-toolbar button:hover { background: var(--accent-dim); }
    .pe-toolbar button.secondary {
        background: var(--bg-card); color: var(--text-primary);
        border: 1px solid var(--border);
    }
    .pe-toolbar button.secondary:hover { background: var(--bg-hover); }
    #tab-editor {
        overflow: hidden;
    }
    #tab-editor.active {
        display: flex;
        flex-direction: column;
    }
    .pe-editor-wrap {
        display: flex;
        flex: 1;
        min-height: 0;
        overflow: hidden;
    }
    .pe-lines {
        width: 36px;
        padding: 8px 4px;
        background: var(--bg-card);
        color: var(--text-muted);
        font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace;
        font-size: 12px;
        line-height: 1.5;
        text-align: right;
        user-select: none;
        border-right: 1px solid var(--border);
        overflow: hidden;
        flex-shrink: 0;
        white-space: pre;
    }
    .pe-editor {
        flex: 1;
        width: 0;
        padding: 8px 10px;
        font-family: 'Cascadia Code', 'Consolas', 'Courier New', monospace;
        font-size: 12px;
        line-height: 1.5;
        background: var(--bg-panel);
        color: var(--text-bright);
        border: none;
        resize: none;
        outline: none;
        overflow: auto;
        white-space: pre;
        word-wrap: normal;
    }
    .pe-results {
        padding: 8px 10px;
        border-top: 1px solid var(--border);
        max-height: 120px;
        overflow-y: auto;
        flex-shrink: 0;
    }
    .pe-msg {
        padding: 4px 8px;
        margin: 2px 0;
        border-radius: 3px;
        font-size: 11px;
        border-left: 3px solid;
    }
    .pe-msg-error { background: rgba(239,68,68,0.08); border-color: var(--error); color: var(--error); }
    .pe-msg-warn { background: rgba(234,179,8,0.08); border-color: var(--warning); color: var(--warning); }
    .pe-msg-ok { background: rgba(34,197,94,0.08); border-color: var(--success); color: var(--success); }
    .pe-test-row {
        display: flex; align-items: center; gap: 6px;
        padding: 3px 8px; margin: 2px 0;
        font-size: 11px; border-radius: 3px;
        background: var(--bg-card);
    }
    .pe-test-dot {
        width: 6px; height: 6px; border-radius: 50%;
    }
    .pe-test-blocked { background: var(--success); }
    .pe-test-allowed { background: var(--error); }

    /* === Filter bar === */
    .filter-bar {
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 4px 0 6px;
        border-bottom: 1px solid var(--border);
        margin-bottom: 4px;
        flex-shrink: 0;
    }
    .filter-input {
        flex: 1;
        padding: 3px 8px;
        background: var(--bg-card);
        color: var(--text-primary);
        border: 1px solid var(--border);
        border-radius: 4px;
        font-size: 11px;
        font-family: inherit;
    }
    .filter-input::placeholder { color: var(--text-muted); }
    .filter-input:focus { border-color: var(--accent); outline: none; }
    .filter-select {
        padding: 3px 6px;
        background: var(--bg-card);
        color: var(--text-primary);
        border: 1px solid var(--border);
        border-radius: 4px;
        font-size: 11px;
        font-family: inherit;
        cursor: pointer;
    }
    .filter-count {
        font-size: 10px;
        color: var(--text-muted);
        white-space: nowrap;
    }

    /* === Empty state === */
    .empty { color: var(--text-muted); font-size: 11px; padding: 12px 0; text-align: center; }
    `;
}
