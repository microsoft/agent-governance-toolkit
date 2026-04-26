# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Minimal web dashboard — polls the hypervisor API and renders agent status.

Uses only stdlib (http.server) so there are no extra dependencies.
Serves a single HTML page on port 8501 that auto-refreshes every 5 seconds.
"""

from __future__ import annotations

import http.server
import json
import os
import urllib.request

API = os.getenv("HYPERVISOR_API", "http://localhost:8000")

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<title>Agent Hypervisor Dashboard</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem; background: #0d1117; color: #c9d1d9; }}
  h1 {{ color: #58a6ff; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
  th, td {{ text-align: left; padding: 0.6rem 1rem; border-bottom: 1px solid #30363d; }}
  th {{ color: #8b949e; }}
  .ring-0 {{ color: #f85149; }}
  .ring-1 {{ color: #d29922; }}
  .ring-2 {{ color: #3fb950; }}
  .ring-3 {{ color: #8b949e; }}
  .health {{ color: #3fb950; font-size: 0.9rem; }}
  .section {{ margin-top: 2rem; }}
  pre {{ background: #161b22; padding: 1rem; border-radius: 6px; overflow-x: auto; }}
</style>
</head>
<body>
<h1>🛡️ Agent Hypervisor Dashboard</h1>
<p class="health">API: {api} — Status: {health_status} — Version: {version}</p>

<div class="section">
<h2>Registered Agents</h2>
<table>
  <tr><th>Agent DID</th><th>Ring</th><th>σ raw</th><th>eff_score</th><th>Session</th></tr>
  {agent_rows}
</table>
</div>

<div class="section">
<h2>Audit Log</h2>
<pre>{audit_log}</pre>
</div>
</body>
</html>
"""


def _fetch_json(path: str) -> list | dict:
    try:
        req = urllib.request.Request(f"{API}{path}")
        with urllib.request.urlopen(req, timeout=3) as resp:
            return json.loads(resp.read())
    except Exception:
        return []


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        health = _fetch_json("/health")
        agents = _fetch_json("/agents")
        audit = _fetch_json("/audit")

        health_status = health.get("status", "unknown") if isinstance(health, dict) else "error"
        version = health.get("version", "?") if isinstance(health, dict) else "?"

        rows = ""
        if isinstance(agents, list):
            for a in agents:
                ring_cls = f"ring-{a.get('ring', 3)}"
                rows += (
                    f"<tr>"
                    f"<td>{a.get('agent_did', '')}</td>"
                    f"<td class='{ring_cls}'>{a.get('ring_name', '')}</td>"
                    f"<td>{a.get('sigma_raw', 0):.2f}</td>"
                    f"<td>{a.get('eff_score', 0):.2f}</td>"
                    f"<td>{a.get('session_id', '')[:12]}…</td>"
                    f"</tr>\n  "
                )

        audit_text = ""
        if isinstance(audit, list):
            for e in audit:
                audit_text += f"[{e.get('timestamp', '')}] {e.get('event', ''):20s} {e.get('agent_did', '')}  {e.get('detail', '')}\n"

        page = HTML.format(
            api=API,
            health_status=health_status,
            version=version,
            agent_rows=rows or "<tr><td colspan='5'>No agents registered</td></tr>",
            audit_log=audit_text or "No audit entries yet.",
        )

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(page.encode())

    def log_message(self, format: str, *args: object) -> None:
        pass  # suppress request logs


def main() -> None:
    server = http.server.HTTPServer(("0.0.0.0", 8501), DashboardHandler)
    print(f"Dashboard running on http://0.0.0.0:8501 (API={API})")
    server.serve_forever()


if __name__ == "__main__":
    main()
