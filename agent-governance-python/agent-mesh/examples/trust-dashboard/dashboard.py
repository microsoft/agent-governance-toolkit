# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AgentMesh Trust Score Dashboard (stdlib-only)
=============================================
Serves a self-contained HTML dashboard that visualises trust scores,
score history, and trust-tier distribution for registered agents.

Usage:
    python dashboard.py [--port PORT]

The page auto-refreshes every 5 seconds by polling ``/api/data``.
"""

from __future__ import annotations

import argparse
import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any

# ---------------------------------------------------------------------------
# Shared data store — mutate via ``update_data()``
# ---------------------------------------------------------------------------

_lock = threading.Lock()
_data: dict[str, Any] = {
    "agents": {},      # name -> {score, protocol, did}
    "history": {},     # name -> [(timestamp_iso, score), ...]
    "tiers": {         # tier_name -> count
        "Verified Partner": 0,
        "Trusted": 0,
        "Standard": 0,
        "Probationary": 0,
        "Untrusted": 0,
    },
}

TIER_RANGES = [
    ("Verified Partner", 900, 1000),
    ("Trusted",          700,  899),
    ("Standard",         500,  699),
    ("Probationary",     300,  499),
    ("Untrusted",          0,  299),
]


def _tier_for_score(score: int) -> str:
    for name, lo, hi in TIER_RANGES:
        if lo <= score <= hi:
            return name
    return "Untrusted"


def _recompute_tiers() -> None:
    counts = {name: 0 for name, _, _ in TIER_RANGES}
    for info in _data["agents"].values():
        counts[_tier_for_score(info["score"])] += 1
    _data["tiers"] = counts


def update_data(
    agents: dict[str, dict] | None = None,
    history: dict[str, list] | None = None,
) -> None:
    """Thread-safe update of the shared data store."""
    with _lock:
        if agents is not None:
            _data["agents"] = agents
            _recompute_tiers()
        if history is not None:
            _data["history"] = history


def get_data() -> dict[str, Any]:
    """Return a snapshot of the current data."""
    with _lock:
        return json.loads(json.dumps(_data))


# ---------------------------------------------------------------------------
# HTML page (embedded)
# ---------------------------------------------------------------------------

_HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>AgentMesh Trust Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
  :root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;
        --accent:#58a6ff}
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--text);
       padding:24px}
  h1{text-align:center;margin-bottom:24px;color:var(--accent)}
  .grid{display:grid;gap:20px}
  .two{grid-template-columns:1fr 1fr}
  .card{background:var(--card);border:1px solid var(--border);border-radius:10px;
        padding:20px}
  .card h2{font-size:1rem;margin-bottom:12px;color:var(--accent)}
  canvas{width:100%!important}
  .kpi-row{display:flex;gap:16px;justify-content:center;margin-bottom:20px;
           flex-wrap:wrap}
  .kpi{background:var(--card);border:1px solid var(--border);border-radius:8px;
       padding:14px 28px;text-align:center;min-width:140px}
  .kpi .value{font-size:1.6rem;font-weight:700;color:var(--accent)}
  .kpi .label{font-size:.75rem;color:#8b949e;margin-top:4px}
  .tier-badge{display:inline-block;padding:2px 8px;border-radius:4px;
              font-size:.75rem;font-weight:600;margin-left:6px}
  .tier-verified{background:#1a7f37;color:#fff}
  .tier-trusted{background:#2ea043;color:#fff}
  .tier-standard{background:#d29922;color:#fff}
  .tier-probationary{background:#db6d28;color:#fff}
  .tier-untrusted{background:#da3633;color:#fff}
  #agent-table{width:100%;border-collapse:collapse;font-size:.85rem}
  #agent-table th,#agent-table td{padding:8px 12px;text-align:left;
    border-bottom:1px solid var(--border)}
  #agent-table th{color:#8b949e;font-weight:600}
  .bar-cell{position:relative;height:20px;background:#21262d;border-radius:4px;
            overflow:hidden}
  .bar-fill{height:100%;border-radius:4px;transition:width .4s}
  @media(max-width:860px){.two{grid-template-columns:1fr}}
</style>
</head>
<body>
<h1>&#x1f6e1; AgentMesh Trust Dashboard</h1>
<div class="kpi-row" id="kpis"></div>
<div class="card" style="margin-bottom:20px;overflow-x:auto">
  <h2>Registered Agents</h2>
  <table id="agent-table"><thead><tr>
    <th>Agent</th><th>Protocol</th><th>Score</th><th>Tier</th><th></th>
  </tr></thead><tbody id="agent-tbody"></tbody></table>
</div>
<div class="grid two">
  <div class="card"><h2>Trust Score History</h2>
    <canvas id="historyChart"></canvas></div>
  <div class="card"><h2>Trust Tier Distribution</h2>
    <canvas id="tierChart"></canvas></div>
</div>
<script>
const TIER_COLORS={
  "Verified Partner":"#1a7f37","Trusted":"#2ea043",
  "Standard":"#d29922","Probationary":"#db6d28","Untrusted":"#da3633"};
const TIER_CSS={
  "Verified Partner":"verified","Trusted":"trusted","Standard":"standard",
  "Probationary":"probationary","Untrusted":"untrusted"};
const LINE_COLORS=[
  "#58a6ff","#f78166","#3fb950","#d2a8ff","#79c0ff",
  "#ffa657","#7ee787","#ff7b72","#a5d6ff","#d29922"];

function tierFor(s){
  if(s>=900) return "Verified Partner";
  if(s>=700) return "Trusted";
  if(s>=500) return "Standard";
  if(s>=300) return "Probationary";
  return "Untrusted";
}
function barColor(s){return TIER_COLORS[tierFor(s)];}

let histChart=null, tierChart=null;

function renderKPIs(agents){
  const scores=Object.values(agents).map(a=>a.score);
  const n=scores.length, avg=n? (scores.reduce((a,b)=>a+b,0)/n).toFixed(0) :0;
  const mn=n? Math.min(...scores):0, mx=n? Math.max(...scores):0;
  document.getElementById("kpis").innerHTML=
    kpi("Agents",n)+kpi("Avg Score",avg)+kpi("Min",mn)+kpi("Max",mx);
}
function kpi(label,value){
  return `<div class="kpi"><div class="value">${value}</div><div class="label">${label}</div></div>`;
}

function renderTable(agents){
  const tbody=document.getElementById("agent-tbody");
  const sorted=Object.entries(agents).sort((a,b)=>b[1].score-a[1].score);
  tbody.innerHTML=sorted.map(([name,info])=>{
    const tier=tierFor(info.score);
    const pct=(info.score/1000*100).toFixed(1);
    return `<tr><td><b>${name}</b></td><td>${info.protocol||""}</td>
      <td>${info.score}</td>
      <td><span class="tier-badge tier-${TIER_CSS[tier]}">${tier}</span></td>
      <td style="width:30%"><div class="bar-cell"><div class="bar-fill"
        style="width:${pct}%;background:${barColor(info.score)}"></div></div></td></tr>`;
  }).join("");
}

function renderHistory(history){
  const datasets=[];
  let idx=0;
  for(const[name,pts] of Object.entries(history)){
    datasets.push({
      label:name,
      data:pts.map(p=>({x:p[0],y:p[1]})),
      borderColor:LINE_COLORS[idx%LINE_COLORS.length],
      borderWidth:2,fill:false,tension:.3,pointRadius:0
    });
    idx++;
  }
  if(histChart){histChart.data.datasets=datasets;histChart.update();}
  else{
    histChart=new Chart(document.getElementById("historyChart"),{
      type:"line",data:{datasets},
      options:{responsive:true,
        scales:{x:{type:"category",ticks:{maxTicksToShow:10,color:"#8b949e"}},
                y:{min:0,max:1000,ticks:{color:"#8b949e"},grid:{color:"#21262d"}}},
        plugins:{legend:{labels:{color:"#c9d1d9",boxWidth:12}}}}
    });
  }
}

function renderTiers(tiers){
  const labels=Object.keys(tiers);
  const data=Object.values(tiers);
  const bg=labels.map(l=>TIER_COLORS[l]);
  if(tierChart){tierChart.data.datasets[0].data=data;tierChart.update();}
  else{
    tierChart=new Chart(document.getElementById("tierChart"),{
      type:"doughnut",
      data:{labels,datasets:[{data,backgroundColor:bg,borderWidth:0}]},
      options:{responsive:true,
        plugins:{legend:{labels:{color:"#c9d1d9"}}}}
    });
  }
}

async function refresh(){
  try{
    const r=await fetch("/api/data");
    const d=await r.json();
    renderKPIs(d.agents);
    renderTable(d.agents);
    renderHistory(d.history);
    renderTiers(d.tiers);
  }catch(e){console.error("refresh failed",e);}
}

refresh();
setInterval(refresh,5000);
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    """Serves the HTML page at ``/`` and JSON data at ``/api/data``."""

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/api/data":
            payload = json.dumps(get_data()).encode()
            self._respond(200, "application/json", payload)
        elif self.path in ("/", "/index.html"):
            self._respond(200, "text/html; charset=utf-8", _HTML_PAGE.encode())
        else:
            self._respond(404, "text/plain", b"Not Found")

    def _respond(self, code: int, content_type: str, body: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Silence default request logging."""
        pass


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

def start_server(port: int = 8050) -> HTTPServer:
    """Start the dashboard server in a daemon thread and return the server."""
    server = HTTPServer(("", port), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    print(f"Dashboard running at http://localhost:{port}")
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="AgentMesh Trust Dashboard")
    parser.add_argument("--port", type=int, default=8050)
    args = parser.parse_args()

    # Seed with demo data so the page isn't blank
    _seed_demo_data()
    server = start_server(args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


def _seed_demo_data() -> None:
    """Populate the store with sample agents for standalone use."""
    import datetime as dt
    import random

    random.seed(42)
    agents = {
        "payment-agent":     {"score": 920, "protocol": "A2A",  "did": "did:web:payments.mesh.io"},
        "customer-service":  {"score": 870, "protocol": "A2A",  "did": "did:web:cs.mesh.io"},
        "data-analyst":      {"score": 810, "protocol": "MCP",  "did": "did:web:analytics.mesh.io"},
        "fraud-detector":    {"score": 940, "protocol": "IATP", "did": "did:web:fraud.mesh.io"},
        "inventory-manager": {"score": 720, "protocol": "MCP",  "did": "did:web:inventory.mesh.io"},
        "email-dispatcher":  {"score": 650, "protocol": "A2A",  "did": "did:web:email.mesh.io"},
        "auth-gateway":      {"score": 950, "protocol": "IATP", "did": "did:web:auth.mesh.io"},
        "report-generator":  {"score": 580, "protocol": "MCP",  "did": "did:web:reports.mesh.io"},
        "scheduler":         {"score": 780, "protocol": "A2A",  "did": "did:web:scheduler.mesh.io"},
        "compliance-bot":    {"score": 890, "protocol": "IATP", "did": "did:web:compliance.mesh.io"},
    }

    now = dt.datetime.now(dt.timezone.utc)
    history: dict[str, list] = {}
    for name, info in agents.items():
        pts = []
        score = info["score"]
        for i in range(48):
            t = now - dt.timedelta(minutes=15 * (47 - i))
            score = max(0, min(1000, score + random.randint(-15, 15)))
            pts.append((t.strftime("%H:%M"), score))
        # Reset final score to the canonical value
        pts[-1] = (pts[-1][0], info["score"])
        history[name] = pts

    update_data(agents=agents, history=history)


if __name__ == "__main__":
    main()
