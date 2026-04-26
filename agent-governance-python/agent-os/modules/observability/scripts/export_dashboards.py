#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Export Agent OS Grafana dashboards to JSON files.

Usage:
    python export_dashboards.py
    
This creates JSON files in the grafana/dashboards/ directory that
can be automatically loaded by Grafana via provisioning.
"""

import json
import os
from pathlib import Path

# Add parent to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agent_os_observability.dashboards import get_grafana_dashboard

DASHBOARDS = [
    "agent-os-overview",
    "agent-os-safety", 
    "agent-os-performance",
    "agent-os-amb",
    "agent-os-cmvk",
]

OUTPUT_DIR = Path(__file__).parent.parent / "grafana" / "dashboards"


def main():
    """Export all dashboards to JSON."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    for name in DASHBOARDS:
        dashboard = get_grafana_dashboard(name)
        output_path = OUTPUT_DIR / f"{name}.json"
        
        with open(output_path, "w") as f:
            json.dump(dashboard, f, indent=2)
        
        panel_count = len(dashboard.get("dashboard", {}).get("panels", []))
        print(f"✓ Exported {name} ({panel_count} panels) → {output_path}")
    
    print(f"\nDone! {len(DASHBOARDS)} dashboards exported to {OUTPUT_DIR}")
    print("\nTo use with Docker Compose:")
    print("  cd agent-governance-python/agent-os/modules/observability")
    print("  docker-compose up -d")
    print("  open http://localhost:3000 (admin/admin)")


if __name__ == "__main__":
    main()
