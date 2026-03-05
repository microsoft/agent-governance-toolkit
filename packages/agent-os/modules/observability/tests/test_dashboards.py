# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for dashboard generation (dashboards.py)."""

import sys
import os
import json

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agent_os_observability.dashboards import get_grafana_dashboard, export_dashboard


DASHBOARD_NAMES = [
    "agent-os-overview",
    "agent-os-safety",
    "agent-os-performance",
    "agent-os-amb",
    "agent-os-cmvk",
]


class TestGetGrafanaDashboard:
    def test_overview_dashboard(self):
        d = get_grafana_dashboard("agent-os-overview")
        assert d["dashboard"]["title"] == "Agent OS - Overview"

    def test_safety_dashboard(self):
        d = get_grafana_dashboard("agent-os-safety")
        assert "Safety" in d["dashboard"]["title"] or "safety" in d["dashboard"]["title"].lower()

    def test_performance_dashboard(self):
        d = get_grafana_dashboard("agent-os-performance")
        assert "Performance" in d["dashboard"]["title"] or "performance" in d["dashboard"]["title"].lower()

    def test_amb_dashboard(self):
        d = get_grafana_dashboard("agent-os-amb")
        assert d["dashboard"]["title"] is not None

    def test_cmvk_dashboard(self):
        d = get_grafana_dashboard("agent-os-cmvk")
        assert d["dashboard"]["title"] is not None

    def test_default_returns_overview(self):
        d = get_grafana_dashboard()
        assert d["dashboard"]["uid"] == "agent-os-overview"

    def test_unknown_name_falls_back_to_overview(self):
        d = get_grafana_dashboard("nonexistent-dashboard")
        assert d["dashboard"]["uid"] == "agent-os-overview"


class TestDashboardStructure:
    @pytest.mark.parametrize("name", DASHBOARD_NAMES)
    def test_has_required_grafana_fields(self, name):
        d = get_grafana_dashboard(name)
        dash = d["dashboard"]
        assert "title" in dash
        assert "panels" in dash
        assert isinstance(dash["panels"], list)
        assert "schemaVersion" in dash

    @pytest.mark.parametrize("name", DASHBOARD_NAMES)
    def test_panels_have_required_fields(self, name):
        d = get_grafana_dashboard(name)
        panels = d["dashboard"]["panels"]
        for panel in panels:
            assert "id" in panel, f"Panel missing 'id' in {name}"
            assert "type" in panel, f"Panel missing 'type' in {name}"
            assert "title" in panel, f"Panel missing 'title' in {name}"
            assert "gridPos" in panel, f"Panel missing 'gridPos' in {name}"
            gp = panel["gridPos"]
            for key in ("h", "w", "x", "y"):
                assert key in gp, f"Panel {panel['id']} missing gridPos.{key} in {name}"

    @pytest.mark.parametrize("name", DASHBOARD_NAMES)
    def test_panels_have_targets_with_expr(self, name):
        d = get_grafana_dashboard(name)
        panels = d["dashboard"]["panels"]
        for panel in panels:
            if "targets" in panel:
                for target in panel["targets"]:
                    assert "expr" in target, f"Target missing 'expr' in panel {panel['id']} of {name}"
                    assert "refId" in target, f"Target missing 'refId' in panel {panel['id']} of {name}"

    @pytest.mark.parametrize("name", DASHBOARD_NAMES)
    def test_promql_references_agent_os_metrics(self, name):
        d = get_grafana_dashboard(name)
        panels = d["dashboard"]["panels"]
        for panel in panels:
            if "targets" in panel:
                for target in panel["targets"]:
                    expr = target["expr"]
                    # AMB dashboard uses amb_ prefix; all others use agent_os_
                    if name == "agent-os-amb":
                        assert "agent_os_" in expr or "amb_" in expr, (
                            f"PromQL '{expr}' doesn't reference expected metrics "
                            f"in panel '{panel['title']}' of {name}"
                        )
                    else:
                        assert "agent_os_" in expr, (
                            f"PromQL '{expr}' doesn't reference agent_os_ metrics "
                            f"in panel '{panel['title']}' of {name}"
                        )


class TestExportDashboard:
    def test_writes_json_to_file(self, tmp_path):
        outfile = tmp_path / "dashboard.json"
        export_dashboard("agent-os-overview", str(outfile))
        assert outfile.exists()
        data = json.loads(outfile.read_text())
        assert "dashboard" in data
        assert data["dashboard"]["uid"] == "agent-os-overview"

    def test_export_all_dashboards(self, tmp_path):
        for name in DASHBOARD_NAMES:
            outfile = tmp_path / f"{name}.json"
            export_dashboard(name, str(outfile))
            assert outfile.exists()
            data = json.loads(outfile.read_text())
            assert "dashboard" in data
