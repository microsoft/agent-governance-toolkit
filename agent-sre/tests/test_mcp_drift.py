# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for MCP Tool Drift Detection.

Covers: ToolSchema, ToolSnapshot, DriftDetector, DriftAlert, DriftReport.
"""


from agent_sre.integrations.mcp import (
    DriftDetector,
    DriftSeverity,
    DriftType,
    ToolSchema,
    ToolSnapshot,
)

# =============================================================================
# ToolSchema
# =============================================================================


class TestToolSchema:
    def test_basic(self):
        t = ToolSchema(name="search", description="Search docs")
        assert t.name == "search"
        assert t.description == "Search docs"

    def test_fingerprint_deterministic(self):
        t = ToolSchema(name="search", description="desc", parameters={"q": {"type": "string"}})
        fp1 = t.fingerprint()
        fp2 = t.fingerprint()
        assert fp1 == fp2

    def test_fingerprint_changes_with_content(self):
        t1 = ToolSchema(name="search", description="v1")
        t2 = ToolSchema(name="search", description="v2")
        assert t1.fingerprint() != t2.fingerprint()

    def test_to_dict(self):
        t = ToolSchema(name="calc", parameters={"x": {"type": "number"}}, required=["x"])
        d = t.to_dict()
        assert d["name"] == "calc"
        assert "x" in d["parameters"]
        assert "x" in d["required"]

    def test_from_dict(self):
        d = {"name": "calc", "description": "Calculator", "parameters": {}, "required": []}
        t = ToolSchema.from_dict(d)
        assert t.name == "calc"


# =============================================================================
# ToolSnapshot
# =============================================================================


class TestToolSnapshot:
    def test_tool_names(self):
        s = ToolSnapshot(
            server_id="mcp-1",
            tools=[ToolSchema(name="a"), ToolSchema(name="b")],
        )
        assert s.tool_names == {"a", "b"}

    def test_get_tool(self):
        s = ToolSnapshot(
            server_id="mcp-1",
            tools=[ToolSchema(name="search"), ToolSchema(name="calc")],
        )
        assert s.get_tool("search") is not None
        assert s.get_tool("missing") is None

    def test_fingerprint(self):
        s = ToolSnapshot(
            server_id="mcp-1",
            tools=[ToolSchema(name="a"), ToolSchema(name="b")],
        )
        assert len(s.fingerprint()) == 16

    def test_to_dict(self):
        s = ToolSnapshot(
            server_id="mcp-1",
            tools=[ToolSchema(name="search")],
        )
        d = s.to_dict()
        assert d["server_id"] == "mcp-1"
        assert len(d["tools"]) == 1


# =============================================================================
# DriftDetector
# =============================================================================


class TestDriftDetector:
    def _make_snapshot(self, server_id="mcp-1", tools=None):
        return ToolSnapshot(server_id=server_id, tools=tools or [])

    def test_first_snapshot_no_drift(self):
        d = DriftDetector()
        s = self._make_snapshot(tools=[ToolSchema(name="search")])
        report = d.compare(s)
        assert not report.has_drift

    def test_no_changes_no_drift(self):
        d = DriftDetector()
        s1 = self._make_snapshot(tools=[ToolSchema(name="search", description="Search")])
        d.set_baseline(s1)
        s2 = self._make_snapshot(tools=[ToolSchema(name="search", description="Search")])
        report = d.compare(s2)
        assert not report.has_drift

    def test_tool_removed(self):
        d = DriftDetector()
        d.set_baseline(self._make_snapshot(tools=[
            ToolSchema(name="search"), ToolSchema(name="calc"),
        ]))
        report = d.compare(self._make_snapshot(tools=[ToolSchema(name="search")]))
        assert report.has_drift
        assert report.critical_count >= 1
        removed = [a for a in report.alerts if a.drift_type == DriftType.TOOL_REMOVED]
        assert len(removed) == 1
        assert removed[0].tool_name == "calc"

    def test_tool_added(self):
        d = DriftDetector()
        d.set_baseline(self._make_snapshot(tools=[ToolSchema(name="search")]))
        report = d.compare(self._make_snapshot(tools=[
            ToolSchema(name="search"), ToolSchema(name="new_tool"),
        ]))
        assert report.has_drift
        added = [a for a in report.alerts if a.drift_type == DriftType.TOOL_ADDED]
        assert len(added) == 1
        assert added[0].severity == DriftSeverity.WARNING

    def test_description_changed(self):
        d = DriftDetector()
        d.set_baseline(self._make_snapshot(tools=[
            ToolSchema(name="search", description="v1"),
        ]))
        report = d.compare(self._make_snapshot(tools=[
            ToolSchema(name="search", description="v2"),
        ]))
        assert report.has_drift
        desc = [a for a in report.alerts if a.drift_type == DriftType.DESCRIPTION_CHANGED]
        assert len(desc) == 1
        assert desc[0].severity == DriftSeverity.INFO

    def test_parameter_added(self):
        d = DriftDetector()
        d.set_baseline(self._make_snapshot(tools=[
            ToolSchema(name="search", parameters={"q": {"type": "string"}}),
        ]))
        report = d.compare(self._make_snapshot(tools=[
            ToolSchema(
                name="search",
                parameters={"q": {"type": "string"}, "limit": {"type": "number"}},
            ),
        ]))
        assert report.has_drift
        added = [a for a in report.alerts if a.drift_type == DriftType.PARAMETER_ADDED]
        assert len(added) == 1
        assert added[0].tool_name == "search"

    def test_required_parameter_added_is_critical(self):
        d = DriftDetector()
        d.set_baseline(self._make_snapshot(tools=[
            ToolSchema(name="search", parameters={"q": {"type": "string"}}, required=["q"]),
        ]))
        report = d.compare(self._make_snapshot(tools=[
            ToolSchema(
                name="search",
                parameters={"q": {"type": "string"}, "api_key": {"type": "string"}},
                required=["q", "api_key"],
            ),
        ]))
        critical_params = [
            a for a in report.alerts
            if a.drift_type == DriftType.PARAMETER_ADDED and a.severity == DriftSeverity.CRITICAL
        ]
        assert len(critical_params) >= 1

    def test_parameter_removed(self):
        d = DriftDetector()
        d.set_baseline(self._make_snapshot(tools=[
            ToolSchema(name="search", parameters={"q": {"type": "string"}, "limit": {"type": "number"}}),
        ]))
        report = d.compare(self._make_snapshot(tools=[
            ToolSchema(name="search", parameters={"q": {"type": "string"}}),
        ]))
        removed = [a for a in report.alerts if a.drift_type == DriftType.PARAMETER_REMOVED]
        assert len(removed) == 1
        assert removed[0].severity == DriftSeverity.CRITICAL

    def test_type_changed(self):
        d = DriftDetector()
        d.set_baseline(self._make_snapshot(tools=[
            ToolSchema(name="calc", parameters={"x": {"type": "string"}}),
        ]))
        report = d.compare(self._make_snapshot(tools=[
            ToolSchema(name="calc", parameters={"x": {"type": "number"}}),
        ]))
        type_changes = [a for a in report.alerts if a.drift_type == DriftType.TYPE_CHANGED]
        assert len(type_changes) == 1
        assert type_changes[0].severity == DriftSeverity.CRITICAL

    def test_required_changed(self):
        d = DriftDetector()
        d.set_baseline(self._make_snapshot(tools=[
            ToolSchema(name="search", parameters={"q": {}, "limit": {}}, required=["q"]),
        ]))
        report = d.compare(self._make_snapshot(tools=[
            ToolSchema(name="search", parameters={"q": {}, "limit": {}}, required=["q", "limit"]),
        ]))
        req_changes = [a for a in report.alerts if a.drift_type == DriftType.REQUIRED_CHANGED]
        assert len(req_changes) == 1

    def test_multiple_changes(self):
        d = DriftDetector()
        d.set_baseline(self._make_snapshot(tools=[
            ToolSchema(name="search", description="v1", parameters={"q": {"type": "string"}}),
            ToolSchema(name="calc"),
        ]))
        report = d.compare(self._make_snapshot(tools=[
            ToolSchema(name="search", description="v2", parameters={"q": {"type": "number"}}),
            # calc removed, new_tool added
            ToolSchema(name="new_tool"),
        ]))
        assert report.has_drift
        assert len(report.alerts) >= 3  # description, type, removed, added

    def test_update_baseline(self):
        d = DriftDetector()
        s1 = self._make_snapshot(tools=[ToolSchema(name="a")])
        d.set_baseline(s1)
        s2 = self._make_snapshot(tools=[ToolSchema(name="b")])
        report = d.compare(s2)
        assert report.has_drift

        # Accept drift as new baseline
        d.update_baseline(s2)
        s3 = self._make_snapshot(tools=[ToolSchema(name="b")])
        report = d.compare(s3)
        assert not report.has_drift

    def test_history(self):
        d = DriftDetector()
        d.set_baseline(self._make_snapshot(tools=[ToolSchema(name="a")]))
        d.compare(self._make_snapshot(tools=[ToolSchema(name="a")]))
        d.compare(self._make_snapshot(tools=[ToolSchema(name="b")]))
        assert len(d.history) == 2

    def test_stats(self):
        d = DriftDetector()
        d.set_baseline(self._make_snapshot(tools=[ToolSchema(name="a")]))
        d.compare(self._make_snapshot(tools=[ToolSchema(name="a")]))
        d.compare(self._make_snapshot(tools=[ToolSchema(name="b")]))
        stats = d.get_stats()
        assert stats["servers_tracked"] == 1
        assert stats["total_comparisons"] == 2
        assert stats["drift_detected"] == 1

    def test_report_to_dict(self):
        d = DriftDetector()
        d.set_baseline(self._make_snapshot(tools=[ToolSchema(name="a")]))
        report = d.compare(self._make_snapshot(tools=[ToolSchema(name="b")]))
        rd = report.to_dict()
        assert "has_drift" in rd
        assert "alerts" in rd
        assert rd["has_drift"] is True

    def test_multi_server(self):
        d = DriftDetector()
        d.set_baseline(self._make_snapshot(server_id="s1", tools=[ToolSchema(name="a")]))
        d.set_baseline(self._make_snapshot(server_id="s2", tools=[ToolSchema(name="b")]))

        r1 = d.compare(self._make_snapshot(server_id="s1", tools=[ToolSchema(name="a")]))
        r2 = d.compare(self._make_snapshot(server_id="s2", tools=[ToolSchema(name="c")]))

        assert not r1.has_drift
        assert r2.has_drift
