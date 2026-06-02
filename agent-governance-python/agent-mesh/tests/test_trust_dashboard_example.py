# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for the trust dashboard example."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType
from urllib.request import urlopen

EXAMPLE_PATH = Path(__file__).resolve().parents[1] / "examples" / "trust-dashboard" / "dashboard.py"


def _load_dashboard_example() -> ModuleType:
    spec = importlib.util.spec_from_file_location("trust_dashboard_example", EXAMPLE_PATH)
    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_trust_dashboard_uses_text_content_for_untrusted_fields() -> None:
    """Agent names and protocol values should be inserted as text, not HTML."""
    dashboard = _load_dashboard_example()

    assert "tbody.innerHTML" not in dashboard._HTML_PAGE
    assert "nameLabel.textContent=name;" in dashboard._HTML_PAGE
    assert 'protocolCell.textContent=info.protocol ?? "";' in dashboard._HTML_PAGE


def test_trust_dashboard_server_keeps_example_payload_shape() -> None:
    """The example still serves the HTML page and JSON data API."""
    dashboard = _load_dashboard_example()
    agent_name = '<img src=x onerror="alert(1)">'
    protocol = '<svg onload="alert(2)">'

    dashboard.update_data(
        agents={
            agent_name: {
                "score": 900,
                "protocol": protocol,
                "did": "did:web:example.mesh.io",
            }
        },
        history={agent_name: [("12:00", 900)]},
    )

    server = dashboard.start_server(port=0)
    try:
        with urlopen(f"http://127.0.0.1:{server.server_port}/") as response:
            assert response.status == 200
            html = response.read().decode("utf-8")

        with urlopen(f"http://127.0.0.1:{server.server_port}/api/data") as response:
            assert response.status == 200
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        server.server_close()

    assert "AgentMesh Trust Dashboard" in html
    assert payload["agents"][agent_name]["protocol"] == protocol
    assert payload["history"][agent_name] == [["12:00", 900]]
    assert payload["tiers"]["Verified Partner"] == 1
