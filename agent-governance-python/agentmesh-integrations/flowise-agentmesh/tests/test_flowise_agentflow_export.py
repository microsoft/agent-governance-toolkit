# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression checks for the Flowise 3.1.4 Agentflow template."""

import json
from pathlib import Path


FLOW_PATH = Path(__file__).resolve().parents[4] / "examples" / "flowise-governance" / "flowise-flow.json"


def test_flowise_export_uses_agentflow_nodes_and_runtime_references() -> None:
    flow = json.loads(FLOW_PATH.read_text(encoding="utf-8"))
    nodes = flow["nodes"]
    nodes_by_id = {node["id"]: node for node in nodes}

    assert len(nodes) == 5
    assert {node["type"] for node in nodes} == {"agentFlow"}
    assert set(nodes_by_id) == {
        "startAgentflow_0",
        "customFunctionAgentflow_0",
        "httpAgentflow_0",
        "customFunctionAgentflow_1",
        "directReplyAgentflow_0",
    }
    assert {node["data"]["name"] for node in nodes} == {
        "startAgentflow",
        "customFunctionAgentflow",
        "httpAgentflow",
        "directReplyAgentflow",
    }
    assert nodes_by_id["startAgentflow_0"]["data"]["version"] == 1.4
    assert nodes_by_id["customFunctionAgentflow_0"]["data"]["version"] == 1.1
    assert nodes_by_id["httpAgentflow_0"]["data"]["version"] == 1.1

    for node in nodes:
        assert {"width", "height", "positionAbsolute", "selected", "dragging"} <= node.keys()

    http_inputs = nodes_by_id["httpAgentflow_0"]["data"]["inputs"]
    assert http_inputs["body"] == "{{ customFunctionAgentflow_0.output.content }}"
    assert http_inputs["bodyType"] == "json"

    formatter_inputs = nodes_by_id["customFunctionAgentflow_1"]["data"]["inputs"]
    assert formatter_inputs["customFunctionInputVariables"] == [
        {
            "variableName": "httpResponse",
            "variableValue": "{{ httpAgentflow_0.output.http }}",
        }
    ]
    assert "$httpResponse" in formatter_inputs["customFunctionJavascriptFunction"]
    assert "response.status" in formatter_inputs["customFunctionJavascriptFunction"]

    reply_inputs = nodes_by_id["directReplyAgentflow_0"]["data"]["inputs"]
    assert reply_inputs["directReplyMessage"] == "{{ customFunctionAgentflow_1.output.content }}"
