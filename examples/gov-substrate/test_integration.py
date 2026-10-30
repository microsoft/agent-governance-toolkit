"""Real combined execution and shutdown regression, explicitly enabled by the operator."""

import os

import pytest
from run_example import run
from run_proof import prove


@pytest.mark.skipif(
    not os.environ.get("GOV_SUBSTRATE_SOURCE"),
    reason="set GOV_SUBSTRATE_SOURCE to a clean local v0.7.0 checkout",
)
def test_real_combined_execution_and_shutdown():
    result = prove(os.environ["GOV_SUBSTRATE_SOURCE"])
    assert result["result"] == "PASS"
    assert all(case["passed"] for case in result["cases"])


@pytest.mark.skipif(
    not os.environ.get("GOV_SUBSTRATE_SOURCE"),
    reason="set GOV_SUBSTRATE_SOURCE to a clean local v0.7.0 checkout",
)
def test_minimal_example():
    result = run(os.environ["GOV_SUBSTRATE_SOURCE"])
    assert result["result"] == "PASS"
    assert all(case["passed"] for case in result["cases"])
