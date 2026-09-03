from pathlib import Path
from decisionassure_impact.cli import _snapshot
from decisionassure_impact.engine import CounterfactualReplayer
from decisionassure_impact.ingestion import iter_traces

ROOT = Path(__file__).parents[2]
def test_synthetic_replay_has_expected_policy_regressions():
    report = CounterfactualReplayer().replay(iter_traces(ROOT / "data/synthetic/sample_traces.jsonl"), _snapshot(ROOT / "data/synthetic/policy_v4.yaml", ROOT / "data/synthetic/authority_baseline.yaml"), _snapshot(ROOT / "data/synthetic/policy_v5.yaml", ROOT / "data/synthetic/authority_proposed.yaml"))
    assert report.total_decisions == 7
    assert report.affected_decisions == 3
    assert report.transitions["ADMISSIBLE→INADMISSIBLE"] == 3
