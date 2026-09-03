# DecisionAssure Impact

## Counterfactual Governance Replay & Change-Impact Engine

Governance changes have blast radius. DecisionAssure Impact replays supplied historical traces against baseline and proposed governance snapshots, then reports which decisions change state before deployment. It is offline, deterministic, and uses a constrained data DSL—never `eval` or an LLM.

```text
baseline → historical traces → proposed governance → replay → impact → risk → decision
```

## Quickstart

```bash
python -m pip install -e '.[dev]'
decisionassure-impact impact --traces data/synthetic/sample_traces.jsonl \
  --policy-current data/synthetic/policy_v4.yaml --policy-proposed data/synthetic/policy_v5.yaml \
  --authority-current data/synthetic/authority_baseline.yaml --authority-proposed data/synthetic/authority_proposed.yaml
```

The included bank fixture is explicitly **SYNTHETIC** and deterministic. `--format json` and `--format html` produce machine-readable and HTML reports. `--ci` exits 1 when the gate blocks; input/configuration errors exit 2.

Real JSON/JSONL data must supply a decision ID, timestamp, action, authority reference, relevant context, and evidence references. Missing information remains unknown or inadmissible according to supplied requirements—it is never assumed valid. See `docs/` for architecture, CI, real-data mapping, and limitations.
