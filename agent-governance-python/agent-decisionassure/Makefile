.PHONY: test coverage demo
test:
	python -m pytest
coverage:
	python -m pytest --cov=decisionassure_impact
demo:
	decisionassure-impact impact --traces data/synthetic/sample_traces.jsonl --policy-current data/synthetic/policy_v4.yaml --policy-proposed data/synthetic/policy_v5.yaml --authority-current data/synthetic/authority_baseline.yaml --authority-proposed data/synthetic/authority_proposed.yaml
