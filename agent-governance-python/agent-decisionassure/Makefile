.PHONY: test coverage demo
test:
	python -m pytest
coverage:
	python -m pytest --cov=agent_decisionassure
demo:
	decisionassure impact --traces data/synthetic/sample_traces.jsonl --policy-current data/synthetic/policy_v4.yaml --policy-proposed data/synthetic/policy_v5.yaml --authority-current data/synthetic/authority_baseline.yaml --authority-proposed data/synthetic/authority_proposed.yaml
