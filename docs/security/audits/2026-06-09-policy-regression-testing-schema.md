# 2026-06-09 — Policy Regression Testing: `agt test` and UTF-8 Schema Fix

PR: [microsoft/agent-governance-toolkit#2869](https://github.com/microsoft/agent-governance-toolkit/pull/2869)

## What changed and why

This PR introduces two things that touch the `agent_os/policies/` path:

### 1. UTF-8 encoding fix in `schema.py`

`PolicyDocument.from_yaml` and `PolicyDocument.from_json` previously opened
files with the platform default encoding returned by the `locale` module.
On Windows this can be `cp1252`, causing `UnicodeDecodeError` for policy files
that contain non-ASCII characters (e.g. Korean or Arabic policy descriptions).
Both methods now pass `encoding="utf-8"` explicitly.

This is a correctness fix with no behavioral change on posture-compliant
systems (Linux CI uses UTF-8 by default). It does not alter any policy
evaluation logic, schema shape, or validation rules.

### 2. `agt test` replay engine (`agent_compliance/policy_test.py`, CLI wiring)

New subcommand that loads a directory of JSON/YAML test fixtures, evaluates
each against the current policy rules via `PolicyEvaluator`, and reports
verdict mismatches. Exit code is 0 on all-pass, 1 on any mismatch.

Fixture format:

```json
{
  "id": "unique-name",
  "input": {"action": "sql_execute"},
  "expected_verdict": "deny",
  "expected_rule": "asi02-block-shell-execution"
}
```

The replay engine is read-only with respect to policies: it instantiates
`PolicyEvaluator` and calls `evaluate()` — no policy mutation or privileged
path is exercised.

## Threat model impact

| Dimension | Direction |
|---|---|
| Policy evaluation logic | **Unchanged.** `PolicyEvaluator` and all rule-matching code are not modified. |
| Schema shape / validation | **Unchanged.** The only edit in `schema.py` is `encoding="utf-8"` on two `open()` calls. No fields added, removed, or changed. |
| Policy bypass surface | **Unchanged.** The replay engine is a read path; it has no write access to policies, identity stores, or the Cedar engine. |
| Credential/secret handling | **No new secrets.** Fixture files include fake `sk-` strings as test data for the ASI-03 credential-leak detection rule. These are allowlisted in `.gitleaks.toml`. |
| Authentication / identity / trust | **Unchanged.** No identity, signing, or trust code is modified. |
| Privilege boundaries | **Unchanged.** Execution rings, kill switch, Cedar evaluation, and approval gates are untouched. |
| Information disclosure | **No new paths.** Fixture files contain synthetic data only. The CLI surfaces `FixtureResult` objects; no internal policy state is exposed beyond what `PolicyDecision` already returns. |
| Backward compatibility | **Preserved.** `encoding="utf-8"` is consistent with Python best practice and does not break any existing caller. |

## Test coverage

| File | Purpose |
|---|---|
| `tests/unit/test_policy_test.py` | Full unit coverage of the replay engine: fixture loading (JSON array, YAML scenarios, directory glob), verdict match, verdict mismatch, rule mismatch, boolean `expected_allowed`, audit action, default action, policy directory, fixture directory, exit-code contract. |
| `tests/unit/test_policy_test.py::TestExampleFixtures` | Integration-level replay of all three bundled fixture files against `examples/policy-templates/general-saas.yaml`. All fixtures must pass before merge. |

## Reviewer focus

1. **`schema.py` is a one-line encoding fix per method.** Confirm no
   evaluation logic, field definition, or validator is touched.
2. **Replay engine is read-only.** `policy_test.py` must never write to
   policy files, mutate `PolicyDocument` objects, or call any privileged
   method beyond `PolicyEvaluator.evaluate()`.
3. **Fixture fake credentials.** The `sk-abc123xyz` string in the new
   fixture files is intentional test data for ASI-03. Confirm it is in
   `examples/policy-templates/fixtures/`
   and covered by the `.gitleaks.toml` allowlist.
