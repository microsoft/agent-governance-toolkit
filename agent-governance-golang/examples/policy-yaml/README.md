# Policy from YAML

Loads a five-rule policy from [`policy.yaml`](./policy.yaml) and exercises
it across six actions: a plain `allow`, two conditional rules
(`review` vs `deny` based on a `classification` context value), an
unmatched-condition fall-through to the default deny, a wildcard
(`api.*`) match, and a default-deny catch-all. Then walks a rate-limited
rule (3 calls per minute) past its limit to show `rate_limit` firing.

Covers [`policy.go`](../../packages/agentmesh/policy.go):
`NewPolicyEngine`, `LoadFromYAML`, `Evaluate`, wildcard matching,
condition matching, and rate-limit windowing.

## Run it

```bash
go run .
```

## Expected output

```text
simple allow                                            action=data.read    decision=allow
conditional review                                      action=data.write   decision=review
conditional deny                                        action=data.write   decision=deny
unmatched classification falls through to default deny  action=data.write   decision=deny
wildcard action match                                   action=api.fetch    decision=allow
default deny                                            action=shell:rm     decision=deny

Rate limit demo (api.* rule allows 3 calls / minute):
  call 1: allow
  call 2: allow
  call 3: allow
  call 4: rate_limit
  call 5: rate_limit
```

The rule order in `policy.yaml` matters: rules are evaluated top to
bottom and the first match wins, so the catch-all `"*"` deny must come
last.

## Where to go next

- [`policy-opa-cedar/`](../policy-opa-cedar/) — same `Evaluate` API,
  delegating to OPA/Rego or Cedar instead of native rules.
- [`audit-chain/`](../audit-chain/) — feed each `Evaluate` decision into
  the tamper-evident audit log.
- [`../README.md`](../../README.md) — full SDK overview.
