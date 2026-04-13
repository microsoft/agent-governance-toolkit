\# AGT verify evidence mode



Branch: wolfe/agt-verify-evidence



Goal:

Make `agt verify` more honest.



Current problem:

`agt verify` checks whether governance components are importable.

That proves code exists.

It does not prove a deployment actually has policies, tools, audit logging, identity, or package evidence configured.



Change:

Add evidence mode.



New CLI:

\- `agt verify`

\- `agt verify --evidence ./agt-evidence.json`

\- `agt verify --evidence ./agt-evidence.json --strict`



Files to change:

\- packages/agent-compliance/src/agent\_compliance/verify.py

\- packages/agent-compliance/src/agent\_compliance/cli/agt.py

\- packages/agent-compliance/tests/test\_integrity\_and\_verify.py

\- packages/agent-compliance/tests/test\_agt\_cli.py

\- docs/tutorials/18-compliance-verification.md



Checks in evidence mode:

\- policy files were reported

\- reported policy files exist

\- loaded policies include deny rule or deny-by-default

\- registered tools were reported

\- audit sink is enabled and has target/path/url

\- identity is enabled

\- package/version manifest exists



Strict mode:

Fail if any evidence check fails.



Commit message:

Add runtime evidence mode to agt verify

