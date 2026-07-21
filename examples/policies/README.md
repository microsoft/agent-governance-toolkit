# Policy Examples

Sample YAML governance policy files for AgentMesh.

Each file in this directory is a self-contained policy configuration that demonstrates how to express a particular class of security or compliance control using the policy engine. They are intended as starting points — review and adapt them for your environment before deploying to production.

## Using this directory

1. **Browse** the `.yaml` files to find a scenario close to what you need. Each file opens with a comment block describing what it covers and any caveats.
2. **Copy** the file into your own project (or reference it by path) and edit the rules, thresholds, and matchers to fit your requirements.
3. **Load** the policy into an agent workflow via the governance runtime. The [Quickstart](../quickstart/) shows runnable end-to-end examples that consume policies from this directory.

## Policy Packs

Multi-file policy libraries for specific regulatory or enterprise scenarios. Each pack has its own README with file listings, usage, and jurisdiction details.

| Directory | Policies | Description |
|-----------|----------|-------------|
| [`african-regulatory/`](african-regulatory/) | 15 | African regulatory and universal agent safety controls for Nigeria, Kenya, South Africa, Uganda, Tanzania, and Ethiopia. Includes OPA Rego reference implementations and a jurisdiction router. |
| [`india-regulatory/`](india-regulatory/) | 5 | Indian regulatory controls for DPDP, CERT-In, RBI, SEBI, and Aadhaar. Includes OPA Rego reference implementations. |
| [`production/`](production/) | 5 | Ready-to-use enterprise policies (`minimal`, `enterprise`, `healthcare`, `financial`, `strict`) with graduated risk levels. |

For pack-specific loading examples and jurisdiction routing, see the README in each pack directory.

## Policy format

All files here follow the schema defined in [`policy-engine/spec`](../../policy-engine/spec/). Refer to that spec for the full list of supported fields, matchers, and enforcement actions.

## Related

- [Quickstart](../quickstart/) — runnable examples that load policies from this directory
- [Policy Engine tutorial](../../docs/tutorials/01-policy-engine.md) — walkthrough of how policies are evaluated
