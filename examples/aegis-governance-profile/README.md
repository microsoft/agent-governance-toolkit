<!-- cspell:words cedarpy pyyaml startswith stdlib -->

# AEGIS Governance Profile

> **Community-contributed and experimental, not an AGT-endorsed or recommended approach.**
> The governance-profile format demonstrated here is not yet standardized and may evolve based on adopter feedback.

A self-contained example that compiles a single declarative **AEGIS governance profile** (YAML) into equivalent **Cedar** and **Rego** policies suitable for AGT's external policy backends.

The example targets operators who think in domain terms — role, allowed actions, denied actions, resource scope — rather than in authorization-language ASTs, and who want one source of truth that fans out to both of AGT's external policy backends without authoring each by hand.

## Contents

```
aegis-governance-profile/
├── README.md                              # this file
├── compile.py                             # standalone compiler (stdlib + PyYAML only)
├── profile-research-agent.yaml            # sample profile 1
├── profile-customer-support-agent.yaml    # sample profile 2
└── tests/
    ├── __init__.py
    └── test_compilation.py                # 60 tests (4 skipped without cedarpy / opa)
```

## Why both Cedar AND Rego from one source?

A reasonable question — Cedar and Rego are themselves policy languages; what does a third format add?

The two languages are *enforcement* layers: each evaluates a request against a policy and returns a decision. Operators running mixed backends today (Cedar for identity / authorization; Rego for data / resource policy) author each language separately and keep them in sync by hand.

The AEGIS profile is an *authoring* layer above both. It expresses the higher-level concepts that governance and compliance stakeholders work in — *what is this class of agent permitted to do, on what scopes, under what role* — and compiles down to both backends from a single reviewed file. The enforcement plane is unchanged; what changes is where authorization intent is authored, reviewed, and audited.

The profile is complementary to AGT's built-in YAML policy DSL, not a substitute: AGT's DSL is tuned for runtime concerns (PII patterns, token caps, content safety) authored close to the enforcement runtime. The profile is tuned for the authorization-intent layer above that.

## Quick start

The compiler depends only on the Python standard library and `PyYAML`. The tests additionally require `pytest`.

```bash
pip install pyyaml pytest

# Compile the research-agent profile to Cedar + Rego
python compile.py --profile profile-research-agent.yaml --output-dir build/

# Run the test suite
python -m pytest tests/ -v
```

Expected compile output:

```text
[compile] profile-research-agent.yaml -> build/research-agent-standard.cedar (50 lines)
[compile] profile-research-agent.yaml -> build/research-agent-standard.rego  (60 lines)
```

Expected pytest output (without optional Cedar / OPA tools installed):

```text
56 passed, 4 skipped
```

With both optional engines installed (`pip install cedarpy` and `opa` on `$PATH`), all 60 tests run — including engine integration that validates emitted policies against the production Cedar and OPA evaluators on a 90-case input matrix:

```text
60 passed
```

See [Tests](#tests) below for the layered breakdown.

## The profile schema (v1)

```yaml
profile:
  id: research-agent-standard          # human-readable identifier
  version: 1.0.0                       # semantic version of this profile
  description: >                       # short prose summary (used in policy headers)
    Standard governance profile for research-class agents...

principal:
  role: researcher                     # principal role this profile applies to

capabilities:
  allowed_actions:                     # snake_case — mapped to Cedar PascalCase
    - web_search
    - document_read
  denied_actions:
    - file_write
    - shell_exec

resource_scopes:
  allowed_patterns:                    # prefix globs (must end with "/*")
    - "public/*"
    - "research/published/*"
  denied_patterns:
    - "customer/pii/*"
    - "internal/confidential/*"
```

| Field | Type | Notes |
|---|---|---|
| `profile.id` | string | Embedded in emitted Cedar / Rego header for traceability. |
| `profile.version` | string | Semantic version; embedded in emitted policy header. |
| `principal.role` | snake_case string | Compiled as a precondition on every permit/allow rule. |
| `capabilities.allowed_actions` | list of snake_case strings | Each becomes a Cedar `permit` and a Rego `allowed_actions` set member. Mapped to Cedar `Action::"PascalCase"` to match AGT's `_tool_to_cedar_action` convention. |
| `capabilities.denied_actions` | list of snake_case strings | Each becomes a Cedar `forbid` (overrides permit) and a Rego `denied_actions` set member. |
| `resource_scopes.allowed_patterns` | list of prefix globs | Each must end with `/*`. Cedar emits `context.resource_path like "<pattern>"`; Rego emits `startswith(input.resource_path, "<prefix>")`. |
| `resource_scopes.denied_patterns` | list of prefix globs | Same as above, but compiled into forbid / deny rules. |

Validation is strict: the loader rejects unknown top-level keys, type mismatches, empty lists, non-snake-case action names, patterns missing the `/*` suffix, and any overlap between allowed and denied action / pattern sets. See `tests/test_compilation.py::TestLoader` for the negative cases.

## Compilation model

`compile.py` reads a profile and emits two files:

* `<profile-id>.cedar` — `permit(...)` for allowed actions gated on role + allowed scope, `forbid(...)` for denied actions, and a catch-all `forbid` for denied scopes.
* `<profile-id>.rego` — `package agentos.aegis`, `import rego.v1`, `default allow := false`, plus `allowed_actions` / `denied_actions` sets, `allowed_resource_patterns` / `denied_resource_patterns` arrays, and the `allow` rule.

Both outputs are deterministic — the same input profile produces byte-identical output on every run.

### Calling convention (consumer side)

The emitted policies expect the AGT execution context to provide two discriminator fields in addition to the standard `tool_name` / `agent_id`:

| Field | Used by | Purpose |
|---|---|---|
| `principal_role` | both | Compared against the profile's `principal.role`. |
| `resource_path` | both | Matched against allowed / denied scope patterns. Cedar uses `like`; Rego uses `startswith`. |

In Cedar these fields appear under `context.<field>` (AGT's `CedarBackend._build_cedar_request` packs all non-standard keys into the Cedar `context` namespace). In Rego they appear under `input.<field>` directly.

### Output sample (Cedar — research-agent-standard)

```cedar
// AEGIS Governance Profile: research-agent-standard v1.0.0
// Schema: AEGIS profile v1
// Standard governance profile for research-class agents...
//
// Generated by aegis-governance-profile/compile.py — DO NOT EDIT BY HAND.

permit(
    principal,
    action in [
        Action::"WebSearch",
        Action::"DocumentRead",
        Action::"SummarizeText",
        Action::"CiteSource"
    ],
    resource
)
when {
    context.principal_role == "researcher" &&
    (
        context.resource_path like "public/*" ||
        context.resource_path like "research/published/*" ||
        context.resource_path like "research/preprints/*"
    )
};

forbid(
    principal,
    action in [
        Action::"FileWrite",
        Action::"ShellExec",
        Action::"SendExternalEmail",
        Action::"DeleteRecord"
    ],
    resource
);

forbid(
    principal,
    action,
    resource
)
when {
    context.resource_path like "customer/pii/*" ||
    context.resource_path like "internal/confidential/*" ||
    context.resource_path like "finance/private/*"
};
```

### Output sample (Rego — research-agent-standard)

The emitted Rego targets [Rego v1](https://www.openpolicyagent.org/docs/latest/opa-1/) (the current standard since OPA 1.0). It uses `import rego.v1` to opt in explicitly, which keeps the file forward-compatible with OPA 1.x and rejects misuse of the older v0 syntax at parse time.

```rego
package agentos.aegis

import rego.v1

default allow := false

allowed_actions := {
    "web_search",
    "document_read",
    "summarize_text",
    "cite_source",
}

denied_actions := {
    "file_write",
    "shell_exec",
    "send_external_email",
    "delete_record",
}

allowed_resource_patterns := [
    "public/",
    "research/published/",
    "research/preprints/",
]

denied_resource_patterns := [
    "customer/pii/",
    "internal/confidential/",
    "finance/private/",
]

allow if {
    input.principal_role == "researcher"
    allowed_actions[input.tool_name]
    in_allowed_scope
    not in_denied_action
    not in_denied_scope
}

in_allowed_scope if {
    some prefix in allowed_resource_patterns
    startswith(input.resource_path, prefix)
}

in_denied_scope if {
    some prefix in denied_resource_patterns
    startswith(input.resource_path, prefix)
}

in_denied_action if {
    denied_actions[input.tool_name]
}
```

### Production engines vs. AGT built-in fallback

The emitted policies are designed for the *production* Cedar and OPA engines:

* Cedar — [`cedarpy`](https://pypi.org/project/cedarpy/) Python bindings, or the `cedar` CLI.
* Rego — the `opa` CLI (local mode) or a remote OPA server.

The compiler uses idiomatic features — Cedar `when` clauses with `like` patterns, Rego `startswith` — that AGT's *built-in fallback* evaluators (`backends.py::CedarBackend._evaluate_builtin`, `OPABackend._evaluate_builtin`) do not parse. To exercise the emitted policies via AGT, install the production tooling per [AGT's policy backends documentation](../../docs/tutorials/08-opa-rego-cedar-policies.md) and the `CedarBackend` / `OPABackend` will pick them up automatically.

## Tests

The test suite has three layers:

1. **Structural** (always runs) — loader validation, snake-to-PascalCase mapping, presence of every action and pattern in the emitted Cedar / Rego, deterministic output (compile twice, byte-identical).

2. **Oracle equivalence** (always runs) — declares the intended authorization semantics once (the AEGIS oracle) and sweeps an input matrix (3 roles × 5 actions × 3 resource paths = 45 cases per profile, 90 cases total) against both profiles. Verifies that emitted Cedar and emitted Rego both encode the oracle's decision on every case, and that the two backends agree with each other. Uses small in-test simulators that parse the specific output shape; intentionally does not import any AGT internal module.

3. **Integration** (skipped if optional tooling is absent) — when [`cedarpy`](https://pypi.org/project/cedarpy/) is importable, runs the emitted Cedar through the real engine; when `opa` is on `$PATH`, runs the emitted Rego through it. Both compare against the same oracle and matrix used in layer 2. Tests that are skipped report the reason rather than failing.

```bash
# All non-integration tests (default).
python -m pytest tests/ -v

# Include cedarpy integration (auto-detected).
pip install cedarpy
python -m pytest tests/ -v

# Include OPA integration (auto-detected via PATH).
# Install OPA: https://www.openpolicyagent.org/docs/latest/#running-opa
python -m pytest tests/ -v

# Skip OPA explicitly even if installed.
AEGIS_PROFILE_SKIP_OPA=1 python -m pytest tests/ -v
```

## Deliberate v1 omissions

The v1 schema covers actions, principal-role gating, and resource-scope rules. The following capabilities are deliberately *not* included in v1:

| Capability | Why deferred |
|---|---|
| **Delegation rules** (`may_delegate_to`, `max_delegation_depth`) | Cedar entity relationships work cleanly only with a defined `entities.json` schema. Compiling correct delegation policy requires schema authoring beyond the example's scope; shipping a half-implementation would mislead. |
| **Rate limits** (`max_operations_per_hour`) | Properly belongs to AGT's runtime concerns (`TokenBucket` in `agent_os.policies.rate_limiting`) rather than the authorization layer Cedar / Rego enforce. Including it would conflate authoring layers. |
| **Temporal constraints** (business hours, timezone gating) | Both Cedar and Rego support time-based predicates, but cleanly compiling them requires a calendar / timezone model the example does not have. |
| **Human-approval gating** (`require_human_approval_when`) | Belongs to AGT's policy decision pipeline, not the policy text itself. Cedar / Rego return allow / deny; "require approval" is a third decision class better expressed in AGT's `PolicyAction` taxonomy. |

A future v2 could add any of these once the conventions for representing them in Cedar and Rego are settled. v1 prioritizes shipping a small, correct, fully-tested authoring surface over a large, partially-implemented one.

## Non-goals

* **Modifying AGT core packages, schemas, or public APIs.** This example contributes only under `examples/`.
* **Adding new dependencies to AGT's package graph.** The compiler depends on PyYAML (already an AGT dependency) plus the standard library.
* **Replacing AGT's built-in YAML policy DSL.** The profile is a complementary authoring layer; AGT's DSL remains the right tool for runtime / content concerns.
* **Performance claims.** This example demonstrates a pattern, not a benchmark.

## Cleanup

The compiler writes Cedar and Rego files to whatever directory is passed to `--output-dir` (defaulting to `build/` under the example directory). Remove that directory when finished:

```bash
rm -rf build/
```

The example creates no other persistent state — no caches, no temporary files outside the output directory, no environment writes. The test suite uses pytest's `tmp_path` fixture for OPA integration runs, which pytest cleans up automatically.

## License

MIT. See the [repository LICENSE](../../LICENSE).
