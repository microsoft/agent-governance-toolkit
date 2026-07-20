---
title: "ADR 0029: Policy distribution and registries with verifiable trust"
last_reviewed: 2026-06-01
owner: agt-maintainers
---

# ADR 0029: Policy distribution and registries with verifiable trust

- Status: proposed
- Date: 2026-05-29

## Context

AGT today ships a fixed set of YAML policy templates inside the
`agent_os.templates.policies` package and loads them through a path-based
loader (`load_policy_yaml`). Anything beyond that ships out-of-band: copied
into `.agents/`, baked into container images, or hand-rolled per deployment.
Three pressures make this insufficient:

1. **Enterprises need an internal distribution channel.** A platform team
   wants to publish "the corporate HIPAA + cost-cap baseline" once and have
   every agent in the org consume it, with versioning, rollout, and rollback.
2. **A community of policy authors is emerging.** Compliance specialists,
   researchers, and framework integrators want to publish reusable policies
   (FedRAMP, ISO 27001, framework-specific guardrails) the same way the
   Python ecosystem publishes packages.
3. **Sideloading a policy is currently a trust hole.** A file on disk that
   parses as valid YAML is loaded. There is no signature, no publisher
   identity, no content-hash check, and no transparency record. An attacker
   who can write to `.agents/` — or proxy an HTTPS fetch — silently changes
   what governs every agent in the deployment.

AGT already has every primitive needed to close this hole: Ed25519 signing
(ADR-0001), `did:web` federation (ADR-0007), JCS + SHA-256 content hashing
and transparency-log split (ADR-0008), fail-closed policy evaluation
(ADR-0013), parent-deny immutability on merge (ADR-0014), the pluggable-
backend Protocol pattern (ADR-0015), and Merkle audit chaining (ADR-0017).
This ADR composes them rather than introducing new cryptographic primitives.

### Scope boundary vs ADR-0008

ADR-0008 governs **runtime** cross-org policy intersection during a live
agent-to-tool call. This ADR governs **supply-chain distribution** of policy
artifacts *before* runtime. They are independent:

- Importing a bundle from Org Y's registry does **not** establish runtime
  federation with Org Y.
- Establishing runtime federation with Org Y does **not** imply that Y's
  policy registry is trusted as a distribution source.

Operators configure each independently and the loader enforces them
separately.

### Relationship to AGT Studio (issue #2638)

[Issue #2638](https://github.com/microsoft/agent-governance-toolkit/issues/2638)
proposes **AGT Studio**, a unified UI for browsing, authoring, testing,
simulating, versioning, and observing AGT policy. Studio is the natural
consumer of every primitive defined in this ADR:

| Studio capability (per #2638)         | What this ADR provides                                                                                              |
|---------------------------------------|---------------------------------------------------------------------------------------------------------------------|
| Browse all policies                   | Federated browse across local cache + every publisher in `trust.yaml` + resolver-fetchable bundles                  |
| Author policies                       | Author targets a bundle; save → tar + JCS manifest + Ed25519 sign → ready for `agt policies publish`                |
| Test / replay / what-if               | Simulator runs against any resolved bundle in the lockfile, identified by `content_hash`                            |
| Regression view                       | Diff two `content_hash`es of the same `(publisher, name)`; surfaces **derived-capability drift** (§3) as first-class |
| Version both engine and policies      | Lockfile entries *are* the version pin                                                                              |
| Live decisions feed                   | Decision audit events carry the loaded bundle's `content_hash` + `log_index` (§6 step 16); Studio renders provenance |
| Audit log viewer w/ chain integrity   | Studio's badge can additionally show bundle attestation status: signature, log inclusion, no revocation              |
| Evidence export                       | Exports include signed manifest + log inclusion proof + lockfile entry; auditors re-verify offline                  |

New Studio surfaces this ADR implies (not yet enumerated in #2638):

- **Trust-root editor** — visual `trust.yaml` editor (publishers, pinned
  JWK thumbprints, per-capability allowlists, `min_version`, operator-local
  revocations).
- **Bundle inspector** — drop a `.tar` or paste a `policy://` URI; shows
  signature status, declared vs derived capabilities, file diff, transitive
  dependency DAG, and transparency-log evidence.
- **Publisher view** — per `trust.yaml` entry: bundles available, versions
  installed, drift, revocation status, last-fetch timestamp.
- **Resolver health** — configured resolvers, last successful fetch, log
  inclusion latency.

**Scope boundary preserved.** #2638 explicitly excludes write-path runtime
control. This ADR keeps the same boundary: Studio MAY edit `trust.yaml` and
the lockfile *as files* (or open a PR against them), but MUST NOT push
trust-root changes into a running deployment. Promotion to production
remains a config-management / GitOps concern.

### Design constraints

- **Fail closed.** Any failure in resolution, fetch, signature verification,
  archive inspection, or trust-root lookup MUST deny load. Partial policy is
  never applied (ADR-0013).
- **Determinism preserved.** A given `policy://` URI + lockfile entry MUST
  resolve to the same bytes across hosts and time (ADR-0004).
- **One crypto story.** Bundle **authority** is always Ed25519 over a
  JCS-canonical manifest, with publisher identity discovered via `did:web`
  or pinned `did:key`. Sigstore/Rekor and SLSA in-toto attestations are
  permitted **only as provenance evidence**, never as the authority that
  decides whether a bundle is trusted.
- **Sovereign trust roots.** Each deployment decides which publishers it
  trusts. There is no global "AGT-blessed" registry. Default trust set is
  empty.
- **Air-gap friendly.** Enterprises that cannot reach a public transparency
  log MUST be able to operate offline with a pinned signed-checkpoint
  workflow.
- **Composition safety survives distribution.** A merged or imported bundle
  MUST NOT be able to weaken, shadow, or lower the priority of any deny rule
  already present in the effective policy set (ADR-0014, generalized).

## Decision

Introduce a content-addressed, signed **policy bundle** format, a pluggable
**resolver** layer that can fetch bundles from local, HTTPS, OCI, and Git
sources, and a deployment-local **trust root** that gates which publishers a
deployment will accept. A mandatory `agt-policies.lock` file pins resolved
content hashes for reproducible loads.

### 1. Bundle format

A policy bundle is a tar archive containing:

```
manifest.json        # JCS-canonical, see schema below
policies/*.yaml      # one or more policy files
attestations/        # optional: in-toto / SLSA provenance, Rekor inclusion proof
LICENSE              # required
README.md            # optional but recommended
```

`manifest.json` schema:

```python
class PolicyBundleManifest(BaseModel):
    schema_version: Literal[1]
    # Publisher identity — reuses ADR-0007 did:web (preferred) or did:key
    publisher: str                     # e.g. "did:web:policies.contoso.com"
    name: str                          # opaque to AGT; identity is (publisher, name)
    version: str                       # strict semver, no ranges
    # SHA-256 over RAW FILE BYTES, not over parsed YAML. Path keys are
    # normalized POSIX paths relative to bundle root.
    files: dict[str, str]              # path -> sha256 hex
    agt_min_version: str
    requires: list[BundleRef] = []
    # Advisory only — see §3 for the enforceable derived version.
    declares: BundleCapabilities
    created_at: str                    # RFC 3339

class BundleRef(BaseModel):
    publisher: str                     # full DID, never bare name
    name: str
    expected_hash: str                 # REQUIRED — exact content_hash pin
    # No version ranges. A bundle pins exact dependency content hashes.

class BundleCapabilities(BaseModel):
    # Author's declaration — used for human review and tooling diff.
    # NOT trusted by the loader; see §3.
    touches_deny_rules: bool
    touches_allow_rules: bool
    touches_egress: bool
    touches_cost_controls: bool
    touches_content_filters: bool
    requires_human_approval: bool
    declared_compliance: list[str] = []
```

The bundle's **content hash** is `SHA-256(JCS(manifest.json))`. File hashes
inside the manifest are raw-byte SHA-256 of each archive entry — YAML
parsing happens only after verification. This avoids the "two YAML parsers
hash to different things" class of confusion.

A **detached signature** (`manifest.json.sig`) covers the JCS-canonical
manifest using Ed25519 (ADR-0001).

### 2. Safe archive ingestion

Archive handling is in the trust boundary. The loader MUST:

- Stream tar entries and reject **before any filesystem write**:
    - absolute paths, `..` components, backslashes, drive letters,
    - symlinks, hardlinks, devices, FIFOs, sparse entries,
    - duplicate path entries,
    - paths not listed in `manifest.files`,
    - total size > configured `max_bundle_bytes` (default 10 MiB),
    - individual entry > configured `max_file_bytes` (default 2 MiB),
    - entry count > configured `max_files` (default 256).
- Compute `SHA-256` from raw entry bytes as they stream past, and hold
  the verified file contents in an **in-memory map**. Implementations
  SHOULD avoid filesystem extraction entirely. If a temp dir is used, it
  MUST be created with restrictive permissions and populated only after
  every hash matches `manifest.files`.
- Reject the bundle if any file in `manifest.files` is missing or any
  archive entry is unlisted.

### 3. Derived capabilities (the trust lever)

Manifest-declared capabilities are advisory. The loader MUST derive
**effective capabilities** by parsing each policy YAML through AGT's
canonical policy model and inspecting which surfaces are touched:

| Effective capability | Triggered by |
| --- | --- |
| `touches_deny_rules` | any `deny:` entry, any external backend marked deny |
| `touches_allow_rules` | any `allow:` entry |
| `touches_egress` | any rule in the egress namespace |
| `touches_cost_controls` | any `limits:` or cost-policy entry |
| `touches_content_filters` | any content-safety pattern |
| `requires_human_approval` | any `requires_approval: true` |

Enforcement (see §6 step 10) compares **derived** capabilities against
`trust.allow_capabilities`. Any unrecognized policy section, custom
external-backend reference (ADR-0015), or unmapped surface MUST be
treated as `unknown` and **fails the load** unless the publisher's trust
entry explicitly opts into `allow_unknown_capabilities: true`. Defaults
are conservative: a community publisher cannot smuggle changes into deny
rules by hiding them in a section the loader does not classify.

### 4. Resolver Protocol

Resolution is pluggable, mirroring ADR-0015's external-backend pattern:

```python
class PolicyBundleResolver(Protocol):
    @property
    def scheme(self) -> str: ...           # "file", "https", "oci", "gh", "git"

    def resolve(self, uri: str) -> ResolvedBundle: ...
    # MUST return raw bytes + the IMMUTABLE coordinate it actually fetched
    # (OCI digest, git commit SHA, asset digest). MUST NOT verify signatures.
```

Built-in resolvers:

| Scheme | URI form | Immutable coord recorded in lockfile |
| --- | --- | --- |
| `file://` | `file:///etc/agt/bundles/hipaa-1.2.0.tar` | sha256 of bytes |
| `https://` | `https://policies.contoso.com/hipaa/1.2.0.tar` | sha256 of bytes |
| `oci://` | `oci://registry.contoso.com/policies/hipaa:1.2.0` | OCI manifest digest |
| `gh://` | `gh://contoso/policies@v1.2.0#hipaa.tar` | git commit SHA + asset SHA-256 |
| `git+https://` | `git+https://github.com/contoso/policies@v1.2.0` | git commit SHA |

Resolver rules baked into the ADR (not deferred):

- Mutable refs (OCI tags, git tags, GitHub release names) MUST be resolved
  to an immutable coordinate **at install time** and pinned in the
  lockfile. Runtime loading MUST consume only the immutable coordinate.
- Git resolvers MUST do a shallow checkout of a single commit. Submodules
  are **rejected** by default. Git LFS is **not hydrated** by default.
- The path inside a git repo MUST resolve to a single bundle archive whose
  internal manifest is verified by the standard pipeline. Loose
  directory-style bundles are not supported in v1.
- Resolvers MUST NOT perform path traversal of any kind; the archive is
  what gets verified.
- A community registry is just a well-known `https://` or `oci://` resolver
  URL plus a `did:web` (or `did:key`) publisher identity. AGT does not
  operate a registry.

### 5. Trust root (`trust.yaml`)

Each deployment ships a `trust.yaml` consumed on startup. **Default trust
set is empty: with no entry, no bundle loads.**

```yaml
schema_version: 1

# Required when require_transparency_log_entry is true.
transparency_log:
  url: https://rekor.sigstore.dev
  # Pin the LOG's public key. Without this the log is just a remote oracle.
  public_key_thumbprint: "sha256:..."

# Global controls (defaults shown)
require_transparency_log_entry: true
require_provenance_attestation: false      # SLSA v1 in-toto
max_bundle_age_days: 365
max_bundle_bytes: 10485760                 # 10 MiB
max_file_bytes:   2097152                  # 2 MiB
max_files:        256
max_dependency_depth: 4
allow_unknown_capabilities: false          # global default

# Operator-local revocations — evaluated independently of publisher revocations
revoked_content_hashes: []
revoked_key_thumbprints: []

publishers:
  - did: did:web:policies.contoso.com
    # Pin PUBLIC KEY MATERIAL, not kid labels. kid is an identifier only.
    pinned_jwk_thumbprints:
      - "sha256:9f1a..."     # current
      - "sha256:c0de..."     # previous, kept until max_bundle_age_days elapse
    # Optional explicit recovery key for revocation in case of key compromise.
    recovery_key_thumbprints:
      - "sha256:reco..."
    min_version: "1.2.0"     # anti-rollback (mirrors ADR-0008 §3)
    allow_capabilities:
      touches_deny_rules: true
      touches_allow_rules: true
      touches_egress: false  # this publisher may not edit egress
      touches_cost_controls: true
      touches_content_filters: true
      requires_human_approval: true

  - did: did:key:z6Mki...
    pinned_jwk_thumbprints: ["sha256:z6m..."]
    min_version: "0.4.0"
    allow_capabilities:
      touches_deny_rules: false      # community bundles cannot edit deny
      touches_allow_rules: true
      touches_egress: false
      touches_cost_controls: false
      touches_content_filters: true
      requires_human_approval: false
```

**Naming and namespacing.** Bundle identity is always `(publisher_did, name)`.
Resolvers MUST NOT resolve unqualified names across registries. This
neutralizes dependency-confusion / typosquat attacks at the resolver layer.

**AGT as a (potential) publisher.** This design lets the AGT project itself
operate a registry on exactly the same footing as any other publisher — for
example, by signing the templates in `agent_os/templates/policies/` with a
project-owned Ed25519 key and distributing them through GitHub Releases or
GHCR. Whether AGT *should* do this, and which policies belong in such a
"known-good" set, is **out of scope for this ADR** and will be decided with
the community in a follow-up. The relevant decisions there — which
compliance frameworks to bless, what review bar applies before a policy
joins the set, how the project's signing key is custodied — are governance
questions, not architecture questions. This ADR only ensures that *when*
such a registry is created, it requires no special-casing: it is a normal
publisher, gets no automatic trust, no special resolver, and no implicit
place in `trust.yaml`. Operators opt in with `agt policies trust add` the
same way they would for any third-party publisher. The current bundled
`load_policy("hipaa")` path is preserved as a zero-trust convenience for
getting started; deployments that want signed, verifiable, revocable
policies use the bundle + trust-root flow.

**Bootstrap.** `trust.yaml` is the deployment's root of trust configuration.
AGT assumes the file is protected by the platform configuration channel
(OS permissions, image immutability, GitOps, MDM, signed K8s ConfigMap).
The loader MUST audit-log the trust-root path, its SHA-256, and its mtime on
every startup so tampering is observable. Signed trust roots are tracked as
follow-up work.

### 6. Verification pipeline

Every bundle load runs this pipeline. **Any step failing is a hard fail
that denies load** (ADR-0013). No "warn and continue".

```
1. resolve(uri)                       -> raw bytes + immutable coord
 2. safe archive scan (§2)             -> in-memory verified file map
 3. recompute SHA-256(JCS(manifest))   -> content_hash
 4. lookup publisher in trust.yaml     -> trust entry or DENY
 5. operator-local revocation check    -> content_hash, key_thumbprint
 6. fetch publisher did:web doc        -> key set (ADR-0007 cache rules)
 7. verify Ed25519 sig over manifest   -> signing key thumbprint MUST be in
                                          trust.pinned_jwk_thumbprints
 8. verify each file SHA-256 matches manifest.files (raw bytes)
 9. derive effective capabilities (§3) -> derived_caps
10. enforce trust entry:
      derived_caps ⊆ trust.allow_capabilities
      no unknown sections unless allow_unknown_capabilities
      semver(version) >= semver(min_version)
      created_at within max_bundle_age_days
11. if require_transparency_log_entry:
      lookup content_hash in pinned log
      verify log signed by trust.transparency_log.public_key_thumbprint
      verify log timestamp >= bundle.created_at
      verify no superseding revocation entry for this content_hash
12. if require_provenance_attestation: verify SLSA v1 in-toto bundle
13. lockfile (mandatory for mutable resolvers, see §7):
      content_hash MUST equal lockfile[uri].content_hash
      immutable_coord MUST equal lockfile entry
14. transitive deps: resolve and verify the full DAG with the same pipeline,
      respecting max_dependency_depth and rejecting cycles
15. merge with deny-union composition (§9)
16. emit audit event with content_hash, immutable_coord, kid, key_thumbprint,
      log_index, derived_caps; chained into ADR-0017 Merkle audit
17. return parsed policy to runtime
```

### 7. Lockfile (`agt-policies.lock`)

The lockfile is the supply-chain teeth of the design and is **mandatory**
for runtime loading of any non-content-addressed reference. Install may
resolve mutable refs; runtime consumes only what the lockfile pins.

```yaml
schema_version: 1
generated_at: "2026-05-29T18:00:00Z"
bundles:
  - uri: oci://registry.contoso.com/policies/hipaa:1.2.0
    immutable_coord: "oci-digest:sha256:9b...e1"
    publisher: did:web:policies.contoso.com
    name: hipaa-baseline
    version: 1.2.0
    content_hash: "sha256:7e1a...c4"
    signing_key_thumbprint: "sha256:9f1a..."
    log:
      index: 18923441
      # Offline checkpoint for air-gap verification
      signed_tree_head: "sth:..."
      inclusion_proof: "iproof:..."
    resolved_at: "2026-05-29T18:00:00Z"
  # Transitive closure MUST be present.
  - uri: oci://registry.contoso.com/policies/cost-cap:0.4.1
    parent_dependency_of:
      - sha256:7e1a...c4
    immutable_coord: "oci-digest:sha256:af...20"
    publisher: did:web:policies.contoso.com
    name: cost-cap
    version: 0.4.1
    content_hash: "sha256:b0b0...ff"
    signing_key_thumbprint: "sha256:9f1a..."
    log:
      index: 18923442
      signed_tree_head: "sth:..."
      inclusion_proof: "iproof:..."
    resolved_at: "2026-05-29T18:00:00Z"
```

- `agt policies install` populates / updates the lockfile.
- `agt policies verify` and the runtime loader refuse to load a bundle
  whose recomputed `content_hash` does not equal the lockfile value, or
  whose resolved `immutable_coord` does not equal the pinned one.
- CI is expected to fail if `git diff agt-policies.lock` is non-empty
  after `agt policies install`.
- For air-gapped operation, `signed_tree_head` + `inclusion_proof` in the
  lockfile let runtime verify transparency-log inclusion **offline** with
  the log public key pinned in `trust.yaml`. No network call needed.

### 8. Revocation

Revocation has two independent paths.

**Publisher revocation** (normal case): the publisher posts a signed
revocation entry to the transparency log:

```python
class RevocationEntry(BaseModel):
    schema_version: Literal[1]
    revokes_content_hash: str
    reason: Literal["key_compromise", "build_compromise", "policy_error", "deprecated"]
    issued_at: str
    publisher: str
    # Ed25519 over JCS(self minus sig), by a currently trusted, non-revoked
    # key OR by a configured recovery_key_thumbprint. A revocation signed
    # only by an already-revoked key is rejected.
    sig: str
    signing_key_thumbprint: str
```

**Operator-local revocation** (key compromise / emergency): operators add
`content_hash` or `key_thumbprint` entries to `trust.yaml` directly.
These are honored regardless of publisher cooperation, enabling
"the publisher's key is on Pastebin, deny everything signed by it" to be
a one-line config change.

Revocation entries are append-only and cannot themselves be withdrawn. A
mistaken revocation is corrected by publishing a new, non-revoked version.

### 9. Composition with deny-union semantics

ADR-0014 makes parent deny rules immutable in single-tree merge. Extending
to a distribution model with potentially many sibling bundles:

> **For distributed bundles, deny rules compose by union across the entire
> import DAG.** No bundle — imported, sibling, or transitive dependency —
> may remove, override, shadow, lower the priority of, or scope-narrow any
> deny rule already present in the effective policy set. Allows are
> evaluated only after the unioned deny set. If two bundles conflict,
> deny wins.

The loader MUST:

- Compute the union of denies across the full resolved DAG before allowing
  any allows from any bundle.
- Reject the policy set if any imported bundle attempts to *retract* a
  deny that exists in any other bundle in the closure.
- Require deterministic import order (lockfile order) and reject cycles.

This neutralizes the "sibling bundle B silently introduces an allow that
defeats A's deny" attack.

### 10. Transparency log invariants

The log is more than a notarization service; it is the
de-duplication oracle for the bundle namespace:

> The log (or the installer talking to it) MUST reject a second live
> mapping of `(publisher, name, version)` to a different `content_hash`.
> Republishing the same version with different content is a hard error,
> not a supported update path. New content requires a new version.

Combined with `min_version` (anti-rollback) and operator-local revocation
(emergency stop), this closes the "publisher key stolen → attacker
republishes `hipaa@1.2.0`" path.

### 11. Bundle validation limits (DoS)

Even a signed bundle from a fully trusted publisher could exhaust the
evaluator. Validation MUST enforce, with defaults configurable in
`trust.yaml`:

- `max_bundle_bytes` (default 10 MiB)
- `max_file_bytes` (default 2 MiB)
- `max_files` (default 256)
- `max_rules_per_policy` (default 1024)
- `max_regex_length` (default 1024 chars)
- `max_dependency_depth` (default 4)
- Regex compilation uses a safe engine (e.g. RE2 / `regex` crate
  unicode-on, backtracking-off) with per-regex compile and match
  timeouts.
- YAML parsing uses `safe_load` with **duplicate-key rejection** and
  unsafe-tag rejection.

### 12. Loader API surface

Backward-compatible. `load_policy("hipaa")` (current behavior, loads
bundled template) keeps working. New entry points:

```python
load_bundle(uri: str, trust: TrustRoot, lock: LockFile) -> PolicyBundle
install_bundle(uri: str, trust: TrustRoot, lock: LockFile) -> LockEntry
verify_bundle(path: str, trust: TrustRoot) -> VerificationResult
```

CLI:

```
agt policies install  oci://registry.contoso.com/policies/hipaa:1.2.0
agt policies verify   .agents/hipaa-1.2.0.tar
agt policies list
agt policies trust add did:web:policies.contoso.com \
    --pin-jwk-thumbprint sha256:9f1a... --min-version 1.2.0
agt policies trust list
agt policies revoke   sha256:7e1a...c4   # operator-local
agt policies ci       --trust-root trust.yaml --lockfile agt-policies.lock
agt policies ci       --sbom out.cdx.json
```

### 13. CI/CD enforcement: same pipeline, earlier gate

The verification pipeline in §6 is a pure function of
`(bundle bytes, trust.yaml, lockfile)`. Nothing in it requires a live
agent runtime. That means **CI runs the same code path the runtime will
run**, gated against the same trust root and lockfile that will ship with
the application. Defense in depth, with zero rule duplication and zero
chance of drift between build-time and runtime checks.

**Build-time gates** (`agt policies ci`, intended for CI):

```yaml
# .github/workflows/agent-policies.yml (illustrative)
- name: Verify policy supply chain
  run: agt policies ci --trust-root trust.yaml --lockfile agt-policies.lock
```

`agt policies ci` runs the §6 pipeline against every bundle referenced by
the lockfile, plus a set of build-only invariants that are too strict to
enforce at runtime (where some flexibility is needed for emergency
operator action):

| Check                                                              | Build | Runtime |
|--------------------------------------------------------------------|:-----:|:-------:|
| Signature, content hash, derived capabilities (§6 steps 1-10)      |   ✅  |   ✅    |
| Transparency-log inclusion, offline proof valid (§6 step 11)       |   ✅  |   ✅    |
| Provenance attestation verified (if required) (§6 step 12)         |   ✅  |   ✅    |
| Lockfile recomputed hash matches resolver output (§6 step 13)      |   ✅  |   ✅    |
| Transitive DAG verified, cycles rejected (§6 step 14)              |   ✅  |   ✅    |
| Deny-union composition holds across DAG (§9)                       |   ✅  |   ✅    |
| Bundle validation limits (§11) satisfied                           |   ✅  |   ✅    |
| Lockfile is complete (every URI resolved, full transitive closure) |   ✅  |   ❌    |
| No drift: `agt policies install --check` produces no changes       |   ✅  |   ❌    |
| No bundle is *only* unpinned (every `uri` has an `immutable_coord`) |   ✅  |   ❌    |
| No operator-local revocations match any pinned bundle              |   ✅  |   ✅    |
| Optional org policy: minimum signature freshness, min log age      |   ✅  |   ❌    |

Build-only checks are the ones that should never happen in a healthy repo
but are valuable to catch before deployment: a developer edited
`trust.yaml` without re-running `agt policies install`, a dependency was
added to a manifest without being pinned, a previously-trusted bundle has
been revoked since the last build.

**SBOM emission.** `agt policies ci --sbom out.json` emits a
CycloneDX-shaped SBOM of the resolved policy closure — every bundle's
`(publisher, name, version, content_hash, immutable_coord, log_index)` —
suitable for stapling to the application's existing SBOM and feeding into
the org's supply-chain attestation pipeline.

**App-build attestation.** The CI step's output (lockfile content_hash +
SBOM hash + trust-root hash + exit code) SHOULD be wrapped in an in-toto
attestation signed by the build pipeline's identity (Sigstore keyless
GitHub OIDC, ADO Workload Identity, etc.). This is the application's
own provenance, separate from per-bundle publisher signatures, and
proves "this build observed these exact policies under this exact trust
root." The runtime can optionally re-verify the app-build attestation
on startup for a fully cryptographic chain from publisher → bundle →
lockfile → application build → running container.

**Drift detection in production.** Beyond the build gate, deployments
SHOULD run `agt policies verify --strict` as a periodic health check
(cron / Kubernetes liveness sidecar / DaemonSet). This catches the
"someone hot-edited a YAML file on a production host" case, because the
verify result will diverge from the lockfile and the deployment can
alarm or self-quarantine. This is the same verification, run
continuously rather than only on load.

**Reference GitHub Action.** Shipped as `microsoft/agt-policies-verify`
alongside this ADR's implementation — a thin wrapper that pins the
`agt` CLI version, runs `agt policies ci`, uploads the SBOM as a
workflow artifact, and (optionally) posts the in-toto attestation to
the configured transparency log. Mirrors the existing pattern for
signing actions (`actions/attest-build-provenance`).

## Consequences

### Benefits

- A sideloaded bundle on disk is no longer trustable by default. The loader
  fails closed unless the trust root explicitly accepts the publisher's
  signing-key thumbprint and the bundle's content hash matches the signed
  manifest.
- The capability allowlist is enforceable because it is derived from the
  parsed policy AST, not from author-declared metadata.
- Enterprises get one published artifact per policy, versioned and
  rollback-controlled by `min_version`, with the lockfile providing
  reproducible loads across hosts and offline-verifiable transparency
  inclusion for air-gapped operation.
- Community publishing becomes possible without AGT operating a registry.
  Deployments accept community publishers granularly, and the deny-union
  composition rule prevents community bundles from weakening corporate
  deny rules even when both are loaded.
- The pluggable resolver Protocol means new transports (Artifactory,
  internal git mirrors, content-addressed object stores) are added without
  changes to the verification pipeline.
- All trust decisions are observable: every load emits an audit event
  with `content_hash`, immutable coordinate, key thumbprint, log index,
  and derived capabilities, chained into the existing Merkle audit
  (ADR-0017).
- No new cryptographic primitives. Ed25519, JCS, SHA-256, `did:web`,
  Merkle, transparency-log split — all already accepted in AGT. Sigstore
  and SLSA participate only as optional provenance, never as authority.
- **CI and runtime run the same verification code.** The build gate
  (§13) is the same `(bundle, trust, lock) → pass/fail` function as the
  runtime loader (§6), so build-time green is a strong guarantee of
  runtime green — and runtime drift (someone hot-edits a YAML on a host)
  is detected by the same code, run on a schedule.

### Tradeoffs

- Operators must maintain `trust.yaml` and `agt-policies.lock`. This is
  genuinely new operational surface, justified by the fact that the
  current implicit-trust model has no defense against sideloading at all.
- Default-deny on the trust root is a usability cliff for new users
  running `agt policies install` for the first time. We mitigate with a
  clear error message and a one-line `agt policies trust add` command,
  not by shipping a populated default trust list.
- The verification pipeline adds a transparency-log lookup on cold load.
  Mitigated by caching the signed tree head and inclusion proof in the
  lockfile, so steady-state loads are local-only and air-gap works.
- Revocation is append-only and authoritative. "Unrevoking" requires a
  new version, which is intended but sometimes surprising.
- Capability derivation requires the loader to understand every policy
  section. Unknown sections fail closed — this is correct behavior but
  imposes a discipline on contributors to update the capability mapping
  whenever a new policy surface lands.
- Operators of `git+https://` resolvers lose access to LFS / submodule
  features without opt-in. We accept this; those surfaces are common
  attack vectors and warrant explicit opt-in in a follow-up ADR.

### Follow-up work

- **Implementation:** `agent_os.policies.bundle`,
  `agent_os.policies.resolver`, `agent_os.policies.trust`,
  `agent_os.policies.lockfile`, plus CLI in `agent_compliance`.
- **Reference signing action:** GitHub Action that builds, signs with a
  publisher's Ed25519 key (HSM- or KMS-backed), uploads to a GitHub
  Release, and posts to the configured transparency log.
- **Private log reference:** Container image and Helm chart for an
  RFC-6962-compatible append-only log producing signed tree heads, for
  air-gapped customers.
- **Signed `trust.yaml`:** detached signature over `trust.yaml` verified
  by a deployment-bootstrap key, closing the "attacker edits trust.yaml"
  hole at the AGT layer instead of relying on the platform config channel.
- **SBOM-in-bundle:** explicit SBOM field, SLSA v1 build-provenance
  integration beyond the current optional flag.
- **Opt-in advanced git features:** submodule policy, LFS hydration policy,
  loose-directory bundles — a follow-up ADR if demand emerges.
- **Migration guide:** how existing `.agents/*.yaml` users adopt
  `trust.yaml` + lockfile without breaking running deployments.
- **License compliance scanning:** advisory tool; license interpretation
  is not in the loader trust boundary.
- **AGT Studio integration ([#2638](https://github.com/microsoft/agent-governance-toolkit/issues/2638)):**
  the trust-root editor, bundle inspector, publisher view, and resolver
  health surfaces described in the Studio-relationship section above are
  the UI counterpart to this ADR. They are tracked in the Studio
  proposal and depend on the loader API surface defined here.
- **AGT-published "known-good" policy set (community decision):** a
  separate proposal, decided with the community, on whether the AGT
  project should operate its own publisher identity and which policies
  (e.g. the existing HIPAA / SOX / GDPR / PCI-DSS / production templates)
  qualify. Includes governance for the review bar, signing-key custody
  (HSM/KMS), release cadence, and revocation process. This ADR is a
  pure enabler — it makes such a registry possible without baking any
  blessed-publisher assumption into the loader.

### Prior art and references

- [ADR-0001](0001-use-ed25519-for-agent-identity.md) — Ed25519 identity primitive
- [ADR-0004](0004-keep-policy-evaluation-deterministic.md) — deterministic evaluation
- [ADR-0007](0007-external-jwks-federation-for-cross-org-identity.md) — `did:web` discovery
- [ADR-0008](0008-cross-org-policy-federation.md) — JCS + SHA-256 + transparency log split (runtime federation, complement to this ADR)
- [ADR-0013](0013-fail-closed-on-policy-evaluation-errors.md) — fail-closed contract
- [ADR-0014](0014-parent-deny-rules-immutable-in-merge.md) — merge immutability (generalized here to import DAG)
- [ADR-0015](0015-pluggable-external-policy-backends.md) — Protocol pattern reused for resolvers
- [ADR-0017](0017-merkle-chain-for-audit-tamper-evidence.md) — audit chain for load events
- [SLSA v1.0](https://slsa.dev/spec/v1.0/) — build provenance (optional attestation in this ADR)
- [Sigstore / Rekor](https://docs.sigstore.dev/) — transparency log (used as log, not as authority)
- [RFC 6962](https://datatracker.ietf.org/doc/html/rfc6962) — CT-style append-only log with signed tree heads
- [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785) — JCS
- [ORAS](https://oras.land/) — OCI artifact distribution for non-image content
- [in-toto](https://in-toto.io/) — attestation framework
- [Issue #2638](https://github.com/microsoft/agent-governance-toolkit/issues/2638) — AGT Studio RFC; UI consumer of this ADR's loader, trust root, lockfile, and audit surfaces
