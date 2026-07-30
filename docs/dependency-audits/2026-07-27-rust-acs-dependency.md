---
title: Rust agentmesh crate takes the ACS workspace dependency
last_reviewed: 2026-07-27
owner: liamcrumm
---

# Rust agentmesh crate takes the ACS workspace dependency

## Which Dependencies Changed And Why

No third-party crate was added or upgraded. `agent-governance-rust/Cargo.lock`
gains `agent_control_specification` because the `agentmesh` crate now evaluates
policy through the ACS engine instead of the vendored v4 path.

The dependency is a path entry pointing at `policy-engine/sdk/rust` inside this
repository, so it resolves to the workspace source rather than a registry
release. The lockfile was regenerated with `cargo generate-lockfile --offline`
and checked with `cargo metadata --offline --locked`, which fails if the
committed lockfile disagrees with the manifests.

## Security Advisory Relevance

No CVE or RustSec advisory is addressed.

The direct dependency added to `agentmesh` is first-party and MIT licensed, and
it is the same engine the Python and TypeScript surfaces evaluate against, so
the three stop being able to disagree about a policy outcome.

It is not free of transitive cost. `Cargo.lock` gains 66 package entries: the
two first-party crates (`agent_control_specification`,
`agent_control_specification_core`) and **64 third-party crates that were not
previously in the workspace graph**, pulled in by the engine's manifest
validation and its unicode handling:

`adler2`, `ahash`, `bytecount`, `crc32fast`, `displaydoc`, `fancy-regex`, `flate2`, `form_urlencoded`, `fraction`, `futures-task`, `futures-util`, `icu_collections`, `icu_locale_core`, `icu_normalizer`, `icu_normalizer_data`, `icu_properties`, `icu_properties_data`, `icu_provider`, `idna`, `idna_adapter`, `iso8601`, `jsonschema`, `litemap`, `miniz_oxide`, `nom`, `num`, `num-cmp`, `num-complex`, `num-iter`, `num-rational`, `percent-encoding`, `potential_utf`, `ring`, `rustls`, `rustls-pki-types`, `rustls-webpki`, `simd-adler32`, `slab`, `stable_deref_trait`, `synstructure`, `tinystr`, `untrusted`, `ureq`, `url`, `utf8_iter`, `uuid`, `webpki-roots`, `windows-targets`, `windows_aarch64_gnullvm`, `windows_aarch64_msvc`, `windows_i686_gnu`, `windows_i686_gnullvm`, `windows_i686_msvc`, `windows_x86_64_gnu`, `windows_x86_64_gnullvm`, `windows_x86_64_msvc`, `writeable`, `yoke`, `yoke-derive`, `zerofrom`, `zerofrom-derive`, `zerotrie`, `zerovec`, `zerovec-derive`

Two clusters account for nearly all of it.

**Manifest validation.** `jsonschema` brings `fancy-regex`, `fraction`, `num*`,
`referencing`, and the `icu_*` unicode tables through `idna`/`url`.

**An HTTP and TLS stack, which matters more.** `ureq`, `rustls`, `ring`, and
`webpki-roots` are all new to this graph. They arrive because the ACS Rust SDK
pins its core features to include `openai_moderation`, `perspective`,
`llama_guard`, `lakera_guard`, and `auto`, and because `Manifest::from_url`
exists. `agentmesh` cannot opt out: the feature set is fixed inside the SDK
crate, not selected by the consumer.

Nothing in `agentmesh` calls a remote annotator or `from_url`, so no egress is
added by this change in practice. The capability is now linked in, though, and
for a governance library that is worth stating plainly rather than describing
the change as pulling nothing new. Narrowing the SDK's feature set so hosts can
build without the network stack is a follow-up on the ACS crate, not on this
PR.

`cargo deny` and `cargo audit` coverage should be confirmed against the new set
before release.

## Breaking Change Risk Assessment

Low. A path dependency inside the workspace changes no published version
constraint for downstream crates, and `cargo check --offline --workspace`
compiles with the crate's four pre-existing warnings unchanged.

The user-visible breaking change is the removal of the v4 policy language
itself, which `BREAKING_CHANGES.md` covers.
