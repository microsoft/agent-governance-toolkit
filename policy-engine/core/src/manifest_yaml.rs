// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bounded manifest YAML parsing retained by AGT.
//!
//! The policy runtime now lives in the `agent_control_spec` crate. That
//! crate exposes `Manifest::from_yaml_str` but not the resource bounded
//! `serde` seed AGT layers over it. The seed is generic input hardening
//! rather than contract semantics, so AGT keeps owning it instead of
//! forking the policy plane.

use agent_control_spec::policy::PolicyConfig;
use agent_control_spec::{JsonValue, Limits, Manifest, RuntimeError};
use serde::de::{DeserializeSeed, Deserializer, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde_json::Map;
use std::fmt;

/// Upper bound on expanded manifest nodes. Guards against YAML anchor
/// expansion blowing up memory before the manifest is ever validated.
const MAX_MANIFEST_PARSE_NODES: usize = 100_000;

/// Manifest grammar versions accepted by the upstream engine.
pub use agent_control_spec::SUPPORTED_VERSIONS;

/// Legacy array form, derived from the upstream grammar rather than copied.
pub const SUPPORTED_MANIFEST_VERSIONS: [&str; 1] = [SUPPORTED_VERSIONS[0]];
const _: () = assert!(
    SUPPORTED_VERSIONS.len() == 1,
    "review the legacy array API when upstream accepts multiple manifest versions"
);

/// Manifest fields the pre-retarget engine implemented that
/// `agent-control-spec` 0.4.0-alpha.3 does not.
///
/// The upstream `RegoPolicyConfig::adapter_config`, `PolicyBinding::adapter_config`,
/// `AnnotatorConfig::fields` and `AnnotationConfig::fields` maps are open, so a
/// manifest declaring one of these keys deserializes and validates cleanly
/// while the feature it asks for is silently absent: an `llm` annotator with a
/// `system_prompt_file` or `system_prompt_url` runs with the default prompt,
/// and a rego policy with a `bundle_url` denies every request with
/// `runtime_error:policy_invocation_failed`. AGT rejects them instead. See
/// `docs/acs-retarget.md`, "Removed manifest fields".
pub const REMOVED_MANIFEST_FIELDS: [&str; 3] =
    ["bundle_url", "system_prompt_file", "system_prompt_url"];

/// Reject a manifest that declares any of [`REMOVED_MANIFEST_FIELDS`].
///
/// Checks every open map a manifest author can reach: each policy definition,
/// each annotator declaration, and each intervention point's policy binding
/// and annotation bindings, since a binding overlays its fields onto the
/// declaration. Cedar policies deny unknown fields upstream and cannot carry
/// them.
pub fn reject_removed_fields(manifest: &Manifest) -> Result<(), RuntimeError> {
    fn check(
        location: impl Fn() -> String,
        keys: impl Iterator<Item = impl AsRef<str>>,
    ) -> Result<(), RuntimeError> {
        for key in keys {
            let key = key.as_ref();
            if REMOVED_MANIFEST_FIELDS.contains(&key) {
                return Err(RuntimeError::ManifestInvalid(format!(
                    "{} declares '{key}', which the pre-retarget engine implemented and                      agent-control-spec {} does not; the field was removed in the retarget                      and is rejected rather than silently ignored. Inline the value or drop                      the field; see policy-engine/docs/acs-retarget.md, 'Removed manifest fields'",
                    location(),
                    agent_control_spec::SUPPORTED_VERSIONS[0]
                )));
            }
        }
        Ok(())
    }

    for (name, policy) in &manifest.policies {
        let adapter_config = match policy {
            PolicyConfig::Rego(config) => &config.adapter_config,
            PolicyConfig::Test(config) => &config.adapter_config,
            PolicyConfig::Custom(config) => &config.adapter_config,
            PolicyConfig::Cedar(_) => continue,
        };
        check(|| format!("policy '{name}'"), adapter_config.keys())?;
    }
    for (name, annotator) in &manifest.annotators {
        check(|| format!("annotator '{name}'"), annotator.fields.keys())?;
    }
    for (point, config) in &manifest.intervention_points {
        check(
            || format!("intervention point '{}' policy binding", point.as_str()),
            config.policy.adapter_config.keys(),
        )?;
        for (name, annotation) in &config.annotations {
            check(
                || {
                    format!(
                        "intervention point '{}' annotation '{name}'",
                        point.as_str()
                    )
                },
                annotation.fields.keys(),
            )?;
        }
    }
    Ok(())
}

/// The overlay-safe subset of manifest validation.
///
/// `agent_control_spec` carries only the strict `Manifest::validate`,
/// which over rejects fragments because it requires at least one
/// intervention point and resolves policy references across the whole
/// document. Deserializing catches structural and grammar errors; this
/// adds back the checks that are meaningful for a fragment and are
/// expressible over the public manifest surface.
pub fn validate_overlay(manifest: &Manifest) -> Result<(), RuntimeError> {
    let version = manifest.agent_control_specification_version.trim();
    if version.is_empty() {
        return Err(RuntimeError::ManifestInvalid(
            "agent_control_specification_version is required".to_string(),
        ));
    }
    if !SUPPORTED_VERSIONS.contains(&version) {
        return Err(RuntimeError::ManifestInvalid(format!(
            "unsupported agent_control_specification_version '{version}'; supported versions are {}",
            SUPPORTED_VERSIONS.join(", ")
        )));
    }
    for extends in &manifest.extends {
        // `ManifestExtends::reference()` is private in agent_control_spec.
        let reference = match extends {
            agent_control_spec::manifest::ManifestExtends::Reference(reference) => {
                reference.as_str()
            }
            agent_control_spec::manifest::ManifestExtends::Url(url) => url.url.as_str(),
        };
        if reference.trim().is_empty() {
            return Err(RuntimeError::ManifestInvalid(
                "extends entries must not be empty".to_string(),
            ));
        }
    }
    for policy_name in manifest.policies.keys() {
        if policy_name.trim().is_empty() {
            return Err(RuntimeError::ManifestInvalid(
                "policy ids must not be empty".to_string(),
            ));
        }
    }
    for annotator_name in manifest.annotators.keys() {
        if annotator_name.trim().is_empty() {
            return Err(RuntimeError::ManifestInvalid(
                "annotator names must not be empty".to_string(),
            ));
        }
    }
    reject_removed_fields(manifest)
}

pub fn parse_manifest_yaml_value(input: &str) -> Result<JsonValue, RuntimeError> {
    let limits = Limits::default();
    if input.len() > limits.max_merged_manifest_bytes {
        return Err(RuntimeError::ResourceLimitExceeded(format!(
            "manifest source size {} exceeds limit {}",
            input.len(),
            limits.max_merged_manifest_bytes
        )));
    }
    let mut documents = serde_yaml::Deserializer::from_str(input);
    let document = documents.next().ok_or_else(|| {
        RuntimeError::ManifestInvalid("manifest source must not be empty".to_string())
    })?;
    let mut budget = ManifestValueBudget::new(limits);
    let parsed = BoundedJsonValueSeed {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(document);
    let value = match parsed {
        Ok(value) => value,
        Err(error) => {
            if let Some(detail) = budget.limit_error.take() {
                return Err(RuntimeError::ResourceLimitExceeded(detail));
            }
            return Err(RuntimeError::ManifestInvalid(error.to_string()));
        }
    };
    if documents.next().is_some() {
        return Err(RuntimeError::ManifestInvalid(
            "manifest source must contain exactly one YAML or JSON document".to_string(),
        ));
    }
    limits.validate_json_depth(&value, "manifest")?;
    let serialized = serde_json::to_vec(&value).map_err(|err| {
        RuntimeError::ManifestInvalid(format!("failed to serialize parsed manifest: {err}"))
    })?;
    if serialized.len() > limits.max_merged_manifest_bytes {
        return Err(RuntimeError::ResourceLimitExceeded(format!(
            "manifest serialized size {} exceeds limit {}",
            serialized.len(),
            limits.max_merged_manifest_bytes
        )));
    }
    Ok(value)
}

/// Full manifest validation. Delegates to the `agent_control_spec` strict
/// validator once the bounded parser has accepted the source.
pub fn validate_manifest_yaml(input: &str) -> Result<(), RuntimeError> {
    let value = parse_manifest_yaml_value(input)?;
    let manifest: Manifest = serde_json::from_value(value)
        .map_err(|err| RuntimeError::ManifestInvalid(err.to_string()))?;
    reject_removed_fields(&manifest)?;
    manifest.validate()
}

/// Overlay validation for manifest fragments.
///
/// AGT's embedded engine had `Manifest::validate_overlay`, a relaxed check
/// for fragments that only become whole after `extends` resolution.
/// `agent_control_spec` 0.4.0-alpha.3 still exposes only the strict
/// `Manifest::validate`, which over rejects fragments because it requires
/// at least one intervention point and resolves policy references. Until
/// ACS grows an overlay entry point this deserializes the fragment, which
/// catches every structural and grammar error, and defers whole manifest
/// coherence to the post `extends` `validate` call the loader performs.
pub fn validate_manifest_overlay_yaml(input: &str) -> Result<(), RuntimeError> {
    let value = parse_manifest_yaml_value(input)?;
    let manifest: Manifest = serde_json::from_value(value)
        .map_err(|err| RuntimeError::ManifestInvalid(err.to_string()))?;
    validate_overlay(&manifest)
}

struct ManifestValueBudget {
    limits: Limits,
    nodes: usize,
    bytes: usize,
    limit_error: Option<String>,
}

impl ManifestValueBudget {
    fn new(limits: Limits) -> Self {
        Self {
            limits,
            nodes: 0,
            bytes: 0,
            limit_error: None,
        }
    }

    fn enter<E: DeError>(&mut self, depth: usize, bytes: usize) -> Result<(), E> {
        if depth > self.limits.max_policy_input_depth {
            let detail = format!(
                "manifest JSON nesting depth exceeds limit {}",
                self.limits.max_policy_input_depth
            );
            self.limit_error = Some(detail.clone());
            return Err(E::custom(detail));
        }
        self.nodes += 1;
        if self.nodes > MAX_MANIFEST_PARSE_NODES {
            let detail =
                format!("manifest expanded node count exceeds limit {MAX_MANIFEST_PARSE_NODES}");
            self.limit_error = Some(detail.clone());
            return Err(E::custom(detail));
        }
        self.add_bytes(bytes)
    }

    fn add_bytes<E: DeError>(&mut self, bytes: usize) -> Result<(), E> {
        self.bytes = self.bytes.saturating_add(bytes);
        if self.bytes > self.limits.max_merged_manifest_bytes {
            let detail = format!(
                "manifest expanded size exceeds limit {}",
                self.limits.max_merged_manifest_bytes
            );
            self.limit_error = Some(detail.clone());
            return Err(E::custom(detail));
        }
        Ok(())
    }
}

struct BoundedJsonValueSeed<'a> {
    budget: &'a mut ManifestValueBudget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for BoundedJsonValueSeed<'_> {
    type Value = JsonValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(BoundedJsonValueVisitor {
            budget: self.budget,
            depth: self.depth,
        })
    }
}

struct BoundedJsonValueVisitor<'a> {
    budget: &'a mut ManifestValueBudget,
    depth: usize,
}

impl<'de> Visitor<'de> for BoundedJsonValueVisitor<'_> {
    type Value = JsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON-compatible YAML value")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.budget.enter(self.depth, 4)?;
        Ok(JsonValue::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_unit()
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.budget.enter(self.depth, if value { 4 } else { 5 })?;
        Ok(JsonValue::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.budget.enter(self.depth, 20)?;
        Ok(JsonValue::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.budget.enter(self.depth, 20)?;
        Ok(JsonValue::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.budget.enter(self.depth, 24)?;
        serde_json::Number::from_f64(value)
            .map(JsonValue::Number)
            .ok_or_else(|| E::custom("manifest numbers must be finite"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.budget.enter(self.depth, json_string_size(value))?;
        Ok(JsonValue::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.budget.enter(self.depth, json_string_size(&value))?;
        Ok(JsonValue::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        self.budget.enter(self.depth, 2)?;
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(1024));
        while let Some(value) = sequence.next_element_seed(BoundedJsonValueSeed {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            if !values.is_empty() {
                self.budget.add_bytes(1)?;
            }
            values.push(value);
        }
        Ok(JsonValue::Array(values))
    }

    fn visit_map<A>(self, mut mapping: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        self.budget.enter(self.depth, 2)?;
        let mut values = Map::new();
        while let Some(key) = mapping.next_key_seed(JsonMapKeySeed)? {
            if values.contains_key(&key) {
                return Err(A::Error::custom(format!(
                    "duplicate manifest mapping key {key:?}"
                )));
            }
            if !values.is_empty() {
                self.budget.add_bytes(1)?;
            }
            self.budget.add_bytes(json_string_size(&key) + 1)?;
            let value = mapping.next_value_seed(BoundedJsonValueSeed {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(JsonValue::Object(values))
    }
}

struct JsonMapKeySeed;

impl<'de> DeserializeSeed<'de> for JsonMapKeySeed {
    type Value = String;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(JsonMapKeyVisitor)
    }
}

struct JsonMapKeyVisitor;

impl Visitor<'_> for JsonMapKeyVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string manifest mapping key")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(value.to_string())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(value)
    }
}

fn json_string_size(value: &str) -> usize {
    serde_json::to_string(value)
        .map(|serialized| serialized.len())
        .unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::{
        reject_removed_fields, validate_manifest_overlay_yaml, validate_manifest_yaml,
        REMOVED_MANIFEST_FIELDS,
    };
    use agent_control_spec::Manifest;

    const VERSION: &str = "agent_control_specification_version: 0.4.0-alpha.1\n";

    fn llm_manifest(annotator_fields: &str) -> String {
        format!(
            "{VERSION}policies:\n  p:\n    type: test\nannotators:\n  judge:\n    type: llm\n\
             {annotator_fields}intervention_points:\n  input:\n    policy_target: $snap.input\n\
             \x20   policy:\n      id: p\n    annotations:\n      judge:\n        from: $target\n"
        )
    }

    fn rego_manifest(policy_fields: &str) -> String {
        format!(
            "{VERSION}policies:\n  p:\n    type: rego\n    query: data.acs.result\n\
             {policy_fields}intervention_points:\n  input:\n    policy_target: $snap.input\n\
             \x20   policy:\n      id: p\n"
        )
    }

    /// The six manifests the review probe showed `Manifest::from_yaml_str`
    /// accepting while the pinned engine had no implementation behind them.
    fn probe_manifests() -> Vec<(&'static str, String, &'static str)> {
        vec![
            (
                "llm annotator with a missing system_prompt_file",
                llm_manifest("    system_prompt_file: prompts/does-not-exist.txt\n"),
                "system_prompt_file",
            ),
            (
                "llm annotator with an inline prompt and an unpinned http system_prompt_url",
                llm_manifest(
                    "    system_prompt: inline\n    system_prompt_url:\n      url: http://prompts.example/p.txt\n",
                ),
                "system_prompt_url",
            ),
            (
                "llm annotator with a pinned https system_prompt_url",
                llm_manifest(&format!(
                    "    system_prompt_url:\n      url: https://prompts.example/p.txt\n      sha256: {}\n",
                    "a".repeat(64)
                )),
                "system_prompt_url",
            ),
            (
                "rego policy with a pinned https bundle_url",
                rego_manifest(&format!(
                    "    bundle_url:\n      url: https://bundles.example/b.tar.gz\n      sha256: {}\n",
                    "b".repeat(64)
                )),
                "bundle_url",
            ),
            (
                "rego policy with an unpinned http bundle_url",
                rego_manifest("    bundle_url:\n      url: http://bundles.example/b.tar.gz\n"),
                "bundle_url",
            ),
            (
                "rego policy with bundle and bundle_url together",
                rego_manifest(&format!(
                    "    bundle: ./policy\n    bundle_url:\n      url: https://bundles.example/b.tar.gz\n      sha256: {}\n",
                    "c".repeat(64)
                )),
                "bundle_url",
            ),
        ]
    }

    #[test]
    fn upstream_parser_still_accepts_the_removed_fields() {
        // The reason the check exists: the pinned engine's open config maps
        // swallow these keys. If upstream starts rejecting them this test
        // fails and the AGT check can be retired.
        for (label, manifest, _) in probe_manifests() {
            let parsed = Manifest::from_yaml_str(&manifest)
                .unwrap_or_else(|error| panic!("{label}: upstream parse failed: {error}"));
            parsed
                .validate()
                .unwrap_or_else(|error| panic!("{label}: upstream validate failed: {error}"));
        }
    }

    #[test]
    fn removed_fields_are_rejected_by_every_validation_entry_point() {
        for (label, manifest, field) in probe_manifests() {
            for (entry, result) in [
                ("validate_manifest_yaml", validate_manifest_yaml(&manifest)),
                (
                    "validate_manifest_overlay_yaml",
                    validate_manifest_overlay_yaml(&manifest),
                ),
                (
                    "reject_removed_fields",
                    reject_removed_fields(&Manifest::from_yaml_str(&manifest).unwrap()),
                ),
            ] {
                let error = match result {
                    Ok(()) => panic!("{label}: {entry} accepted"),
                    Err(error) => error,
                };
                assert_eq!(
                    error.reason(),
                    "runtime_error:manifest_invalid",
                    "{label}: {entry}"
                );
                let detail = error.detail();
                assert!(
                    detail.contains(&format!("'{field}'")),
                    "{label}: {entry}: {detail}"
                );
                assert!(
                    detail.contains("docs/acs-retarget.md"),
                    "{label}: {entry}: {detail}"
                );
            }
        }
    }

    #[test]
    fn removed_fields_are_rejected_on_bindings_too() {
        // A binding overlays its fields onto the declaration, so the same
        // keys are reachable there.
        let annotation_binding = format!(
            "{VERSION}policies:\n  p:\n    type: test\nannotators:\n  judge:\n    type: llm\n\
             intervention_points:\n  input:\n    policy_target: $snap.input\n    policy:\n      id: p\n\
             \x20   annotations:\n      judge:\n        from: $target\n        system_prompt_file: x.txt\n"
        );
        let error = validate_manifest_yaml(&annotation_binding).unwrap_err();
        assert!(
            error.detail().starts_with(
                "intervention point 'input' annotation 'judge' declares 'system_prompt_file'"
            ),
            "{}",
            error.detail()
        );

        let policy_binding = format!(
            "{VERSION}policies:\n  p:\n    type: rego\n    query: data.acs.result\n\
             intervention_points:\n  input:\n    policy_target: $snap.input\n    policy:\n      id: p\n\
             \x20     bundle_url:\n        url: https://bundles.example/b.tar.gz\n        sha256: {}\n",
            "d".repeat(64)
        );
        let error = validate_manifest_yaml(&policy_binding).unwrap_err();
        assert!(
            error
                .detail()
                .starts_with("intervention point 'input' policy binding declares 'bundle_url'"),
            "{}",
            error.detail()
        );

        let custom_policy = format!(
            "{VERSION}policies:\n  p:\n    type: custom\n    adapter: mine\n    bundle_url: x\n\
             intervention_points:\n  input:\n    policy_target: $snap.input\n    policy:\n      id: p\n"
        );
        let error = validate_manifest_overlay_yaml(&custom_policy).unwrap_err();
        assert!(
            error
                .detail()
                .starts_with("policy 'p' declares 'bundle_url'"),
            "{}",
            error.detail()
        );
    }

    #[test]
    fn manifests_without_removed_fields_still_pass() {
        let inline_prompt = llm_manifest("    system_prompt: You are a judge.\n");
        validate_manifest_yaml(&inline_prompt).unwrap();
        validate_manifest_overlay_yaml(&inline_prompt).unwrap();
        let local_bundle = rego_manifest("    bundle: ./policy\n");
        validate_manifest_yaml(&local_bundle).unwrap();
        validate_manifest_overlay_yaml(&local_bundle).unwrap();
        assert_eq!(REMOVED_MANIFEST_FIELDS.len(), 3);
    }
}
