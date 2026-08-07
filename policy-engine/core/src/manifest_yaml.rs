// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bounded manifest YAML parsing retained by AGT.
//!
//! The policy runtime now lives in the `agent_control_spec` crate. That
//! crate exposes `Manifest::from_yaml_str` but not the resource bounded
//! `serde` seed AGT layers over it. The seed is generic input hardening
//! rather than contract semantics, so AGT keeps owning it instead of
//! forking the policy plane.

use agent_control_spec::{JsonValue, Limits, Manifest, RuntimeError};
use serde::de::{DeserializeSeed, Deserializer, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde_json::Map;
use std::fmt;

/// Upper bound on expanded manifest nodes. Guards against YAML anchor
/// expansion blowing up memory before the manifest is ever validated.
const MAX_MANIFEST_PARSE_NODES: usize = 100_000;

/// Manifest grammar versions this toolkit accepts. Mirrors the private
/// list in `agent_control_spec`, which does not export it.
pub const SUPPORTED_MANIFEST_VERSIONS: [&str; 1] = ["0.4.0-alpha.1"];

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
    if !SUPPORTED_MANIFEST_VERSIONS.contains(&version) {
        return Err(RuntimeError::ManifestInvalid(format!(
            "unsupported agent_control_specification_version '{version}'; supported versions are {}",
            SUPPORTED_MANIFEST_VERSIONS.join(", ")
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
    Ok(())
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
    manifest.validate()
}

/// Overlay validation for manifest fragments.
///
/// AGT's embedded engine had `Manifest::validate_overlay`, a relaxed check
/// for fragments that only become whole after `extends` resolution.
/// `agent_control_spec` 0.4.0-alpha.1 exposes only the strict
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
