use crate::{
    annotation::{AnnotationConfig, AnnotatorConfig, AnnotatorInvocation, AnnotatorType},
    constants::manifest_version,
    paths::PathRoot,
    policy::{
        resolve_relative_string, validate_policy_binding, validate_policy_definition,
        PolicyBinding, PolicyConfig,
    },
    InterventionPoint, JsonPath, JsonValue, Limits, RuntimeError,
};

// LLM annotator prompt source field names. These mirror the constants in the
// feature gated `dispatchers::constants` module. They are duplicated here
// because manifest validation is always compiled while the bundled
// dispatchers are gated behind the `default-dispatchers` feature.
const FIELD_SYSTEM_PROMPT: &str = "system_prompt";
const FIELD_PROMPT: &str = "prompt";
const FIELD_SYSTEM_PROMPT_FILE: &str = "system_prompt_file";
const FIELD_SYSTEM_PROMPT_URL: &str = "system_prompt_url";
const MAX_MANIFEST_PARSE_NODES: usize = 100_000;
use serde::{
    de::{DeserializeSeed, Error as DeError, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_json::Map;
use std::{
    collections::BTreeMap,
    fmt, fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub agent_control_specification_version: String,
    #[serde(default = "empty_object")]
    pub metadata: JsonValue,
    #[serde(default)]
    pub extends: Vec<ManifestExtends>,
    #[serde(default)]
    pub policies: BTreeMap<String, PolicyConfig>,
    #[serde(default)]
    pub intervention_points: BTreeMap<InterventionPoint, InterventionPointConfig>,
    #[serde(default)]
    pub tools: BTreeMap<String, ToolConfig>,
    #[serde(default)]
    pub annotators: BTreeMap<String, AnnotatorConfig>,
    /// AGT D5: optional top-level `approval` section that configures the
    /// escalation backend used for `escalate` verdicts. The runtime
    /// validates the shape per AGT-MANIFEST-1.0 §1 and SPECIFICATION.md
    /// §24 but does not consult resolver configuration; that plumbing lives
    /// in host SDKs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalSection>,
    /// Runtime provenance, not part of the manifest grammar. True when this
    /// manifest was loaded from a URL via `Manifest::from_url`. Skipped by serde
    /// so it never appears in canonical output. A URL sourced manifest is
    /// treated as untrusted for host local access, so the bundled `llm`
    /// dispatcher will not fall back to host environment credentials for it.
    #[serde(skip)]
    pub url_sourced: bool,
}

/// AGT D5: parsed shape of the manifest's optional `approval` block.
///
/// The runtime treats this section as opaque host configuration. It is
/// validated for structural well-formedness during manifest validation and
/// then consulted only by the host approval path described in
/// SPECIFICATION §17.1.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalSection {
    /// Name of the resolver consulted by default. When absent the host
    /// approval path defaults to `deny` per SPECIFICATION.md §24.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_resolver: Option<String>,
    /// Maximum wait in seconds before `on_timeout` triggers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u64>,
    /// Behaviour applied when `timeout_seconds` elapses without a decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_timeout: Option<ApprovalOnTimeout>,
    /// Soft cap on approvals per agent within `fatigue_window_seconds`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fatigue_threshold: Option<u64>,
    /// Window in seconds across which the fatigue counter accumulates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fatigue_window_seconds: Option<u64>,
    /// Named resolver configurations. Keys are resolver names referenced by
    /// `default_resolver`; values carry an opaque host-defined config plus a
    /// discriminating `type` field.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub resolvers: BTreeMap<String, ApprovalResolverConfig>,
}

/// AGT D5: timeout behaviour enum for the `approval.on_timeout` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApprovalOnTimeout {
    Deny,
    Allow,
    Suspend,
}

/// AGT D5: a single entry under `approval.resolvers`.
///
/// `type` is a discriminator preserved verbatim. All remaining keys are
/// captured under `additional_properties` so host-defined resolver
/// configuration round-trips without loss.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ApprovalResolverConfig {
    #[serde(rename = "type")]
    pub resolver_type: String,
    #[serde(flatten)]
    pub additional_properties: BTreeMap<String, JsonValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ManifestExtends {
    Reference(String),
    Url(ManifestUrlExtends),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestUrlExtends {
    pub url: String,
    #[serde(default)]
    pub integrity: Option<String>,
    #[serde(default)]
    pub sha256: Option<String>,
}

impl ManifestExtends {
    fn reference(&self) -> &str {
        match self {
            Self::Reference(reference) => reference,
            Self::Url(url) => &url.url,
        }
    }
}

impl PartialEq<&str> for ManifestExtends {
    fn eq(&self, other: &&str) -> bool {
        self.reference() == *other
    }
}

impl PartialEq<String> for ManifestExtends {
    fn eq(&self, other: &String) -> bool {
        self.reference() == other
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterventionPointConfig {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub policy_target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_target_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name_from: Option<String>,
    #[serde(default)]
    pub annotations: BTreeMap<String, AnnotationConfig>,
    #[serde(default, skip_serializing_if = "is_empty_policy_binding")]
    pub policy: PolicyBinding,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ToolConfig {
    #[serde(flatten)]
    pub fields: BTreeMap<String, JsonValue>,
}

impl ToolConfig {
    pub fn to_projected_value(&self, name: &str) -> JsonValue {
        let mut map = Map::new();
        for (key, value) in &self.fields {
            map.insert(key.clone(), value.clone());
        }
        map.insert("name".to_string(), JsonValue::String(name.to_string()));
        JsonValue::Object(map)
    }
}

impl Manifest {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, RuntimeError> {
        ManifestLoader::default().load(path.as_ref())
    }

    /// AGT D5: accessor for the optional top-level `approval` section.
    pub fn approval(&self) -> Option<&ApprovalSection> {
        self.approval.as_ref()
    }

    /// Rewrite manifest-relative policy paths (rego `bundle`, adapter_config
    /// `data`/`data_paths`, and binding-level data paths) against `base_dir`.
    /// Applied per source file during file-based loading so paths resolve
    /// against the manifest that declared them rather than the process CWD.
    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        for config in self.policies.values_mut() {
            config.resolve_relative_paths(base_dir);
        }
        for intervention_point in self.intervention_points.values_mut() {
            intervention_point.policy.resolve_relative_paths(base_dir);
        }
        for annotator in self.annotators.values_mut() {
            if let Some(JsonValue::String(path)) =
                annotator.fields.get_mut(FIELD_SYSTEM_PROMPT_FILE)
            {
                if let Some(resolved) = resolve_relative_string(path, base_dir) {
                    *path = resolved;
                }
            }
        }
    }

    /// Reject fields on a manifest that was not loaded from the file system, i.e.
    /// a URL sourced manifest, that would let the remote manifest reach a local
    /// resource or a host privilege at dispatch. Without a file system manifest
    /// root, filesystem path fields resolve against the process working
    /// directory, so a rego `bundle`, an annotator `system_prompt_file`, a cedar
    /// path, or adapter `data` fails closed. A remote rego `bundle_url` also
    /// fails closed, because the bundled OPA dispatcher would run that attacker
    /// chosen rego with the host environment and network, so it could read a host
    /// secret through `opa.runtime` and exfiltrate it through `http.send`.
    /// Separately, a URL sourced manifest also controls an `llm` annotator's
    /// dispatch `endpoint`, so it MUST NOT be allowed to read host environment
    /// secrets through `api_key_env` / `aws_*_env`; otherwise a malicious remote
    /// manifest could name `AWS_SECRET_ACCESS_KEY` and ship it to an attacker
    /// chosen endpoint. All of these fail closed, so a URL sourced manifest
    /// references a remote prompt through `system_prompt_url` or supplies policy
    /// and credentials inline rather than from the host file system or host env.
    ///
    /// The scan covers the annotator declarations AND each declaration overlaid
    /// with its intervention point binding, because
    /// `AnnotatorInvocation::from_annotation` overlays binding fields, so a
    /// binding could otherwise smuggle a `system_prompt_file` or a host env
    /// secret field past an otherwise clean declaration. The bundled `llm`
    /// dispatcher's provider default credential fallback (which reads a host env
    /// var with no manifest field, so a field scan cannot see it) is closed
    /// separately at dispatch through the `url_sourced` flag.
    ///
    /// `fully_pinned` is true only when the top level URL load and every URL
    /// `extends` entry in the chain carried a verified hash pin. A fully pinned
    /// chain is content addressed end to end, so the host that chose the top pin
    /// transitively vouches for every merged byte, including a rego `bundle_url`
    /// and its own pin. The remote rego `bundle_url` rejection is therefore
    /// skipped for a fully pinned chain, matching the file sourced trust model.
    /// The local filesystem path fields and the host environment secret fields
    /// stay rejected regardless, because their content is not part of the pin.
    fn reject_url_sourced_local_access(&self, fully_pinned: bool) -> Result<(), RuntimeError> {
        for (name, annotator) in &self.annotators {
            reject_url_sourced_annotator_fields(&format!("annotator '{name}'"), &annotator.fields)?;
        }
        for (point, config) in &self.intervention_points {
            for (annotation_name, annotation) in &config.annotations {
                let Some(annotator) = self.annotators.get(annotation_name) else {
                    continue;
                };
                let invocation = AnnotatorInvocation::from_annotation(annotator, annotation);
                reject_url_sourced_annotator_fields(
                    &format!("annotation '{annotation_name}' for intervention point {point}"),
                    &invocation.fields,
                )?;
            }
        }
        for (id, policy) in &self.policies {
            policy.reject_filesystem_path_fields(&format!("policy '{id}'"))?;
            if !fully_pinned {
                policy.reject_url_sourced_remote_bundle(&format!("policy '{id}'"))?;
            }
        }
        for (point, config) in &self.intervention_points {
            config.policy.reject_filesystem_path_fields(&format!(
                "intervention point {point} policy binding"
            ))?;
        }
        Ok(())
    }

    pub fn from_path_with_limits(
        path: impl AsRef<Path>,
        limits: Limits,
    ) -> Result<Self, RuntimeError> {
        ManifestLoader::with_limits(limits).load(path.as_ref())
    }

    /// Load a top level manifest from an HTTPS URL. The fetch reuses the URL
    /// `extends` trust gate defined in section 2.2 of the specification, so the
    /// URL MUST be HTTPS, carries no ambient credentials, and is bounded by the
    /// same body size limit as URL extends. The `sha256` pin is optional and
    /// mirrors URL `extends`, where an unpinned URL is trusted because the host
    /// chose it. Pass `None` for an unpinned load; a supplied pin (including a
    /// blank string) MUST be a 64 character hexadecimal SHA-256 digest over the
    /// fetched bytes, and a mismatch, a malformed pin, a non HTTPS URL, a fetch
    /// error, or a body size breach MUST fail closed. A URL sourced manifest
    /// cannot reference local files, so a rego `bundle`, an annotator
    /// `system_prompt_file`, a cedar path, or adapter `data` field fails closed;
    /// use the `*_url` forms or inline text instead. A rego `bundle_url` is
    /// allowed only when the whole load chain is fully pinned, that is the top
    /// level pin is present and every URL `extends` entry carries a pin, because
    /// the pin chain makes the bundle host vouched as in a file sourced manifest.
    pub fn from_url(url: &str, sha256: Option<&str>) -> Result<Self, RuntimeError> {
        Self::from_url_with_limits(url, sha256, Limits::default())
    }

    /// Load a top level manifest from an HTTPS URL with explicit limits. See
    /// [`Manifest::from_url`] for the trust gate and the optional pin.
    pub fn from_url_with_limits(
        url: &str,
        sha256: Option<&str>,
        limits: Limits,
    ) -> Result<Self, RuntimeError> {
        ManifestLoader::with_limits(limits).load_url(url, sha256)
    }

    pub fn merge_chain(manifests: Vec<Self>) -> Result<Self, RuntimeError> {
        if manifests.is_empty() {
            return Err(RuntimeError::ManifestInvalid(
                "manifest chain must not be empty".to_string(),
            ));
        }

        let mut resolved: Option<Manifest> = None;
        for (index, manifest) in manifests.into_iter().enumerate() {
            validate_chain_extends(&manifest, index)?;
            if !manifest.extends.is_empty() {
                return Err(RuntimeError::ManifestInvalid(format!(
                    "manifest chain entry {index} contains unresolved extends"
                )));
            }
            merge_resolved_manifest(&mut resolved, manifest, &ManifestSource::ChainEntry(index))?;
        }

        let manifest = resolved.expect("non-empty manifests guaranteed by check above");
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn from_yaml_chain(inputs: &[&str]) -> Result<Self, RuntimeError> {
        if inputs.is_empty() {
            return Err(RuntimeError::ManifestInvalid(
                "manifest yaml chain must not be empty".to_string(),
            ));
        }

        let mut manifests = Vec::with_capacity(inputs.len());
        for (index, input) in inputs.iter().enumerate() {
            let manifest: Self = serde_yaml::from_str(input).map_err(|err| {
                RuntimeError::ManifestInvalid(format!(
                    "failed to parse manifest chain entry {index} as YAML: {err}"
                ))
            })?;
            manifests.push(manifest);
        }
        Self::merge_chain(manifests)
    }

    pub fn from_yaml_str(input: &str) -> Result<Self, RuntimeError> {
        let manifest: Self = serde_yaml::from_str(input)
            .map_err(|err| RuntimeError::ManifestInvalid(err.to_string()))?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn from_json_str(input: &str) -> Result<Self, RuntimeError> {
        let manifest: Self = serde_json::from_str(input)
            .map_err(|err| RuntimeError::ManifestInvalid(err.to_string()))?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), RuntimeError> {
        self.validate_overlay()?;
        if self.intervention_points.is_empty() {
            return Err(RuntimeError::ManifestInvalid(
                "at least one intervention point config is required".to_string(),
            ));
        }
        for (intervention_point, config) in &self.intervention_points {
            validate_point_config(*intervention_point, config, self)?;
        }
        Ok(())
    }

    pub fn validate_overlay(&self) -> Result<(), RuntimeError> {
        let version = self.agent_control_specification_version.trim();
        if version.is_empty() {
            return Err(RuntimeError::ManifestInvalid(
                "agent_control_specification_version is required".to_string(),
            ));
        }
        if !manifest_version::SUPPORTED.contains(&version) {
            return Err(RuntimeError::ManifestInvalid(format!(
                "unsupported agent_control_specification_version '{version}'; supported versions are {}",
                manifest_version::SUPPORTED.join(", ")
            )));
        }

        for extends in &self.extends {
            if extends.reference().trim().is_empty() {
                return Err(RuntimeError::ManifestInvalid(
                    "extends entries must not be empty".to_string(),
                ));
            }
            validate_extends_trust(extends)?;
        }

        for (policy_name, policy_config) in &self.policies {
            if policy_name.trim().is_empty() {
                return Err(RuntimeError::ManifestInvalid(
                    "policy ids must not be empty".to_string(),
                ));
            }
            validate_policy_definition(policy_name, policy_config)?;
        }

        for annotator_name in self.annotators.keys() {
            if annotator_name.trim().is_empty() {
                return Err(RuntimeError::ManifestInvalid(
                    "annotator names must not be empty".to_string(),
                ));
            }
        }

        for (annotator_name, annotator) in &self.annotators {
            validate_annotator_prompt_sources(annotator_name, annotator)?;
        }

        if let Some(approval) = &self.approval {
            validate_approval_section(approval)?;
        }

        Ok(())
    }
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

pub fn validate_manifest_yaml(input: &str) -> Result<(), RuntimeError> {
    let value = parse_manifest_yaml_value(input)?;
    let manifest: Manifest = serde_json::from_value(value)
        .map_err(|err| RuntimeError::ManifestInvalid(err.to_string()))?;
    manifest.validate()
}

pub fn validate_manifest_overlay_yaml(input: &str) -> Result<(), RuntimeError> {
    let value = parse_manifest_yaml_value(input)?;
    let manifest: Manifest = serde_json::from_value(value)
        .map_err(|err| RuntimeError::ManifestInvalid(err.to_string()))?;
    manifest.validate_overlay()
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

fn validate_point_config(
    intervention_point: InterventionPoint,
    config: &InterventionPointConfig,
    manifest: &Manifest,
) -> Result<(), RuntimeError> {
    let policy_target = &config.policy_target;
    if policy_target.trim().is_empty() {
        return Err(RuntimeError::ManifestInvalid(format!(
            "intervention point {intervention_point} must define policy_target after extends resolution"
        )));
    }
    let policy_target_path = JsonPath::parse_with_snapshot_alias(policy_target).map_err(|err| {
        RuntimeError::ManifestInvalid(format!(
            "invalid policy_target for intervention point {intervention_point}: {err}"
        ))
    })?;
    if policy_target_path.root() != PathRoot::Snap {
        return Err(RuntimeError::ManifestInvalid(format!(
            "policy_target for intervention point {intervention_point} must use $, $snap, or a snapshot alias"
        )));
    }

    if let Some(kind) = &config.policy_target_kind {
        if kind.trim().is_empty() {
            return Err(RuntimeError::ManifestInvalid(format!(
                "policy_target_kind for intervention point {intervention_point} must not be empty"
            )));
        }
    }

    if let Some(tool_name_from) = &config.tool_name_from {
        if !intervention_point.is_tool_intervention_point() {
            return Err(RuntimeError::ManifestInvalid(format!(
                "tool_name_from is only valid on tool intervention points, not {intervention_point}"
            )));
        }
        let tool_path = JsonPath::parse_with_snapshot_alias(tool_name_from).map_err(|err| {
            RuntimeError::ManifestInvalid(format!(
                "invalid tool_name_from for intervention point {intervention_point}: {err}"
            ))
        })?;
        if tool_path.root() != PathRoot::Snap {
            return Err(RuntimeError::ManifestInvalid(format!(
                "tool_name_from for intervention point {intervention_point} must use $, $snap, or a snapshot alias"
            )));
        }
    }

    for (annotation_name, annotation_config) in &config.annotations {
        if !manifest.annotators.contains_key(annotation_name) {
            return Err(RuntimeError::ManifestInvalid(format!(
                "intervention point {intervention_point} references unknown annotator '{annotation_name}'"
            )));
        }
        if annotation_config.fields.contains_key("annotator") {
            return Err(RuntimeError::ManifestInvalid(format!(
                "annotation '{annotation_name}' for intervention point {intervention_point} must use the annotations map key as the annotator name"
            )));
        }
        if annotation_config.from.trim().is_empty() {
            return Err(RuntimeError::ManifestInvalid(format!(
                "annotation '{annotation_name}' for intervention point {intervention_point} must define from"
            )));
        }
        let from_path =
            JsonPath::parse_with_snapshot_alias(&annotation_config.from).map_err(|err| {
                RuntimeError::ManifestInvalid(format!(
                    "invalid annotation '{annotation_name}' from path for intervention point {intervention_point}: {err}"
                ))
            })?;
        if from_path.references_pi_annotations() {
            return Err(RuntimeError::ManifestInvalid(format!(
                "annotation '{annotation_name}' for intervention point {intervention_point} must not reference existing policy-input annotations"
            )));
        }
        if let Some(annotator) = manifest.annotators.get(annotation_name) {
            validate_merged_annotation_prompt_sources(
                intervention_point,
                annotation_name,
                annotation_config,
                annotator,
            )?;
        }
    }

    let policy = &config.policy;
    if policy.id.trim().is_empty() {
        return Err(RuntimeError::ManifestInvalid(format!(
            "intervention point {intervention_point} must define policy after extends resolution"
        )));
    }
    let policy_config = manifest.policies.get(&policy.id).ok_or_else(|| {
        RuntimeError::ManifestInvalid(format!(
            "intervention point {intervention_point} references unknown policy '{}'",
            policy.id
        ))
    })?;
    validate_policy_binding(intervention_point, policy, policy_config)?;

    Ok(())
}

fn validate_approval_section(approval: &ApprovalSection) -> Result<(), RuntimeError> {
    if let Some(default_resolver) = &approval.default_resolver {
        if default_resolver.trim().is_empty() {
            return Err(RuntimeError::ManifestInvalid(
                "approval.default_resolver must not be empty".to_string(),
            ));
        }
        if !approval.resolvers.is_empty()
            && !approval.resolvers.contains_key(default_resolver.as_str())
        {
            return Err(RuntimeError::ManifestInvalid(format!(
                "approval.default_resolver '{default_resolver}' does not match any entry under approval.resolvers"
            )));
        }
    }

    if let Some(timeout_seconds) = approval.timeout_seconds {
        if timeout_seconds == 0 {
            return Err(RuntimeError::ManifestInvalid(
                "approval.timeout_seconds must be greater than zero".to_string(),
            ));
        }
    }

    if let Some(fatigue_threshold) = approval.fatigue_threshold {
        if fatigue_threshold == 0 {
            return Err(RuntimeError::ManifestInvalid(
                "approval.fatigue_threshold must be greater than zero".to_string(),
            ));
        }
    }

    if let Some(fatigue_window_seconds) = approval.fatigue_window_seconds {
        if fatigue_window_seconds == 0 {
            return Err(RuntimeError::ManifestInvalid(
                "approval.fatigue_window_seconds must be greater than zero".to_string(),
            ));
        }
    }

    for (resolver_name, resolver_config) in &approval.resolvers {
        if resolver_name.trim().is_empty() {
            return Err(RuntimeError::ManifestInvalid(
                "approval.resolvers entries must have non-empty names".to_string(),
            ));
        }
        if resolver_config.resolver_type.trim().is_empty() {
            return Err(RuntimeError::ManifestInvalid(format!(
                "approval.resolvers.{resolver_name}.type must not be empty"
            )));
        }
    }

    Ok(())
}

fn empty_object() -> JsonValue {
    JsonValue::Object(Map::new())
}

fn is_empty_policy_binding(policy: &PolicyBinding) -> bool {
    policy.id.is_empty() && policy.query.is_none() && policy.adapter_config.is_empty()
}

struct ManifestLoader {
    stack: Vec<ManifestLocation>,
    trust_root: Option<PathBuf>,
    limits: Limits,
    url_bodies: BTreeMap<String, Vec<u8>>,
    fetcher: Box<dyn ExtendsFetcher>,
    /// Tracks whether every fetch in a URL load chain carried a verified hash
    /// pin. Set by `load_url` from the top level pin and cleared whenever an
    /// unpinned URL `extends` entry is resolved. Only meaningful for a URL
    /// sourced load. A fully pinned chain is content addressed end to end, so
    /// the host that chose the top pin transitively vouches for every merged
    /// byte, which lets a fully pinned URL sourced manifest carry a remote rego
    /// `bundle_url`.
    chain_fully_pinned: bool,
}

impl Default for ManifestLoader {
    fn default() -> Self {
        Self::with_limits(Limits::default())
    }
}

impl ManifestLoader {
    fn with_limits(limits: Limits) -> Self {
        Self {
            stack: Vec::new(),
            trust_root: None,
            limits,
            url_bodies: BTreeMap::new(),
            fetcher: Box::new(HttpExtendsFetcher),
            chain_fully_pinned: false,
        }
    }

    #[cfg(test)]
    fn with_limits_and_fetcher(limits: Limits, fetcher: Box<dyn ExtendsFetcher>) -> Self {
        Self {
            stack: Vec::new(),
            trust_root: None,
            limits,
            url_bodies: BTreeMap::new(),
            fetcher,
            chain_fully_pinned: false,
        }
    }

    fn load(&mut self, path: &Path) -> Result<Manifest, RuntimeError> {
        let canonical_path = canonicalize_manifest_path(path, None)?;
        let trust_root = canonical_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let previous_root = self.trust_root.replace(trust_root);
        let result = self.load_location(ManifestLocation::Path(canonical_path));
        self.trust_root = previous_root;
        let manifest = result?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Load a top level manifest fetched from an HTTPS URL. The URL and optional
    /// pin pass through the same trust gate as a URL `extends` entry. A URL
    /// sourced top level manifest has no filesystem trust root, so any local
    /// path `extends` inside it resolves against the URL rather than the file
    /// system, and filesystem path fields fail closed. A supplied pin (including
    /// a blank string) must be a valid 64 character hex digest or the load fails
    /// closed; pass `None` for an unpinned load.
    fn load_url(&mut self, url: &str, sha256: Option<&str>) -> Result<Manifest, RuntimeError> {
        let pin = ManifestUrlExtends {
            url: url.to_string(),
            integrity: None,
            sha256: sha256.map(str::to_string),
        };
        let extends = ManifestExtends::Url(pin);
        validate_extends_trust(&extends)?;
        let normalized = validate_https_url(url)?;
        let body = self.fetch_url_body(&normalized)?;
        verify_extends_hash(&extends, &normalized, &body)?;
        // The top level node is pinned when a hash was supplied and verified
        // above. An unpinned URL extends entry resolved during the load below
        // clears this, so it stays true only for a fully pinned chain.
        self.chain_fully_pinned = sha256.is_some();
        let location = ManifestLocation::Url(normalized);
        let previous_root = self.trust_root.take();
        let result = self.load_location_with_body(location.clone(), Some(body), &location);
        self.trust_root = previous_root;
        let mut manifest = result?;
        manifest.url_sourced = true;
        manifest.reject_url_sourced_local_access(self.chain_fully_pinned)?;
        manifest.validate()?;
        Ok(manifest)
    }

    fn load_extends_path(
        &mut self,
        include_path: &Path,
        including_manifest: &Path,
        extends_entry: &str,
    ) -> Result<Manifest, RuntimeError> {
        let canonical_path = canonicalize_manifest_path(include_path, Some(including_manifest))?;
        let trust_root = self.trust_root.as_ref().ok_or_else(|| {
            RuntimeError::ManifestInvalid(
                "manifest loader trust root was not initialized".to_string(),
            )
        })?;
        if !canonical_path.starts_with(trust_root) {
            return Err(RuntimeError::ManifestInvalid(format!(
                "extends entry '{extends_entry}' in '{}' resolves outside manifest root '{}': '{}'",
                including_manifest.display(),
                trust_root.display(),
                canonical_path.display()
            )));
        }
        self.load_location(ManifestLocation::Path(canonical_path))
    }

    fn load_extends_url(
        &mut self,
        url: String,
        including: &ManifestLocation,
        extends: &ManifestExtends,
    ) -> Result<Manifest, RuntimeError> {
        // An unpinned URL extends entry leaves its bytes mutable at the source,
        // so the merged chain is no longer content addressed from the top pin.
        // Clear the chain pin flag so a remote rego bundle merged in anywhere is
        // still rejected.
        if !extends_is_pinned(extends) {
            self.chain_fully_pinned = false;
        }
        let normalized = validate_https_url(&url)?;
        let body = self.fetch_url_body(&normalized)?;
        verify_extends_hash(extends, &normalized, &body)?;
        self.load_location_with_body(ManifestLocation::Url(normalized), Some(body), including)
    }

    fn load_location(&mut self, location: ManifestLocation) -> Result<Manifest, RuntimeError> {
        self.load_location_with_body(location.clone(), None, &location)
    }

    fn load_location_with_body(
        &mut self,
        location: ManifestLocation,
        body: Option<Vec<u8>>,
        including: &ManifestLocation,
    ) -> Result<Manifest, RuntimeError> {
        if self.stack.len() + 1 > self.limits.max_extends_depth {
            return Err(RuntimeError::ResourceLimitExceeded(format!(
                "manifest extends depth exceeds limit {} at '{}'",
                self.limits.max_extends_depth,
                location.label()
            )));
        }

        if let Some(start) = self.stack.iter().position(|path| path == &location) {
            let mut cycle: Vec<String> = self.stack[start..]
                .iter()
                .map(ManifestLocation::label)
                .collect();
            cycle.push(location.label());
            return Err(RuntimeError::ManifestInvalid(format!(
                "manifest extends cycle detected: {}",
                cycle.join(" -> ")
            )));
        }

        let source_bytes = match body {
            Some(body) => body,
            None => self.read_location_body(&location, including)?,
        };
        let source = String::from_utf8(source_bytes).map_err(|err| {
            RuntimeError::ManifestInvalid(format!(
                "manifest '{}' is not valid UTF-8: {err}",
                location.label()
            ))
        })?;
        let mut manifest = parse_manifest_source(&source, &location)?;
        validate_extends_entries(&manifest, &location)?;
        if let ManifestLocation::Path(canonical_path) = &location {
            let parent_dir_buf = canonical_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf();
            manifest.resolve_relative_paths(&parent_dir_buf);
        }

        self.stack.push(location.clone());
        let mut resolved: Option<Manifest> = None;
        let extends = manifest.extends.clone();
        for extends_entry in extends {
            let (included_manifest, included_source) =
                match resolve_extends_entry(&location, &extends_entry)? {
                    ResolvedExtends::Path(include_path) => {
                        let including_path = match &location {
                            ManifestLocation::Path(path) => path,
                            ManifestLocation::Url(_) => {
                                return Err(RuntimeError::ManifestInvalid(format!(
                                    "remote manifest '{}' cannot extend local path '{}'",
                                    location.label(),
                                    extends_entry.reference()
                                )))
                            }
                        };
                        let canonical_path =
                            canonicalize_manifest_path(&include_path, Some(including_path))?;
                        let manifest = self.load_extends_path(
                            &include_path,
                            including_path,
                            extends_entry.reference(),
                        )?;
                        (manifest, ManifestLocation::Path(canonical_path))
                    }
                    ResolvedExtends::Url(url) => {
                        let normalized = validate_https_url(&url)?;
                        let manifest =
                            self.load_extends_url(normalized.clone(), &location, &extends_entry)?;
                        (manifest, ManifestLocation::Url(normalized))
                    }
                };
            merge_resolved_manifest(
                &mut resolved,
                included_manifest,
                &ManifestSource::Location(included_source),
            )?;
            self.validate_merged_manifest_size(&resolved)?;
        }
        self.stack.pop();

        manifest.extends.clear();
        merge_resolved_manifest(
            &mut resolved,
            manifest,
            &ManifestSource::Location(location.clone()),
        )?;
        self.validate_merged_manifest_size(&resolved)?;
        Ok(resolved.expect("current manifest should always be merged"))
    }

    fn read_location_body(
        &mut self,
        location: &ManifestLocation,
        _including: &ManifestLocation,
    ) -> Result<Vec<u8>, RuntimeError> {
        match location {
            ManifestLocation::Path(path) => fs::read(path).map_err(|err| {
                RuntimeError::ManifestInvalid(format!(
                    "failed to read manifest file '{}': {err}",
                    path.display()
                ))
            }),
            ManifestLocation::Url(url) => self.fetch_url_body(url),
        }
    }

    fn fetch_url_body(&mut self, url: &str) -> Result<Vec<u8>, RuntimeError> {
        if let Some(body) = self.url_bodies.get(url) {
            return Ok(body.clone());
        }
        let body = self.fetcher.fetch(url, self.limits)?;
        if body.len() > self.limits.max_manifest_url_bytes {
            return Err(RuntimeError::ResourceLimitExceeded(format!(
                "manifest URL extends body from '{url}' is {} bytes, exceeding limit {}",
                body.len(),
                self.limits.max_manifest_url_bytes
            )));
        }
        self.url_bodies.insert(url.to_string(), body.clone());
        Ok(body)
    }

    fn validate_merged_manifest_size(
        &self,
        resolved: &Option<Manifest>,
    ) -> Result<(), RuntimeError> {
        let Some(manifest) = resolved else {
            return Ok(());
        };
        let serialized = serde_json::to_vec(manifest).map_err(|err| {
            RuntimeError::ResourceLimitExceeded(format!(
                "failed to serialize merged manifest for resource limit check: {err}"
            ))
        })?;
        if serialized.len() > self.limits.max_merged_manifest_bytes {
            return Err(RuntimeError::ResourceLimitExceeded(format!(
                "merged manifest serialized size {} exceeds limit {}",
                serialized.len(),
                self.limits.max_merged_manifest_bytes
            )));
        }
        Ok(())
    }
}

fn canonicalize_manifest_path(
    path: &Path,
    including_manifest: Option<&Path>,
) -> Result<PathBuf, RuntimeError> {
    fs::canonicalize(path).map_err(|err| {
        let detail = match including_manifest {
            Some(including_manifest) => format!(
                "failed to resolve extends file '{}' from '{}': {err}",
                path.display(),
                including_manifest.display()
            ),
            None => format!(
                "failed to resolve manifest file '{}': {err}",
                path.display()
            ),
        };
        RuntimeError::ManifestInvalid(detail)
    })
}

fn parse_manifest_source(
    source: &str,
    location: &ManifestLocation,
) -> Result<Manifest, RuntimeError> {
    let parse_as_json = location.is_json();
    if parse_as_json {
        serde_json::from_str(source).map_err(|err| {
            RuntimeError::ManifestInvalid(format!(
                "failed to parse manifest '{}' as JSON: {err}",
                location.label()
            ))
        })
    } else {
        serde_yaml::from_str(source).map_err(|err| {
            RuntimeError::ManifestInvalid(format!(
                "failed to parse manifest '{}' as YAML: {err}",
                location.label()
            ))
        })
    }
}

fn validate_extends_entries(
    manifest: &Manifest,
    location: &ManifestLocation,
) -> Result<(), RuntimeError> {
    for extends in &manifest.extends {
        if extends.reference().trim().is_empty() {
            return Err(RuntimeError::ManifestInvalid(format!(
                "extends entries in '{}' must not be empty",
                location.label()
            )));
        }
        validate_extends_trust(extends)?;
    }
    Ok(())
}

fn validate_chain_extends(manifest: &Manifest, index: usize) -> Result<(), RuntimeError> {
    let source = format!("manifest chain entry {index}");
    for extends in &manifest.extends {
        if extends.reference().trim().is_empty() {
            return Err(RuntimeError::ManifestInvalid(format!(
                "extends entries in {source} must not be empty"
            )));
        }
        validate_extends_trust(extends)?;
    }
    Ok(())
}

/// True when a URL `extends` entry carries a verified hash pin. A path
/// reference is never pinned. Used to track whether a URL load chain is
/// content addressed end to end.
fn extends_is_pinned(extends: &ManifestExtends) -> bool {
    matches!(
        extends,
        ManifestExtends::Url(url) if url.integrity.is_some() || url.sha256.is_some()
    )
}

fn validate_extends_trust(extends: &ManifestExtends) -> Result<(), RuntimeError> {
    if let ManifestExtends::Url(url) = extends {
        if url.integrity.is_some() && url.sha256.is_some() {
            return Err(RuntimeError::ManifestInvalid(format!(
                "extends URL '{}' must not define both integrity and sha256",
                url.url
            )));
        }
        if let Some(integrity) = &url.integrity {
            parse_integrity(integrity)?;
        }
        if let Some(sha256) = &url.sha256 {
            parse_sha256_hex(sha256)?;
        }
    }
    Ok(())
}

/// Validate the prompt source declared on an annotator. The LLM annotator
/// preset accepts an inline `system_prompt` (or its `prompt` alias), a
/// manifest relative `system_prompt_file`, or a pinned `system_prompt_url`.
/// At most one source may be set. A `system_prompt_url` MUST be an HTTPS URL
/// carrying a `sha256` or `integrity` pin, matching the extends trust gate.
/// The check runs for every construction path because `Manifest::validate`
/// is called by both the file loader and the runtime constructor.
fn validate_annotator_prompt_sources(
    name: &str,
    annotator: &AnnotatorConfig,
) -> Result<(), RuntimeError> {
    validate_prompt_source_fields(
        &format!("annotator '{name}'"),
        annotator.annotator_type == AnnotatorType::Llm,
        &annotator.fields,
    )
}

/// Reject the host local access fields on one resolved annotator field map of a
/// URL sourced manifest. Rejects the filesystem `system_prompt_file` source and
/// the four host environment secret fields (`api_key_env`, `aws_*_env`). Applied
/// to each annotator declaration and to each declaration merged with its
/// intervention point binding, so a binding cannot smuggle one of these fields
/// past a clean declaration. The error substrings ("filesystem path field",
/// "host environment secret field", "URL sourced manifest") are stable and
/// asserted by tests.
fn reject_url_sourced_annotator_fields(
    label: &str,
    fields: &BTreeMap<String, JsonValue>,
) -> Result<(), RuntimeError> {
    const HOST_ENV_SECRET_FIELDS: &[&str] = &[
        "api_key_env",
        "aws_access_key_id_env",
        "aws_secret_access_key_env",
        "aws_session_token_env",
    ];
    if fields.contains_key(FIELD_SYSTEM_PROMPT_FILE) {
        return Err(RuntimeError::ManifestInvalid(format!(
            "{label} declares filesystem path field 'system_prompt_file' in a URL sourced manifest; use 'system_prompt_url' instead"
        )));
    }
    for field in HOST_ENV_SECRET_FIELDS {
        if fields.contains_key(*field) {
            return Err(RuntimeError::ManifestInvalid(format!(
                "{label} declares host environment secret field '{field}' in a URL sourced manifest; a URL sourced manifest must not read host secrets because it also controls the dispatch endpoint and could exfiltrate them, supply the credential inline instead"
            )));
        }
    }
    Ok(())
}

/// Validate the prompt-source fields of a field map. Enforces at most one of
/// `system_prompt`/`prompt`, `system_prompt_file`, or `system_prompt_url`; that
/// a file source is a non empty string; and that a URL source is a pinned HTTPS
/// object. `is_llm` gates the file/url sources to the `llm` annotator type.
///
/// This runs against both the annotator declaration and, separately, the
/// declaration merged with each intervention point's annotation binding, since
/// `AnnotatorInvocation::from_annotation` overlays binding fields over the
/// declaration. Without the merged check a binding could set an inline `prompt`
/// that silently overrides a pinned `system_prompt_url` on the declaration,
/// defeating the pin requirement.
fn validate_prompt_source_fields(
    context: &str,
    is_llm: bool,
    fields: &BTreeMap<String, JsonValue>,
) -> Result<(), RuntimeError> {
    let has_inline = fields.contains_key(FIELD_SYSTEM_PROMPT) || fields.contains_key(FIELD_PROMPT);
    let has_file = fields.contains_key(FIELD_SYSTEM_PROMPT_FILE);
    let has_url = fields.contains_key(FIELD_SYSTEM_PROMPT_URL);

    if (has_file || has_url) && !is_llm {
        return Err(RuntimeError::ManifestInvalid(format!(
            "{context} declares a system prompt source but only the 'llm' annotator type consumes one"
        )));
    }

    let source_count = [has_inline, has_file, has_url]
        .into_iter()
        .filter(|set| *set)
        .count();
    if source_count > 1 {
        return Err(RuntimeError::ManifestInvalid(format!(
            "{context} must declare at most one of system_prompt/prompt, system_prompt_file, or system_prompt_url"
        )));
    }

    if has_file {
        match fields.get(FIELD_SYSTEM_PROMPT_FILE) {
            Some(JsonValue::String(value)) if !value.trim().is_empty() => {}
            _ => {
                return Err(RuntimeError::ManifestInvalid(format!(
                    "{context} system_prompt_file must be a non empty string"
                )))
            }
        }
    }

    if let Some(value) = fields.get(FIELD_SYSTEM_PROMPT_URL) {
        validate_pinned_https_url(&format!("{context} system_prompt_url"), value)?;
    }

    Ok(())
}

/// Validate the effective prompt source of an opted-in annotation, i.e. the
/// annotator declaration overlaid with the binding fields. Mirrors the merge in
/// `AnnotatorInvocation::from_annotation` so a binding cannot smuggle in a
/// second, weaker prompt source.
fn validate_merged_annotation_prompt_sources(
    intervention_point: InterventionPoint,
    annotation_name: &str,
    annotation_config: &AnnotationConfig,
    annotator: &AnnotatorConfig,
) -> Result<(), RuntimeError> {
    let mut merged = annotator.fields.clone();
    for (key, value) in &annotation_config.fields {
        merged.insert(key.clone(), value.clone());
    }
    validate_prompt_source_fields(
        &format!("annotation '{annotation_name}' for intervention point {intervention_point}"),
        annotator.annotator_type == AnnotatorType::Llm,
        &merged,
    )
}

/// Validate that a manifest field is a pinned HTTPS URL object. The value MUST
/// be an object with a `url` member and a `sha256` or `integrity` pin, the URL
/// MUST be HTTPS, and the two pin forms MUST NOT appear together. Reused by the
/// annotator `system_prompt_url` and the rego `bundle_url` fields. Unlike
/// extends, an unpinned URL is rejected so a default dispatcher never trusts an
/// unverified remote artefact. Returns the parsed pin for the caller.
pub(crate) fn validate_pinned_https_url(
    context: &str,
    value: &JsonValue,
) -> Result<ManifestUrlExtends, RuntimeError> {
    let url_extends: ManifestUrlExtends = serde_json::from_value(value.clone()).map_err(|err| {
        RuntimeError::ManifestInvalid(format!(
            "{context} must be an object with 'url' and a 'sha256' or 'integrity' pin: {err}"
        ))
    })?;
    if url_extends.integrity.is_none() && url_extends.sha256.is_none() {
        return Err(RuntimeError::ManifestInvalid(format!(
            "{context} must declare a 'sha256' or 'integrity' pin"
        )));
    }
    validate_extends_trust(&ManifestExtends::Url(url_extends.clone()))?;
    validate_https_url(&url_extends.url)?;
    Ok(url_extends)
}

/// Fetch a pinned HTTPS artefact at dispatch time over the extends fetch path
/// and trust gate. Reused by the bundled LLM dispatcher (system prompt) and the
/// bundled OPA dispatcher (rego bundle). Fails closed on a non HTTPS URL, a
/// missing pin, a fetch error, a size breach, or a hash mismatch. The body is
/// capped at `limits.max_manifest_url_bytes`, the same cap as URL extends.
#[cfg(any(feature = "default-dispatchers", feature = "opa"))]
pub(crate) fn fetch_pinned_https_bytes(
    value: &JsonValue,
    limits: Limits,
) -> Result<Vec<u8>, RuntimeError> {
    fetch_pinned_https_bytes_with(value, limits, &HttpExtendsFetcher)
}

#[cfg(any(feature = "default-dispatchers", feature = "opa", test))]
fn fetch_pinned_https_bytes_with(
    value: &JsonValue,
    limits: Limits,
    fetcher: &dyn ExtendsFetcher,
) -> Result<Vec<u8>, RuntimeError> {
    let url_extends = validate_pinned_https_url("pinned URL", value)?;
    let extends = ManifestExtends::Url(url_extends.clone());
    let normalized = validate_https_url(&url_extends.url)?;
    let body = fetcher.fetch(&normalized, limits)?;
    if body.len() > limits.max_manifest_url_bytes {
        return Err(RuntimeError::ResourceLimitExceeded(format!(
            "pinned URL body from '{normalized}' exceeds limit {}",
            limits.max_manifest_url_bytes
        )));
    }
    verify_extends_hash(&extends, &normalized, &body)?;
    Ok(body)
}

/// Fetch a pinned HTTPS prompt and decode it as UTF-8 text. Used by the bundled
/// LLM dispatcher so a default judge reads its system prompt from a verified
/// remote source.
#[cfg(feature = "default-dispatchers")]
pub(crate) fn fetch_pinned_https_text(
    value: &JsonValue,
    limits: Limits,
) -> Result<String, RuntimeError> {
    let body = fetch_pinned_https_bytes(value, limits)?;
    String::from_utf8(body).map_err(|err| {
        RuntimeError::ManifestInvalid(format!("pinned URL body is not valid UTF-8: {err}"))
    })
}

fn resolve_extends_entry(
    parent: &ManifestLocation,
    extends: &ManifestExtends,
) -> Result<ResolvedExtends, RuntimeError> {
    match extends {
        ManifestExtends::Reference(reference) => resolve_reference(parent, reference),
        ManifestExtends::Url(url) => {
            resolve_url_reference(parent, &url.url).map(ResolvedExtends::Url)
        }
    }
}

fn resolve_reference(
    parent: &ManifestLocation,
    reference: &str,
) -> Result<ResolvedExtends, RuntimeError> {
    if has_url_scheme(reference) {
        let url = validate_https_url(reference)?;
        return Ok(ResolvedExtends::Url(url));
    }
    match parent {
        ManifestLocation::Path(path) => {
            let parent_dir = path.parent().unwrap_or_else(|| Path::new("."));
            let extends_path = Path::new(reference);
            if extends_path.is_absolute() {
                Ok(ResolvedExtends::Path(extends_path.to_path_buf()))
            } else {
                Ok(ResolvedExtends::Path(parent_dir.join(extends_path)))
            }
        }
        ManifestLocation::Url(_) => {
            resolve_url_reference(parent, reference).map(ResolvedExtends::Url)
        }
    }
}

fn resolve_url_reference(parent: &ManifestLocation, raw: &str) -> Result<String, RuntimeError> {
    let parsed = match url::Url::parse(raw) {
        Ok(url) => url,
        Err(url::ParseError::RelativeUrlWithoutBase) => match parent {
            ManifestLocation::Url(base) => {
                let base_url = url::Url::parse(base).map_err(|err| {
                    RuntimeError::ManifestInvalid(format!(
                        "internal manifest URL '{base}' is invalid: {err}"
                    ))
                })?;
                base_url.join(raw).map_err(|err| {
                    RuntimeError::ManifestInvalid(format!(
                        "failed to resolve URL extends entry '{raw}' from '{base}': {err}"
                    ))
                })?
            }
            ManifestLocation::Path(path) => {
                return Err(RuntimeError::ManifestInvalid(format!(
                    "extends URL '{raw}' in '{}' must be absolute HTTPS",
                    path.display()
                )))
            }
        },
        Err(err) => {
            return Err(RuntimeError::ManifestInvalid(format!(
                "extends URL '{raw}' is invalid: {err}"
            )))
        }
    };
    validate_url_components(parsed)
}

fn validate_https_url(raw: &str) -> Result<String, RuntimeError> {
    let parsed = url::Url::parse(raw).map_err(|err| {
        RuntimeError::ManifestInvalid(format!("extends URL '{raw}' is invalid: {err}"))
    })?;
    validate_url_components(parsed)
}

fn validate_url_components(mut parsed: url::Url) -> Result<String, RuntimeError> {
    if parsed.scheme() != "https" {
        return Err(RuntimeError::ManifestInvalid(format!(
            "extends URL '{}' uses unsupported URL scheme '{}'; only https is allowed",
            parsed,
            parsed.scheme()
        )));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(RuntimeError::ManifestInvalid(format!(
            "extends URL '{}' must not include credentials",
            parsed
        )));
    }
    if parsed.fragment().is_some() {
        return Err(RuntimeError::ManifestInvalid(format!(
            "extends URL '{}' must not include a fragment",
            parsed
        )));
    }
    // SSRF guard: reject a literal loopback or link-local destination. Link-local
    // covers the cloud metadata endpoint 169.254.169.254 (and fe80::/10). RFC1918
    // private ranges are intentionally NOT blocked here, because hosting a policy
    // bundle or manifest on an internal HTTPS host is a legitimate deployment;
    // hostname based SSRF (a name that resolves into these ranges, or DNS
    // rebinding) and per redirect hop re validation are tracked follow-ups.
    match parsed.host() {
        Some(url::Host::Ipv4(ip)) if is_blocked_fetch_ip(std::net::IpAddr::V4(ip)) => {
            return Err(RuntimeError::ManifestInvalid(format!(
                "URL '{parsed}' targets a loopback or link-local address, which is blocked to prevent SSRF to a host-local or cloud metadata endpoint"
            )));
        }
        Some(url::Host::Ipv6(ip)) if is_blocked_fetch_ip(std::net::IpAddr::V6(ip)) => {
            return Err(RuntimeError::ManifestInvalid(format!(
                "URL '{parsed}' targets a loopback or link-local address, which is blocked to prevent SSRF to a host-local or cloud metadata endpoint"
            )));
        }
        _ => {}
    }
    parsed.set_fragment(None);
    Ok(parsed.to_string())
}

/// Return true for IP destinations that a manifest URL fetch must not target,
/// to prevent server side request forgery to the host itself or to a cloud
/// metadata endpoint. Loopback, the unspecified address, the IPv4 broadcast
/// address, and link-local (IPv4 169.254.0.0/16 including 169.254.169.254, and
/// IPv6 fe80::/10) are blocked. RFC1918 and IPv6 unique-local are deliberately
/// allowed so internal HTTPS policy hosting keeps working. IPv4-mapped
/// (`::ffff:a.b.c.d`) and IPv4-compatible (`::a.b.c.d`) IPv6 literals are
/// canonicalized to their embedded IPv4 address first, so a dual-stack host
/// cannot route past the guard via `[::ffff:169.254.169.254]` or
/// `[::ffff:127.0.0.1]`.
fn is_blocked_fetch_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_blocked_fetch_ipv4(v4),
        std::net::IpAddr::V6(v6) => {
            // Native IPv6 specials first, so ::1 and :: are caught here before
            // the IPv4 canonicalization below (to_ipv4 would otherwise map ::1
            // to 0.0.0.1 and let it slip through).
            if v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // IPv4-mapped (::ffff:a.b.c.d): the dual-stack form a connect()
            // routes to the embedded IPv4 address.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_fetch_ipv4(v4);
            }
            // IPv4-compatible (::a.b.c.d, deprecated): the ::1 / :: cases are
            // already handled above, so any remaining embedded IPv4 is checked.
            if let Some(v4) = v6.to_ipv4() {
                return is_blocked_fetch_ipv4(v4);
            }
            false
        }
    }
}

/// Block list for a concrete IPv4 destination of a manifest URL fetch. Shared by
/// the IPv4 arm and the IPv4-mapped/compatible IPv6 canonicalization.
fn is_blocked_fetch_ipv4(v4: std::net::Ipv4Addr) -> bool {
    v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() || v4.is_broadcast()
}

fn has_url_scheme(reference: &str) -> bool {
    let trimmed = reference.trim_start();
    if !trimmed.contains("://") {
        return false;
    }
    let Some(colon_index) = trimmed.find(':') else {
        return false;
    };
    trimmed[..colon_index]
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic())
        && trimmed[..colon_index]
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '-' | '.'))
}

fn verify_extends_hash(
    extends: &ManifestExtends,
    url: &str,
    body: &[u8],
) -> Result<(), RuntimeError> {
    let ManifestExtends::Url(url_extends) = extends else {
        return Ok(());
    };
    let actual = sha256_digest(body);
    if let Some(expected) = &url_extends.sha256 {
        let expected = parse_sha256_hex(expected)?;
        if actual.as_slice() != expected.as_slice() {
            return Err(RuntimeError::ManifestInvalid(format!(
                "sha256 mismatch for extends URL '{url}'"
            )));
        }
    }
    if let Some(expected) = &url_extends.integrity {
        let expected = parse_integrity(expected)?;
        if actual.as_slice() != expected.as_slice() {
            return Err(RuntimeError::ManifestInvalid(format!(
                "integrity mismatch for extends URL '{url}'"
            )));
        }
    }
    Ok(())
}

fn sha256_digest(body: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(body);
    hasher.finalize().into()
}

fn parse_integrity(raw: &str) -> Result<Vec<u8>, RuntimeError> {
    use base64::Engine;
    let digest = raw.trim().strip_prefix("sha256-").ok_or_else(|| {
        RuntimeError::ManifestInvalid(format!(
            "extends integrity '{raw}' must use sha256-<base64>"
        ))
    })?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(digest)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(digest))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(digest))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(digest))
        .map_err(|_| {
            RuntimeError::ManifestInvalid(format!(
                "extends integrity '{raw}' must use sha256-<base64>"
            ))
        })?;
    if decoded.len() != crate::constants::sha256::DIGEST_BYTES {
        return Err(RuntimeError::ManifestInvalid(format!(
            "extends integrity '{raw}' must contain a {} byte sha256 digest",
            crate::constants::sha256::DIGEST_BYTES
        )));
    }
    Ok(decoded)
}

fn parse_sha256_hex(raw: &str) -> Result<Vec<u8>, RuntimeError> {
    let trimmed = raw.trim();
    if trimmed.len() != crate::constants::sha256::HEX_LEN
        || !trimmed.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        return Err(RuntimeError::ManifestInvalid(format!(
            "extends sha256 '{raw}' must be {} lowercase or uppercase hex characters",
            crate::constants::sha256::HEX_LEN
        )));
    }
    (0..trimmed.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&trimmed[index..index + 2], 16).map_err(|err| {
                RuntimeError::ManifestInvalid(format!("extends sha256 '{raw}' is invalid: {err}"))
            })
        })
        .collect()
}

trait ExtendsFetcher {
    fn fetch(&self, url: &str, limits: Limits) -> Result<Vec<u8>, RuntimeError>;
}

struct HttpExtendsFetcher;

impl ExtendsFetcher for HttpExtendsFetcher {
    fn fetch(&self, url: &str, limits: Limits) -> Result<Vec<u8>, RuntimeError> {
        // redirects(0) disables ureq's built in redirect follower so this
        // fetcher follows redirects itself and re runs every hop target through
        // `validate_url_components` (HTTPS only plus the SSRF IP block). ureq's
        // built in follower only enforces `https_only`, so without manual
        // following a vetted public URL could 302 to an internal or loopback
        // HTTPS host that the initial SSRF check would have rejected.
        let agent = ureq::AgentBuilder::new()
            .https_only(true)
            .try_proxy_from_env(false)
            .redirects(0)
            .timeout(Duration::from_millis(limits.manifest_url_timeout_ms))
            .build();
        self.fetch_with_agent(url, limits, agent)
    }
}

impl HttpExtendsFetcher {
    fn fetch_with_agent(
        &self,
        url: &str,
        limits: Limits,
        agent: ureq::Agent,
    ) -> Result<Vec<u8>, RuntimeError> {
        use ureq::OrAnyStatus as _;

        let max_redirects = limits.max_manifest_url_redirects;
        let mut current = url.to_string();
        // One initial request plus up to `max_redirects` validated hops.
        for _hop in 0..=max_redirects {
            let response = agent.get(&current).call().or_any_status().map_err(|err| {
                RuntimeError::ManifestInvalid(format!("failed to fetch extends URL '{url}': {err}"))
            })?;
            let status = response.status();
            if (300..400).contains(&status) {
                let location = response.header("Location").ok_or_else(|| {
                    RuntimeError::ManifestInvalid(format!(
                        "extends URL '{current}' returned redirect status {status} without a Location header"
                    ))
                })?;
                // Re validate the redirect target before following it, so a
                // redirect cannot escape the HTTPS and SSRF guards.
                current = resolve_redirect_target(&current, location)?;
                continue;
            }
            if status >= 400 {
                return Err(RuntimeError::ManifestInvalid(format!(
                    "failed to fetch extends URL '{url}': HTTP {status}"
                )));
            }
            let mut body = Vec::new();
            let mut reader = response
                .into_reader()
                .take(limits.max_manifest_url_bytes as u64 + 1);
            reader.read_to_end(&mut body).map_err(|err| {
                RuntimeError::ManifestInvalid(format!(
                    "failed to read extends URL '{url}' response body: {err}"
                ))
            })?;
            if body.len() > limits.max_manifest_url_bytes {
                return Err(RuntimeError::ResourceLimitExceeded(format!(
                    "manifest URL extends body from '{url}' exceeds limit {}",
                    limits.max_manifest_url_bytes
                )));
            }
            return Ok(body);
        }
        Err(RuntimeError::ManifestInvalid(format!(
            "too many redirects (more than {max_redirects}) while fetching extends URL '{url}'"
        )))
    }
}

/// Resolve a redirect `Location` against the current URL and re validate it
/// through the same HTTPS plus SSRF guard as the initial fetch URL, so a
/// redirect hop cannot downgrade to plain HTTP or target a loopback, link-local,
/// or cloud metadata destination. A relative `Location` is joined against the
/// current URL. Returns the normalized HTTPS URL to follow next, or fails closed.
fn resolve_redirect_target(current: &str, location: &str) -> Result<String, RuntimeError> {
    let base = url::Url::parse(current).map_err(|err| {
        RuntimeError::ManifestInvalid(format!(
            "internal redirect base URL '{current}' is invalid: {err}"
        ))
    })?;
    let joined = base.join(location).map_err(|err| {
        RuntimeError::ManifestInvalid(format!(
            "failed to resolve redirect target '{location}' from '{current}': {err}"
        ))
    })?;
    validate_url_components(joined)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ManifestLocation {
    Path(PathBuf),
    Url(String),
}

impl ManifestLocation {
    fn label(&self) -> String {
        match self {
            Self::Path(path) => path.display().to_string(),
            Self::Url(url) => url.clone(),
        }
    }

    fn is_json(&self) -> bool {
        match self {
            Self::Path(path) => path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("json")),
            Self::Url(raw) => url::Url::parse(raw)
                .ok()
                .and_then(|url| {
                    Path::new(url.path())
                        .extension()
                        .and_then(|extension| extension.to_str().map(str::to_string))
                })
                .is_some_and(|extension| extension.eq_ignore_ascii_case("json")),
        }
    }
}

enum ResolvedExtends {
    Path(PathBuf),
    Url(String),
}

#[derive(Debug)]
enum ManifestSource {
    Location(ManifestLocation),
    ChainEntry(usize),
}

impl ManifestSource {
    fn label(&self) -> String {
        match self {
            Self::Location(location) => location.label(),
            Self::ChainEntry(index) => format!("manifest chain entry {index}"),
        }
    }
}

fn merge_resolved_manifest(
    resolved: &mut Option<Manifest>,
    incoming: Manifest,
    source: &ManifestSource,
) -> Result<(), RuntimeError> {
    if let Some(existing) = resolved {
        merge_manifest(existing, incoming, source)
    } else {
        *resolved = Some(incoming);
        Ok(())
    }
}

fn merge_manifest(
    existing: &mut Manifest,
    incoming: Manifest,
    source: &ManifestSource,
) -> Result<(), RuntimeError> {
    if existing.agent_control_specification_version != incoming.agent_control_specification_version
    {
        return manifest_merge_conflict("agent_control_specification_version", source);
    }
    merge_metadata(existing, incoming.metadata, source)?;
    merge_string_keyed_map(&mut existing.tools, incoming.tools, "tools", source)?;
    merge_string_keyed_map(
        &mut existing.annotators,
        incoming.annotators,
        "annotators",
        source,
    )?;
    merge_string_keyed_map(
        &mut existing.policies,
        incoming.policies,
        "policies",
        source,
    )?;
    merge_intervention_points(
        &mut existing.intervention_points,
        incoming.intervention_points,
        source,
    )?;
    merge_approval(&mut existing.approval, incoming.approval, source)?;
    Ok(())
}

fn merge_approval(
    existing: &mut Option<ApprovalSection>,
    incoming: Option<ApprovalSection>,
    source: &ManifestSource,
) -> Result<(), RuntimeError> {
    let Some(incoming) = incoming else {
        return Ok(());
    };
    match existing {
        Some(existing_value) if existing_value == &incoming => Ok(()),
        Some(_) => manifest_merge_conflict("approval", source),
        None => {
            *existing = Some(incoming);
            Ok(())
        }
    }
}

fn merge_metadata(
    existing: &mut Manifest,
    incoming_metadata: JsonValue,
    source: &ManifestSource,
) -> Result<(), RuntimeError> {
    let empty = empty_object();
    if incoming_metadata == empty {
        return Ok(());
    }
    if existing.metadata == empty {
        existing.metadata = incoming_metadata;
        return Ok(());
    }
    if existing.metadata == incoming_metadata {
        return Ok(());
    }
    match (&mut existing.metadata, incoming_metadata) {
        (JsonValue::Object(existing), JsonValue::Object(incoming)) => {
            merge_metadata_object(existing, incoming, "metadata", source)
        }
        _ => manifest_merge_conflict("metadata", source),
    }
}

fn merge_metadata_object(
    existing: &mut Map<String, JsonValue>,
    incoming: Map<String, JsonValue>,
    path: &str,
    source: &ManifestSource,
) -> Result<(), RuntimeError> {
    for (key, value) in incoming {
        let field = format!("{path}.{key}");
        match existing.get_mut(&key) {
            Some(existing_value) if existing_value == &value => {}
            Some(JsonValue::Object(existing_object)) => match value {
                JsonValue::Object(incoming_object) => {
                    merge_metadata_object(existing_object, incoming_object, &field, source)?
                }
                _ => return manifest_merge_conflict(&field, source),
            },
            Some(_) => return manifest_merge_conflict(&field, source),
            None => {
                existing.insert(key, value);
            }
        }
    }
    Ok(())
}

fn merge_string_keyed_map<T>(
    existing: &mut BTreeMap<String, T>,
    incoming: BTreeMap<String, T>,
    map_name: &str,
    source: &ManifestSource,
) -> Result<(), RuntimeError>
where
    T: PartialEq,
{
    for (key, value) in incoming {
        match existing.get(&key) {
            Some(existing_value) if existing_value == &value => {}
            Some(_) => {
                return manifest_merge_conflict(&format!("{map_name}.{key}"), source);
            }
            None => {
                existing.insert(key, value);
            }
        }
    }
    Ok(())
}

fn merge_intervention_points(
    existing: &mut BTreeMap<InterventionPoint, InterventionPointConfig>,
    incoming: BTreeMap<InterventionPoint, InterventionPointConfig>,
    source: &ManifestSource,
) -> Result<(), RuntimeError> {
    for (intervention_point, config) in incoming {
        match existing.get_mut(&intervention_point) {
            Some(existing_config) => {
                merge_point_config(intervention_point, existing_config, config, source)?
            }
            None => {
                existing.insert(intervention_point, config);
            }
        }
    }
    Ok(())
}

fn merge_point_config(
    intervention_point: InterventionPoint,
    existing: &mut InterventionPointConfig,
    incoming: InterventionPointConfig,
    source: &ManifestSource,
) -> Result<(), RuntimeError> {
    if existing == &incoming {
        return Ok(());
    }
    let point_path = format!("intervention_points.{intervention_point}");
    if !incoming.policy_target.is_empty() {
        if existing.policy_target.is_empty() {
            existing.policy_target = incoming.policy_target;
        } else if existing.policy_target != incoming.policy_target {
            return manifest_merge_conflict(&format!("{point_path}.policy_target"), source);
        }
    }
    if let Some(policy_target_kind) = incoming.policy_target_kind {
        match &existing.policy_target_kind {
            Some(existing_policy_target_kind)
                if existing_policy_target_kind != &policy_target_kind =>
            {
                return manifest_merge_conflict(
                    &format!("{point_path}.policy_target_kind"),
                    source,
                );
            }
            None => existing.policy_target_kind = Some(policy_target_kind),
            _ => {}
        }
    }
    if let Some(tool_name_from) = incoming.tool_name_from {
        match &existing.tool_name_from {
            Some(existing_tool_name_from) if existing_tool_name_from != &tool_name_from => {
                return manifest_merge_conflict(&format!("{point_path}.tool_name_from"), source);
            }
            None => existing.tool_name_from = Some(tool_name_from),
            _ => {}
        }
    }
    if !is_empty_policy_binding(&incoming.policy) {
        if is_empty_policy_binding(&existing.policy) {
            existing.policy = incoming.policy;
        } else if existing.policy != incoming.policy {
            return manifest_merge_conflict(&format!("{point_path}.policy"), source);
        }
    }
    merge_string_keyed_map(
        &mut existing.annotations,
        incoming.annotations,
        &format!("{point_path}.annotations"),
        source,
    )
}

fn manifest_merge_conflict<T>(field: &str, source: &ManifestSource) -> Result<T, RuntimeError> {
    Err(RuntimeError::ManifestInvalid(format!(
        "manifest extends conflict for {field} from '{}': duplicate definitions must be identical or additive",
        source.label()
    )))
}

#[cfg(test)]
mod approval_section_tests {
    use super::*;
    use serde_json::json;

    const MINIMAL_BASE: &str = r#"agent_control_specification_version: 0.3.0-alpha
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: test_policy
    policy_target: $snap.input
"#;

    fn manifest_with(extra: &str) -> Result<Manifest, RuntimeError> {
        let mut input = String::from(MINIMAL_BASE);
        input.push_str(extra);
        Manifest::from_yaml_str(&input)
    }

    #[test]
    fn manifest_without_approval_section_parses_and_returns_none() {
        let manifest = manifest_with("").expect("baseline manifest parses");
        assert!(manifest.approval.is_none());
        assert!(manifest.approval().is_none());
    }

    #[test]
    fn manifest_rejects_unknown_agent_control_specification_version() {
        let error = Manifest::from_yaml_str(
            r#"agent_control_specification_version: banana
policies:
  test_policy:
    type: test
intervention_points:
  input:
    policy_target: $snap.input
    policy:
      id: test_policy
"#,
        )
        .unwrap_err();
        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(error
            .detail()
            .contains("unsupported agent_control_specification_version"));
    }

    #[test]
    fn minimal_approval_with_matching_default_resolver_parses() {
        let manifest = manifest_with(
            r#"approval:
  default_resolver: webhook
  resolvers:
    webhook:
      type: webhook
"#,
        )
        .expect("minimal approval parses");
        let approval = manifest.approval().expect("approval is present");
        assert_eq!(approval.default_resolver.as_deref(), Some("webhook"));
        assert_eq!(approval.resolvers.len(), 1);
        assert_eq!(
            approval.resolvers.get("webhook").unwrap().resolver_type,
            "webhook"
        );
    }

    #[test]
    fn full_approval_section_parses_with_resolver_type_discriminator_preserved() {
        let manifest = manifest_with(
            r#"approval:
  default_resolver: webhook
  timeout_seconds: 300
  on_timeout: suspend
  fatigue_threshold: 5
  fatigue_window_seconds: 3600
  resolvers:
    webhook:
      type: webhook
      url: https://example.com/approve
      auth:
        type: bearer
        env: AGT_APPROVAL_TOKEN
    local:
      type: local
      file: /var/lib/agt/approvals/
"#,
        )
        .expect("full approval parses");
        let approval = manifest.approval().expect("approval present");
        assert_eq!(approval.default_resolver.as_deref(), Some("webhook"));
        assert_eq!(approval.timeout_seconds, Some(300));
        assert_eq!(approval.on_timeout, Some(ApprovalOnTimeout::Suspend));
        assert_eq!(approval.fatigue_threshold, Some(5));
        assert_eq!(approval.fatigue_window_seconds, Some(3600));

        let webhook = approval.resolvers.get("webhook").expect("webhook resolver");
        assert_eq!(webhook.resolver_type, "webhook");
        assert_eq!(
            webhook
                .additional_properties
                .get("url")
                .and_then(|value| value.as_str()),
            Some("https://example.com/approve")
        );

        let local = approval.resolvers.get("local").expect("local resolver");
        assert_eq!(local.resolver_type, "local");
        assert_eq!(
            local
                .additional_properties
                .get("file")
                .and_then(|value| value.as_str()),
            Some("/var/lib/agt/approvals/")
        );
    }

    #[test]
    fn default_resolver_naming_missing_resolver_is_manifest_invalid() {
        let error = manifest_with(
            r#"approval:
  default_resolver: missing
  resolvers:
    webhook:
      type: webhook
"#,
        )
        .expect_err("default_resolver must match a resolver entry");
        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(
            error.detail().contains("missing"),
            "detail names the missing resolver: {}",
            error.detail()
        );
    }

    #[test]
    fn unknown_on_timeout_value_is_manifest_invalid() {
        let error = manifest_with(
            r#"approval:
  on_timeout: escalate
"#,
        )
        .expect_err("on_timeout enum is restricted to deny | allow | suspend");
        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
    }

    #[test]
    fn zero_timeout_seconds_is_manifest_invalid() {
        let error = manifest_with(
            r#"approval:
  timeout_seconds: 0
"#,
        )
        .expect_err("zero timeout_seconds must reject");
        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(error.detail().contains("timeout_seconds"));
    }

    #[test]
    fn zero_fatigue_threshold_is_manifest_invalid() {
        let error = manifest_with(
            r#"approval:
  fatigue_threshold: 0
"#,
        )
        .expect_err("zero fatigue_threshold must reject");
        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(error.detail().contains("fatigue_threshold"));
    }

    #[test]
    fn zero_fatigue_window_seconds_is_manifest_invalid() {
        let error = manifest_with(
            r#"approval:
  fatigue_window_seconds: 0
"#,
        )
        .expect_err("zero fatigue_window_seconds must reject");
        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(error.detail().contains("fatigue_window_seconds"));
    }

    #[test]
    fn negative_numeric_fields_fail_to_parse_as_manifest_invalid() {
        let error = manifest_with(
            r#"approval:
  timeout_seconds: -1
"#,
        )
        .expect_err("negative timeout_seconds must reject");
        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
    }

    #[test]
    fn arbitrary_host_defined_resolver_keys_round_trip_without_loss() {
        let yaml = r#"approval:
  resolvers:
    custom:
      type: custom
      backend:
        kind: queue
        topic: approvals
      retries: 3
      labels:
        - high-trust
        - secure
"#;
        let manifest = manifest_with(yaml).expect("custom resolver parses");
        let resolver = manifest
            .approval()
            .unwrap()
            .resolvers
            .get("custom")
            .expect("custom resolver present");
        assert_eq!(resolver.resolver_type, "custom");
        assert_eq!(
            resolver.additional_properties.get("backend"),
            Some(&json!({"kind": "queue", "topic": "approvals"}))
        );
        assert_eq!(
            resolver.additional_properties.get("retries"),
            Some(&json!(3))
        );
        assert_eq!(
            resolver.additional_properties.get("labels"),
            Some(&json!(["high-trust", "secure"]))
        );

        let serialized = serde_json::to_value(&manifest).expect("serialize round trip");
        let approval_json = serialized
            .get("approval")
            .expect("approval present in serialized form");
        let resolver_json = approval_json
            .pointer("/resolvers/custom")
            .expect("serialized resolver entry");
        assert_eq!(resolver_json["type"], json!("custom"));
        assert_eq!(resolver_json["backend"]["kind"], json!("queue"));
        assert_eq!(resolver_json["labels"], json!(["high-trust", "secure"]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use serde_json::json;
    use std::{
        cell::RefCell,
        collections::BTreeMap,
        fs,
        io::{Read, Write},
        net::TcpListener,
        path::Path,
        rc::Rc,
        thread::{self, JoinHandle},
    };

    #[derive(Clone)]
    struct MockFetcher {
        bodies: Rc<BTreeMap<String, Vec<u8>>>,
        calls: Rc<RefCell<BTreeMap<String, usize>>>,
    }

    impl MockFetcher {
        fn new(bodies: BTreeMap<String, Vec<u8>>) -> Self {
            Self {
                bodies: Rc::new(bodies),
                calls: Rc::new(RefCell::new(BTreeMap::new())),
            }
        }

        fn calls(&self, url: &str) -> usize {
            self.calls.borrow().get(url).copied().unwrap_or(0)
        }
    }

    impl ExtendsFetcher for MockFetcher {
        fn fetch(&self, url: &str, _limits: Limits) -> Result<Vec<u8>, RuntimeError> {
            *self.calls.borrow_mut().entry(url.to_string()).or_insert(0) += 1;
            self.bodies.get(url).cloned().ok_or_else(|| {
                RuntimeError::ManifestInvalid(format!("mock fetch missing body for {url}"))
            })
        }
    }

    fn base_manifest() -> &'static str {
        r#"agent_control_specification_version: 0.3.1-beta
policies:
  p:
    type: test
intervention_points:
  input:
    policy_target: $snap.input
    policy:
      id: p
"#
    }

    #[test]
    fn parses_manifest_yaml_with_runtime_scalar_semantics() {
        let value = parse_manifest_yaml_value(
            r#"agent_control_specification_version: 0.3.1-beta
metadata:
  on: 0b1010
  date: 2026-07-16
"#,
        )
        .unwrap();

        assert_eq!(value["metadata"]["on"], json!(10));
        assert_eq!(value["metadata"]["date"], json!("2026-07-16"));
    }

    #[test]
    fn rejects_duplicate_manifest_yaml_keys() {
        let error = parse_manifest_yaml_value(
            r#"agent_control_specification_version: 0.3.0-alpha
agent_control_specification_version: 0.3.1-beta
"#,
        )
        .unwrap_err();

        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(error.detail().contains("duplicate manifest mapping key"));
    }

    #[test]
    fn bounds_yaml_alias_expansion_during_deserialization() {
        let payload = "x".repeat(1024);
        let aliases = std::iter::repeat_n("*shared", 1_100)
            .collect::<Vec<_>>()
            .join(", ");
        let yaml = format!(
            "agent_control_specification_version: 0.3.1-beta\nmetadata:\n  shared: &shared \"{payload}\"\n  copies: [{aliases}]\n"
        );

        let error = parse_manifest_yaml_value(&yaml).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:resource_limit_exceeded");
        assert!(error
            .detail()
            .contains("manifest expanded size exceeds limit"));
    }

    #[test]
    fn bounds_json_escaped_aliases_during_deserialization() {
        let payload = "\\0".repeat(60_000);
        let aliases = std::iter::repeat_n("*shared", 16)
            .collect::<Vec<_>>()
            .join(", ");
        let yaml = format!(
            "agent_control_specification_version: 0.3.1-beta\nmetadata:\n  shared: &shared \"{payload}\"\n  copies: [{aliases}]\n"
        );

        let error = parse_manifest_yaml_value(&yaml).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:resource_limit_exceeded");
        assert!(error
            .detail()
            .contains("manifest expanded size exceeds limit"));
    }

    #[test]
    fn rejects_non_string_manifest_mapping_keys() {
        let error = parse_manifest_yaml_value(
            "agent_control_specification_version: 0.3.1-beta\nmetadata:\n  1: value\n",
        )
        .unwrap_err();

        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(error.detail().contains("a string manifest mapping key"));
    }

    fn root_path(name: &str, yaml: &str) -> PathBuf {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("https-extends-unit");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        fs::write(&path, yaml).unwrap();
        path
    }

    fn load_with_fetcher(
        path: &Path,
        fetcher: MockFetcher,
        limits: Limits,
    ) -> Result<Manifest, RuntimeError> {
        ManifestLoader::with_limits_and_fetcher(limits, Box::new(fetcher)).load(path)
    }

    fn load_url_with_fetcher(
        url: &str,
        sha256: Option<&str>,
        fetcher: MockFetcher,
        limits: Limits,
    ) -> Result<Manifest, RuntimeError> {
        ManifestLoader::with_limits_and_fetcher(limits, Box::new(fetcher)).load_url(url, sha256)
    }

    fn sri(body: &[u8]) -> String {
        let digest = sha256_digest(body);
        format!(
            "sha256-{}",
            base64::engine::general_purpose::STANDARD.encode(digest)
        )
    }

    fn hex_sha256(body: &[u8]) -> String {
        sha256_digest(body)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    #[test]
    fn extends_allows_annotation_only_point_overlay() {
        let base = root_path(
            "annotation-only-base.yaml",
            r#"agent_control_specification_version: 0.3.1-beta
metadata:
  name: base
policies:
  p:
    type: test
annotators:
  base_classifier:
    type: classifier
intervention_points:
  input:
    policy_target: $snap.input
    policy:
      id: p
    annotations:
      base_classifier:
        from: $policy_target.text
"#,
        );
        let overlay = root_path(
            "annotation-only-overlay.yaml",
            &format!(
                r#"agent_control_specification_version: 0.3.1-beta
extends:
  - {}
annotators:
  overlay_classifier:
    type: classifier
intervention_points:
  input:
    annotations:
      overlay_classifier:
        from: $policy_target.text
"#,
                base.file_name().unwrap().to_string_lossy()
            ),
        );

        let manifest = Manifest::from_path(&overlay).unwrap();
        let input = manifest
            .intervention_points
            .get(&InterventionPoint::Input)
            .unwrap();
        assert_eq!(input.policy_target, "$snap.input");
        assert_eq!(input.policy.id, "p");
        assert!(input.annotations.contains_key("base_classifier"));
        assert!(input.annotations.contains_key("overlay_classifier"));
        assert!(manifest.annotators.contains_key("base_classifier"));
        assert!(manifest.annotators.contains_key("overlay_classifier"));
    }

    fn http_response(status: &str, headers: &[(&str, String)], body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        for (name, value) in headers {
            response.push_str(name);
            response.push_str(": ");
            response.push_str(value);
            response.push_str("\r\n");
        }
        response.push_str("\r\n");
        let mut bytes = response.into_bytes();
        bytes.extend_from_slice(body);
        bytes
    }

    fn request_path(request: &[u8]) -> String {
        String::from_utf8_lossy(request)
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or("/")
            .to_string()
    }

    fn spawn_http_server<F>(requests: usize, mut respond: F) -> (String, JoinHandle<()>)
    where
        F: FnMut(String, String) -> Vec<u8> + Send + 'static,
    {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let thread_base_url = base_url.clone();
        let handle = thread::spawn(move || {
            for _ in 0..requests {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0_u8; 2048];
                let read = stream.read(&mut request).unwrap();
                let path = request_path(&request[..read]);
                let response = respond(thread_base_url.clone(), path);
                stream.write_all(&response).unwrap();
            }
        });
        (base_url, handle)
    }

    fn local_http_agent(redirects: usize) -> ureq::Agent {
        ureq::AgentBuilder::new()
            .try_proxy_from_env(false)
            .redirects(redirects as u32)
            .build()
    }

    #[test]
    fn real_http_fetcher_rejects_http_before_network_fetch() {
        let error = HttpExtendsFetcher
            .fetch("http://127.0.0.1/manifest.yaml", Limits::default())
            .unwrap_err();

        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(
            error.detail().contains("https")
                || error.detail().contains("HTTP is forbidden")
                || error.detail().contains("unsupported")
        );
    }

    #[test]
    fn real_http_fetcher_streaming_body_cap_fails_closed() {
        let (base_url, handle) = spawn_http_server(1, |_base_url, _path| {
            http_response("200 OK", &[], b"abcdef")
        });
        let limits = Limits {
            max_manifest_url_bytes: 4,
            ..Limits::default()
        };

        let error = HttpExtendsFetcher
            .fetch_with_agent(
                &format!("{base_url}/large.yaml"),
                limits,
                local_http_agent(0),
            )
            .unwrap_err();
        handle.join().unwrap();

        assert_eq!(error.reason(), "runtime_error:resource_limit_exceeded");
        assert!(error.detail().contains("exceeds limit 4"));
    }

    #[test]
    fn real_http_fetcher_rejects_http_error_status() {
        let (base_url, handle) = spawn_http_server(1, |_base_url, _path| {
            http_response("404 Not Found", &[], b"missing")
        });

        let error = HttpExtendsFetcher
            .fetch_with_agent(
                &format!("{base_url}/missing.yaml"),
                Limits::default(),
                local_http_agent(0),
            )
            .unwrap_err();
        handle.join().unwrap();

        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(error.detail().contains("HTTP 404"));
    }

    #[test]
    fn real_http_fetcher_revalidates_redirect_hop() {
        // A redirect hop is re-run through validate_url_components, so a vetted
        // public URL cannot bounce to a loopback or cloud metadata HTTPS host,
        // and cannot downgrade to plain HTTP. Two cases, each a single 302.
        for (location, expect) in [
            ("https://127.0.0.1:9/secret.yaml", "loopback or link-local"),
            ("http://policy.example/next.yaml", "https"),
        ] {
            let location_owned = location.to_string();
            let (base_url, handle) = spawn_http_server(1, move |_base_url, _path| {
                http_response("302 Found", &[("Location", location_owned.clone())], b"")
            });

            let error = HttpExtendsFetcher
                .fetch_with_agent(
                    &format!("{base_url}/start.yaml"),
                    Limits::default(),
                    local_http_agent(0),
                )
                .unwrap_err();
            handle.join().unwrap();

            assert_eq!(error.reason(), "runtime_error:manifest_invalid");
            assert!(
                error.detail().contains(expect),
                "redirect to {location} should be blocked ({expect}), got: {}",
                error.detail()
            );
        }
    }

    #[test]
    fn real_http_fetcher_enforces_redirect_cap() {
        // With per-hop re-validation a redirect chain to a non-loopback HTTPS
        // host is followed, but the hop count is capped. The local server keeps
        // redirecting to a fresh HTTPS host; the cap stops the chain before any
        // are followed beyond the limit.
        let (base_url, handle) = spawn_http_server(1, |_base_url, path| {
            let next = if path == "/start.yaml" {
                "https://policy.example/middle.yaml"
            } else {
                "https://policy.example/end.yaml"
            };
            http_response("302 Found", &[("Location", next.to_string())], b"")
        });

        let error = HttpExtendsFetcher
            .fetch_with_agent(
                &format!("{base_url}/start.yaml"),
                Limits {
                    max_manifest_url_redirects: 0,
                    ..Limits::default()
                },
                local_http_agent(0),
            )
            .unwrap_err();
        handle.join().unwrap();

        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(
            error.detail().contains("too many redirects"),
            "got: {}",
            error.detail()
        );
    }

    #[test]
    fn https_string_extends_fetches_and_merges() {
        let url = "https://policy.example/base.yaml";
        let fetcher = MockFetcher::new(BTreeMap::from([(
            url.to_string(),
            base_manifest().as_bytes().to_vec(),
        )]));
        let path = root_path(
            "https-string.yaml",
            &format!(
                "agent_control_specification_version: 0.3.1-beta\nextends:\n  - {url}\nmetadata:\n  name: child\n"
            ),
        );

        let manifest = load_with_fetcher(&path, fetcher.clone(), Limits::default()).unwrap();

        assert!(manifest.extends.is_empty());
        assert!(manifest.policies.contains_key("p"));
        assert_eq!(fetcher.calls(url), 1);
    }

    #[test]
    fn https_object_extends_accepts_matching_integrity() {
        let url = "https://policy.example/pinned.yaml";
        let body = base_manifest().as_bytes().to_vec();
        let fetcher = MockFetcher::new(BTreeMap::from([(url.to_string(), body.clone())]));
        let path = root_path(
            "https-integrity.yaml",
            &format!(
                "agent_control_specification_version: 0.3.1-beta\nextends:\n  - url: {url}\n    integrity: {}\n",
                sri(&body)
            ),
        );

        let manifest = load_with_fetcher(&path, fetcher, Limits::default()).unwrap();

        assert!(manifest.policies.contains_key("p"));
    }

    #[test]
    fn https_object_extends_rejects_mismatched_sha256() {
        let url = "https://policy.example/bad-pin.yaml";
        let body = base_manifest().as_bytes().to_vec();
        let fetcher = MockFetcher::new(BTreeMap::from([(url.to_string(), body)]));
        let path = root_path(
            "https-bad-sha.yaml",
            &format!(
                "agent_control_specification_version: 0.3.1-beta\nextends:\n  - url: {url}\n    sha256: {}\n",
                "00".repeat(32)
            ),
        );

        let error = load_with_fetcher(&path, fetcher, Limits::default()).unwrap_err();

        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(error.detail().contains("sha256 mismatch"));
    }

    #[test]
    fn url_extends_rejects_http_and_unsupported_schemes() {
        for (name, url) in [
            ("http-reject.yaml", "http://policy.example/base.yaml"),
            ("ftp-reject.yaml", "ftp://policy.example/base.yaml"),
        ] {
            let path = root_path(
                name,
                &format!("agent_control_specification_version: 0.3.1-beta\nextends:\n  - {url}\n"),
            );
            let error =
                load_with_fetcher(&path, MockFetcher::new(BTreeMap::new()), Limits::default())
                    .unwrap_err();
            assert_eq!(error.reason(), "runtime_error:manifest_invalid");
            assert!(error.detail().contains("unsupported URL scheme"));
        }
    }

    #[test]
    fn url_extends_detects_url_cycles() {
        let url = "https://policy.example/cycle.yaml";
        let body =
            format!("agent_control_specification_version: 0.3.1-beta\nextends:\n  - {url}\n");
        let fetcher = MockFetcher::new(BTreeMap::from([(url.to_string(), body.into_bytes())]));
        let path = root_path(
            "https-cycle.yaml",
            &format!("agent_control_specification_version: 0.3.1-beta\nextends:\n  - {url}\n"),
        );

        let error = load_with_fetcher(&path, fetcher, Limits::default()).unwrap_err();

        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(error.detail().contains("manifest extends cycle detected"));
    }

    #[test]
    fn url_extends_body_size_limit_fails_closed() {
        let url = "https://policy.example/large.yaml";
        let fetcher = MockFetcher::new(BTreeMap::from([(url.to_string(), b"abcdef".to_vec())]));
        let path = root_path(
            "https-large.yaml",
            &format!("agent_control_specification_version: 0.3.1-beta\nextends:\n  - {url}\n"),
        );

        let error = load_with_fetcher(
            &path,
            fetcher,
            Limits {
                max_manifest_url_bytes: 4,
                ..Limits::default()
            },
        )
        .unwrap_err();

        assert_eq!(error.reason(), "runtime_error:resource_limit_exceeded");
    }

    #[test]
    fn from_url_fetches_and_validates_pinned_manifest() {
        let url = "https://policy.example/top.yaml";
        let body = base_manifest().as_bytes().to_vec();
        let pin = hex_sha256(&body);
        let fetcher = MockFetcher::new(BTreeMap::from([(url.to_string(), body)]));

        let manifest =
            load_url_with_fetcher(url, Some(&pin), fetcher.clone(), Limits::default()).unwrap();

        assert!(manifest.policies.contains_key("p"));
        assert!(manifest
            .intervention_points
            .contains_key(&InterventionPoint::Input));
        assert_eq!(fetcher.calls(url), 1);
    }

    #[test]
    fn from_url_allows_missing_pin() {
        // The pin is optional, mirroring URL extends, so an unpinned URL is
        // fetched and validated because the host chose it.
        let url = "https://policy.example/top.yaml";
        let body = base_manifest().as_bytes().to_vec();
        let fetcher = MockFetcher::new(BTreeMap::from([(url.to_string(), body)]));

        let manifest =
            load_url_with_fetcher(url, None, fetcher.clone(), Limits::default()).unwrap();

        assert!(manifest.policies.contains_key("p"));
        assert_eq!(fetcher.calls(url), 1);
    }

    #[test]
    fn from_url_rejects_blank_pin() {
        // A supplied but blank pin is a malformed pin and fails closed, matching
        // URL extends; only `None` means unpinned. The fetch never runs.
        let url = "https://policy.example/top.yaml";
        let body = base_manifest().as_bytes().to_vec();
        for pin in ["", "   "] {
            let fetcher = MockFetcher::new(BTreeMap::from([(url.to_string(), body.clone())]));
            let error = load_url_with_fetcher(url, Some(pin), fetcher.clone(), Limits::default())
                .unwrap_err();
            assert_eq!(error.reason(), "runtime_error:manifest_invalid");
            assert_eq!(fetcher.calls(url), 0);
        }
    }

    #[test]
    fn from_url_rejects_filesystem_path_fields() {
        // A URL sourced manifest cannot reference local files; each filesystem
        // path field fails closed so a remote manifest cannot read local files.
        let url = "https://policy.example/top.yaml";
        let cases = [
            // rego bundle path
            "agent_control_specification_version: 0.3.1-beta\npolicies:\n  p:\n    type: rego\n    bundle: ./policy\nintervention_points:\n  input:\n    policy_target: $snap.input\n    policy:\n      id: p\n",
            // annotator system_prompt_file
            "agent_control_specification_version: 0.3.1-beta\npolicies:\n  p:\n    type: test\nannotators:\n  judge:\n    type: llm\n    system_prompt_file: /etc/secret\nintervention_points:\n  input:\n    policy_target: $snap.input\n    policy:\n      id: p\n",
            // cedar policy_path
            "agent_control_specification_version: 0.3.1-beta\npolicies:\n  p:\n    type: cedar\n    policy_path: /etc/policy.cedar\nintervention_points:\n  input:\n    policy_target: $snap.input\n    policy:\n      id: p\n",
            // adapter data path
            "agent_control_specification_version: 0.3.1-beta\npolicies:\n  p:\n    type: rego\n    bundle_url:\n      url: https://policy.example/b.tar.gz\n      sha256: 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n    data: /etc/data.json\nintervention_points:\n  input:\n    policy_target: $snap.input\n    policy:\n      id: p\n",
        ];
        for body in cases {
            let fetcher = MockFetcher::new(BTreeMap::from([(
                url.to_string(),
                body.as_bytes().to_vec(),
            )]));
            let error = load_url_with_fetcher(url, None, fetcher, Limits::default()).unwrap_err();
            assert_eq!(error.reason(), "runtime_error:manifest_invalid");
            assert!(error.detail().contains("URL sourced manifest"));
        }
    }

    #[test]
    fn from_url_rejects_host_env_secret_fields() {
        // A URL sourced manifest also picks the dispatch endpoint, so it must not
        // read host environment secrets, or a remote manifest could name a
        // credential env var and exfiltrate it to an attacker endpoint.
        let url = "https://policy.example/top.yaml";
        for field in [
            "api_key_env",
            "aws_access_key_id_env",
            "aws_secret_access_key_env",
            "aws_session_token_env",
        ] {
            let body = format!(
                "agent_control_specification_version: 0.3.1-beta\npolicies:\n  p:\n    type: test\nannotators:\n  judge:\n    type: llm\n    {field}: AWS_SECRET_ACCESS_KEY\nintervention_points:\n  input:\n    policy_target: $snap.input\n    policy:\n      id: p\n"
            );
            let fetcher = MockFetcher::new(BTreeMap::from([(url.to_string(), body.into_bytes())]));
            let error = load_url_with_fetcher(url, None, fetcher, Limits::default()).unwrap_err();
            assert_eq!(error.reason(), "runtime_error:manifest_invalid");
            assert!(error.detail().contains("host environment secret"));
        }
    }

    #[test]
    fn from_url_rejects_host_env_secret_in_annotation_binding() {
        // Regression: a binding overlays its fields onto the annotator
        // declaration via AnnotatorInvocation::from_annotation, so a clean
        // declaration plus a binding that injects api_key_env must still fail
        // closed. A definition-only scan would miss this.
        let url = "https://policy.example/top.yaml";
        let body = "agent_control_specification_version: 0.3.1-beta\npolicies:\n  p:\n    type: test\nannotators:\n  judge:\n    type: llm\nintervention_points:\n  input:\n    policy_target: $snap.input\n    policy:\n      id: p\n    annotations:\n      judge:\n        from: $policy_target.text\n        api_key_env: AWS_SECRET_ACCESS_KEY\n".to_string();
        let fetcher = MockFetcher::new(BTreeMap::from([(url.to_string(), body.into_bytes())]));
        let error = load_url_with_fetcher(url, None, fetcher, Limits::default()).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(error.detail().contains("host environment secret"));
    }

    #[test]
    fn from_url_marks_manifest_url_sourced() {
        // Provenance: a URL loaded manifest is flagged url_sourced so the host
        // annotator dispatcher refuses host environment credentials for it. A
        // string or file loaded manifest stays url_sourced false by default.
        let url = "https://policy.example/top.yaml";
        let body = base_manifest().as_bytes().to_vec();
        let fetcher = MockFetcher::new(BTreeMap::from([(url.to_string(), body)]));
        let url_manifest = load_url_with_fetcher(url, None, fetcher, Limits::default()).unwrap();
        assert!(url_manifest.url_sourced);

        let string_manifest = Manifest::from_yaml_str(base_manifest()).unwrap();
        assert!(!string_manifest.url_sourced);
    }

    #[test]
    fn from_url_rejects_remote_rego_bundle_url() {
        // Security regression: an unpinned URL sourced (untrusted) manifest must
        // not carry a remote rego bundle_url, because the bundled OPA dispatcher
        // would run the fetched rego with the host environment and network, so
        // attacker chosen rego could read a host secret via opa.runtime and
        // exfiltrate it via http.send. The hash pin on the bundle does not
        // establish trust because the same unpinned manifest chooses both the
        // bundle URL and the pin. This test loads the top with no pin.
        let url = "https://policy.example/top.yaml";
        let body = "agent_control_specification_version: 0.3.1-beta\npolicies:\n  guard:\n    type: rego\n    query: data.x.verdict\n    bundle_url:\n      url: https://policy.example/bundle.tar.gz\n      sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nintervention_points:\n  input:\n    policy_target: $snap.input\n    policy:\n      id: guard\n".to_string();
        let fetcher = MockFetcher::new(BTreeMap::from([(url.to_string(), body.into_bytes())]));
        let error = load_url_with_fetcher(url, None, fetcher, Limits::default()).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(
            error.detail().contains("remote rego 'bundle_url'"),
            "got: {}",
            error.detail()
        );
        // A file sourced manifest with the same bundle_url stays valid.
        let file_manifest = Manifest::from_yaml_str(
            "agent_control_specification_version: 0.3.1-beta\npolicies:\n  guard:\n    type: rego\n    query: data.x.verdict\n    bundle_url:\n      url: https://policy.example/bundle.tar.gz\n      sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nintervention_points:\n  input:\n    policy_target: $snap.input\n    policy:\n      id: guard\n",
        );
        assert!(file_manifest.is_ok(), "file sourced bundle_url stays valid");
    }

    #[test]
    fn from_url_pinned_allows_remote_rego_bundle_url() {
        // A fully pinned URL sourced manifest is content addressed end to end, so
        // the host that chose the top level pin transitively vouches for the
        // bundle URL and its pin. The remote rego bundle_url is therefore allowed,
        // matching the file sourced trust model.
        let url = "https://policy.example/top.yaml";
        let body = "agent_control_specification_version: 0.3.1-beta\npolicies:\n  guard:\n    type: rego\n    query: data.x.verdict\n    bundle_url:\n      url: https://policy.example/bundle.tar.gz\n      sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nintervention_points:\n  input:\n    policy_target: $snap.input\n    policy:\n      id: guard\n".as_bytes().to_vec();
        let pin = hex_sha256(&body);
        let fetcher = MockFetcher::new(BTreeMap::from([(url.to_string(), body)]));
        let manifest = load_url_with_fetcher(url, Some(&pin), fetcher, Limits::default()).unwrap();
        assert!(manifest.url_sourced);
        assert!(manifest.policies.contains_key("guard"));
    }

    #[test]
    fn from_url_pinned_with_unpinned_url_extends_rejects_bundle_url() {
        // A pinned top that pulls in an unpinned URL extends is not fully pinned,
        // because the child bytes stay mutable at the source. A remote rego
        // bundle_url merged in from that child must still be rejected.
        let top_url = "https://policy.example/top.yaml";
        let child_url = "https://policy.example/child.yaml";
        let child_body = "agent_control_specification_version: 0.3.1-beta\npolicies:\n  guard:\n    type: rego\n    query: data.x.verdict\n    bundle_url:\n      url: https://policy.example/bundle.tar.gz\n      sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nintervention_points:\n  input:\n    policy_target: $snap.input\n    policy:\n      id: guard\n".as_bytes().to_vec();
        let top_body =
            format!("agent_control_specification_version: 0.3.1-beta\nextends:\n  - {child_url}\n")
                .into_bytes();
        let pin = hex_sha256(&top_body);
        let fetcher = MockFetcher::new(BTreeMap::from([
            (top_url.to_string(), top_body),
            (child_url.to_string(), child_body),
        ]));
        let error =
            load_url_with_fetcher(top_url, Some(&pin), fetcher, Limits::default()).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(
            error.detail().contains("remote rego 'bundle_url'"),
            "got: {}",
            error.detail()
        );
    }

    #[test]
    fn from_url_pinned_still_rejects_local_bundle() {
        // Even a fully pinned chain pins the path string, not the file content at
        // dispatch, so a local rego bundle path stays rejected for a URL sourced
        // manifest regardless of the pin.
        let url = "https://policy.example/top.yaml";
        let body = "agent_control_specification_version: 0.3.1-beta\npolicies:\n  guard:\n    type: rego\n    query: data.x.verdict\n    bundle: ./policy\nintervention_points:\n  input:\n    policy_target: $snap.input\n    policy:\n      id: guard\n".as_bytes().to_vec();
        let pin = hex_sha256(&body);
        let fetcher = MockFetcher::new(BTreeMap::from([(url.to_string(), body)]));
        let error = load_url_with_fetcher(url, Some(&pin), fetcher, Limits::default()).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(
            error.detail().contains("filesystem path field 'bundle'"),
            "got: {}",
            error.detail()
        );
    }

    #[test]
    fn from_url_rejects_system_prompt_file_in_annotation_binding() {
        // Regression: same binding overlay path for the filesystem source.
        let url = "https://policy.example/top.yaml";
        let body = "agent_control_specification_version: 0.3.1-beta\npolicies:\n  p:\n    type: test\nannotators:\n  judge:\n    type: llm\nintervention_points:\n  input:\n    policy_target: $snap.input\n    policy:\n      id: p\n    annotations:\n      judge:\n        from: $policy_target.text\n        system_prompt_file: /etc/secret\n".to_string();
        let fetcher = MockFetcher::new(BTreeMap::from([(url.to_string(), body.into_bytes())]));
        let error = load_url_with_fetcher(url, None, fetcher, Limits::default()).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(error.detail().contains("filesystem path field"));
    }

    #[test]
    fn ssrf_guard_blocks_ipv4_mapped_and_compatible_ipv6() {
        // Regression: an IPv4-mapped or IPv4-compatible IPv6 literal must be
        // canonicalized to its embedded IPv4 address, so a dual-stack host
        // cannot route to a loopback or cloud-metadata endpoint via these forms.
        use std::net::{IpAddr, Ipv6Addr};
        for literal in [
            "::ffff:169.254.169.254",
            "::ffff:127.0.0.1",
            "::ffff:0.0.0.0",
            "::127.0.0.1",
            "::1",
            "::",
            "fe80::1",
        ] {
            let ip: Ipv6Addr = literal.parse().unwrap();
            assert!(
                is_blocked_fetch_ip(IpAddr::V6(ip)),
                "expected {literal} to be blocked"
            );
        }
        // A mapped public address must not be a false positive.
        let public: Ipv6Addr = "::ffff:8.8.8.8".parse().unwrap();
        assert!(!is_blocked_fetch_ip(IpAddr::V6(public)));

        // End to end through the URL trust gate.
        assert!(validate_https_url("https://[::ffff:169.254.169.254]/meta").is_err());
        assert!(validate_https_url("https://[::ffff:127.0.0.1]/x").is_err());
        assert!(validate_https_url("https://[2606:4700:4700::1111]/dns").is_ok());
    }

    #[test]
    fn from_url_rejects_sha256_mismatch() {
        let url = "https://policy.example/top.yaml";
        let body = base_manifest().as_bytes().to_vec();
        let fetcher = MockFetcher::new(BTreeMap::from([(url.to_string(), body)]));

        let error = load_url_with_fetcher(url, Some(&"00".repeat(32)), fetcher, Limits::default())
            .unwrap_err();

        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(error.detail().contains("sha256 mismatch"));
    }

    #[test]
    fn from_url_rejects_non_https_scheme() {
        // The HTTPS requirement holds whether or not a pin is supplied.
        let url = "http://policy.example/top.yaml";
        let error = load_url_with_fetcher(
            url,
            None,
            MockFetcher::new(BTreeMap::new()),
            Limits::default(),
        )
        .unwrap_err();

        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(error.detail().contains("unsupported URL scheme"));
    }

    #[test]
    fn from_url_rejects_loopback_and_link_local_ssrf() {
        // A loopback or link-local destination is blocked before any fetch, so a
        // manifest URL cannot be aimed at the host itself or a cloud metadata
        // endpoint. RFC1918 private hosts stay allowed for internal hosting.
        for url in [
            "https://127.0.0.1/m.yaml",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/m.yaml",
            "https://0.0.0.0/m.yaml",
        ] {
            let error = load_url_with_fetcher(
                url,
                None,
                MockFetcher::new(BTreeMap::new()),
                Limits::default(),
            )
            .unwrap_err();
            assert_eq!(error.reason(), "runtime_error:manifest_invalid");
            assert!(
                error.detail().contains("loopback or link-local"),
                "unexpected detail for {url}: {}",
                error.detail()
            );
        }
    }

    #[test]
    fn from_url_resolves_pinned_remote_extends() {
        let parent_url = "https://policy.example/parent.yaml";
        let parent_body = base_manifest().as_bytes().to_vec();
        let child_url = "https://policy.example/child.yaml";
        let child_body = format!(
            "agent_control_specification_version: 0.3.1-beta\nextends:\n  - url: {parent_url}\n    sha256: {}\nmetadata:\n  name: child\n",
            hex_sha256(&parent_body)
        )
        .into_bytes();
        let child_pin = hex_sha256(&child_body);
        let fetcher = MockFetcher::new(BTreeMap::from([
            (parent_url.to_string(), parent_body),
            (child_url.to_string(), child_body),
        ]));

        let manifest =
            load_url_with_fetcher(child_url, Some(&child_pin), fetcher, Limits::default()).unwrap();

        assert!(manifest.extends.is_empty());
        assert!(manifest.policies.contains_key("p"));
    }

    #[test]
    fn from_url_relative_extends_resolves_against_url_not_filesystem() {
        let parent_url = "https://policy.example/base.yaml";
        let parent_body = base_manifest().as_bytes().to_vec();
        let child_url = "https://policy.example/child.yaml";
        // A relative reference under a URL parent resolves to a sibling URL, so a
        // URL sourced manifest never reaches the local filesystem.
        let child_body =
            "agent_control_specification_version: 0.3.1-beta\nextends:\n  - ./base.yaml\nmetadata:\n  name: child\n"
                .as_bytes()
                .to_vec();
        let child_pin = hex_sha256(&child_body);
        let fetcher = MockFetcher::new(BTreeMap::from([
            (parent_url.to_string(), parent_body),
            (child_url.to_string(), child_body),
        ]));

        let manifest = load_url_with_fetcher(
            child_url,
            Some(&child_pin),
            fetcher.clone(),
            Limits::default(),
        )
        .unwrap();

        assert!(manifest.policies.contains_key("p"));
        assert_eq!(fetcher.calls(parent_url), 1);
    }

    #[test]
    fn from_url_body_size_limit_fails_closed() {
        let url = "https://policy.example/top.yaml";
        let body = base_manifest().as_bytes().to_vec();
        let pin = hex_sha256(&body);
        let fetcher = MockFetcher::new(BTreeMap::from([(url.to_string(), body)]));

        let error = load_url_with_fetcher(
            url,
            Some(&pin),
            fetcher,
            Limits {
                max_manifest_url_bytes: 4,
                ..Limits::default()
            },
        )
        .unwrap_err();

        assert_eq!(error.reason(), "runtime_error:resource_limit_exceeded");
    }

    #[test]
    fn duplicate_url_extends_fetches_once_and_merges_identical() {
        let url = "https://policy.example/duplicate.yaml";
        let body = base_manifest().as_bytes().to_vec();
        let fetcher = MockFetcher::new(BTreeMap::from([(url.to_string(), body)]));
        let path = root_path(
            "https-duplicate.yaml",
            &format!(
                "agent_control_specification_version: 0.3.1-beta\nextends:\n  - {url}\n  - {url}\n"
            ),
        );

        let manifest = load_with_fetcher(&path, fetcher.clone(), Limits::default()).unwrap();

        assert!(manifest.policies.contains_key("p"));
        assert_eq!(fetcher.calls(url), 1);
    }

    #[test]
    fn sha256_helper_matches_known_digest() {
        assert_eq!(
            hex_sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    fn llm_manifest(annotator_body: &str) -> String {
        format!(
            r#"agent_control_specification_version: 0.3.1-beta
policies:
  p:
    type: test
annotators:
  judge:
    type: llm
{annotator_body}intervention_points:
  input:
    policy_target: $snap.input
    policy:
      id: p
"#
        )
    }

    #[test]
    fn llm_annotator_accepts_inline_system_prompt() {
        let manifest = Manifest::from_yaml_str(&llm_manifest("    system_prompt: be strict\n"))
            .expect("inline prompt is valid");
        assert!(manifest.annotators.contains_key("judge"));
    }

    #[test]
    fn llm_annotator_accepts_system_prompt_file_alone() {
        Manifest::from_yaml_str(&llm_manifest("    system_prompt_file: ./prompt.txt\n"))
            .expect("file prompt is valid");
    }

    #[test]
    fn llm_annotator_rejects_inline_and_file_together() {
        let error = Manifest::from_yaml_str(&llm_manifest(
            "    system_prompt: inline\n    system_prompt_file: ./prompt.txt\n",
        ))
        .unwrap_err();
        assert!(error.detail().contains("at most one"), "got: {error}");
    }

    #[test]
    fn binding_prompt_cannot_override_pinned_declaration_url() {
        // Regression: an annotation binding `prompt` must not bypass the
        // declaration's pinned system_prompt_url. The effective merged config
        // has two sources, so validation must fail closed; otherwise the
        // unpinned binding prompt silently overrides the pinned URL at dispatch.
        let yaml = r#"agent_control_specification_version: 0.3.1-beta
policies:
  p:
    type: test
annotators:
  judge:
    type: llm
    system_prompt_url:
      url: https://policy.example/p.txt
      sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
intervention_points:
  input:
    policy_target: $snap.input
    policy:
      id: p
    annotations:
      judge:
        from: $snap.input.text
        prompt: LOCAL_OVERRIDE
"#;
        let error = Manifest::from_yaml_str(yaml).unwrap_err();
        assert!(error.detail().contains("at most one"), "got: {error}");
    }

    #[test]
    fn binding_prompt_alone_on_inline_declaration_is_allowed() {
        // A binding may still set a single prompt source when the declaration
        // sets none; this must remain valid.
        let yaml = r#"agent_control_specification_version: 0.3.1-beta
policies:
  p:
    type: test
annotators:
  judge:
    type: llm
intervention_points:
  input:
    policy_target: $snap.input
    policy:
      id: p
    annotations:
      judge:
        from: $snap.input.text
        prompt: from the binding
"#;
        Manifest::from_yaml_str(yaml).expect("single binding prompt source is valid");
    }

    #[test]
    fn llm_annotator_rejects_prompt_alias_and_url_together() {
        let body = "    prompt: inline\n    system_prompt_url:\n      url: https://policy.example/p.txt\n      sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
        let error = Manifest::from_yaml_str(&llm_manifest(body)).unwrap_err();
        assert!(error.detail().contains("at most one"), "got: {error}");
    }

    #[test]
    fn llm_annotator_rejects_system_prompt_url_without_pin() {
        let body = "    system_prompt_url:\n      url: https://policy.example/p.txt\n";
        let error = Manifest::from_yaml_str(&llm_manifest(body)).unwrap_err();
        assert!(
            error.detail().contains("must declare a 'sha256'"),
            "got: {error}"
        );
    }

    #[test]
    fn llm_annotator_rejects_non_https_system_prompt_url() {
        let body = "    system_prompt_url:\n      url: http://policy.example/p.txt\n      sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";
        let error = Manifest::from_yaml_str(&llm_manifest(body)).unwrap_err();
        assert!(
            error.detail().contains("only https is allowed"),
            "got: {error}"
        );
    }

    #[test]
    fn system_prompt_file_on_classifier_is_rejected() {
        let yaml = r#"agent_control_specification_version: 0.3.1-beta
policies:
  p:
    type: test
annotators:
  c:
    type: classifier
    system_prompt_file: ./prompt.txt
intervention_points:
  input:
    policy_target: $snap.input
    policy:
      id: p
"#;
        let error = Manifest::from_yaml_str(yaml).unwrap_err();
        assert!(error.detail().contains("only the 'llm'"), "got: {error}");
    }

    #[test]
    fn resolve_relative_paths_rewrites_system_prompt_file() {
        let mut manifest =
            Manifest::from_yaml_str(&llm_manifest("    system_prompt_file: ./prompt.txt\n"))
                .unwrap();
        manifest.resolve_relative_paths(Path::new("/repo/agent"));
        let resolved = manifest.annotators["judge"]
            .fields
            .get("system_prompt_file")
            .and_then(JsonValue::as_str)
            .unwrap();
        assert_eq!(resolved, "/repo/agent/./prompt.txt");
    }

    #[test]
    fn fetch_pinned_https_bytes_returns_verified_body() {
        let url = "https://policy.example/prompt.txt";
        let body = b"be strict and concise".to_vec();
        let fetcher = MockFetcher::new(BTreeMap::from([(url.to_string(), body.clone())]));
        let value = serde_json::json!({"url": url, "sha256": hex_sha256(&body)});
        let fetched =
            fetch_pinned_https_bytes_with(&value, Limits::default(), &fetcher).expect("fetch ok");
        assert_eq!(fetched, body);
    }

    #[test]
    fn fetch_pinned_https_bytes_rejects_hash_mismatch() {
        let url = "https://policy.example/prompt.txt";
        let fetcher = MockFetcher::new(BTreeMap::from([(url.to_string(), b"tampered".to_vec())]));
        let value = serde_json::json!({"url": url, "sha256": hex_sha256(b"original")});
        let error = fetch_pinned_https_bytes_with(&value, Limits::default(), &fetcher).unwrap_err();
        assert!(error.detail().contains("sha256 mismatch"), "got: {error}");
    }

    #[test]
    fn fetch_pinned_https_bytes_rejects_missing_pin() {
        let url = "https://policy.example/prompt.txt";
        let fetcher = MockFetcher::new(BTreeMap::from([(url.to_string(), b"x".to_vec())]));
        let value = serde_json::json!({"url": url});
        let error = fetch_pinned_https_bytes_with(&value, Limits::default(), &fetcher).unwrap_err();
        assert!(
            error.detail().contains("must declare a 'sha256'"),
            "got: {error}"
        );
        assert_eq!(fetcher.calls(url), 0, "must not fetch an unpinned URL");
    }

    #[test]
    fn fetch_pinned_https_bytes_accepts_sri_integrity() {
        let url = "https://policy.example/prompt.txt";
        let body = b"audit everything".to_vec();
        let fetcher = MockFetcher::new(BTreeMap::from([(url.to_string(), body.clone())]));
        let value = serde_json::json!({"url": url, "integrity": sri(&body)});
        let fetched =
            fetch_pinned_https_bytes_with(&value, Limits::default(), &fetcher).expect("fetch ok");
        assert_eq!(fetched, body);
    }
}
