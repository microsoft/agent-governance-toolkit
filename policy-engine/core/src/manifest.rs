use crate::{
    annotation::{AnnotationConfig, AnnotatorConfig},
    paths::PathRoot,
    policy::{validate_policy_binding, validate_policy_definition, PolicyBinding, PolicyConfig},
    InterventionPoint, JsonPath, JsonValue, Limits, RuntimeError,
};
use serde::{Deserialize, Serialize};
use serde_json::Map;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub agent_control_specification_version: String,
    #[serde(default = "empty_object")]
    pub metadata: JsonValue,
    #[serde(default)]
    pub extends: Vec<String>,
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
    /// validates the shape per AGT-MANIFEST-1.0 §1 and SPECIFICATION-AGT-DELTA
    /// §D5 but does not consult resolver configuration; that plumbing lives
    /// in host SDKs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalSection>,
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
    /// approval path defaults to `deny` per SPECIFICATION-AGT-DELTA §D5.
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterventionPointConfig {
    pub policy_target: String,
    #[serde(default)]
    pub policy_target_kind: Option<String>,
    #[serde(default)]
    pub tool_name_from: Option<String>,
    #[serde(default)]
    pub annotations: BTreeMap<String, AnnotationConfig>,
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
    }

    pub fn from_path_with_limits(
        path: impl AsRef<Path>,
        limits: Limits,
    ) -> Result<Self, RuntimeError> {
        ManifestLoader::with_limits(limits).load(path.as_ref())
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
        if self.agent_control_specification_version.trim().is_empty() {
            return Err(RuntimeError::ManifestInvalid(
                "agent_control_specification_version is required".to_string(),
            ));
        }

        for extends in &self.extends {
            if extends.trim().is_empty() {
                return Err(RuntimeError::ManifestInvalid(
                    "extends entries must not be empty".to_string(),
                ));
            }
        }

        if self.intervention_points.is_empty() {
            return Err(RuntimeError::ManifestInvalid(
                "at least one intervention point config is required".to_string(),
            ));
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

        for (intervention_point, config) in &self.intervention_points {
            validate_point_config(*intervention_point, config, self)?;
        }

        if let Some(approval) = &self.approval {
            validate_approval_section(approval)?;
        }

        Ok(())
    }
}

fn validate_point_config(
    intervention_point: InterventionPoint,
    config: &InterventionPointConfig,
    manifest: &Manifest,
) -> Result<(), RuntimeError> {
    let policy_target_path =
        JsonPath::parse_with_snapshot_alias(&config.policy_target).map_err(|err| {
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
    }

    let policy_config = manifest.policies.get(&config.policy.id).ok_or_else(|| {
        RuntimeError::ManifestInvalid(format!(
            "intervention point {intervention_point} references unknown policy '{}'",
            config.policy.id
        ))
    })?;
    validate_policy_binding(intervention_point, &config.policy, policy_config)?;

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

#[derive(Default)]
struct ManifestLoader {
    stack: Vec<PathBuf>,
    trust_root: Option<PathBuf>,
    limits: Limits,
}

impl ManifestLoader {
    fn with_limits(limits: Limits) -> Self {
        Self {
            stack: Vec::new(),
            trust_root: None,
            limits,
        }
    }

    fn load(&mut self, path: &Path) -> Result<Manifest, RuntimeError> {
        let canonical_path = canonicalize_manifest_path(path, None)?;
        let trust_root = canonical_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let previous_root = self.trust_root.replace(trust_root);
        let result = self.load_canonical(canonical_path);
        self.trust_root = previous_root;
        let manifest = result?;
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
        self.load_canonical(canonical_path)
    }

    fn load_canonical(&mut self, canonical_path: PathBuf) -> Result<Manifest, RuntimeError> {
        if self.stack.len() + 1 > self.limits.max_extends_depth {
            return Err(RuntimeError::ResourceLimitExceeded(format!(
                "manifest extends depth exceeds limit {} at '{}'",
                self.limits.max_extends_depth,
                canonical_path.display()
            )));
        }

        if let Some(start) = self.stack.iter().position(|path| path == &canonical_path) {
            let mut cycle: Vec<String> = self.stack[start..]
                .iter()
                .map(|path| path.display().to_string())
                .collect();
            cycle.push(canonical_path.display().to_string());
            return Err(RuntimeError::ManifestInvalid(format!(
                "manifest extends cycle detected: {}",
                cycle.join(" -> ")
            )));
        }

        let source = fs::read_to_string(&canonical_path).map_err(|err| {
            RuntimeError::ManifestInvalid(format!(
                "failed to read manifest file '{}': {err}",
                canonical_path.display()
            ))
        })?;
        let mut manifest = parse_manifest_file(&source, &canonical_path)?;
        validate_extends_entries(&manifest, &canonical_path)?;
        let parent_dir_buf = canonical_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        manifest.resolve_relative_paths(&parent_dir_buf);

        self.stack.push(canonical_path.clone());
        let mut resolved: Option<Manifest> = None;
        let parent_dir = parent_dir_buf.as_path();
        let extends = manifest.extends.clone();
        for extends_entry in extends {
            let include_path = resolve_extends_path(parent_dir, &extends_entry, &canonical_path)?;
            let included_manifest =
                self.load_extends_path(&include_path, &canonical_path, &extends_entry)?;
            merge_resolved_manifest(
                &mut resolved,
                included_manifest,
                &ManifestSource::Path(include_path.clone()),
            )?;
            self.validate_merged_manifest_size(&resolved)?;
        }
        self.stack.pop();

        manifest.extends.clear();
        merge_resolved_manifest(
            &mut resolved,
            manifest,
            &ManifestSource::Path(canonical_path.clone()),
        )?;
        self.validate_merged_manifest_size(&resolved)?;
        Ok(resolved.expect("current manifest should always be merged"))
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

fn parse_manifest_file(source: &str, path: &Path) -> Result<Manifest, RuntimeError> {
    let parse_as_json = path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"));
    if parse_as_json {
        serde_json::from_str(source).map_err(|err| {
            RuntimeError::ManifestInvalid(format!(
                "failed to parse manifest file '{}' as JSON: {err}",
                path.display()
            ))
        })
    } else {
        serde_yaml::from_str(source).map_err(|err| {
            RuntimeError::ManifestInvalid(format!(
                "failed to parse manifest file '{}' as YAML: {err}",
                path.display()
            ))
        })
    }
}

fn validate_extends_entries(manifest: &Manifest, path: &Path) -> Result<(), RuntimeError> {
    for extends in &manifest.extends {
        if extends.trim().is_empty() {
            return Err(RuntimeError::ManifestInvalid(format!(
                "extends entries in '{}' must not be empty",
                path.display()
            )));
        }
        reject_url_shaped_extends(extends, &path.display().to_string())?;
    }
    Ok(())
}

fn validate_chain_extends(manifest: &Manifest, index: usize) -> Result<(), RuntimeError> {
    let source = format!("manifest chain entry {index}");
    for extends in &manifest.extends {
        if extends.trim().is_empty() {
            return Err(RuntimeError::ManifestInvalid(format!(
                "extends entries in {source} must not be empty"
            )));
        }
        reject_url_shaped_extends(extends, &source)?;
    }
    Ok(())
}

fn reject_url_shaped_extends(extends_entry: &str, source: &str) -> Result<(), RuntimeError> {
    let trimmed = extends_entry.trim_start();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return Err(RuntimeError::ManifestInvalid(format!(
            "extends entry '{extends_entry}' in {source} uses an unsupported URL scheme"
        )));
    }
    Ok(())
}

fn resolve_extends_path(
    parent_dir: &Path,
    extends_entry: &str,
    including_manifest: &Path,
) -> Result<PathBuf, RuntimeError> {
    reject_url_shaped_extends(extends_entry, &including_manifest.display().to_string())?;
    let extends_path = Path::new(extends_entry);
    if extends_path.is_absolute() {
        Ok(extends_path.to_path_buf())
    } else {
        Ok(parent_dir.join(extends_path))
    }
}

#[derive(Debug)]
enum ManifestSource {
    Path(PathBuf),
    ChainEntry(usize),
}

impl ManifestSource {
    fn label(&self) -> String {
        match self {
            Self::Path(path) => path.display().to_string(),
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
    if existing.metadata == empty {
        existing.metadata = incoming_metadata;
    } else if incoming_metadata != empty && existing.metadata != incoming_metadata {
        return manifest_merge_conflict("metadata", source);
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
    if existing.policy_target != incoming.policy_target {
        return manifest_merge_conflict(&format!("{point_path}.policy_target"), source);
    }
    if existing.policy_target_kind != incoming.policy_target_kind {
        return manifest_merge_conflict(&format!("{point_path}.policy_target_kind"), source);
    }
    if existing.tool_name_from != incoming.tool_name_from {
        return manifest_merge_conflict(&format!("{point_path}.tool_name_from"), source);
    }
    if existing.policy != incoming.policy {
        return manifest_merge_conflict(&format!("{point_path}.policy"), source);
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
