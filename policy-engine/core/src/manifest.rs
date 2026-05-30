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
    Ok(())
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
