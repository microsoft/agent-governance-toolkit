use crate::{
    canonical_json,
    constants::{cedar_field, engine},
    InterventionPoint, JsonValue, RuntimeError,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

const DATA_PATH_KEYS: [&str; 2] = ["data", "data_paths"];

fn resolve_relative_string(value: &str, base_dir: &Path) -> Option<String> {
    if value.is_empty() {
        return None;
    }
    let candidate = Path::new(value);
    if candidate.is_absolute() {
        return None;
    }
    Some(base_dir.join(candidate).to_string_lossy().into_owned())
}

fn resolve_data_path_value(value: &mut JsonValue, base_dir: &Path) {
    match value {
        JsonValue::String(path) => {
            if let Some(resolved) = resolve_relative_string(path, base_dir) {
                *path = resolved;
            }
        }
        JsonValue::Array(items) => {
            for item in items.iter_mut() {
                if let JsonValue::String(path) = item {
                    if let Some(resolved) = resolve_relative_string(path, base_dir) {
                        *path = resolved;
                    }
                }
            }
        }
        _ => {}
    }
}

fn resolve_adapter_config_paths(adapter_config: &mut BTreeMap<String, JsonValue>, base_dir: &Path) {
    for key in DATA_PATH_KEYS {
        if let Some(value) = adapter_config.get_mut(key) {
            resolve_data_path_value(value, base_dir);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyConfig {
    Rego(RegoPolicyConfig),
    /// AGT D3.1 built-in Cedar policy type. See
    /// `policy-engine/spec/SPECIFICATION.md` §12.4.
    Cedar(CedarPolicyConfig),
    Test(TestPolicyConfig),
    Custom(CustomPolicyConfig),
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PolicyBinding {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub adapter_config: BTreeMap<String, JsonValue>,
}

impl PolicyConfig {
    pub fn engine_type(&self) -> &'static str {
        match self {
            Self::Rego(_) => engine::REGO,
            Self::Cedar(_) => engine::CEDAR,
            Self::Test(_) => engine::TEST,
            Self::Custom(_) => engine::CUSTOM,
        }
    }

    /// Rewrite manifest-relative policy paths against the directory of the
    /// manifest file that declared them. Absolute paths are left unchanged.
    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        match self {
            Self::Rego(config) => {
                if let Some(bundle) = config.bundle.as_mut() {
                    if let Some(resolved) = resolve_relative_string(bundle, base_dir) {
                        *bundle = resolved;
                    }
                }
                resolve_adapter_config_paths(&mut config.adapter_config, base_dir);
            }
            Self::Cedar(config) => {
                for path in [
                    &mut config.policy_path,
                    &mut config.entities_path,
                    &mut config.schema_path,
                ] {
                    if let Some(value) = path.as_mut() {
                        if let Some(resolved) = resolve_relative_string(value, base_dir) {
                            *value = resolved;
                        }
                    }
                }
            }
            Self::Test(config) => {
                resolve_adapter_config_paths(&mut config.adapter_config, base_dir)
            }
            Self::Custom(config) => {
                resolve_adapter_config_paths(&mut config.adapter_config, base_dir)
            }
        }
    }
}

impl PolicyBinding {
    /// Rewrite manifest-relative data paths declared on a policy binding
    /// against the directory of the manifest file that declared them.
    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        resolve_adapter_config_paths(&mut self.adapter_config, base_dir);
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegoPolicyConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub adapter_config: BTreeMap<String, JsonValue>,
}

/// AGT D3.1 Cedar policy definition. Either `policy_set` (inline Cedar text)
/// or `policy_path` (filesystem location) MUST be provided; never both.
/// Unknown fields are rejected per ACS schema strictness.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CedarPolicyConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_set: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entities_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_path: Option<String>,
    /// Optional Cedar request template object. The shape is intentionally
    /// open for the AGT v5 milestone; dispatchers MAY interpret it to override
    /// the default principal/action/resource/context mapping defined in
    /// `SPECIFICATION.md` §12.4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<JsonValue>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TestPolicyConfig {
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub adapter_config: BTreeMap<String, JsonValue>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CustomPolicyConfig {
    pub adapter: String,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub adapter_config: BTreeMap<String, JsonValue>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PreparedPolicyInvocation {
    Rego(RegoPolicyInvocation),
    /// AGT D3 cedar invocation handed to a `CedarPolicyDispatcher`.
    Cedar(CedarPolicyInvocation),
    Test(TestPolicyInvocation),
    Custom(CustomPolicyInvocation),
}

impl PreparedPolicyInvocation {
    pub fn engine_type(&self) -> &'static str {
        match self {
            Self::Rego(_) => engine::REGO,
            Self::Cedar(_) => engine::CEDAR,
            Self::Test(_) => engine::TEST,
            Self::Custom(_) => engine::CUSTOM,
        }
    }

    pub fn policy_input(&self) -> Option<&JsonValue> {
        match self {
            Self::Rego(invocation) => Some(&invocation.input),
            Self::Cedar(invocation) => Some(&invocation.input),
            Self::Test(invocation) => Some(&invocation.input),
            Self::Custom(invocation) => Some(&invocation.input),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RegoPolicyInvocation {
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub adapter_config: BTreeMap<String, JsonValue>,
    pub input: JsonValue,
    pub canonical_input: String,
}

/// AGT D3 prepared cedar invocation. Carries the resolved cedar policy
/// source (inline `policy_set` text or a `policy_path` location), the
/// optional `entities_path` / `schema_path` artefacts, the optional
/// request-template `query`, and the final policy input the runtime built
/// for this intervention point.
///
/// The dispatcher owns Cedar evaluation per `SPECIFICATION.md` §12.3.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CedarPolicyInvocation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_set: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entities_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<JsonValue>,
    pub input: JsonValue,
    pub canonical_input: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TestPolicyInvocation {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub adapter_config: BTreeMap<String, JsonValue>,
    pub input: JsonValue,
    pub canonical_input: String,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CustomPolicyInvocation {
    pub adapter: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub adapter_config: BTreeMap<String, JsonValue>,
    pub input: JsonValue,
    pub canonical_input: String,
}

pub fn validate_policy_definition(name: &str, config: &PolicyConfig) -> Result<(), RuntimeError> {
    match config {
        PolicyConfig::Rego(config) => {
            validate_optional_string("rego.query", config.query.as_deref())?;
            validate_optional_string("rego.bundle", config.bundle.as_deref())?;
            for field in cedar_field::ALL {
                if config.adapter_config.contains_key(field) {
                    return Err(RuntimeError::ManifestInvalid(format!(
                        "rego.{field} is reserved for the cedar policy type; rego policies declare a bundle"
                    )));
                }
            }
            Ok(())
        }
        PolicyConfig::Cedar(config) => validate_cedar_config(config),
        PolicyConfig::Test(_) => Ok(()),
        PolicyConfig::Custom(config) => validate_required_string("custom.adapter", &config.adapter),
    }
    .map_err(|error| {
        RuntimeError::ManifestInvalid(format!("invalid policy '{name}': {}", error.detail()))
    })
}

fn validate_cedar_config(config: &CedarPolicyConfig) -> Result<(), RuntimeError> {
    match (config.policy_set.as_deref(), config.policy_path.as_deref()) {
        (Some(_), Some(_)) => Err(RuntimeError::ManifestInvalid(
            "cedar policies must declare exactly one of policy_set or policy_path, not both"
                .to_string(),
        )),
        (None, None) => Err(RuntimeError::ManifestInvalid(
            "cedar policies must declare exactly one of policy_set or policy_path".to_string(),
        )),
        _ => Ok(()),
    }?;
    validate_optional_string("cedar.policy_set", config.policy_set.as_deref())?;
    validate_optional_string("cedar.policy_path", config.policy_path.as_deref())?;
    validate_optional_string("cedar.entities_path", config.entities_path.as_deref())?;
    validate_optional_string("cedar.schema_path", config.schema_path.as_deref())?;
    if let Some(query) = &config.query {
        if !query.is_object() {
            return Err(RuntimeError::ManifestInvalid(
                "cedar.query must be a JSON object when present".to_string(),
            ));
        }
    }
    Ok(())
}

pub fn validate_policy_binding(
    intervention_point: InterventionPoint,
    binding: &PolicyBinding,
    config: &PolicyConfig,
) -> Result<(), RuntimeError> {
    if binding.id.trim().is_empty() {
        return Err(RuntimeError::ManifestInvalid(format!(
            "policy.id for intervention point {intervention_point} must not be empty"
        )));
    }
    validate_optional_string("policy.query", binding.query.as_deref()).map_err(|error| {
        RuntimeError::ManifestInvalid(format!(
            "invalid policy binding for intervention point {intervention_point}: {}",
            error.detail()
        ))
    })?;
    if matches!(config, PolicyConfig::Rego(_)) {
        let top_level_query = match config {
            PolicyConfig::Rego(config) => config.query.as_deref(),
            _ => None,
        };
        if binding.query.as_deref().or(top_level_query).is_none() {
            return Err(RuntimeError::ManifestInvalid(format!(
                "rego policy for intervention point {intervention_point} requires policy.query"
            )));
        }
    }
    Ok(())
}

pub fn prepare_policy_invocation(
    config: &PolicyConfig,
    binding: &PolicyBinding,
    final_policy_input: &JsonValue,
) -> Result<PreparedPolicyInvocation, RuntimeError> {
    match config {
        PolicyConfig::Rego(config) => Ok(PreparedPolicyInvocation::Rego(RegoPolicyInvocation {
            query: binding
                .query
                .clone()
                .or_else(|| config.query.clone())
                .ok_or_else(|| {
                    RuntimeError::PolicyInvocationFailed(
                        "rego policy invocation requires a query".to_string(),
                    )
                })?,
            bundle: config.bundle.clone(),
            adapter_config: merge_adapter_config(&config.adapter_config, &binding.adapter_config),
            input: final_policy_input.clone(),
            canonical_input: canonical_policy_input(final_policy_input)?,
        })),
        PolicyConfig::Cedar(config) => Ok(PreparedPolicyInvocation::Cedar(CedarPolicyInvocation {
            policy_set: config.policy_set.clone(),
            policy_path: config.policy_path.clone(),
            entities_path: config.entities_path.clone(),
            schema_path: config.schema_path.clone(),
            query: config.query.clone(),
            input: final_policy_input.clone(),
            canonical_input: canonical_policy_input(final_policy_input)?,
        })),
        PolicyConfig::Test(config) => Ok(PreparedPolicyInvocation::Test(TestPolicyInvocation {
            adapter_config: merge_adapter_config(&config.adapter_config, &binding.adapter_config),
            input: final_policy_input.clone(),
            canonical_input: canonical_policy_input(final_policy_input)?,
        })),
        PolicyConfig::Custom(config) => {
            Ok(PreparedPolicyInvocation::Custom(CustomPolicyInvocation {
                adapter: config.adapter.clone(),
                adapter_config: merge_adapter_config(
                    &config.adapter_config,
                    &binding.adapter_config,
                ),
                input: final_policy_input.clone(),
                canonical_input: canonical_policy_input(final_policy_input)?,
            }))
        }
    }
}

fn validate_required_string(field: &str, value: &str) -> Result<(), RuntimeError> {
    if value.trim().is_empty() {
        Err(RuntimeError::ManifestInvalid(format!(
            "{field} must not be empty"
        )))
    } else {
        Ok(())
    }
}

fn validate_optional_string(field: &str, value: Option<&str>) -> Result<(), RuntimeError> {
    match value {
        Some(value) if value.trim().is_empty() => Err(RuntimeError::ManifestInvalid(format!(
            "{field} must not be empty"
        ))),
        _ => Ok(()),
    }
}

fn canonical_policy_input(final_policy_input: &JsonValue) -> Result<String, RuntimeError> {
    canonical_json(final_policy_input).map_err(|err| {
        RuntimeError::PolicyInvocationFailed(format!("failed to canonicalize policy input: {err}"))
    })
}

fn merge_adapter_config(
    base: &BTreeMap<String, JsonValue>,
    overrides: &BTreeMap<String, JsonValue>,
) -> BTreeMap<String, JsonValue> {
    let mut merged = base.clone();
    for (key, value) in overrides {
        merged.insert(key.clone(), value.clone());
    }
    merged
}

#[cfg(test)]
mod path_resolution_tests {
    use super::*;
    use serde_json::json;
    use std::path::Path;

    fn rego_with(bundle: Option<&str>, adapter: serde_json::Value) -> PolicyConfig {
        PolicyConfig::Rego(RegoPolicyConfig {
            query: Some("data.x.verdict".to_string()),
            bundle: bundle.map(str::to_string),
            adapter_config: adapter
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        })
    }

    #[test]
    fn relative_bundle_is_resolved_against_base_dir() {
        let mut config = rego_with(Some("./policy"), json!({}));
        config.resolve_relative_paths(Path::new("/repo/agent"));
        match config {
            PolicyConfig::Rego(c) => assert_eq!(c.bundle.as_deref(), Some("/repo/agent/./policy")),
            _ => panic!("expected rego"),
        }
    }

    #[test]
    fn absolute_bundle_is_left_unchanged() {
        let mut config = rego_with(Some("/abs/policy"), json!({}));
        config.resolve_relative_paths(Path::new("/repo/agent"));
        match config {
            PolicyConfig::Rego(c) => assert_eq!(c.bundle.as_deref(), Some("/abs/policy")),
            _ => panic!("expected rego"),
        }
    }

    #[test]
    fn adapter_data_paths_string_and_array_are_resolved() {
        let mut config = rego_with(
            Some("bundle"),
            json!({"data": "d.json", "data_paths": ["a.json", "/abs/b.json"]}),
        );
        config.resolve_relative_paths(Path::new("/base"));
        match config {
            PolicyConfig::Rego(c) => {
                assert_eq!(c.adapter_config["data"], json!("/base/d.json"));
                assert_eq!(
                    c.adapter_config["data_paths"],
                    json!(["/base/a.json", "/abs/b.json"])
                );
            }
            _ => panic!("expected rego"),
        }
    }

    #[test]
    fn binding_data_paths_are_resolved() {
        let mut binding = PolicyBinding {
            id: "p".to_string(),
            query: None,
            adapter_config: [("data".to_string(), json!("rules.json"))]
                .into_iter()
                .collect(),
        };
        binding.resolve_relative_paths(Path::new("/base"));
        assert_eq!(binding.adapter_config["data"], json!("/base/rules.json"));
    }
}

#[cfg(test)]
mod cedar_manifest_tests {
    //! AGT M2.S2 D1 manifest-side validation for the cedar policy type, per
    //! `policy-engine/spec/SPECIFICATION.md` §12.4. These tests
    //! cover the strict cross-type rules: a rego policy that carries a
    //! cedar-reserved field is rejected, a cedar policy that declares the
    //! rego-shaped `bundle` field is rejected, and a cedar policy that
    //! declares either zero or two of `policy_set` / `policy_path` is
    //! rejected.

    use crate::Manifest;

    fn parse(yaml: &str) -> Result<Manifest, crate::RuntimeError> {
        Manifest::from_yaml_str(yaml)
    }

    fn cedar_manifest(policy_body: &str) -> String {
        format!(
            r#"agent_control_specification_version: 0.3.0-alpha
policies:
  guard:
    type: cedar
{policy_body}
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: guard
    policy_target: $snap.input
"#
        )
    }

    #[test]
    fn rego_with_cedar_policy_set_field_is_rejected() {
        let yaml = r#"agent_control_specification_version: 0.3.0-alpha
policies:
  bad_rego:
    type: rego
    query: data.x.verdict
    bundle: ./policy
    policy_set: "permit(principal, action, resource);"
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: bad_rego
    policy_target: $snap.input
"#;
        let error = parse(yaml).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(
            error.detail().contains("policy_set"),
            "error detail should mention the reserved cedar field, got: {}",
            error.detail()
        );
    }

    #[test]
    fn rego_with_cedar_policy_path_field_is_rejected() {
        let yaml = r#"agent_control_specification_version: 0.3.0-alpha
policies:
  bad_rego:
    type: rego
    query: data.x.verdict
    bundle: ./policy
    policy_path: ./cedar/policy.cedar
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: bad_rego
    policy_target: $snap.input
"#;
        let error = parse(yaml).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(error.detail().contains("policy_path"));
    }

    #[test]
    fn cedar_with_rego_bundle_field_is_rejected() {
        let yaml = cedar_manifest(
            r#"    policy_set: "permit(principal, action, resource);"
    bundle: ./rego/bundle
"#,
        );
        let error = parse(&yaml).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(
            error.detail().contains("bundle") || error.detail().contains("unknown field"),
            "expected error to mention the rejected bundle field, got: {}",
            error.detail()
        );
    }

    #[test]
    fn cedar_with_neither_policy_set_nor_policy_path_is_rejected() {
        let yaml = cedar_manifest("");
        let error = parse(&yaml).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(
            error.detail().contains("policy_set") && error.detail().contains("policy_path"),
            "expected error to require exactly one of policy_set or policy_path, got: {}",
            error.detail()
        );
    }

    #[test]
    fn cedar_with_both_policy_set_and_policy_path_is_rejected() {
        let yaml = cedar_manifest(
            r#"    policy_set: "permit(principal, action, resource);"
    policy_path: ./cedar/policy.cedar
"#,
        );
        let error = parse(&yaml).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(
            error.detail().contains("not both"),
            "expected error to forbid declaring both fields, got: {}",
            error.detail()
        );
    }

    #[test]
    fn cedar_with_only_policy_set_is_accepted() {
        let yaml = cedar_manifest(
            r#"    policy_set: "permit(principal, action, resource);"
"#,
        );
        let manifest = parse(&yaml).expect("cedar manifest should parse");
        let policy = manifest
            .policies
            .get("guard")
            .expect("guard policy present");
        assert_eq!(policy.engine_type(), "cedar");
    }

    #[test]
    fn cedar_with_only_policy_path_is_accepted() {
        let yaml = cedar_manifest(
            r#"    policy_path: ./cedar/policy.cedar
    entities_path: ./cedar/entities.json
    schema_path: ./cedar/schema.cedarschema
"#,
        );
        let manifest = parse(&yaml).expect("cedar manifest should parse");
        let policy = manifest
            .policies
            .get("guard")
            .expect("guard policy present");
        assert_eq!(policy.engine_type(), "cedar");
    }

    #[test]
    fn cedar_with_unknown_field_is_rejected() {
        let yaml = cedar_manifest(
            r#"    policy_set: "permit(principal, action, resource);"
    not_a_cedar_field: surprise
"#,
        );
        let error = parse(&yaml).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
    }

    #[test]
    fn cedar_non_object_query_is_rejected() {
        let yaml = cedar_manifest(
            r#"    policy_set: "permit(principal, action, resource);"
    query: "not-an-object"
"#,
        );
        let error = parse(&yaml).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:manifest_invalid");
        assert!(error.detail().contains("query"));
    }
}
