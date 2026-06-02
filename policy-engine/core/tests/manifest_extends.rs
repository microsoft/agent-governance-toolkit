use agent_control_specification_core::{InterventionPoint, Manifest};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
};

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/extends")
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("core crate should live under the repository root")
        .to_path_buf()
}

fn assert_manifest_invalid(path: PathBuf, expected_detail: &str) {
    let error = Manifest::from_path(&path).unwrap_err();
    assert_eq!(error.reason(), "runtime_error:manifest_invalid");
    assert!(
        error.detail().contains(expected_detail),
        "{} detail should contain {expected_detail:?}, got {:?}",
        path.display(),
        error.detail()
    );
}

fn yaml_files_with_manifest_version(root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    collect_files(root, &mut paths);
    paths
        .into_iter()
        .filter(|path| {
            matches!(
                path.extension().and_then(|ext| ext.to_str()),
                Some("yaml" | "yml")
            )
        })
        .filter(|path| {
            fs::read_to_string(path)
                .map(|text| text.contains("agent_control_specification_version"))
                .unwrap_or(false)
        })
        .collect()
}

fn collect_files(root: &Path, paths: &mut Vec<PathBuf>) {
    if !root.exists() {
        return;
    }
    for entry in
        fs::read_dir(root).unwrap_or_else(|err| panic!("failed to read {}: {err}", root.display()))
    {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_files(&path, paths);
        } else {
            paths.push(path);
        }
    }
}

fn collect_manifest_versions(root: &Path, versions: &mut Vec<(String, String)>) {
    let mut paths = Vec::new();
    collect_files(root, &mut paths);
    for path in paths {
        let Some(extension) = path.extension().and_then(|ext| ext.to_str()) else {
            continue;
        };
        if !matches!(extension, "json" | "yaml" | "yml" | "py") {
            continue;
        }
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        if !text.contains("agent_control_specification_version") {
            continue;
        }
        if extension == "json" {
            if let Ok(value) = serde_json::from_str::<Value>(&text) {
                collect_manifest_versions_from_json(&path, &value, versions);
                continue;
            }
        }
        collect_manifest_versions_from_text(&path, &text, versions);
    }
}

fn collect_manifest_versions_from_json(
    path: &Path,
    value: &Value,
    versions: &mut Vec<(String, String)>,
) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if key == "agent_control_specification_version" {
                    if let Some(version) = value.as_str() {
                        versions.push((path.display().to_string(), version.to_string()));
                    }
                }
                if key == "manifest_yaml" {
                    if let Some(text) = value.as_str() {
                        collect_manifest_versions_from_text(path, text, versions);
                    }
                }
                collect_manifest_versions_from_json(path, value, versions);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_manifest_versions_from_json(path, value, versions);
            }
        }
        _ => {}
    }
}

fn collect_manifest_versions_from_text(
    path: &Path,
    text: &str,
    versions: &mut Vec<(String, String)>,
) {
    for line in text.lines() {
        let Some((_, raw_version)) = line.split_once("agent_control_specification_version:") else {
            continue;
        };
        let version = raw_version
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .split("\\n")
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .next()
            .unwrap_or_default();
        if version.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
            versions.push((path.display().to_string(), version.to_string()));
        }
    }
}

#[test]
fn path_loader_merges_ordered_extends_and_relative_paths() {
    let manifest = Manifest::from_path(fixture_root().join("ordered/child.yaml")).unwrap();

    assert!(manifest.extends.is_empty());
    assert_eq!(manifest.metadata["name"], "extends-ordered");
    assert!(manifest.policies.contains_key("shared_policy"));
    assert!(manifest.policies.contains_key("duplicate_policy"));
    assert!(manifest.policies.contains_key("child_policy"));
    assert!(manifest.tools.contains_key("search"));
    assert!(manifest.tools.contains_key("wire_transfer"));
    assert!(manifest.annotators.contains_key("base_classifier"));
    assert!(manifest.annotators.contains_key("child_classifier"));
    assert!(manifest
        .intervention_points
        .contains_key(&InterventionPoint::Input));
    assert!(manifest
        .intervention_points
        .contains_key(&InterventionPoint::Output));
    assert!(manifest
        .intervention_points
        .contains_key(&InterventionPoint::PreToolCall));

    let input = &manifest.intervention_points[&InterventionPoint::Input];
    assert_eq!(input.policy.id, "shared_policy");
    assert!(input.annotations.contains_key("base_classifier"));
    assert!(input.annotations.contains_key("child_classifier"));
    assert_eq!(
        manifest.intervention_points[&InterventionPoint::Output]
            .policy
            .id,
        "shared_policy"
    );
}

#[test]
fn metadata_merges_additive_keys() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("manifest-extends-metadata-additive");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("base.yaml"),
        r#"agent_control_specification_version: "0.3.1-beta"
metadata:
  name: metadata-additive
  owner:
    team: policy
policies:
  p:
    type: test
intervention_points:
  input:
    policy_target: "$snap.input"
    policy:
      id: p
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("child.yaml"),
        r#"agent_control_specification_version: "0.3.1-beta"
extends:
  - base.yaml
metadata:
  name: metadata-additive
  use_case: healthcare-intake
  owner:
    contact: security
"#,
    )
    .unwrap();

    let manifest = Manifest::from_path(root.join("child.yaml")).unwrap();

    assert_eq!(manifest.metadata["name"], "metadata-additive");
    assert_eq!(manifest.metadata["use_case"], "healthcare-intake");
    assert_eq!(manifest.metadata["owner"]["team"], "policy");
    assert_eq!(manifest.metadata["owner"]["contact"], "security");
}

#[test]
fn metadata_conflicting_duplicate_keys_fail_closed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("manifest-extends-metadata-conflict");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("base.yaml"),
        r#"agent_control_specification_version: "0.3.1-beta"
metadata:
  name: parent-name
policies:
  p:
    type: test
intervention_points:
  input:
    policy_target: "$snap.input"
    policy:
      id: p
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("child.yaml"),
        r#"agent_control_specification_version: "0.3.1-beta"
extends:
  - base.yaml
metadata:
  name: child-name
"#,
    )
    .unwrap();

    assert_manifest_invalid(
        root.join("child.yaml"),
        "manifest extends conflict for metadata.name",
    );
}

#[test]
fn duplicate_identical_definitions_are_allowed() {
    let manifest = Manifest::from_path(fixture_root().join("ordered/child.yaml")).unwrap();

    assert!(manifest.policies.contains_key("duplicate_policy"));
    assert_eq!(manifest.policies.len(), 3);
    assert_eq!(manifest.tools.len(), 2);
}

#[test]
fn conflicting_policy_definitions_fail_closed() {
    assert_manifest_invalid(
        fixture_root().join("conflict/policy-conflict.yaml"),
        "manifest extends conflict for policies.shared_policy",
    );
}

#[test]
fn conflicting_intervention_point_definitions_fail_closed() {
    assert_manifest_invalid(
        fixture_root().join("conflict/intervention-point-conflict.yaml"),
        "manifest extends conflict for intervention_points.input.policy_target",
    );
}

#[test]
fn cycles_fail_closed_with_clear_error() {
    assert_manifest_invalid(
        fixture_root().join("cycle/a.yaml"),
        "manifest extends cycle detected",
    );
}

#[test]
fn missing_extends_files_fail_closed_with_clear_error() {
    assert_manifest_invalid(
        fixture_root().join("missing/child.yaml"),
        "failed to resolve extends file",
    );
}

#[test]
fn path_loader_rejects_extends_that_escape_trust_root() {
    assert_manifest_invalid(
        fixture_root().join("confinement/root/escape.yaml"),
        "resolves outside manifest root",
    );
}

#[test]
fn path_loader_allows_extends_inside_trust_root() {
    let manifest =
        Manifest::from_path(fixture_root().join("confinement/root/inside.yaml")).unwrap();

    assert!(manifest.extends.is_empty());
    assert_eq!(manifest.metadata["name"], "inside-child");
    assert!(manifest.policies.contains_key("confinement_policy"));
    assert!(manifest
        .intervention_points
        .contains_key(&InterventionPoint::Input));
}

#[test]
fn path_loader_rejects_url_shaped_extends_entries() {
    assert_manifest_invalid(
        fixture_root().join("confinement/root/url.yaml"),
        "unsupported URL scheme",
    );
}

#[test]
fn yaml_chain_rejects_url_shaped_extends_entries() {
    let yaml = "\
agent_control_specification_version: 0.3.1-beta
extends:
  - https://example.invalid/base.yaml
";
    let error = Manifest::from_yaml_chain(&[yaml]).unwrap_err();
    assert_eq!(error.reason(), "runtime_error:manifest_invalid");
    assert!(
        error.detail().contains("unresolved extends"),
        "error should explain unresolved extends, got {:?}",
        error.detail()
    );
}

#[test]
fn committed_example_manifest_loads_through_path_loader() {
    let manifest = Manifest::from_path(repo_root().join("examples/bank_agent/manifest.yaml"))
        .expect("committed example manifest should load through Manifest::from_path");
    assert_eq!(manifest.agent_control_specification_version, "0.3.1-beta");
    assert_eq!(manifest.metadata["name"], "bank-agent");
    assert_eq!(manifest.intervention_points.len(), 8);
}

#[test]
fn committed_example_and_fixture_manifest_files_load_through_path_loader() {
    let roots = [
        repo_root().join("examples"),
        repo_root().join("tests/fixtures/smoke"),
    ];
    let mut checked = Vec::new();
    for root in roots {
        for path in yaml_files_with_manifest_version(&root) {
            let display = path.display().to_string();
            if display.contains("/examples/from_agentshield/") {
                continue;
            }
            Manifest::from_path(&path)
                .unwrap_or_else(|err| panic!("{} should load: {err}", path.display()));
            checked.push(path);
        }
    }
    for path in [
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/manifests/minimal-all-interventions.yaml"),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/extends/ordered/child.yaml"),
    ] {
        Manifest::from_path(&path)
            .unwrap_or_else(|err| panic!("{} should load: {err}", path.display()));
        checked.push(path);
    }
    assert!(
        checked.len() >= 10,
        "expected committed manifests to be checked"
    );
}

#[test]
fn all_committed_manifest_version_values_are_supported() {
    let roots = [
        repo_root().join("examples"),
        repo_root().join("spec"),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests"),
        repo_root().join("sdk"),
        repo_root().join("generator"),
        repo_root().join("tests"),
        repo_root()
            .parent()
            .expect("policy-engine should live under repository root")
            .join("agent-governance-python"),
    ];
    let mut versions = Vec::new();
    for root in roots {
        collect_manifest_versions(&root, &mut versions);
    }
    versions.sort();
    versions.dedup();
    assert!(
        versions.len() >= 4,
        "expected multiple committed ACS versions"
    );

    for (source, version) in versions {
        let yaml = format!(
            "agent_control_specification_version: {version}\npolicies:\n  p:\n    type: test\nintervention_points:\n  input:\n    policy:\n      id: p\n    policy_target: $snap.input\n"
        );
        Manifest::from_yaml_str(&yaml)
            .unwrap_or_else(|err| panic!("{source} uses unsupported version {version}: {err}"));
    }
}

#[test]
fn building_a_runtime_from_unresolved_extends_fails_closed() {
    use agent_control_specification_core::{
        AnnotatorDispatcher, AnnotatorInvocation, PolicyDispatcher, PreparedPolicyInvocation,
        Runtime,
    };
    use serde_json::{json, Value};
    use std::sync::Arc;

    struct StubAnnotator;
    impl AnnotatorDispatcher for StubAnnotator {
        fn dispatch(
            &self,
            _name: &str,
            _annotator: &AnnotatorInvocation,
            _input: &Value,
        ) -> Result<Value, agent_control_specification_core::RuntimeError> {
            Ok(json!({}))
        }
    }
    struct StubPolicy;
    impl PolicyDispatcher for StubPolicy {
        fn evaluate(
            &self,
            _invocation: &PreparedPolicyInvocation,
        ) -> Result<Value, agent_control_specification_core::RuntimeError> {
            Ok(json!({"decision": "allow"}))
        }
    }

    // A `Manifest` may carry `extends` as data (the frozen contract), but an
    // unresolved `extends` must never reach an enforcing runtime: dropping the
    // bases would silently discard their intervention points and policies.
    let yaml = "\
agent_control_specification_version: 0.3.1-beta
extends:
  - ./base.yaml
intervention_points:
  input:
    policy_target: $.input
    policy:
      id: p
      query: data.p.verdict
policies:
  p:
    type: rego
    bundle: ./policy
    query: data.p.verdict
";
    let manifest = Manifest::from_yaml_str(yaml).expect("string loader preserves extends as data");
    assert_eq!(manifest.extends, vec!["./base.yaml"]);

    let result = Runtime::new(manifest, Arc::new(StubAnnotator), Arc::new(StubPolicy));
    let error = match result {
        Ok(_) => panic!("an unresolved extends must fail closed at runtime construction"),
        Err(error) => error,
    };
    assert_eq!(error.reason(), "runtime_error:manifest_invalid");
    assert!(
        error.detail().contains("extends"),
        "error should explain the unresolved extends, got {:?}",
        error.detail()
    );
}

#[test]
fn path_loader_clears_extends_so_validation_passes() {
    let manifest = Manifest::from_path(fixture_root().join("ordered/child.yaml")).unwrap();
    assert!(
        manifest.extends.is_empty(),
        "loader must clear resolved extends"
    );
}
