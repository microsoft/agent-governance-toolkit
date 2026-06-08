use crate::{constants::policy_input as pi_key, InterventionPoint, JsonValue};
use serde_json::Map;
use sha2::{Digest, Sha256};
use std::fmt::Write;

pub fn build_policy_input(
    intervention_point: InterventionPoint,
    policy_target_path: &str,
    policy_target_kind: Option<&str>,
    policy_target_value: JsonValue,
    snapshot: JsonValue,
    annotations: JsonValue,
    tool: JsonValue,
) -> JsonValue {
    let mut policy_target = Map::new();
    policy_target.insert(
        pi_key::KIND.to_string(),
        policy_target_kind
            .map(|kind| JsonValue::String(kind.to_string()))
            .unwrap_or(JsonValue::Null),
    );
    policy_target.insert(
        pi_key::PATH.to_string(),
        JsonValue::String(policy_target_path.to_string()),
    );
    policy_target.insert(pi_key::VALUE.to_string(), policy_target_value);

    let mut root = Map::new();
    root.insert(
        pi_key::INTERVENTION_POINT.to_string(),
        JsonValue::String(intervention_point.as_str().to_string()),
    );
    root.insert(
        pi_key::POLICY_TARGET.to_string(),
        JsonValue::Object(policy_target),
    );
    root.insert(pi_key::SNAPSHOT.to_string(), snapshot);
    root.insert(pi_key::ANNOTATIONS.to_string(), annotations);
    root.insert(pi_key::TOOL.to_string(), tool);
    JsonValue::Object(root)
}

pub fn canonical_json(value: &JsonValue) -> Result<String, serde_json::Error> {
    serde_json::to_string(&sort_json(value))
}

pub fn action_identity(value: &JsonValue) -> Result<String, serde_json::Error> {
    let canonical = canonical_json(value)?;
    let digest = Sha256::digest(canonical.as_bytes());
    let mut hex = String::with_capacity(71);
    hex.push_str("sha256:");
    for byte in digest {
        write!(&mut hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(hex)
}

fn sort_json(value: &JsonValue) -> JsonValue {
    match value {
        JsonValue::Array(items) => JsonValue::Array(items.iter().map(sort_json).collect()),
        JsonValue::Object(map) => {
            let mut keys: Vec<_> = map.keys().cloned().collect();
            keys.sort();
            let mut sorted = Map::new();
            for key in keys {
                if let Some(value) = map.get(&key) {
                    sorted.insert(key, sort_json(value));
                }
            }
            JsonValue::Object(sorted)
        }
        other => other.clone(),
    }
}
