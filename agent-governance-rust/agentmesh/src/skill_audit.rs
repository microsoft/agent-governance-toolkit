// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Trusted skill provenance and deterministic, hash-only context metadata.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Normalized skill provenance and before/after context hashes for audit events.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillAuditMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skill_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skill_origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_source_trust: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_hash_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_hash_after: Option<String>,
}

/// Skill identifiers supplied explicitly from framework-owned state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedSkillMetadataSource {
    skill_name: Option<String>,
    skill_origin: Option<String>,
}

impl TrustedSkillMetadataSource {
    /// Creates a trusted source after trimming empty values.
    pub fn new(skill_name: Option<&str>, skill_origin: Option<&str>) -> Option<Self> {
        let skill_name = normalize(skill_name);
        let skill_origin = normalize(skill_origin);
        if skill_name.is_none() && skill_origin.is_none() {
            return None;
        }
        Some(Self {
            skill_name,
            skill_origin,
        })
    }

    /// Returns the normalized framework-owned skill name, if available.
    pub fn skill_name(&self) -> Option<&str> {
        self.skill_name.as_deref()
    }

    /// Returns the normalized framework-owned skill origin, if available.
    pub fn skill_origin(&self) -> Option<&str> {
        self.skill_origin.as_deref()
    }
}

/// Builds skill audit metadata from an explicit trusted source and JSON contexts.
///
/// Context objects are used only for hashing; skill fields are never extracted from
/// request or context payloads.
pub fn build_skill_audit_metadata(
    trusted_source: Option<&TrustedSkillMetadataSource>,
    context_before: Option<&Value>,
    context_after: Option<&Value>,
) -> Option<SkillAuditMetadata> {
    let skill_name = trusted_source.and_then(|source| source.skill_name.clone());
    let skill_origin = trusted_source.and_then(|source| source.skill_origin.clone());
    let provenance_source_trust = if skill_name.is_some() || skill_origin.is_some() {
        Some("trusted".to_string())
    } else {
        None
    };
    let context_hash_before = context_before.and_then(hash_context);
    let context_hash_after = context_after.and_then(hash_context);

    if skill_name.is_none()
        && skill_origin.is_none()
        && context_hash_before.is_none()
        && context_hash_after.is_none()
    {
        return None;
    }

    Some(SkillAuditMetadata {
        skill_name,
        skill_origin,
        provenance_source_trust,
        context_hash_before,
        context_hash_after,
    })
}

/// Returns a deterministic SHA-256 hash of a JSON-serializable context.
///
/// Object keys are sorted recursively. Null and non-serializable values return
/// `None`, allowing callers to omit the hash without blocking governance.
pub fn hash_context<T: Serialize>(context: &T) -> Option<String> {
    let value = serde_json::to_value(context).ok()?;
    if value.is_null() {
        return None;
    }

    let canonical = canonicalize(value);
    let serialized = serde_json::to_vec(&canonical).ok()?;
    let digest = Sha256::digest(serialized);
    Some(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn normalize(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        Value::Object(object) => {
            let mut properties: Vec<_> = object.into_iter().collect();
            properties.sort_by(|left, right| left.0.cmp(&right.0));
            let mut sorted = Map::new();
            for (key, value) in properties {
                sorted.insert(key, canonicalize(value));
            }
            Value::Object(sorted)
        }
        scalar => scalar,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serializer;

    #[test]
    fn trusted_metadata_is_trimmed_and_marked() {
        let trusted = TrustedSkillMetadataSource::new(Some("  planner  "), Some(" catalog "))
            .expect("non-empty metadata should create a trusted source");
        let context = serde_json::json!({"input": "hello"});
        let metadata = build_skill_audit_metadata(Some(&trusted), Some(&context), None)
            .expect("trusted metadata should be emitted");

        assert_eq!(trusted.skill_name(), Some("planner"));
        assert_eq!(trusted.skill_origin(), Some("catalog"));
        assert_eq!(metadata.skill_name.as_deref(), Some("planner"));
        assert_eq!(metadata.skill_origin.as_deref(), Some("catalog"));
        assert_eq!(metadata.provenance_source_trust.as_deref(), Some("trusted"));
        assert!(metadata.context_hash_before.is_some());
        assert!(metadata.context_hash_after.is_none());
    }

    #[test]
    fn payload_skill_fields_are_not_trusted_metadata() {
        let payload = serde_json::json!({
            "skill_name": "spoofed_skill",
            "skill_origin": "untrusted_request"
        });
        let metadata = build_skill_audit_metadata(None, Some(&payload), None)
            .expect("context hash should still be emitted");

        assert!(metadata.skill_name.is_none());
        assert!(metadata.skill_origin.is_none());
        assert!(metadata.provenance_source_trust.is_none());
        assert!(metadata.context_hash_before.is_some());
    }

    #[test]
    fn context_hash_is_stable_for_nested_object_key_order() {
        let left = serde_json::json!({
            "outer": {"z": 2, "a": 1},
            "items": [{"b": 2, "a": 1}]
        });
        let right = serde_json::json!({
            "items": [{"a": 1, "b": 2}],
            "outer": {"a": 1, "z": 2}
        });

        assert_eq!(hash_context(&left), hash_context(&right));
    }

    #[test]
    fn context_hash_matches_shared_canonical_utf8_json() {
        let context = serde_json::json!({"text": "<&>+ café"});

        assert_eq!(
            hash_context(&context).as_deref(),
            Some("64fc8ac088af1d1df47ae20c50f35b46a0037eb05a13c2cd6745da93e03ad9e9")
        );
    }

    #[test]
    fn context_hash_fails_safely_for_null_or_unserializable_context() {
        struct UnsupportedContext;

        impl Serialize for UnsupportedContext {
            fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                Err(serde::ser::Error::custom("unsupported context"))
            }
        }

        assert!(hash_context(&Value::Null).is_none());
        assert!(hash_context(&UnsupportedContext).is_none());
        assert!(TrustedSkillMetadataSource::new(Some(" "), None).is_none());
    }
}
