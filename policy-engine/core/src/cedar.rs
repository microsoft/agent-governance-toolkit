//! AGT D3 cedar dispatcher surface.
//!
//! See `policy-engine/spec/SPECIFICATION.md` §12.4 for the normative
//! contract. This module provides three pieces:
//!
//! 1. [`CedarPolicyDispatcher`] is the trait a host implements to evaluate a
//!    [`CedarPolicyInvocation`]. It is parallel to the rego dispatcher path
//!    that lives in [`crate::opa`]; both ultimately satisfy the runtime
//!    [`crate::PolicyDispatcher`] trait so the [`crate::Runtime`] can call
//!    into either backend uniformly.
//! 2. [`CedarTestDispatcher`] is a deterministic test double, always
//!    compiled, that parses a small JSON pseudo-cedar policy set, builds a
//!    cedar [`CedarRequest`] from the policy input per D3.2, and emits an
//!    `allow`, `deny`, or advice-translated verdict per D3.3.
//! 3. [`CedarBuiltinDispatcher`] is the AGT M2.S5 D7 feature-gated bundled
//!    dispatcher backed by the upstream `cedar-policy` crate. It is gated
//!    behind the `cedar` Cargo feature so callers that do not want the
//!    heavyweight cedar dep can opt out at build time.
//!
//! The dispatcher returns a verdict-shaped `JsonValue` exactly like the OPA
//! dispatcher does, and the runtime then normalizes the value via
//! [`crate::normalize_policy_output`]. Errors fail closed with the matching
//! reserved reason from `RuntimeError`.

use crate::{
    constants::policy_input as pi_key, runtime::PolicyDispatcher, CedarPolicyInvocation, JsonValue,
    PreparedPolicyInvocation, RuntimeError,
};
use serde::Deserialize;
use serde_json::{json, Map};

/// Cedar dispatcher contract. Implementations evaluate a prepared cedar
/// invocation and return a verdict-shaped `JsonValue` that the runtime feeds
/// to [`crate::normalize_policy_output`]. Errors fail closed with
/// `runtime_error:policy_invocation_failed` or `runtime_error:policy_output_invalid`.
pub trait CedarPolicyDispatcher: Send + Sync {
    fn evaluate_cedar(&self, invocation: &CedarPolicyInvocation)
        -> Result<JsonValue, RuntimeError>;
}

/// Cedar request derived from the policy input per AGT D3.2 default mapping.
/// The dispatcher is responsible for translating this into the cedar crate's
/// native `Request` type when evaluating against the upstream engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CedarRequest {
    pub principal: CedarEntity,
    pub action: CedarEntity,
    pub resource: CedarEntity,
    pub context_keys: Vec<String>,
}

/// Cedar entity reference of the form `Type::"id"`. The test dispatcher uses
/// this string form directly; the builtin dispatcher parses it into the
/// upstream cedar crate's `EntityUid` when evaluating.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CedarEntity {
    pub kind: String,
    pub id: String,
}

impl CedarEntity {
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: id.into(),
        }
    }

    pub fn as_display(&self) -> String {
        format!("{}::\"{}\"", self.kind, self.id)
    }
}

/// Build the cedar request per AGT D3.2 default mapping. Returns
/// `runtime_error:policy_invocation_failed` when the input is missing the
/// envelope identifiers required by [`spec/agt/AGT-SNAPSHOT-1.0.md`] §1.
pub fn build_cedar_request(policy_input: &JsonValue) -> Result<CedarRequest, RuntimeError> {
    let object = policy_input.as_object().ok_or_else(|| {
        RuntimeError::PolicyInvocationFailed(
            "cedar dispatcher received non-object policy input".to_string(),
        )
    })?;

    let snapshot = object
        .get(pi_key::SNAPSHOT)
        .and_then(JsonValue::as_object)
        .ok_or_else(|| {
            RuntimeError::PolicyInvocationFailed(
                "cedar policy input is missing snapshot object".to_string(),
            )
        })?;

    let envelope = snapshot
        .get("envelope")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| {
            RuntimeError::PolicyInvocationFailed(
                "cedar policy input snapshot is missing the AGT envelope".to_string(),
            )
        })?;

    let agent_id = envelope
        .get("agent")
        .and_then(JsonValue::as_object)
        .and_then(|agent| agent.get("id"))
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            RuntimeError::PolicyInvocationFailed(
                "cedar policy input envelope is missing agent.id".to_string(),
            )
        })?;

    let intervention_point = object
        .get(pi_key::INTERVENTION_POINT)
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            RuntimeError::PolicyInvocationFailed(
                "cedar policy input is missing intervention_point".to_string(),
            )
        })?;

    let resource = resource_entity(object);

    let mut context_keys: Vec<String> = snapshot
        .keys()
        .filter(|key| *key != "envelope")
        .cloned()
        .collect();
    if let Some(JsonValue::Object(annotations)) = object.get(pi_key::ANNOTATIONS) {
        for key in annotations.keys() {
            let key = format!("annotations.{key}");
            if !context_keys.contains(&key) {
                context_keys.push(key);
            }
        }
    }
    context_keys.sort();

    Ok(CedarRequest {
        principal: CedarEntity::new("Agent", agent_id),
        action: CedarEntity::new("Action", intervention_point),
        resource,
        context_keys,
    })
}

fn resource_entity(policy_input: &Map<String, JsonValue>) -> CedarEntity {
    if let Some(JsonValue::Object(tool)) = policy_input.get(pi_key::TOOL) {
        if let Some(name) = tool.get("name").and_then(JsonValue::as_str) {
            return CedarEntity::new("Tool", name);
        }
    }
    let kind = policy_input
        .get(pi_key::POLICY_TARGET)
        .and_then(JsonValue::as_object)
        .and_then(|target| target.get(pi_key::KIND))
        .and_then(JsonValue::as_str)
        .unwrap_or("unspecified");
    CedarEntity::new("PolicyTarget", kind)
}

/// Deterministic cedar test dispatcher. The dispatcher parses
/// [`CedarPolicyInvocation::policy_set`] as a small JSON pseudo-cedar
/// document, builds a [`CedarRequest`] from the policy input per
/// [`build_cedar_request`], and applies the rules with a simple equality
/// match. This is the test double tests can drive without linking the
/// upstream cedar crate. It satisfies the AGT M2.S2 D3.3 contract for
/// allow / deny / advice translation.
///
/// The pseudo-cedar JSON shape is:
///
/// ```jsonc
/// {
///   "rules": [
///     { "effect": "forbid", "principal": "any", "action": "Action::\"pre_tool_call\"", "resource": "Tool::\"banned\"" },
///     { "effect": "permit", "principal": "any", "action": "any", "resource": "any" },
///     { "effect": "permit", "principal": "Agent::\"alice\"", "action": "Action::\"output\"", "resource": "PolicyTarget::\"assistant_output\"",
///       "advice": { "verdict": "warn", "reason": "needs_review" } }
///   ]
/// }
/// ```
///
/// Rules are scanned in declared order; the first `forbid` match wins.
/// Otherwise the first `permit` match wins. A permit rule MAY carry an
/// `advice` object, which is validated against the AGT D3.3 cedar advice
/// shape and translated into the corresponding verdict.
#[derive(Debug, Clone, Default)]
pub struct CedarTestDispatcher;

impl CedarTestDispatcher {
    pub fn new() -> Self {
        Self
    }
}

impl CedarPolicyDispatcher for CedarTestDispatcher {
    fn evaluate_cedar(
        &self,
        invocation: &CedarPolicyInvocation,
    ) -> Result<JsonValue, RuntimeError> {
        let policy_set_text = invocation.policy_set.as_deref().ok_or_else(|| {
            RuntimeError::PolicyInvocationFailed(
                "cedar test dispatcher requires an inline policy_set; policy_path is reserved for the builtin dispatcher".to_string(),
            )
        })?;
        let policy_set = parse_test_policy_set(policy_set_text)?;
        let request = build_cedar_request(&invocation.input)?;
        match policy_set.decide(&request) {
            TestDecision::Forbid(reason) => Ok(json!({
                "decision": "deny",
                "reason": reason,
            })),
            TestDecision::Permit { advice: None } => Ok(json!({ "decision": "allow" })),
            TestDecision::Permit {
                advice: Some(advice),
            } => translate_advice(advice),
            TestDecision::NoMatch => Ok(json!({
                "decision": "deny",
                "reason": "no_matching_policy",
            })),
        }
    }
}

impl PolicyDispatcher for CedarTestDispatcher {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        match invocation {
            PreparedPolicyInvocation::Cedar(invocation) => self.evaluate_cedar(invocation),
            other => Err(RuntimeError::PolicyInvocationFailed(format!(
                "cedar test dispatcher only supports Cedar invocations; received {} invocation",
                other.engine_type()
            ))),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct TestPolicySetDoc {
    #[serde(default)]
    rules: Vec<TestRuleDoc>,
}

#[derive(Debug, Clone, Deserialize)]
struct TestRuleDoc {
    effect: TestEffectDoc,
    #[serde(default)]
    principal: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    advice: Option<JsonValue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum TestEffectDoc {
    Permit,
    Forbid,
}

#[derive(Debug, Clone)]
struct TestPolicySet {
    rules: Vec<TestRule>,
}

#[derive(Debug, Clone)]
struct TestRule {
    effect: TestEffectDoc,
    principal: Option<CedarEntity>,
    action: Option<CedarEntity>,
    resource: Option<CedarEntity>,
    reason: Option<String>,
    advice: Option<JsonValue>,
}

#[derive(Debug)]
enum TestDecision {
    Forbid(String),
    Permit { advice: Option<JsonValue> },
    NoMatch,
}

impl TestPolicySet {
    fn decide(&self, request: &CedarRequest) -> TestDecision {
        let mut permit: Option<&TestRule> = None;
        for rule in &self.rules {
            if !rule.matches(request) {
                continue;
            }
            match rule.effect {
                TestEffectDoc::Forbid => {
                    return TestDecision::Forbid(
                        rule.reason
                            .clone()
                            .unwrap_or_else(|| "forbid_rule_matched".to_string()),
                    );
                }
                TestEffectDoc::Permit if permit.is_none() => {
                    permit = Some(rule);
                }
                TestEffectDoc::Permit => {}
            }
        }
        match permit {
            Some(rule) => TestDecision::Permit {
                advice: rule.advice.clone(),
            },
            None => TestDecision::NoMatch,
        }
    }
}

impl TestRule {
    fn matches(&self, request: &CedarRequest) -> bool {
        entity_matches(self.principal.as_ref(), &request.principal)
            && entity_matches(self.action.as_ref(), &request.action)
            && entity_matches(self.resource.as_ref(), &request.resource)
    }
}

fn entity_matches(pattern: Option<&CedarEntity>, actual: &CedarEntity) -> bool {
    match pattern {
        None => true,
        Some(entity) => entity == actual,
    }
}

fn parse_test_policy_set(text: &str) -> Result<TestPolicySet, RuntimeError> {
    let doc: TestPolicySetDoc = serde_json::from_str(text).map_err(|err| {
        RuntimeError::PolicyInvocationFailed(format!(
            "cedar test dispatcher failed to parse policy_set as JSON: {err}"
        ))
    })?;
    let mut rules = Vec::with_capacity(doc.rules.len());
    for (index, rule) in doc.rules.into_iter().enumerate() {
        rules.push(TestRule {
            effect: rule.effect,
            principal: parse_entity_pattern("principal", index, rule.principal.as_deref())?,
            action: parse_entity_pattern("action", index, rule.action.as_deref())?,
            resource: parse_entity_pattern("resource", index, rule.resource.as_deref())?,
            reason: rule.reason,
            advice: rule.advice,
        });
    }
    Ok(TestPolicySet { rules })
}

fn parse_entity_pattern(
    field: &str,
    index: usize,
    text: Option<&str>,
) -> Result<Option<CedarEntity>, RuntimeError> {
    let raw = match text {
        None => return Ok(None),
        Some(value) => value.trim(),
    };
    if raw.is_empty() || raw.eq_ignore_ascii_case("any") || raw == "*" {
        return Ok(None);
    }
    let Some((kind, rest)) = raw.split_once("::") else {
        return Err(RuntimeError::PolicyInvocationFailed(format!(
            "cedar test policy rule {index} field '{field}' must be 'any' or 'Type::\"id\"', got '{raw}'"
        )));
    };
    let id = rest
        .trim_start_matches('"')
        .trim_end_matches('"')
        .to_string();
    if kind.trim().is_empty() || id.is_empty() {
        return Err(RuntimeError::PolicyInvocationFailed(format!(
            "cedar test policy rule {index} field '{field}' is missing a type or id: '{raw}'"
        )));
    }
    Ok(Some(CedarEntity::new(kind.trim(), id)))
}

/// Translate AGT D3.3 cedar advice into a verdict-shaped `JsonValue` ready
/// for [`crate::normalize_policy_output`]. Advice missing the `verdict`
/// field, advice with an unknown verdict value, or transform advice missing
/// its body fail closed with `runtime_error:policy_output_invalid`. Path
/// validation (rooted at `$policy_target`) is delegated to
/// [`crate::verdict::Transform::from_value`] inside `normalize_policy_output`,
/// which produces `runtime_error:transform_target_forbidden` for an
/// out-of-target path.
pub fn translate_advice(advice: JsonValue) -> Result<JsonValue, RuntimeError> {
    let object = advice.as_object().ok_or_else(|| {
        RuntimeError::PolicyOutputInvalid("cedar advice must be a JSON object".to_string())
    })?;

    let verdict = object
        .get("verdict")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            RuntimeError::PolicyOutputInvalid(
                "cedar advice is missing the required 'verdict' field".to_string(),
            )
        })?;
    if !matches!(verdict, "warn" | "escalate" | "transform") {
        return Err(RuntimeError::PolicyOutputInvalid(format!(
            "cedar advice 'verdict' must be one of warn, escalate, transform; got '{verdict}'"
        )));
    }

    let mut out = Map::new();
    out.insert(
        "decision".to_string(),
        JsonValue::String(verdict.to_string()),
    );

    if let Some(reason) = object.get("reason") {
        match reason {
            JsonValue::Null => {}
            JsonValue::String(_) => {
                out.insert("reason".to_string(), reason.clone());
            }
            _ => {
                return Err(RuntimeError::PolicyOutputInvalid(
                    "cedar advice 'reason' must be a string".to_string(),
                ))
            }
        }
    }
    if let Some(message) = object.get("message") {
        match message {
            JsonValue::Null => {}
            JsonValue::String(_) => {
                out.insert("message".to_string(), message.clone());
            }
            _ => {
                return Err(RuntimeError::PolicyOutputInvalid(
                    "cedar advice 'message' must be a string".to_string(),
                ))
            }
        }
    }

    if verdict == "transform" {
        let transform = object.get("transform").ok_or_else(|| {
            RuntimeError::PolicyOutputInvalid(
                "cedar advice with verdict 'transform' requires a transform object".to_string(),
            )
        })?;
        if !transform.is_object() {
            return Err(RuntimeError::PolicyOutputInvalid(
                "cedar advice 'transform' must be a JSON object".to_string(),
            ));
        }
        out.insert("transform".to_string(), transform.clone());
    } else if object.contains_key("transform") {
        return Err(RuntimeError::PolicyOutputInvalid(
            "cedar advice 'transform' is only permitted when verdict is 'transform'".to_string(),
        ));
    }

    Ok(JsonValue::Object(out))
}

/// AGT M2.S5 D7 bundled cedar dispatcher backed by the upstream
/// `cedar-policy` crate. Gated behind the `cedar` Cargo feature so that
/// hosts that never need real cedar evaluation do not have to compile the
/// cedar runtime. The dispatcher parses the inline `policy_set` text (or
/// the file pointed to by `policy_path`), builds a `cedar_policy::Request`
/// from the [`CedarRequest`] produced by [`build_cedar_request`], and runs
/// the upstream authorizer. The result is translated into the verdict
/// JSON the runtime feeds to [`crate::normalize_policy_output`]: a cedar
/// `Allow` becomes `{"decision":"allow"}` and a cedar `Deny` becomes
/// `{"decision":"deny","reason":"no_matching_policy"}` (or
/// `runtime_error:policy_invocation_failed` when the authorizer surfaces a
/// hard error).
///
/// Cedar policy annotations and richer advice translation remain the job
/// of the host-facing [`CedarPolicyDispatcher`] implementations; the
/// builtin restricts itself to the standard allow / deny contract that the
/// upstream `Authorizer::is_authorized` exposes.
#[cfg(feature = "cedar")]
#[derive(Debug, Clone, Default)]
pub struct CedarBuiltinDispatcher;

#[cfg(feature = "cedar")]
impl CedarBuiltinDispatcher {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "cedar")]
impl CedarPolicyDispatcher for CedarBuiltinDispatcher {
    fn evaluate_cedar(
        &self,
        invocation: &CedarPolicyInvocation,
    ) -> Result<JsonValue, RuntimeError> {
        builtin::evaluate(invocation)
    }
}

#[cfg(feature = "cedar")]
impl PolicyDispatcher for CedarBuiltinDispatcher {
    fn evaluate(&self, invocation: &PreparedPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        match invocation {
            PreparedPolicyInvocation::Cedar(invocation) => self.evaluate_cedar(invocation),
            other => Err(RuntimeError::PolicyInvocationFailed(format!(
                "cedar builtin dispatcher only supports Cedar invocations; received {} invocation",
                other.engine_type()
            ))),
        }
    }
}

#[cfg(feature = "cedar")]
mod builtin {
    //! Upstream-cedar evaluation helpers for [`super::CedarBuiltinDispatcher`].
    //!
    //! Kept in a private module so the cedar crate imports never leak into
    //! the public API surface even when the `cedar` feature is enabled.

    use super::{build_cedar_request, CedarEntity, CedarRequest};
    use crate::{CedarPolicyInvocation, JsonValue, RuntimeError};
    use cedar_policy::{
        Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request, Schema,
        ValidationMode, Validator,
    };
    use serde_json::json;
    use std::{fs, str::FromStr};

    pub(super) fn evaluate(invocation: &CedarPolicyInvocation) -> Result<JsonValue, RuntimeError> {
        let policy_text = load_policy_text(invocation)?;
        let policy_set = PolicySet::from_str(&policy_text).map_err(|err| {
            RuntimeError::PolicyInvocationFailed(format!(
                "cedar builtin dispatcher failed to parse policy_set: {err}"
            ))
        })?;
        let schema = load_schema(invocation.schema_path.as_deref())?;
        validate_policy_set(&policy_set, schema.as_ref())?;
        let entities = load_entities(invocation.entities_path.as_deref(), schema.as_ref())?;
        let request = build_cedar_request(&invocation.input)?;
        let cedar_request = build_authorizer_request(&request, schema.as_ref())?;

        let authorizer = Authorizer::new();
        let answer = authorizer.is_authorized(&cedar_request, &policy_set, &entities);
        let hard_errors = answer.diagnostics().errors().cloned().collect::<Vec<_>>();
        if !hard_errors.is_empty() {
            let detail = hard_errors
                .iter()
                .map(|err| err.to_string())
                .collect::<Vec<_>>()
                .join("; ");
            return Err(RuntimeError::PolicyInvocationFailed(format!(
                "cedar builtin dispatcher authorizer reported errors: {detail}"
            )));
        }

        match answer.decision() {
            Decision::Allow => Ok(json!({ "decision": "allow" })),
            Decision::Deny => Ok(json!({
                "decision": "deny",
                "reason": "no_matching_policy",
            })),
        }
    }

    fn load_policy_text(invocation: &CedarPolicyInvocation) -> Result<String, RuntimeError> {
        match (
            invocation.policy_set.as_deref(),
            invocation.policy_path.as_deref(),
        ) {
            (Some(text), None) => Ok(text.to_string()),
            (None, Some(path)) => fs::read_to_string(path).map_err(|err| {
                RuntimeError::PolicyInvocationFailed(format!(
                    "cedar builtin dispatcher failed to read policy_path '{path}': {err}"
                ))
            }),
            (Some(_), Some(_)) => Err(RuntimeError::PolicyInvocationFailed(
                "cedar builtin dispatcher received both policy_set and policy_path; manifest validation must reject this earlier".to_string(),
            )),
            (None, None) => Err(RuntimeError::PolicyInvocationFailed(
                "cedar builtin dispatcher requires either policy_set or policy_path".to_string(),
            )),
        }
    }

    fn load_schema(path: Option<&str>) -> Result<Option<Schema>, RuntimeError> {
        let Some(path) = path else {
            return Ok(None);
        };
        let json_text = fs::read_to_string(path).map_err(|err| {
            RuntimeError::PolicyInvocationFailed(format!(
                "cedar builtin dispatcher failed to read schema_path '{path}': {err}"
            ))
        })?;
        let schema = Schema::from_json_str(&json_text).map_err(|err| {
            RuntimeError::PolicyInvocationFailed(format!(
                "cedar builtin dispatcher failed to parse schema_path '{path}': {err}"
            ))
        })?;
        Ok(Some(schema))
    }

    fn validate_policy_set(
        policy_set: &PolicySet,
        schema: Option<&Schema>,
    ) -> Result<(), RuntimeError> {
        let Some(schema) = schema else {
            return Ok(());
        };
        let result = Validator::new(schema.clone()).validate(policy_set, ValidationMode::Strict);
        if result.validation_passed() {
            Ok(())
        } else {
            Err(RuntimeError::PolicyInvocationFailed(format!(
                "cedar builtin dispatcher policy_set failed schema validation: {result}"
            )))
        }
    }

    fn load_entities(
        path: Option<&str>,
        schema: Option<&Schema>,
    ) -> Result<Entities, RuntimeError> {
        let Some(path) = path else {
            return Ok(Entities::empty());
        };
        let json_text = fs::read_to_string(path).map_err(|err| {
            RuntimeError::PolicyInvocationFailed(format!(
                "cedar builtin dispatcher failed to read entities_path '{path}': {err}"
            ))
        })?;
        Entities::from_json_str(&json_text, schema).map_err(|err| {
            RuntimeError::PolicyInvocationFailed(format!(
                "cedar builtin dispatcher failed to parse entities at '{path}': {err}"
            ))
        })
    }

    fn build_authorizer_request(
        request: &CedarRequest,
        schema: Option<&Schema>,
    ) -> Result<Request, RuntimeError> {
        let principal = entity_uid(&request.principal, "principal")?;
        let action = entity_uid(&request.action, "action")?;
        let resource = entity_uid(&request.resource, "resource")?;
        Request::new(principal, action, resource, Context::empty(), schema).map_err(|err| {
            RuntimeError::PolicyInvocationFailed(format!(
                "cedar builtin dispatcher failed to build authorizer request: {err}"
            ))
        })
    }

    fn entity_uid(entity: &CedarEntity, field: &str) -> Result<EntityUid, RuntimeError> {
        EntityUid::from_str(&entity.as_display()).map_err(|err| {
            RuntimeError::PolicyInvocationFailed(format!(
                "cedar builtin dispatcher failed to parse {field} entity '{}': {err}",
                entity.as_display()
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    //! AGT M2.S2 D3.3 dispatcher behaviour tests. Each test drives the
    //! [`CedarTestDispatcher`] against a hand-crafted policy input that
    //! mirrors the AGT snapshot shape from `spec/agt/AGT-SNAPSHOT-1.0.md` §1
    //! and asserts the verdict the runtime would emit after normalizing the
    //! dispatcher's JsonValue through [`crate::normalize_policy_output`].

    use super::*;
    use crate::{normalize_policy_output, Decision};
    use serde_json::json;
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    fn invocation(policy_set: &str, input: JsonValue) -> CedarPolicyInvocation {
        CedarPolicyInvocation {
            policy_set: Some(policy_set.to_string()),
            policy_path: None,
            entities_path: None,
            schema_path: None,
            query: None,
            input: input.clone(),
            canonical_input: serde_json::to_string(&input).unwrap(),
        }
    }

    fn tool_input(agent_id: &str, tool_name: &str) -> JsonValue {
        json!({
            "intervention_point": "pre_tool_call",
            "policy_target": {
                "kind": "tool_args",
                "path": "$snap.tool_call.args",
                "value": {"q": "hello"}
            },
            "snapshot": {
                "envelope": {
                    "agent": {"id": agent_id, "version": "1.0", "name": agent_id},
                    "session": {"id": "sess-1", "started_at": "2026-01-01T00:00:00Z"},
                    "intervention_point": "pre_tool_call",
                    "timestamp": "2026-01-01T00:00:01Z",
                    "budgets": {"tool_call_count": 0, "token_count": 0, "elapsed_seconds": 0.0, "cost_usd": 0.0}
                },
                "tool_call": {"name": tool_name, "args": {"q": "hello"}, "id": "call-1"}
            },
            "annotations": {},
            "tool": {"name": tool_name}
        })
    }

    #[cfg(feature = "cedar")]
    fn cedar_test_dir(name: &str) -> PathBuf {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("cedar-dispatcher-tests")
            .join(name);
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[cfg(feature = "cedar")]
    fn write_cedar_test_file(dir: &Path, name: &str, content: &str) -> String {
        let path = dir.join(name);
        fs::write(&path, content).unwrap();
        path.display().to_string()
    }

    #[cfg(feature = "cedar")]
    fn schema_for_tool_resource() -> &'static str {
        r#"{
            "": {
                "entityTypes": {
                    "Agent": {"shape": {"type": "Record", "attributes": {}}},
                    "Tool": {"shape": {"type": "Record", "attributes": {}}},
                    "PolicyTarget": {"shape": {"type": "Record", "attributes": {}}}
                },
                "actions": {
                    "pre_tool_call": {
                        "appliesTo": {
                            "principalTypes": ["Agent"],
                            "resourceTypes": ["Tool"]
                        }
                    }
                }
            }
        }"#
    }

    #[cfg(feature = "cedar")]
    fn schema_for_policy_target_resource() -> &'static str {
        r#"{
            "": {
                "entityTypes": {
                    "Agent": {"shape": {"type": "Record", "attributes": {}}},
                    "Tool": {"shape": {"type": "Record", "attributes": {}}},
                    "PolicyTarget": {"shape": {"type": "Record", "attributes": {}}}
                },
                "actions": {
                    "pre_tool_call": {
                        "appliesTo": {
                            "principalTypes": ["Agent"],
                            "resourceTypes": ["PolicyTarget"]
                        }
                    }
                }
            }
        }"#
    }

    // ── D3.2 request mapping ──────────────────────────────────────────

    #[test]
    fn build_cedar_request_maps_principal_action_resource_per_d32() {
        let input = tool_input("agent-x", "hello");
        let request = build_cedar_request(&input).expect("request built");
        assert_eq!(request.principal, CedarEntity::new("Agent", "agent-x"));
        assert_eq!(request.action, CedarEntity::new("Action", "pre_tool_call"));
        assert_eq!(request.resource, CedarEntity::new("Tool", "hello"));
        assert!(request.context_keys.contains(&"tool_call".to_string()));
    }

    #[test]
    fn build_cedar_request_uses_policy_target_kind_when_no_tool() {
        let input = json!({
            "intervention_point": "output",
            "policy_target": {"kind": "assistant_output", "path": "$snap.response", "value": {}},
            "snapshot": {
                "envelope": {
                    "agent": {"id": "agent-y"},
                    "session": {"id": "s"},
                    "intervention_point": "output",
                    "timestamp": "t",
                    "budgets": {}
                },
                "response": {"content": ""}
            },
            "annotations": {},
            "tool": null
        });
        let request = build_cedar_request(&input).expect("request built");
        assert_eq!(request.principal, CedarEntity::new("Agent", "agent-y"));
        assert_eq!(request.action, CedarEntity::new("Action", "output"));
        assert_eq!(
            request.resource,
            CedarEntity::new("PolicyTarget", "assistant_output")
        );
    }

    #[test]
    fn build_cedar_request_fails_closed_when_envelope_missing_agent_id() {
        let input = json!({
            "intervention_point": "input",
            "policy_target": {"kind": "user_input", "path": "$snap.input", "value": {}},
            "snapshot": {"envelope": {"agent": {}}},
            "annotations": {},
            "tool": null
        });
        let error = build_cedar_request(&input).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    }

    // ── D3.3 allow / deny ─────────────────────────────────────────────

    #[test]
    fn test_dispatcher_allow_path() {
        let policy_set = r#"{
            "rules": [
                {"effect": "permit", "principal": "any", "action": "any", "resource": "any"}
            ]
        }"#;
        let inv = invocation(policy_set, tool_input("agent-1", "hello"));
        let output = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap();
        let verdict = normalize_policy_output(output).unwrap();
        assert_eq!(verdict.decision, Decision::Allow);
    }

    #[test]
    fn test_dispatcher_deny_path() {
        let policy_set = r#"{
            "rules": [
                {"effect": "forbid", "principal": "any", "action": "Action::\"pre_tool_call\"", "resource": "Tool::\"banned\"", "reason": "tool_banned"},
                {"effect": "permit", "principal": "any", "action": "any", "resource": "any"}
            ]
        }"#;
        let inv = invocation(policy_set, tool_input("agent-1", "banned"));
        let output = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap();
        let verdict = normalize_policy_output(output).unwrap();
        assert_eq!(verdict.decision, Decision::Deny);
        assert_eq!(verdict.reason.as_deref(), Some("tool_banned"));
    }

    #[test]
    fn test_dispatcher_no_matching_rule_denies() {
        let policy_set = r#"{
            "rules": [
                {"effect": "permit", "principal": "Agent::\"alice\"", "action": "any", "resource": "any"}
            ]
        }"#;
        let inv = invocation(policy_set, tool_input("bob", "hello"));
        let output = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap();
        let verdict = normalize_policy_output(output).unwrap();
        assert_eq!(verdict.decision, Decision::Deny);
        assert_eq!(verdict.reason.as_deref(), Some("no_matching_policy"));
    }

    // ── D3.3 advice translation ───────────────────────────────────────

    #[test]
    fn test_dispatcher_advice_translates_to_transform() {
        let policy_set = r#"{
            "rules": [
                {"effect": "permit", "principal": "any", "action": "any", "resource": "any",
                 "advice": {"verdict": "transform", "reason": "scrub_pii",
                            "transform": {"path": "$policy_target.value.q", "value": "[REDACTED]"}}}
            ]
        }"#;
        let inv = invocation(policy_set, tool_input("agent-1", "hello"));
        let output = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap();
        let verdict = normalize_policy_output(output).unwrap();
        assert_eq!(verdict.decision, Decision::Transform);
        let transform = verdict.transform.as_ref().expect("transform present");
        assert_eq!(transform.path, "$policy_target.value.q");
        assert_eq!(transform.value, json!("[REDACTED]"));
        assert_eq!(verdict.reason.as_deref(), Some("scrub_pii"));
    }

    #[test]
    fn test_dispatcher_advice_translates_to_escalate() {
        let policy_set = r#"{
            "rules": [
                {"effect": "permit", "principal": "any", "action": "any", "resource": "any",
                 "advice": {"verdict": "escalate", "reason": "human_review", "message": "needs sign-off"}}
            ]
        }"#;
        let inv = invocation(policy_set, tool_input("agent-1", "hello"));
        let output = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap();
        let verdict = normalize_policy_output(output).unwrap();
        assert_eq!(verdict.decision, Decision::Escalate);
        assert_eq!(verdict.reason.as_deref(), Some("human_review"));
        assert_eq!(verdict.message.as_deref(), Some("needs sign-off"));
    }

    #[test]
    fn test_dispatcher_advice_translates_to_warn() {
        let policy_set = r#"{
            "rules": [
                {"effect": "permit", "principal": "any", "action": "any", "resource": "any",
                 "advice": {"verdict": "warn", "reason": "low_confidence"}}
            ]
        }"#;
        let inv = invocation(policy_set, tool_input("agent-1", "hello"));
        let output = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap();
        let verdict = normalize_policy_output(output).unwrap();
        assert_eq!(verdict.decision, Decision::Warn);
        assert_eq!(verdict.reason.as_deref(), Some("low_confidence"));
    }

    // ── D3.3 malformed advice ─────────────────────────────────────────

    #[test]
    fn test_dispatcher_malformed_advice_missing_verdict_fails_closed() {
        let policy_set = r#"{
            "rules": [
                {"effect": "permit", "principal": "any", "action": "any", "resource": "any",
                 "advice": {"reason": "no_verdict_field"}}
            ]
        }"#;
        let inv = invocation(policy_set, tool_input("agent-1", "hello"));
        let error = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    }

    #[test]
    fn test_dispatcher_malformed_advice_unknown_verdict_fails_closed() {
        let policy_set = r#"{
            "rules": [
                {"effect": "permit", "principal": "any", "action": "any", "resource": "any",
                 "advice": {"verdict": "approve"}}
            ]
        }"#;
        let inv = invocation(policy_set, tool_input("agent-1", "hello"));
        let error = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    }

    #[test]
    fn test_dispatcher_transform_advice_without_body_fails_closed() {
        let policy_set = r#"{
            "rules": [
                {"effect": "permit", "principal": "any", "action": "any", "resource": "any",
                 "advice": {"verdict": "transform"}}
            ]
        }"#;
        let inv = invocation(policy_set, tool_input("agent-1", "hello"));
        let error = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    }

    #[test]
    fn test_dispatcher_warn_advice_with_transform_body_fails_closed() {
        let policy_set = r#"{
            "rules": [
                {"effect": "permit", "principal": "any", "action": "any", "resource": "any",
                 "advice": {"verdict": "warn",
                            "transform": {"path": "$policy_target.value", "value": "x"}}}
            ]
        }"#;
        let inv = invocation(policy_set, tool_input("agent-1", "hello"));
        let error = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    }

    // ── D1.1 transform target confinement ─────────────────────────────

    #[test]
    fn test_dispatcher_transform_path_outside_policy_target_fails_closed() {
        let policy_set = r#"{
            "rules": [
                {"effect": "permit", "principal": "any", "action": "any", "resource": "any",
                 "advice": {"verdict": "transform",
                            "transform": {"path": "$snap.tool_call.args.q", "value": "[REDACTED]"}}}
            ]
        }"#;
        let inv = invocation(policy_set, tool_input("agent-1", "hello"));
        // The dispatcher emits the verdict JSON verbatim; the runtime's
        // normalize_policy_output is what enforces $policy_target confinement
        // per AGT D1.1, returning runtime_error:transform_target_forbidden.
        let output = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap();
        let error = normalize_policy_output(output).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:transform_target_forbidden");
    }

    // ── Dispatcher error paths ────────────────────────────────────────

    #[test]
    fn test_dispatcher_requires_inline_policy_set() {
        let inv = CedarPolicyInvocation {
            policy_set: None,
            policy_path: Some("/no/such/file.cedar".to_string()),
            entities_path: None,
            schema_path: None,
            query: None,
            input: tool_input("agent-1", "hello"),
            canonical_input: "{}".to_string(),
        };
        let error = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    }

    #[test]
    fn test_dispatcher_invalid_policy_set_json_fails_closed() {
        let inv = invocation("not json", tool_input("agent-1", "hello"));
        let error = CedarTestDispatcher::new().evaluate_cedar(&inv).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    }

    #[test]
    fn test_dispatcher_rejects_non_cedar_invocation_through_policy_dispatcher() {
        use crate::{PolicyDispatcher, PreparedPolicyInvocation, TestPolicyInvocation};

        let other = PreparedPolicyInvocation::Test(TestPolicyInvocation {
            adapter_config: Default::default(),
            input: json!({}),
            canonical_input: "{}".to_string(),
        });
        let error = CedarTestDispatcher::new().evaluate(&other).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    }

    // ── translate_advice unit checks (independent of the dispatcher) ──

    #[test]
    fn translate_advice_rejects_non_object() {
        let error = translate_advice(json!("warn")).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    }

    #[test]
    fn translate_advice_rejects_non_string_reason() {
        let error = translate_advice(json!({"verdict": "warn", "reason": 7})).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_output_invalid");
    }

    #[test]
    fn translate_advice_round_trips_warn() {
        let value = translate_advice(json!({"verdict": "warn"})).unwrap();
        assert_eq!(value["decision"], json!("warn"));
    }

    // ── M2.S5 D7 builtin dispatcher (feature `cedar`) ─────────────────

    #[cfg(feature = "cedar")]
    #[test]
    fn builtin_dispatcher_allows_trivial_permit_all_policy() {
        let policy_set = "permit(principal, action, resource);";
        let inv = invocation(policy_set, tool_input("agent-1", "hello"));
        let output = CedarBuiltinDispatcher::new()
            .evaluate_cedar(&inv)
            .expect("builtin cedar dispatcher returns ok for permit-all");
        let verdict = normalize_policy_output(output).unwrap();
        assert_eq!(verdict.decision, Decision::Allow);
    }

    #[cfg(feature = "cedar")]
    #[test]
    fn builtin_dispatcher_denies_when_no_policy_matches() {
        let policy_set = "permit(principal == Agent::\"alice\", action, resource);";
        let inv = invocation(policy_set, tool_input("bob", "hello"));
        let output = CedarBuiltinDispatcher::new()
            .evaluate_cedar(&inv)
            .expect("builtin cedar dispatcher returns ok for deny");
        let verdict = normalize_policy_output(output).unwrap();
        assert_eq!(verdict.decision, Decision::Deny);
        assert_eq!(verdict.reason.as_deref(), Some("no_matching_policy"));
    }

    #[cfg(feature = "cedar")]
    #[test]
    fn builtin_dispatcher_with_valid_schema_accepts_conformant_request() {
        let dir = cedar_test_dir("valid-schema-accepts");
        let schema_path = write_cedar_test_file(&dir, "schema.json", schema_for_tool_resource());
        let mut inv = invocation(
            "permit(principal, action == Action::\"pre_tool_call\", resource == Tool::\"hello\");",
            tool_input("agent-1", "hello"),
        );
        inv.schema_path = Some(schema_path);

        let output = CedarBuiltinDispatcher::new()
            .evaluate_cedar(&inv)
            .expect("schema-conformant cedar request should evaluate");
        let verdict = normalize_policy_output(output).unwrap();

        assert_eq!(verdict.decision, Decision::Allow);
    }

    #[cfg(feature = "cedar")]
    #[test]
    fn builtin_dispatcher_with_valid_schema_rejects_nonconformant_request() {
        let dir = cedar_test_dir("valid-schema-rejects");
        let schema_path =
            write_cedar_test_file(&dir, "schema.json", schema_for_policy_target_resource());
        let mut inv = invocation(
            "permit(principal, action == Action::\"pre_tool_call\", resource);",
            tool_input("agent-1", "hello"),
        );
        inv.schema_path = Some(schema_path);

        let error = CedarBuiltinDispatcher::new()
            .evaluate_cedar(&inv)
            .unwrap_err();

        assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
        assert!(
            error.detail().contains("authorizer request")
                || error.detail().contains("failed schema validation"),
            "{}",
            error.detail()
        );
    }

    #[cfg(feature = "cedar")]
    #[test]
    fn builtin_dispatcher_fails_closed_when_schema_path_is_missing() {
        let missing_schema = cedar_test_dir("missing-schema").join("missing-schema.json");
        let mut inv = invocation(
            "permit(principal, action, resource);",
            tool_input("agent-1", "hello"),
        );
        inv.schema_path = Some(missing_schema.display().to_string());
        let error = CedarBuiltinDispatcher::new()
            .evaluate_cedar(&inv)
            .unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
        assert!(error.detail().contains("schema_path"));
    }

    #[cfg(feature = "cedar")]
    #[test]
    fn builtin_dispatcher_fails_closed_when_schema_path_is_malformed() {
        let dir = cedar_test_dir("malformed-schema");
        let schema_path = write_cedar_test_file(&dir, "schema.json", "{not valid schema json");
        let mut inv = invocation(
            "permit(principal, action, resource);",
            tool_input("agent-1", "hello"),
        );
        inv.schema_path = Some(schema_path);

        let error = CedarBuiltinDispatcher::new()
            .evaluate_cedar(&inv)
            .unwrap_err();

        assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
        assert!(error.detail().contains("parse schema_path"));
    }

    #[cfg(feature = "cedar")]
    #[test]
    fn builtin_dispatcher_rejects_non_cedar_invocation_through_policy_dispatcher() {
        use crate::{PolicyDispatcher, PreparedPolicyInvocation, TestPolicyInvocation};

        let other = PreparedPolicyInvocation::Test(TestPolicyInvocation {
            adapter_config: Default::default(),
            input: json!({}),
            canonical_input: "{}".to_string(),
        });
        let error = CedarBuiltinDispatcher::new().evaluate(&other).unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    }

    #[cfg(feature = "cedar")]
    #[test]
    fn builtin_dispatcher_surfaces_parser_errors_as_policy_invocation_failed() {
        let inv = invocation("not a valid cedar policy", tool_input("agent-1", "hello"));
        let error = CedarBuiltinDispatcher::new()
            .evaluate_cedar(&inv)
            .unwrap_err();
        assert_eq!(error.reason(), "runtime_error:policy_invocation_failed");
    }
}
