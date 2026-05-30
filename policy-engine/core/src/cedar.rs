//! AGT D3 cedar dispatcher surface.
//!
//! See `policy-engine/spec/SPECIFICATION-AGT-DELTA.md` §D3 for the normative
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
//! 3. [`CedarBuiltinDispatcher`] is a feature-gated wrapper around the
//!    upstream `cedar-policy` crate. It links only when the `cedar` cargo
//!    feature is enabled; the trait surface above stays available either way.
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
    fn evaluate_cedar(
        &self,
        invocation: &CedarPolicyInvocation,
    ) -> Result<JsonValue, RuntimeError>;
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

    let mut context_keys: Vec<String> = snapshot.keys().filter(|key| *key != "envelope").cloned().collect();
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
    out.insert("decision".to_string(), JsonValue::String(verdict.to_string()));

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

/// Feature-gated cedar dispatcher backed by the upstream `cedar-policy`
/// crate is deferred from M2.S2 per the prompt's fallback. The dispatcher
/// trait, the [`CedarTestDispatcher`] reference implementation, and the
/// manifest plumbing ship now; a follow-up milestone will land the builtin
/// once a build environment with a `cc`-compatible C toolchain is available
/// (the current toolchain in the AGT dev container is `zig cc`, which
/// rejects the `--target=x86_64-unknown-linux-gnu` target query the
/// `cc-rs` crate passes when compiling the `psm` transitive dependency of
/// `cedar-policy`'s `stacker` dep). Hosts that need real cedar evaluation
/// today implement [`CedarPolicyDispatcher`] themselves and link the
/// `cedar-policy` crate at the host crate level.
const _: () = ();
