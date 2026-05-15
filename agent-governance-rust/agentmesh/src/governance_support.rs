// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Additional governance primitives for compliance, authority, federation, and risk tooling.

use crate::audit::verify_audit_entries;
use crate::types::AuditEntry;
use cedar_policy::{
    Authorizer as CedarAuthorizer, Context as CedarContext, Decision as CedarRuntimeDecision,
    Entities as CedarEntities, EntityUid as CedarEntityUid, PolicySet as CedarPolicySet,
    Request as CedarRequest,
};
use regex::Regex;
use regorus::{Engine as RegoEngine, Value as RegoValue};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

fn unix_secs_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceFramework {
    EuAiAct,
    Soc2,
    Hipaa,
    Gdpr,
}

impl ComplianceFramework {
    /// Approximate count of high-level controls for this framework, used
    /// as the denominator when computing a compliance score.
    ///
    /// Each value reflects the framework's published top-level groupings:
    ///
    /// * **EU AI Act** — 8 obligations for high-risk AI systems
    ///   (Articles 8–15: risk management, data governance, technical
    ///   documentation, record-keeping, transparency, human oversight,
    ///   accuracy/robustness/cybersecurity, quality management).
    /// * **SOC 2** — 5 Trust Services Criteria categories (Security,
    ///   Availability, Confidentiality, Processing Integrity, Privacy).
    /// * **HIPAA** — 3 Security Rule safeguard categories
    ///   (Administrative, Physical, Technical) plus the Privacy Rule and
    ///   Breach Notification Rule = 5.
    /// * **GDPR** — 7 data-protection principles enumerated in
    ///   Article 5(1) (lawfulness, purpose limitation, data minimisation,
    ///   accuracy, storage limitation, integrity & confidentiality,
    ///   accountability).
    ///
    /// These are coarse approximations chosen because the framework
    /// publishes them at this level; deployments with a richer control
    /// catalogue should compute their own score rather than rely on this
    /// engine's report.
    pub fn default_control_count(self) -> u32 {
        match self {
            ComplianceFramework::EuAiAct => 8,
            ComplianceFramework::Soc2 => 5,
            ComplianceFramework::Hipaa => 5,
            ComplianceFramework::Gdpr => 7,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceViolation {
    pub violation_id: String,
    pub timestamp_secs: u64,
    pub agent_did: String,
    pub action_type: String,
    pub control_id: String,
    pub framework: ComplianceFramework,
    pub severity: String,
    pub description: String,
    pub evidence: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub report_id: String,
    pub generated_at_secs: u64,
    pub framework: ComplianceFramework,
    pub total_controls: u32,
    pub controls_failed: u32,
    pub compliance_score: f64,
    pub violations: Vec<ComplianceViolation>,
    pub recommendations: Vec<String>,
}

pub struct ComplianceEngine {
    frameworks: Vec<ComplianceFramework>,
    violations: Mutex<Vec<ComplianceViolation>>,
}

impl ComplianceEngine {
    pub fn new(frameworks: Vec<ComplianceFramework>) -> Self {
        Self {
            frameworks: if frameworks.is_empty() {
                vec![ComplianceFramework::Soc2]
            } else {
                frameworks
            },
            violations: Mutex::new(Vec::new()),
        }
    }

    pub fn enabled_frameworks(&self) -> &[ComplianceFramework] {
        &self.frameworks
    }

    pub fn record_violation(
        &self,
        framework: ComplianceFramework,
        agent_did: &str,
        action_type: &str,
        control_id: &str,
        severity: &str,
        description: &str,
    ) -> ComplianceViolation {
        let violation = ComplianceViolation {
            violation_id: format!("violation_{:016x}", rand::random::<u64>()),
            timestamp_secs: unix_secs_now(),
            agent_did: agent_did.to_string(),
            action_type: action_type.to_string(),
            control_id: control_id.to_string(),
            framework,
            severity: severity.to_string(),
            description: description.to_string(),
            evidence: HashMap::new(),
        };
        self.violations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(violation.clone());
        violation
    }

    pub fn generate_report(&self, framework: ComplianceFramework) -> ComplianceReport {
        let violations = self
            .violations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|violation| violation.framework == framework)
            .cloned()
            .collect::<Vec<_>>();
        let controls_failed = violations.len() as u32;
        let total_controls = framework.default_control_count();
        // `.max(1)` is a defensive floor: if a future variant ever returns
        // 0 the score becomes 0 rather than `0/0 == NaN`.
        let denominator = total_controls.max(1);
        let compliance_score = ((denominator.saturating_sub(controls_failed)) as f64
            / denominator as f64)
            * 100.0;
        ComplianceReport {
            report_id: format!("report_{:016x}", rand::random::<u64>()),
            generated_at_secs: unix_secs_now(),
            framework,
            total_controls,
            controls_failed,
            compliance_score,
            recommendations: if violations.is_empty() {
                vec!["No action required".to_string()]
            } else {
                vec!["Review and remediate recorded violations".to_string()]
            },
            violations,
        }
    }
}

impl Default for ComplianceEngine {
    fn default() -> Self {
        Self::new(vec![ComplianceFramework::Soc2])
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditChain {
    pub entries: Vec<AuditEntry>,
}

pub trait AuditSink: Send + Sync {
    fn record(&self, entry: &AuditEntry) -> std::io::Result<()>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedAuditEntry {
    pub entry: AuditEntry,
    pub signature: String,
}

pub struct FileAuditSink {
    path: PathBuf,
}

impl FileAuditSink {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl AuditSink for FileAuditSink {
    fn record(&self, entry: &AuditEntry) -> std::io::Result<()> {
        let mut entries = if self.path.exists() {
            serde_json::from_str::<Vec<AuditEntry>>(&fs::read_to_string(&self.path)?)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        entries.push(entry.clone());
        // serde_json::to_string_pretty fails on non-finite floats (NaN, ±Inf)
        // inside `details` because JSON has no representation for them.
        // Propagate the error instead of panicking on the audit-write path.
        let serialized =
            serde_json::to_string_pretty(&entries).map_err(std::io::Error::other)?;
        fs::write(&self.path, serialized)
    }
}

pub struct HashChainVerifier;

impl HashChainVerifier {
    pub fn verify(entries: &[AuditEntry]) -> bool {
        verify_audit_entries(entries, None)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowResult {
    pub allowed: bool,
    pub would_allow: bool,
    pub reason: Option<String>,
    pub recorded_at_secs: u64,
}

pub struct ShadowMode {
    results: Mutex<Vec<ShadowResult>>,
}

impl ShadowMode {
    pub fn new() -> Self {
        Self {
            results: Mutex::new(Vec::new()),
        }
    }

    pub fn record(&self, allowed: bool, would_allow: bool, reason: Option<String>) -> ShadowResult {
        let result = ShadowResult {
            allowed,
            would_allow,
            reason,
            recorded_at_secs: unix_secs_now(),
        };
        self.results
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(result.clone());
        result
    }
}

impl Default for ShadowMode {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DelegationInfo {
    pub agent_did: String,
    pub parent_did: Option<String>,
    pub delegation_depth: u32,
    pub delegated_capabilities: Vec<String>,
    pub chain_verified: bool,
    pub chain_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustInfo {
    pub score: u32,
    pub risk_level: String,
    pub identity_score: u32,
    pub behavior_score: u32,
    pub network_score: u32,
    pub compliance_score: u32,
}

impl Default for TrustInfo {
    fn default() -> Self {
        Self {
            score: 500,
            risk_level: "medium".to_string(),
            identity_score: 50,
            behavior_score: 50,
            network_score: 50,
            compliance_score: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ActionRequest {
    pub action_type: String,
    pub tool_name: Option<String>,
    pub resource: Option<String>,
    pub parameters: HashMap<String, Value>,
    pub requested_spend: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityDecision {
    pub decision: String,
    pub effective_scope: Vec<String>,
    pub effective_spend_limit: Option<f64>,
    pub narrowing_reason: Option<String>,
    pub trust_tier: String,
    pub matched_invariants: Vec<String>,
    pub timestamp_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityRequest {
    pub delegation: DelegationInfo,
    pub trust: TrustInfo,
    pub action: ActionRequest,
    pub context: HashMap<String, Value>,
}

pub trait AuthorityResolver: Send + Sync {
    fn resolve(&self, request: &AuthorityRequest) -> AuthorityDecision;
}

pub struct DefaultAuthorityResolver;

impl AuthorityResolver for DefaultAuthorityResolver {
    fn resolve(&self, request: &AuthorityRequest) -> AuthorityDecision {
        AuthorityDecision {
            decision: "deny".to_string(),
            effective_scope: request.delegation.delegated_capabilities.clone(),
            effective_spend_limit: None,
            narrowing_reason: Some(
                "default authority resolver is fail-closed; provide a custom resolver to grant access"
                    .to_string(),
            ),
            trust_tier: "unknown".to_string(),
            matched_invariants: Vec::new(),
            timestamp_secs: unix_secs_now(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    In,
    NotIn,
    Matches,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustCondition {
    pub field: String,
    pub operator: ConditionOperator,
    pub value: Value,
}

impl TrustCondition {
    pub fn evaluate(&self, context: &HashMap<String, Value>) -> bool {
        let actual = context.get(&self.field);
        match (&self.operator, actual) {
            (ConditionOperator::Eq, Some(actual)) => actual == &self.value,
            (ConditionOperator::Ne, Some(actual)) => actual != &self.value,
            (ConditionOperator::Gt, Some(Value::Number(actual))) => {
                actual.as_f64().unwrap_or(0.0) > self.value.as_f64().unwrap_or(0.0)
            }
            (ConditionOperator::Gte, Some(Value::Number(actual))) => {
                actual.as_f64().unwrap_or(0.0) >= self.value.as_f64().unwrap_or(0.0)
            }
            (ConditionOperator::Lt, Some(Value::Number(actual))) => {
                actual.as_f64().unwrap_or(0.0) < self.value.as_f64().unwrap_or(0.0)
            }
            (ConditionOperator::Lte, Some(Value::Number(actual))) => {
                actual.as_f64().unwrap_or(0.0) <= self.value.as_f64().unwrap_or(0.0)
            }
            (ConditionOperator::In, Some(actual)) => self
                .value
                .as_array()
                .map(|arr| arr.contains(actual))
                .unwrap_or(false),
            (ConditionOperator::NotIn, Some(actual)) => self
                .value
                .as_array()
                .map(|arr| !arr.contains(actual))
                .unwrap_or(false),
            (ConditionOperator::Matches, Some(Value::String(actual))) => self
                .value
                .as_str()
                .and_then(|pattern| {
                    crate::regex_cache::compiled_regex(pattern).map(|regex| regex.is_match(actual))
                })
                .unwrap_or(false),
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRule {
    pub name: String,
    pub description: Option<String>,
    pub condition: TrustCondition,
    pub action: String,
    pub priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustDefaults {
    pub min_trust_score: u32,
    pub max_delegation_depth: u32,
    pub allowed_namespaces: Vec<String>,
    pub require_handshake: bool,
}

impl Default for TrustDefaults {
    fn default() -> Self {
        Self {
            min_trust_score: 500,
            max_delegation_depth: 3,
            allowed_namespaces: vec!["*".to_string()],
            require_handshake: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustPolicy {
    pub name: String,
    pub version: String,
    pub description: Option<String>,
    pub rules: Vec<TrustRule>,
    pub defaults: TrustDefaults,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustPolicyDecision {
    pub action: String,
    pub rule_name: Option<String>,
    pub matched: bool,
}

pub struct PolicyEvaluator {
    policies: Vec<TrustPolicy>,
}

impl PolicyEvaluator {
    pub fn new(policies: Vec<TrustPolicy>) -> Self {
        Self { policies }
    }

    pub fn evaluate(&self, context: &HashMap<String, Value>) -> TrustPolicyDecision {
        let mut rules = self
            .policies
            .iter()
            .flat_map(|policy| policy.rules.iter())
            .collect::<Vec<_>>();
        rules.sort_by_key(|rule| rule.priority);
        for rule in rules {
            if rule.condition.evaluate(context) {
                return TrustPolicyDecision {
                    action: rule.action.clone(),
                    rule_name: Some(rule.name.clone()),
                    matched: true,
                };
            }
        }
        TrustPolicyDecision {
            action: "deny".to_string(),
            rule_name: None,
            matched: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OPADecision {
    pub allow: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDiagnosticSeverity {
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBackendDiagnostic {
    pub severity: PolicyDiagnosticSeverity,
    pub message: String,
    pub expression: String,
}

impl PolicyBackendDiagnostic {
    /// Reserved for the in-progress policy compiler subsystem below
    /// (`parse_opa_rules` / `parse_cedar_rules` and friends). Kept here so
    /// the diagnostic API stays symmetric with `::error` once the compiler
    /// callers come online.
    #[allow(dead_code)]
    fn warning(message: impl Into<String>, expression: impl Into<String>) -> Self {
        Self {
            severity: PolicyDiagnosticSeverity::Warning,
            message: message.into(),
            expression: expression.into(),
        }
    }

    fn error(message: impl Into<String>, expression: impl Into<String>) -> Self {
        Self {
            severity: PolicyDiagnosticSeverity::Error,
            message: message.into(),
            expression: expression.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRuleTrace {
    pub rule_name: String,
    pub effect: String,
    pub clause_index: usize,
    pub expression: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyBackendTrace {
    pub matched_rules: Vec<PolicyRuleTrace>,
    pub default_applied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OPAEvaluation {
    pub decision: OPADecision,
    pub trace: PolicyBackendTrace,
}

pub struct OPAEvaluator {
    _rego: String,
    engine: Option<RegoEngine>,
    package_paths: Vec<String>,
    diagnostics: Vec<PolicyBackendDiagnostic>,
}

impl OPAEvaluator {
    pub fn new(rego: &str) -> Self {
        let mut diagnostics = Vec::new();
        let mut engine = RegoEngine::new();
        let mut package_paths = Vec::new();
        let compiled_engine = match engine.add_policy("policy.rego".to_string(), rego.to_string()) {
            Ok(package_path) => {
                package_paths.push(package_path);
                Some(engine)
            }
            Err(error) => {
                diagnostics.push(PolicyBackendDiagnostic::error(
                    "failed to compile rego policy",
                    error.to_string(),
                ));
                None
            }
        };
        Self {
            _rego: rego.to_string(),
            engine: compiled_engine,
            package_paths,
            diagnostics,
        }
    }

    pub fn evaluate(&self, input: &HashMap<String, Value>) -> OPADecision {
        self.evaluate_with_trace(input).decision
    }

    pub fn evaluate_with_trace(&self, input: &HashMap<String, Value>) -> OPAEvaluation {
        let Some(mut engine) = self.engine.clone() else {
            return OPAEvaluation {
                decision: OPADecision {
                    allow: false,
                    reason: Some("rego policy failed to compile".to_string()),
                },
                trace: PolicyBackendTrace {
                    matched_rules: Vec::new(),
                    default_applied: true,
                },
            };
        };

        let rego_input = match rego_input_value(input) {
            Ok(value) => value,
            Err(error) => {
                return OPAEvaluation {
                    decision: OPADecision {
                        allow: false,
                        reason: Some(format!("rego input serialization failed: {error}")),
                    },
                    trace: PolicyBackendTrace {
                        matched_rules: Vec::new(),
                        default_applied: true,
                    },
                };
            }
        };
        engine.set_input(rego_input);

        let mut matched_rules = Vec::new();
        let mut denied = false;
        let mut allowed = false;

        for package_path in &self.package_paths {
            if evaluate_rego_rule(&mut engine, package_path, "deny") {
                denied = true;
                matched_rules.push(PolicyRuleTrace {
                    rule_name: format!("{package_path}.deny"),
                    effect: "deny".to_string(),
                    clause_index: 0,
                    expression: package_path.clone(),
                });
            }
            if evaluate_rego_rule(&mut engine, package_path, "allow") {
                allowed = true;
                matched_rules.push(PolicyRuleTrace {
                    rule_name: format!("{package_path}.allow"),
                    effect: "allow".to_string(),
                    clause_index: 0,
                    expression: package_path.clone(),
                });
            }
        }

        let default_applied = !denied && !allowed;
        let reason = if denied {
            Some("rego deny rule matched request".to_string())
        } else if allowed {
            Some("rego allow rule matched request".to_string())
        } else {
            Some("rego default deny applied".to_string())
        };

        OPAEvaluation {
            decision: OPADecision {
                allow: !denied && allowed,
                reason,
            },
            trace: PolicyBackendTrace {
                matched_rules,
                default_applied,
            },
        }
    }

    pub fn diagnostics(&self) -> &[PolicyBackendDiagnostic] {
        &self.diagnostics
    }
}

pub fn load_rego_into_engine(rego: &str) -> OPAEvaluator {
    OPAEvaluator::new(rego)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CedarDecision {
    pub allow: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CedarEvaluation {
    pub decision: CedarDecision,
    pub trace: PolicyBackendTrace,
}

pub struct CedarEvaluator {
    _policy: String,
    policy_set: Option<CedarPolicySet>,
    diagnostics: Vec<PolicyBackendDiagnostic>,
}

impl CedarEvaluator {
    pub fn new(policy: &str) -> Self {
        let (policy_set, diagnostics) = match CedarPolicySet::from_str(policy) {
            Ok(policy_set) => (Some(policy_set), Vec::new()),
            Err(error) => (
                None,
                vec![PolicyBackendDiagnostic::error(
                    "failed to compile cedar policy",
                    error.to_string(),
                )],
            ),
        };
        Self {
            _policy: policy.to_string(),
            policy_set,
            diagnostics,
        }
    }

    pub fn evaluate(&self, input: &HashMap<String, Value>) -> CedarDecision {
        self.evaluate_with_trace(input).decision
    }

    pub fn evaluate_with_trace(&self, input: &HashMap<String, Value>) -> CedarEvaluation {
        let Some(policy_set) = self.policy_set.clone() else {
            return CedarEvaluation {
                decision: CedarDecision {
                    allow: false,
                    reason: Some("cedar policy failed to compile".to_string()),
                },
                trace: PolicyBackendTrace {
                    matched_rules: Vec::new(),
                    default_applied: true,
                },
            };
        };

        let request = match cedar_request(input) {
            Ok(request) => request,
            Err(error) => {
                return CedarEvaluation {
                    decision: CedarDecision {
                        allow: false,
                        reason: Some(format!("cedar request build failed: {error}")),
                    },
                    trace: PolicyBackendTrace {
                        matched_rules: Vec::new(),
                        default_applied: true,
                    },
                };
            }
        };

        let entities = match cedar_entities(input) {
            Ok(entities) => entities,
            Err(error) => {
                return CedarEvaluation {
                    decision: CedarDecision {
                        allow: false,
                        reason: Some(format!("cedar entities build failed: {error}")),
                    },
                    trace: PolicyBackendTrace {
                        matched_rules: Vec::new(),
                        default_applied: true,
                    },
                };
            }
        };

        let response = CedarAuthorizer::new().is_authorized(&request, &policy_set, &entities);
        let permit = response.decision() == CedarRuntimeDecision::Allow;
        let matched_rules = response
            .diagnostics()
            .reason()
            .map(|policy_id| PolicyRuleTrace {
                rule_name: policy_id.to_string(),
                effect: if permit {
                    "permit".to_string()
                } else {
                    "forbid".to_string()
                },
                clause_index: 0,
                expression: policy_id.to_string(),
            })
            .collect::<Vec<_>>();
        let default_applied = matched_rules.is_empty();
        let error_details = response
            .diagnostics()
            .errors()
            .map(|error| error.to_string())
            .collect::<Vec<_>>();

        CedarEvaluation {
            decision: CedarDecision {
                allow: permit,
                reason: if permit {
                    Some("cedar permit policy matched request".to_string())
                } else if !error_details.is_empty() {
                    Some(format!(
                        "cedar evaluation error: {}",
                        error_details.join("; ")
                    ))
                } else {
                    Some("cedar default deny applied".to_string())
                },
            },
            trace: PolicyBackendTrace {
                matched_rules,
                default_applied,
            },
        }
    }

    pub fn diagnostics(&self) -> &[PolicyBackendDiagnostic] {
        &self.diagnostics
    }
}

pub fn load_cedar_into_engine(policy: &str) -> CedarEvaluator {
    CedarEvaluator::new(policy)
}

fn rego_input_value(input: &HashMap<String, Value>) -> Result<RegoValue, String> {
    let input_json = serde_json::to_string(input).map_err(|error| error.to_string())?;
    RegoValue::from_json_str(&input_json).map_err(|error| error.to_string())
}

fn evaluate_rego_rule(engine: &mut RegoEngine, package_path: &str, rule_name: &str) -> bool {
    let rule_path = format!("{package_path}.{rule_name}");
    engine.eval_allow_query(rule_path, false)
}

fn cedar_request(input: &HashMap<String, Value>) -> Result<CedarRequest, String> {
    let principal = cedar_entity_uid_from_input(input, "principal", "Principal")?;
    let action = cedar_entity_uid_from_input(input, "action", "Action")?;
    let resource = cedar_entity_uid_from_input(input, "resource", "Resource")?;
    let context = cedar_context(input)?;
    Ok(CedarRequest::new(principal, action, resource, context))
}

fn cedar_context(input: &HashMap<String, Value>) -> Result<CedarContext, String> {
    match input.get("context") {
        Some(Value::Object(context)) => {
            CedarContext::from_json_value(Value::Object(context.clone()), None)
                .map_err(|error| error.to_string())
        }
        Some(_) => Err("context must be a JSON object".to_string()),
        None => Ok(CedarContext::empty()),
    }
}

fn cedar_entities(input: &HashMap<String, Value>) -> Result<CedarEntities, String> {
    match input.get("entities") {
        Some(value) => {
            CedarEntities::from_json_value(value.clone(), None).map_err(|error| error.to_string())
        }
        None => Ok(CedarEntities::empty()),
    }
}

fn cedar_entity_uid_from_input(
    input: &HashMap<String, Value>,
    key: &str,
    default_type: &str,
) -> Result<Option<CedarEntityUid>, String> {
    let Some(value) = input.get(key) else {
        return Ok(None);
    };
    let Value::String(value) = value else {
        return Err(format!("{key} must be a string"));
    };
    let raw = if value.contains("::") && value.contains('"') {
        value.clone()
    } else {
        format!(r#"{default_type}::"{}""#, cedar_escape_identifier(value))
    };
    CedarEntityUid::from_str(&raw)
        .map(Some)
        .map_err(|error| error.to_string())
}

fn cedar_escape_identifier(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

// ---------------------------------------------------------------------------
// In-progress policy-expression compiler.
//
// The items below (PolicyOperator / PolicyCondition / PolicyRuleClause /
// CompiledPolicyRule plus the `parse_*`, `compile_*`, `collect_*`, `split_*`,
// `normalize_*`, `resolve_*`, `looks_like_*`, and `strip_*` free functions)
// form a self-contained subsystem for parsing OPA/Cedar rule bodies into a
// compiled in-memory AST. Production code does not yet route through it —
// the live `PolicyEvaluator` calls regorus / cedar-policy directly — so the
// whole tree is dead-code-warned. Items are individually marked
// `#[allow(dead_code)]` (not the parent module) so that any other genuinely
// dead code added to this file continues to surface in `cargo check`.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyOperator {
    Eq,
    Ne,
    Gt,
    Gte,
    Lt,
    Lte,
    In,
    NotIn,
    Contains,
    StartsWith,
    EndsWith,
    RegexMatch,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct PolicyCondition {
    path: String,
    operator: PolicyOperator,
    expected: Value,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
struct PolicyRuleClause {
    conditions: Vec<PolicyCondition>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct CompiledPolicyRule {
    name: String,
    raw_expression: String,
    clauses: Vec<PolicyRuleClause>,
}

#[allow(dead_code)]
impl CompiledPolicyRule {
    fn matches<'a>(&'a self, input: &HashMap<String, Value>) -> Option<(&'a Self, usize)> {
        self.clauses
            .iter()
            .enumerate()
            .find(|(_, clause)| clause.matches(input))
            .map(|(clause_index, _)| (self, clause_index))
    }
}

#[allow(dead_code)]
impl PolicyRuleClause {
    fn matches(&self, input: &HashMap<String, Value>) -> bool {
        self.conditions
            .iter()
            .all(|condition| condition.matches(input))
    }
}

#[allow(dead_code)]
impl PolicyCondition {
    fn matches(&self, input: &HashMap<String, Value>) -> bool {
        let Some(actual) = resolve_policy_value(input, &self.path) else {
            return false;
        };
        match self.operator {
            PolicyOperator::Eq => actual == &self.expected,
            PolicyOperator::Ne => actual != &self.expected,
            PolicyOperator::Gt => actual
                .as_f64()
                .zip(self.expected.as_f64())
                .map(|(actual, expected)| actual > expected)
                .unwrap_or(false),
            PolicyOperator::Gte => actual
                .as_f64()
                .zip(self.expected.as_f64())
                .map(|(actual, expected)| actual >= expected)
                .unwrap_or(false),
            PolicyOperator::Lt => actual
                .as_f64()
                .zip(self.expected.as_f64())
                .map(|(actual, expected)| actual < expected)
                .unwrap_or(false),
            PolicyOperator::Lte => actual
                .as_f64()
                .zip(self.expected.as_f64())
                .map(|(actual, expected)| actual <= expected)
                .unwrap_or(false),
            PolicyOperator::In => self
                .expected
                .as_array()
                .map(|values| values.contains(actual))
                .unwrap_or(false),
            PolicyOperator::NotIn => self
                .expected
                .as_array()
                .map(|values| !values.contains(actual))
                .unwrap_or(false),
            PolicyOperator::Contains => actual
                .as_array()
                .map(|values| values.contains(&self.expected))
                .or_else(|| {
                    actual
                        .as_str()
                        .zip(self.expected.as_str())
                        .map(|(actual, expected)| actual.contains(expected))
                })
                .unwrap_or(false),
            PolicyOperator::StartsWith => actual
                .as_str()
                .zip(self.expected.as_str())
                .map(|(actual, expected)| actual.starts_with(expected))
                .unwrap_or(false),
            PolicyOperator::EndsWith => actual
                .as_str()
                .zip(self.expected.as_str())
                .map(|(actual, expected)| actual.ends_with(expected))
                .unwrap_or(false),
            PolicyOperator::RegexMatch => actual
                .as_str()
                .zip(self.expected.as_str())
                .and_then(|(actual, expected)| {
                    crate::regex_cache::compiled_regex(expected)
                        .map(|regex| regex.is_match(actual))
                })
                .unwrap_or(false),
        }
    }
}

#[allow(dead_code)]
fn parse_opa_rules(
    source: &str,
    rule_name: &str,
    diagnostics: &mut Vec<PolicyBackendDiagnostic>,
) -> Vec<CompiledPolicyRule> {
    collect_policy_bodies(source, rule_name, "if")
        .into_iter()
        .enumerate()
        .filter_map(|(index, body)| {
            compile_policy_rule(
                format!("{rule_name}[{}]", index + 1),
                body,
                "input.",
                diagnostics,
            )
        })
        .collect()
}

#[allow(dead_code)]
fn parse_cedar_rules(
    source: &str,
    keyword: &str,
    diagnostics: &mut Vec<PolicyBackendDiagnostic>,
) -> Vec<CompiledPolicyRule> {
    collect_policy_bodies(source, keyword, "when")
        .into_iter()
        .enumerate()
        .filter_map(|(index, body)| {
            compile_policy_rule(format!("{keyword}[{}]", index + 1), body, "", diagnostics)
        })
        .collect()
}

#[allow(dead_code)]
fn collect_policy_bodies(source: &str, rule_name: &str, keyword: &str) -> Vec<String> {
    let start = format!("{rule_name}");
    let mut results = Vec::new();
    let mut current = String::new();
    let mut collecting = false;
    for raw_line in source.lines() {
        let line = raw_line.trim();
        if !collecting && line.starts_with(&start) && line.contains(keyword) {
            if let Some((_, body)) = line.split_once(keyword) {
                let body = body
                    .trim()
                    .trim_start_matches('{')
                    .trim_end_matches(';')
                    .trim();
                if body.ends_with('}') {
                    results.push(body.trim_end_matches('}').trim().to_string());
                } else if body.is_empty() || line.ends_with('{') {
                    collecting = true;
                    current.clear();
                } else {
                    results.push(body.to_string());
                }
            }
            continue;
        }

        if collecting {
            if line.ends_with("};") || line == "}" || line == "};" {
                collecting = false;
                if !current.trim().is_empty() {
                    results.push(current.trim().to_string());
                }
                current.clear();
            } else {
                if !current.is_empty() {
                    current.push_str(" && ");
                }
                current.push_str(line.trim_end_matches(';'));
            }
        }
    }
    results
}

#[allow(dead_code)]
fn compile_policy_rule(
    name: String,
    raw_expression: String,
    prefix_to_trim: &str,
    diagnostics: &mut Vec<PolicyBackendDiagnostic>,
) -> Option<CompiledPolicyRule> {
    let clauses = split_top_level(&raw_expression, &["||", " or "])
        .into_iter()
        .filter_map(|clause| parse_policy_clause(&clause, prefix_to_trim, diagnostics))
        .collect::<Vec<_>>();

    if clauses.is_empty() {
        diagnostics.push(PolicyBackendDiagnostic::warning(
            format!("no supported conditions were parsed for {name}"),
            raw_expression,
        ));
        None
    } else {
        Some(CompiledPolicyRule {
            name,
            raw_expression,
            clauses,
        })
    }
}

#[allow(dead_code)]
fn parse_policy_clause(
    clause: &str,
    prefix_to_trim: &str,
    diagnostics: &mut Vec<PolicyBackendDiagnostic>,
) -> Option<PolicyRuleClause> {
    let conditions = split_top_level(clause, &["&&", ",", " and "])
        .into_iter()
        .filter_map(|part| parse_policy_condition(part.trim(), prefix_to_trim, diagnostics))
        .collect::<Vec<_>>();
    if conditions.is_empty() {
        None
    } else {
        Some(PolicyRuleClause { conditions })
    }
}

#[allow(dead_code)]
fn split_top_level(input: &str, delimiters: &[&str]) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut iter = input.char_indices().peekable();

    'outer: while let Some((idx, ch)) = iter.next() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == active_quote {
                quote = None;
            }
            continue;
        }

        match ch {
            '"' | '\'' => quote = Some(ch),
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '{' => brace_depth += 1,
            '}' => brace_depth = brace_depth.saturating_sub(1),
            _ => {}
        }

        if paren_depth == 0 && bracket_depth == 0 && brace_depth == 0 {
            for delimiter in delimiters {
                if input[idx..].starts_with(delimiter) {
                    let segment = input[start..idx].trim();
                    if !segment.is_empty() {
                        parts.push(segment.to_string());
                    }
                    start = idx + delimiter.len();
                    while let Some((next_idx, _)) = iter.peek() {
                        if *next_idx < start {
                            iter.next();
                        } else {
                            break;
                        }
                    }
                    continue 'outer;
                }
            }
        }
    }

    let tail = input[start..].trim();
    if !tail.is_empty() {
        parts.push(tail.to_string());
    }
    parts
}

#[allow(dead_code)]
fn parse_policy_condition(
    input: &str,
    prefix_to_trim: &str,
    diagnostics: &mut Vec<PolicyBackendDiagnostic>,
) -> Option<PolicyCondition> {
    let trimmed = strip_wrapping_parentheses(input.trim());

    for (operator_text, operator) in [
        (" not in ", PolicyOperator::NotIn),
        (" in ", PolicyOperator::In),
    ] {
        if let Some((left, right)) = trimmed.split_once(operator_text) {
            return Some(PolicyCondition {
                path: normalize_policy_path(left, prefix_to_trim),
                operator,
                expected: parse_policy_value(right.trim()),
            });
        }
    }
    for (operator_text, operator) in [
        ("==", PolicyOperator::Eq),
        ("!=", PolicyOperator::Ne),
        (">=", PolicyOperator::Gte),
        ("<=", PolicyOperator::Lte),
        (">", PolicyOperator::Gt),
        ("<", PolicyOperator::Lt),
    ] {
        if let Some((left, right)) = trimmed.split_once(operator_text) {
            return Some(PolicyCondition {
                path: normalize_policy_path(left, prefix_to_trim),
                operator,
                expected: parse_policy_value(right.trim()),
            });
        }
    }

    if let Some(condition) = parse_policy_function(trimmed, prefix_to_trim, diagnostics) {
        return Some(condition);
    }

    if let Some(inner) = trimmed.strip_prefix("not ") {
        return Some(PolicyCondition {
            path: normalize_policy_path(inner, prefix_to_trim),
            operator: PolicyOperator::Eq,
            expected: Value::from(false),
        });
    }
    if let Some(inner) = trimmed.strip_prefix('!') {
        return Some(PolicyCondition {
            path: normalize_policy_path(inner, prefix_to_trim),
            operator: PolicyOperator::Eq,
            expected: Value::from(false),
        });
    }
    if looks_like_boolean_path(trimmed) {
        return Some(PolicyCondition {
            path: normalize_policy_path(trimmed, prefix_to_trim),
            operator: PolicyOperator::Eq,
            expected: Value::from(true),
        });
    }

    diagnostics.push(PolicyBackendDiagnostic::warning(
        "unsupported policy expression",
        trimmed,
    ));
    None
}

#[allow(dead_code)]
fn parse_policy_function(
    input: &str,
    prefix_to_trim: &str,
    diagnostics: &mut Vec<PolicyBackendDiagnostic>,
) -> Option<PolicyCondition> {
    let open_paren = input.find('(')?;
    if !input.ends_with(')') {
        return None;
    }

    let function_name = input[..open_paren].trim();
    let args = split_top_level(&input[open_paren + 1..input.len() - 1], &[","]);
    match function_name {
        "startswith" | "endswith" | "contains" | "regex.match" if args.len() == 2 => {
            let (path, expected) = if function_name == "regex.match" {
                (
                    normalize_policy_path(&args[1], prefix_to_trim),
                    parse_policy_value(args[0].trim()),
                )
            } else {
                (
                    normalize_policy_path(&args[0], prefix_to_trim),
                    parse_policy_value(args[1].trim()),
                )
            };
            if function_name == "regex.match" {
                if let Some(pattern) = expected.as_str() {
                    if Regex::new(pattern).is_err() {
                        diagnostics.push(PolicyBackendDiagnostic::warning(
                            "invalid regex pattern",
                            input,
                        ));
                        return None;
                    }
                }
            }
            Some(PolicyCondition {
                path,
                operator: match function_name {
                    "startswith" => PolicyOperator::StartsWith,
                    "endswith" => PolicyOperator::EndsWith,
                    "contains" => PolicyOperator::Contains,
                    "regex.match" => PolicyOperator::RegexMatch,
                    _ => unreachable!(),
                },
                expected,
            })
        }
        "startswith" | "endswith" | "contains" | "regex.match" => {
            diagnostics.push(PolicyBackendDiagnostic::warning(
                "policy function requires two arguments",
                input,
            ));
            None
        }
        _ => None,
    }
}

#[allow(dead_code)]
fn looks_like_boolean_path(input: &str) -> bool {
    !input.is_empty()
        && !input.contains(' ')
        && !input.contains('(')
        && !input.contains(')')
        && !input.contains("==")
        && !input.contains("!=")
        && !input.contains(">=")
        && !input.contains("<=")
        && !input.contains('>')
        && !input.contains('<')
}

#[allow(dead_code)]
fn strip_wrapping_parentheses(input: &str) -> &str {
    let mut trimmed = input.trim();
    while trimmed.starts_with('(') && trimmed.ends_with(')') && trimmed.len() > 1 {
        trimmed = trimmed[1..trimmed.len() - 1].trim();
    }
    trimmed
}

#[allow(dead_code)]
fn normalize_policy_path(path: &str, prefix_to_trim: &str) -> String {
    strip_wrapping_parentheses(path.trim())
        .trim_start_matches(prefix_to_trim)
        .to_string()
}

#[allow(dead_code)]
fn parse_policy_value(input: &str) -> Value {
    let trimmed = strip_wrapping_parentheses(input.trim());
    if (trimmed.starts_with('[') && trimmed.ends_with(']'))
        || (trimmed.starts_with('{') && trimmed.ends_with('}'))
    {
        return serde_json::from_str(trimmed).unwrap_or_else(|_| {
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                Value::Array(
                    split_top_level(
                        trimmed.trim_start_matches('[').trim_end_matches(']'),
                        &[","],
                    )
                    .into_iter()
                    .map(|part| parse_policy_value(part.trim()))
                    .collect(),
                )
            } else {
                Value::String(trimmed.to_string())
            }
        });
    }
    if trimmed.eq_ignore_ascii_case("null") {
        Value::Null
    } else if let Ok(number) = trimmed.parse::<f64>() {
        Value::from(number)
    } else if trimmed.eq_ignore_ascii_case("true") {
        Value::from(true)
    } else if trimmed.eq_ignore_ascii_case("false") {
        Value::from(false)
    } else {
        Value::from(trimmed.trim_matches('"').trim_matches('\''))
    }
}

#[allow(dead_code)]
fn resolve_policy_value<'a>(input: &'a HashMap<String, Value>, path: &str) -> Option<&'a Value> {
    let mut parts = path.split('.');
    let first = parts.next()?;
    let mut current = input.get(first)?;
    for part in parts {
        current = current.as_object()?.get(part)?;
    }
    Some(current)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCategory {
    DataAccess,
    Execution,
    Spend,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgPolicyRule {
    pub name: String,
    pub category: PolicyCategory,
    pub action_pattern: String,
    pub decision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgPolicy {
    pub organization_id: String,
    pub rules: Vec<OrgPolicyRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgPolicyDecision {
    pub decision: String,
    pub matched_rule: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgTrustAgreement {
    pub source_org: String,
    pub target_org: String,
    pub min_trust_score: u32,
    pub allowed_classifications: Vec<DataClassification>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDelegation {
    pub from_org: String,
    pub to_org: String,
    pub allowed_categories: Vec<PolicyCategory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationDecision {
    pub allowed: bool,
    pub reason: Option<String>,
}

pub trait FederationStore: Send + Sync {
    /// Persist a policy for an organization.
    ///
    /// Implementations may fail for I/O reasons (file-backed stores) or
    /// serialization reasons; callers must handle the error rather than
    /// silently lose the write.
    fn save_policy(&self, policy: OrgPolicy) -> std::io::Result<()>;
    fn get_policy(&self, organization_id: &str) -> Option<OrgPolicy>;
}

#[derive(Default)]
pub struct InMemoryFederationStore {
    policies: Mutex<HashMap<String, OrgPolicy>>,
}

impl FederationStore for InMemoryFederationStore {
    fn save_policy(&self, policy: OrgPolicy) -> std::io::Result<()> {
        self.policies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(policy.organization_id.clone(), policy);
        Ok(())
    }

    fn get_policy(&self, organization_id: &str) -> Option<OrgPolicy> {
        self.policies
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(organization_id)
            .cloned()
    }
}

pub struct FileFederationStore {
    path: PathBuf,
    inner: InMemoryFederationStore,
}

impl FileFederationStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            inner: InMemoryFederationStore::default(),
        }
    }

    fn read_policy_map(&self) -> HashMap<String, OrgPolicy> {
        fs::read_to_string(&self.path)
            .ok()
            .and_then(|content| serde_json::from_str::<HashMap<String, OrgPolicy>>(&content).ok())
            .unwrap_or_default()
    }
}

impl FederationStore for FileFederationStore {
    fn save_policy(&self, policy: OrgPolicy) -> std::io::Result<()> {
        self.inner.save_policy(policy.clone())?;
        let mut policies = self.read_policy_map();
        policies.insert(policy.organization_id.clone(), policy);
        let serialized =
            serde_json::to_string_pretty(&policies).map_err(std::io::Error::other)?;
        fs::write(&self.path, serialized)
    }

    fn get_policy(&self, organization_id: &str) -> Option<OrgPolicy> {
        self.inner
            .get_policy(organization_id)
            .or_else(|| self.read_policy_map().remove(organization_id))
    }
}

pub struct FederationEngine {
    store: Arc<dyn FederationStore>,
}

impl FederationEngine {
    pub fn new(store: Arc<dyn FederationStore>) -> Self {
        Self { store }
    }

    pub fn evaluate(&self, organization_id: &str, action: &str) -> FederationDecision {
        let Some(policy) = self.store.get_policy(organization_id) else {
            return FederationDecision {
                allowed: false,
                reason: Some("no organization policy".to_string()),
            };
        };
        let matched = policy
            .rules
            .iter()
            .find(|rule| action.starts_with(rule.action_pattern.trim_end_matches('*')));
        match matched {
            Some(rule) if rule.decision == "deny" => FederationDecision {
                allowed: false,
                reason: Some(format!("blocked by rule '{}'", rule.name)),
            },
            Some(rule) => FederationDecision {
                allowed: true,
                reason: Some(format!("allowed by rule '{}'", rule.name)),
            },
            None => FederationDecision {
                allowed: false,
                reason: Some("no matching rule".to_string()),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnexIVSection {
    pub title: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnexIVDocument {
    pub title: String,
    pub sections: Vec<AnnexIVSection>,
}

pub struct TechnicalDocumentationExporter;

impl TechnicalDocumentationExporter {
    pub fn to_json(document: &AnnexIVDocument) -> String {
        serde_json::to_string_pretty(document).unwrap()
    }

    pub fn to_markdown(document: &AnnexIVDocument) -> String {
        let mut output = format!("# {}\n\n", document.title);
        for section in &document.sections {
            output.push_str(&format!("## {}\n\n{}\n\n", section.title, section.content));
        }
        output
    }
}

pub fn annex_iv_to_json(document: &AnnexIVDocument) -> String {
    TechnicalDocumentationExporter::to_json(document)
}

pub fn annex_iv_to_markdown(document: &AnnexIVDocument) -> String {
    TechnicalDocumentationExporter::to_markdown(document)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Minimal,
    Limited,
    High,
    Unacceptable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRiskProfile {
    pub agent_id: String,
    pub handles_sensitive_data: bool,
    pub supports_autonomous_actions: bool,
    pub user_facing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationResult {
    pub risk_level: RiskLevel,
    pub rationale: String,
}

pub struct EUAIActRiskClassifier;

impl EUAIActRiskClassifier {
    pub fn classify(profile: &AgentRiskProfile) -> ClassificationResult {
        if profile.supports_autonomous_actions && profile.handles_sensitive_data {
            ClassificationResult {
                risk_level: RiskLevel::High,
                rationale: "autonomous behavior with sensitive data".to_string(),
            }
        } else if profile.user_facing {
            ClassificationResult {
                risk_level: RiskLevel::Limited,
                rationale: "user-facing but lower autonomy".to_string(),
            }
        } else {
            ClassificationResult {
                risk_level: RiskLevel::Minimal,
                rationale: "low-risk helper profile".to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compliance_engine_reports_violations() {
        let engine = ComplianceEngine::default();
        engine.record_violation(
            ComplianceFramework::Soc2,
            "did:agentmesh:test",
            "data.read",
            "SOC2-CC6.1",
            "high",
            "missing approval",
        );
        let report = engine.generate_report(ComplianceFramework::Soc2);
        assert_eq!(report.controls_failed, 1);
        assert!(report.compliance_score < 100.0);
    }

    #[test]
    fn compliance_report_uses_framework_specific_control_count() {
        let engine = ComplianceEngine::new(vec![
            ComplianceFramework::Soc2,
            ComplianceFramework::Gdpr,
            ComplianceFramework::Hipaa,
            ComplianceFramework::EuAiAct,
        ]);
        for framework in [
            ComplianceFramework::Soc2,
            ComplianceFramework::Gdpr,
            ComplianceFramework::Hipaa,
            ComplianceFramework::EuAiAct,
        ] {
            let report = engine.generate_report(framework);
            assert_eq!(
                report.total_controls,
                framework.default_control_count(),
                "report denominator must match the framework's published \
                 top-level control count, not a hardcoded value"
            );
        }
    }

    #[test]
    fn compliance_score_is_full_when_no_violations() {
        let engine = ComplianceEngine::default();
        let report = engine.generate_report(ComplianceFramework::Soc2);
        assert_eq!(report.controls_failed, 0);
        assert_eq!(report.compliance_score, 100.0);
    }

    #[test]
    fn compliance_score_reflects_one_violation_relative_to_framework_size() {
        let engine = ComplianceEngine::default();
        engine.record_violation(
            ComplianceFramework::Soc2,
            "did:agentmesh:test",
            "x",
            "c",
            "low",
            "d",
        );
        let report = engine.generate_report(ComplianceFramework::Soc2);
        // SOC 2 = 5 top-level criteria, 1 failed → 4/5 = 80%.
        assert_eq!(report.compliance_score, 80.0);
    }

    #[test]
    fn compliance_score_floors_at_zero_when_violations_exceed_controls() {
        let engine = ComplianceEngine::default();
        for i in 0..10 {
            engine.record_violation(
                ComplianceFramework::Soc2,
                "did:agentmesh:test",
                "x",
                &format!("c{i}"),
                "low",
                "d",
            );
        }
        let report = engine.generate_report(ComplianceFramework::Soc2);
        assert_eq!(report.compliance_score, 0.0);
    }

    #[test]
    fn each_framework_publishes_a_nonzero_control_count() {
        // Guards the divide-by-zero floor in `generate_report`: every
        // variant must contribute a positive denominator.
        for framework in [
            ComplianceFramework::EuAiAct,
            ComplianceFramework::Soc2,
            ComplianceFramework::Hipaa,
            ComplianceFramework::Gdpr,
        ] {
            assert!(framework.default_control_count() > 0);
        }
    }

    #[test]
    fn shadow_mode_records_results() {
        let shadow = ShadowMode::new();
        let result = shadow.record(false, true, Some("would have allowed".into()));
        assert!(result.would_allow);
        assert!(!result.allowed);
    }

    #[test]
    fn policy_evaluator_matches_rule() {
        let evaluator = PolicyEvaluator::new(vec![TrustPolicy {
            name: "default".into(),
            version: "1.0".into(),
            description: None,
            rules: vec![TrustRule {
                name: "deny-low-trust".into(),
                description: None,
                condition: TrustCondition {
                    field: "trust_score".into(),
                    operator: ConditionOperator::Lt,
                    value: Value::from(500),
                },
                action: "deny".into(),
                priority: 1,
            }],
            defaults: TrustDefaults::default(),
        }]);
        let decision = evaluator.evaluate(&HashMap::from([(
            "trust_score".to_string(),
            Value::from(400),
        )]));
        assert_eq!(decision.action, "deny");
    }

    #[test]
    fn policy_evaluator_denies_when_no_rule_matches() {
        let evaluator = PolicyEvaluator::new(vec![TrustPolicy {
            name: "default".into(),
            version: "1.0".into(),
            description: None,
            rules: vec![TrustRule {
                name: "allow-high-trust".into(),
                description: None,
                condition: TrustCondition {
                    field: "trust_score".into(),
                    operator: ConditionOperator::Gte,
                    value: Value::from(700),
                },
                action: "allow".into(),
                priority: 1,
            }],
            defaults: TrustDefaults::default(),
        }]);
        let decision = evaluator.evaluate(&HashMap::from([(
            "trust_score".to_string(),
            Value::from(400),
        )]));
        assert_eq!(decision.action, "deny");
        assert!(!decision.matched);
    }

    #[test]
    fn federation_engine_applies_rules() {
        let store = Arc::new(InMemoryFederationStore::default());
        store
            .save_policy(OrgPolicy {
                organization_id: "contoso".into(),
                rules: vec![OrgPolicyRule {
                    name: "deny-shell".into(),
                    category: PolicyCategory::Execution,
                    action_pattern: "shell".into(),
                    decision: "deny".into(),
                }],
            })
            .unwrap();
        let engine = FederationEngine::new(store);
        assert!(!engine.evaluate("contoso", "shell:rm").allowed);
    }

    #[test]
    fn federation_engine_denies_without_policy_or_rule_match() {
        let store = Arc::new(InMemoryFederationStore::default());
        store
            .save_policy(OrgPolicy {
                organization_id: "contoso".into(),
                rules: vec![OrgPolicyRule {
                    name: "allow-data".into(),
                    category: PolicyCategory::DataAccess,
                    action_pattern: "data.read".into(),
                    decision: "allow".into(),
                }],
            })
            .unwrap();
        let engine = FederationEngine::new(store);
        assert!(!engine.evaluate("missing", "data.read").allowed);
        assert!(!engine.evaluate("contoso", "shell:rm").allowed);
    }

    #[test]
    fn eu_ai_act_classifier_scores_profiles() {
        let result = EUAIActRiskClassifier::classify(&AgentRiskProfile {
            agent_id: "agent".into(),
            handles_sensitive_data: true,
            supports_autonomous_actions: true,
            user_facing: true,
        });
        assert_eq!(result.risk_level, RiskLevel::High);
    }

    #[test]
    fn opa_and_cedar_evaluators_execute_real_rules() {
        let opa = OPAEvaluator::new(
            r#"
                package agt
                import rego.v1
                default allow := false
                allow if input.trust_score >= 700
                deny if input.action == "shell:rm"
            "#,
        );
        let cedar = CedarEvaluator::new(
            r#"
                permit(principal, action, resource)
                when { context.trust_score >= 700 && action == Action::"data.read" };

                forbid(principal, action, resource)
                when { action == Action::"shell:rm" };
            "#,
        );
        let mut opa_input = HashMap::new();
        opa_input.insert("trust_score".to_string(), Value::from(800));
        opa_input.insert("action".to_string(), Value::from("data.read"));

        let mut cedar_context = serde_json::Map::new();
        cedar_context.insert("trust_score".to_string(), Value::from(800));
        let cedar_input = HashMap::from([
            ("context".to_string(), Value::Object(cedar_context)),
            ("action".to_string(), Value::from("data.read")),
        ]);

        let opa_decision = opa.evaluate(&opa_input);
        let cedar_decision = cedar.evaluate(&cedar_input);

        assert!(opa_decision.allow);
        assert!(cedar_decision.allow);
    }

    #[test]
    fn opa_and_cedar_support_membership_and_block_bodies() {
        let opa = OPAEvaluator::new(
            r#"
                package agt
                import rego.v1
                default allow := false
                allow if {
                    input.trust_score >= 700
                    input.action in ["data.read","data.write"]
                }
            "#,
        );
        let cedar = CedarEvaluator::new(
            r#"
                permit(principal, action, resource)
                when {
                    context.trust_score >= 700 &&
                    action in [Action::"data.read", Action::"data.write"]
                };
            "#,
        );
        let mut opa_input = HashMap::new();
        opa_input.insert("trust_score".to_string(), Value::from(800));
        opa_input.insert("action".to_string(), Value::from("data.read"));

        let mut cedar_context = serde_json::Map::new();
        cedar_context.insert("trust_score".to_string(), Value::from(800));
        let cedar_input = HashMap::from([
            ("context".to_string(), Value::Object(cedar_context)),
            ("action".to_string(), Value::from("data.read")),
        ]);

        assert!(opa.evaluate(&opa_input).allow);
        assert!(cedar.evaluate(&cedar_input).allow);
    }

    #[test]
    fn opa_backend_supports_functions_or_clauses_and_trace_output() {
        let opa = OPAEvaluator::new(
            r#"
                package agt
                import rego.v1
                # comments should not influence defaults
                default allow := false
                allow if startswith(input.resource, "repo/")
                allow if "trusted" in input.labels
                allow if regex.match("^ops:", input.action)
                deny if {
                    regex.match("^shell:", input.action)
                    not input.approved
                }
            "#,
        );

        let allow_input = HashMap::from([
            ("resource".to_string(), Value::from("repo/docs")),
            (
                "labels".to_string(),
                Value::Array(vec![Value::from("trusted"), Value::from("internal")]),
            ),
            ("action".to_string(), Value::from("data.read")),
            ("approved".to_string(), Value::from(true)),
        ]);
        let allow_eval = opa.evaluate_with_trace(&allow_input);
        assert!(allow_eval.decision.allow);
        assert!(!allow_eval.trace.default_applied);
        assert!(!allow_eval.trace.matched_rules.is_empty());
        assert!(opa.diagnostics().is_empty());

        let deny_input = HashMap::from([
            ("resource".to_string(), Value::from("repo/secrets")),
            ("action".to_string(), Value::from("shell:rm")),
            ("approved".to_string(), Value::from(false)),
        ]);
        assert!(!opa.evaluate(&deny_input).allow);
    }

    #[test]
    fn cedar_backend_supports_functions_trace_and_diagnostics() {
        let cedar = CedarEvaluator::new(
            r#"
                permit(
                    principal == Principal::"did:mesh:trusted",
                    action,
                    resource == Resource::"vault://customer-secrets"
                )
                when {
                    context.break_glass ||
                    context.resource_class == "vault"
                };

                forbid(principal, action == Action::"admin:delete", resource)
                when {
                    !context.approved
                };
            "#,
        );

        let context = serde_json::Map::from_iter([
            ("break_glass".to_string(), Value::from(false)),
            ("approved".to_string(), Value::from(true)),
            ("resource_class".to_string(), Value::from("vault")),
        ]);
        let permit_input = HashMap::from([
            ("principal".to_string(), Value::from("did:mesh:trusted")),
            ("action".to_string(), Value::from("data.read")),
            (
                "resource".to_string(),
                Value::from("vault://customer-secrets"),
            ),
            ("context".to_string(), Value::Object(context)),
        ]);
        let permit_eval = cedar.evaluate_with_trace(&permit_input);
        assert!(permit_eval.decision.allow);
        assert!(!permit_eval.trace.default_applied);
        assert!(!permit_eval.trace.matched_rules.is_empty());
        assert!(cedar.diagnostics().is_empty());

        let context = serde_json::Map::from_iter([
            ("break_glass".to_string(), Value::from(false)),
            ("approved".to_string(), Value::from(false)),
            ("resource_class".to_string(), Value::from("vault")),
        ]);
        let forbid_input = HashMap::from([
            ("principal".to_string(), Value::from("did:mesh:trusted")),
            ("action".to_string(), Value::from("admin:delete")),
            (
                "resource".to_string(),
                Value::from("vault://customer-secrets"),
            ),
            ("context".to_string(), Value::Object(context)),
        ]);
        assert!(!cedar.evaluate(&forbid_input).allow);

        let invalid = CedarEvaluator::new(
            r#"
                permit(principal, action, resource)
                when { context. == true };
            "#,
        );
        assert!(!invalid.diagnostics().is_empty());
    }

    #[test]
    fn file_federation_store_persists_multiple_orgs() {
        let temp = tempfile::NamedTempFile::new().unwrap();
        let store = FileFederationStore::new(temp.path());

        store
            .save_policy(OrgPolicy {
                organization_id: "org-a".into(),
                rules: vec![],
            })
            .unwrap();
        store
            .save_policy(OrgPolicy {
                organization_id: "org-b".into(),
                rules: vec![],
            })
            .unwrap();

        assert!(store.get_policy("org-a").is_some());
        assert!(store.get_policy("org-b").is_some());
    }

    /// Regression: prior to fallibilizing the trait, FileFederationStore
    /// used `let _ = fs::write(...)` and silently swallowed I/O errors.
    /// A path pointing into a non-existent directory now surfaces as an
    /// Err instead of being lost.
    #[test]
    fn file_federation_store_returns_err_on_unwriteable_path() {
        let unwriteable = std::env::temp_dir()
            .join("agentmesh-federation-store-tests-nonexistent-parent")
            .join("policies.json");
        let _ = fs::remove_dir_all(unwriteable.parent().unwrap());

        let store = FileFederationStore::new(&unwriteable);
        let result = store.save_policy(OrgPolicy {
            organization_id: "ghost".into(),
            rules: vec![],
        });
        assert!(
            result.is_err(),
            "expected save_policy to surface the I/O error, got Ok"
        );
    }

    #[test]
    fn hash_chain_verifier_uses_stored_timestamps() {
        use sha2::{Digest, Sha256};

        fn digest(input: &str) -> String {
            let mut hasher = Sha256::new();
            hasher.update(input.as_bytes());
            hasher
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        }

        let first = AuditEntry {
            seq: 0,
            timestamp: "2026-01-01T00:00:00Z".into(),
            agent_id: "agent-1".into(),
            action: "data.read".into(),
            decision: "allow".into(),
            previous_hash: String::new(),
            hash: digest("0|2026-01-01T00:00:00Z|agent-1|data.read|allow|"),
        };
        let second_prev = first.hash.clone();
        let second = AuditEntry {
            seq: 1,
            timestamp: "2026-01-01T00:00:01Z".into(),
            agent_id: "agent-1".into(),
            action: "shell:rm".into(),
            decision: "deny".into(),
            previous_hash: second_prev.clone(),
            hash: digest(&format!(
                "1|2026-01-01T00:00:01Z|agent-1|shell:rm|deny|{second_prev}"
            )),
        };

        assert!(HashChainVerifier::verify(&[first, second]));
    }
}
