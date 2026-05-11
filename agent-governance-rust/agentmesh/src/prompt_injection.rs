// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Deterministic prompt-injection detection for Rust agents.
//!
//! This module ports the AGT Python detector's public behavior into the Rust
//! SDK while tightening audit/evidence handling: public findings use stable
//! rule IDs or hashes only, never raw prompt excerpts, canary tokens,
//! blocklist entries, or custom regex bodies.

use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DEFAULT_AUDIT_CAPACITY: usize = 10_000;
const MIN_LIST_ENTRY_LEN: usize = 3;

/// Classification of a prompt-injection signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum InjectionType {
    DirectOverride,
    DelimiterAttack,
    EncodingAttack,
    RolePlay,
    ContextManipulation,
    CanaryLeak,
    MultiTurnEscalation,
}

/// Severity of a prompt-injection signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ThreatLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// Detection sensitivity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Sensitivity {
    Strict,
    #[default]
    Balanced,
    Permissive,
}

/// Detector configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionConfig {
    #[serde(default)]
    pub sensitivity: Sensitivity,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
    #[serde(default)]
    pub blocklist: Vec<String>,
    #[serde(default)]
    pub allowlist: Vec<String>,
    #[serde(default = "default_audit_capacity")]
    pub audit_capacity: usize,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            sensitivity: Sensitivity::Balanced,
            custom_patterns: Vec::new(),
            blocklist: Vec::new(),
            allowlist: Vec::new(),
            audit_capacity: DEFAULT_AUDIT_CAPACITY,
        }
    }
}

/// Top-level prompt-injection config file shape.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptInjectionConfig {
    #[serde(default)]
    pub detection: DetectionConfig,
}

/// Per-call detection options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionOptions {
    pub source: String,
    pub canary_tokens: Vec<String>,
}

impl Default for DetectionOptions {
    fn default() -> Self {
        Self {
            source: "unknown".to_string(),
            canary_tokens: Vec::new(),
        }
    }
}

/// Outcome of scanning one prompt input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectionResult {
    pub is_injection: bool,
    pub threat_level: ThreatLevel,
    pub injection_type: Option<InjectionType>,
    pub confidence: f64,
    pub matched_patterns: Vec<String>,
    pub explanation: String,
}

impl DetectionResult {
    pub fn clean() -> Self {
        Self {
            is_injection: false,
            threat_level: ThreatLevel::None,
            injection_type: None,
            confidence: 0.0,
            matched_patterns: Vec::new(),
            explanation: "No injection patterns detected".to_string(),
        }
    }

    fn fail_closed(error: &str) -> Self {
        Self {
            is_injection: true,
            threat_level: ThreatLevel::Critical,
            injection_type: Some(InjectionType::DirectOverride),
            confidence: 1.0,
            matched_patterns: vec!["detection_error".to_string()],
            explanation: format!("Detection failed closed: {error}"),
        }
    }
}

/// Hash-only audit record for a detection attempt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub timestamp_unix_ms: u128,
    pub input_hash: String,
    pub source: String,
    pub result: DetectionResult,
}

impl AuditRecord {
    /// Audit records intentionally never expose raw input.
    pub fn raw_input(&self) -> Option<&str> {
        None
    }
}

/// Errors returned by detector construction/config parsing.
#[derive(Debug, thiserror::Error)]
pub enum PromptInjectionError {
    #[error("allowlist entry is invalid: {entry:?}")]
    InvalidAllowlistEntry { entry: String },
    #[error("blocklist entry is invalid: {entry:?}")]
    InvalidBlocklistEntry { entry: String },
    #[error("custom pattern {pattern_index} is invalid: {source}")]
    InvalidCustomPattern {
        pattern_index: usize,
        source: regex::Error,
    },
    #[error("built-in pattern {name} is invalid: {source}")]
    InvalidBuiltInPattern {
        name: &'static str,
        source: regex::Error,
    },
    #[error("failed to read prompt-injection config: {0}")]
    ConfigIo(#[from] std::io::Error),
    #[error("failed to parse prompt-injection config: {0}")]
    ConfigParse(#[from] serde_yaml::Error),
}

/// Deterministic prompt-injection detector with bounded hash-only audit.
#[derive(Debug)]
pub struct PromptInjectionDetector {
    config: DetectionConfig,
    custom_patterns: Vec<CompiledCustomPattern>,
    direct_patterns: Vec<CompiledRule>,
    delimiter_patterns: Vec<CompiledRule>,
    role_play_patterns: Vec<CompiledRule>,
    context_patterns: Vec<CompiledRule>,
    multi_turn_patterns: Vec<CompiledRule>,
    audit_log: VecDeque<AuditRecord>,
}

impl PromptInjectionDetector {
    pub fn new() -> Result<Self, PromptInjectionError> {
        Self::with_config(DetectionConfig::default())
    }

    pub fn with_config(config: DetectionConfig) -> Result<Self, PromptInjectionError> {
        validate_entries(&config.allowlist, EntryKind::Allowlist)?;
        validate_entries(&config.blocklist, EntryKind::Blocklist)?;

        let custom_patterns = config
            .custom_patterns
            .iter()
            .enumerate()
            .map(|(idx, pattern)| {
                Regex::new(pattern)
                    .map(|regex| CompiledCustomPattern {
                        regex,
                        rule_id: format!("custom:sha256:{}", sha256_prefix(pattern)),
                    })
                    .map_err(|source| PromptInjectionError::InvalidCustomPattern {
                        pattern_index: idx,
                        source,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            direct_patterns: compile_rules("direct", DIRECT_RULES)?,
            delimiter_patterns: compile_rules("delimiter", DELIMITER_RULES)?,
            role_play_patterns: compile_rules("role_play", ROLE_PLAY_RULES)?,
            context_patterns: compile_rules("context", CONTEXT_RULES)?,
            multi_turn_patterns: compile_rules("multi_turn", MULTI_TURN_RULES)?,
            audit_log: VecDeque::with_capacity(config.audit_capacity.min(1024)),
            custom_patterns,
            config,
        })
    }

    pub fn from_yaml_str(raw: &str) -> Result<Self, PromptInjectionError> {
        let config: PromptInjectionConfig = serde_yaml::from_str(raw)?;
        Self::with_config(config.detection)
    }

    pub fn from_yaml_file(path: impl AsRef<std::path::Path>) -> Result<Self, PromptInjectionError> {
        let raw = std::fs::read_to_string(path)?;
        Self::from_yaml_str(&raw)
    }

    pub fn detect(&mut self, text: &str) -> DetectionResult {
        self.detect_with_options(text, DetectionOptions::default())
    }

    pub fn detect_with_options(
        &mut self,
        text: &str,
        options: DetectionOptions,
    ) -> DetectionResult {
        let result = self
            .detect_impl(text, &options)
            .unwrap_or_else(|err| DetectionResult::fail_closed(&err));
        self.record_audit(text, options.source, result.clone());
        result
    }

    pub fn detect_batch(&mut self, texts: &[String]) -> Vec<DetectionResult> {
        texts.iter().map(|text| self.detect(text)).collect()
    }

    pub fn audit_log(&self) -> Vec<AuditRecord> {
        self.audit_log.iter().cloned().collect()
    }

    fn detect_impl(
        &self,
        text: &str,
        options: &DetectionOptions,
    ) -> Result<DetectionResult, String> {
        let text_lower = text.to_ascii_lowercase();

        for blocked in &self.config.blocklist {
            if text_lower.contains(&blocked.to_ascii_lowercase()) {
                return Ok(DetectionResult {
                    is_injection: true,
                    threat_level: ThreatLevel::High,
                    injection_type: Some(InjectionType::DirectOverride),
                    confidence: 1.0,
                    matched_patterns: vec![format!("blocklist:sha256:{}", sha256_prefix(blocked))],
                    explanation: "Input matched configured blocklist rule".to_string(),
                });
            }
        }

        let mut findings = Vec::new();
        findings.extend(self.scan_rules(
            text,
            &self.direct_patterns,
            InjectionType::DirectOverride,
        ));
        findings.extend(self.scan_rules(
            text,
            &self.delimiter_patterns,
            InjectionType::DelimiterAttack,
        ));
        findings.extend(self.scan_encoding(text));
        findings.extend(self.scan_rules(text, &self.role_play_patterns, InjectionType::RolePlay));
        findings.extend(self.scan_rules(
            text,
            &self.context_patterns,
            InjectionType::ContextManipulation,
        ));
        findings.extend(self.scan_canaries(text, &options.canary_tokens));
        findings.extend(self.scan_rules(
            text,
            &self.multi_turn_patterns,
            InjectionType::MultiTurnEscalation,
        ));
        findings.extend(self.scan_custom_patterns(text));

        let mut filtered = findings
            .into_iter()
            .filter(|finding| self.passes_sensitivity(finding))
            .collect::<Vec<_>>();

        if !self.config.allowlist.is_empty() {
            filtered = self.filter_allowlisted(text, filtered);
        }

        if filtered.is_empty() {
            return Ok(DetectionResult::clean());
        }

        let highest = filtered
            .iter()
            .max_by_key(|finding| finding.threat_level)
            .ok_or_else(|| "missing highest finding".to_string())?;
        let max_confidence = filtered
            .iter()
            .map(|finding| finding.confidence)
            .fold(0.0_f64, f64::max)
            .clamp(0.0, 1.0);
        let matched_patterns = filtered
            .iter()
            .map(|finding| finding.rule_id.clone())
            .collect::<Vec<_>>();

        Ok(DetectionResult {
            is_injection: true,
            threat_level: highest.threat_level,
            injection_type: Some(highest.injection_type),
            confidence: round3(max_confidence),
            matched_patterns,
            explanation: format!(
                "Detected {:?} ({:?} threat) from {} signal(s)",
                highest.injection_type,
                highest.threat_level,
                filtered.len()
            ),
        })
    }

    fn scan_rules(
        &self,
        text: &str,
        rules: &[CompiledRule],
        injection_type: InjectionType,
    ) -> Vec<Finding> {
        rules
            .iter()
            .filter_map(|rule| {
                rule.regex.find(text).map(|matched| Finding {
                    injection_type,
                    threat_level: rule.threat_level,
                    confidence: rule.confidence,
                    rule_id: rule.rule_id.clone(),
                    span: Some((matched.start(), matched.end())),
                })
            })
            .collect()
    }

    fn scan_encoding(&self, text: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        if text.to_ascii_lowercase().contains("rot13") {
            findings.push(Finding::new(
                InjectionType::EncodingAttack,
                ThreatLevel::Medium,
                0.65,
                "encoding:rot13_reference",
            ));
        }
        if text.to_ascii_lowercase().contains("base64 decode") {
            findings.push(Finding::new(
                InjectionType::EncodingAttack,
                ThreatLevel::Medium,
                0.65,
                "encoding:base64_reference",
            ));
        }
        if text.contains("\\x") {
            findings.push(Finding::new(
                InjectionType::EncodingAttack,
                ThreatLevel::Medium,
                0.7,
                "encoding:hex_escape",
            ));
        }
        if text.contains("\\u") {
            findings.push(Finding::new(
                InjectionType::EncodingAttack,
                ThreatLevel::Medium,
                0.7,
                "encoding:unicode_escape",
            ));
        }

        for token in text
            .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' || ch == '='))
        {
            if token.len() < 12 || token.len() % 4 != 0 {
                continue;
            }
            if let Ok(decoded) = STANDARD.decode(token.as_bytes()) {
                if let Ok(decoded_text) = String::from_utf8(decoded) {
                    let lower = decoded_text.to_ascii_lowercase();
                    if contains_decoded_malicious_keyword(&lower) {
                        findings.push(Finding::new(
                            InjectionType::EncodingAttack,
                            ThreatLevel::High,
                            0.9,
                            "encoding:decoded_instruction",
                        ));
                    }
                }
            }
        }

        findings
    }

    fn scan_canaries(&self, text: &str, canary_tokens: &[String]) -> Vec<Finding> {
        canary_tokens
            .iter()
            .filter(|token| !token.trim().is_empty() && text.contains(token.as_str()))
            .map(|token| {
                Finding::new(
                    InjectionType::CanaryLeak,
                    ThreatLevel::Critical,
                    1.0,
                    format!("canary:sha256:{}", sha256_prefix(token)),
                )
            })
            .collect()
    }

    fn scan_custom_patterns(&self, text: &str) -> Vec<Finding> {
        self.custom_patterns
            .iter()
            .filter_map(|pattern| {
                pattern.regex.find(text).map(|matched| Finding {
                    injection_type: InjectionType::DirectOverride,
                    threat_level: ThreatLevel::High,
                    confidence: 0.8,
                    rule_id: pattern.rule_id.clone(),
                    span: Some((matched.start(), matched.end())),
                })
            })
            .collect()
    }

    fn passes_sensitivity(&self, finding: &Finding) -> bool {
        match self.config.sensitivity {
            Sensitivity::Strict => {
                finding.threat_level >= ThreatLevel::Low && finding.confidence >= 0.4
            }
            Sensitivity::Balanced => {
                finding.threat_level >= ThreatLevel::Medium && finding.confidence >= 0.5
            }
            Sensitivity::Permissive => {
                finding.threat_level >= ThreatLevel::High && finding.confidence >= 0.75
            }
        }
    }

    fn filter_allowlisted(&self, text: &str, findings: Vec<Finding>) -> Vec<Finding> {
        let lower = text.to_ascii_lowercase();
        let spans = self
            .config
            .allowlist
            .iter()
            .flat_map(|entry| {
                let needle = entry.to_ascii_lowercase();
                let len = needle.len();
                lower
                    .match_indices(&needle)
                    .map(|(start, _)| (start, start + len))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        findings
            .into_iter()
            .filter(|finding| match finding.span {
                Some(span) => !spans.iter().any(|allow| overlaps(span, *allow)),
                None => true,
            })
            .collect()
    }

    fn record_audit(&mut self, text: &str, source: String, result: DetectionResult) {
        let cap = self.config.audit_capacity;
        if cap == 0 {
            return;
        }
        while self.audit_log.len() >= cap {
            self.audit_log.pop_front();
        }
        self.audit_log.push_back(AuditRecord {
            timestamp_unix_ms: unix_ms_now(),
            input_hash: sha256_hex(text),
            source,
            result,
        });
    }
}

fn default_audit_capacity() -> usize {
    DEFAULT_AUDIT_CAPACITY
}

#[derive(Debug, Clone)]
struct CompiledRule {
    regex: Regex,
    rule_id: String,
    threat_level: ThreatLevel,
    confidence: f64,
}

#[derive(Debug, Clone)]
struct CompiledCustomPattern {
    regex: Regex,
    rule_id: String,
}

#[derive(Debug, Clone)]
struct Finding {
    injection_type: InjectionType,
    threat_level: ThreatLevel,
    confidence: f64,
    rule_id: String,
    span: Option<(usize, usize)>,
}

impl Finding {
    fn new(
        injection_type: InjectionType,
        threat_level: ThreatLevel,
        confidence: f64,
        rule_id: impl Into<String>,
    ) -> Self {
        Self {
            injection_type,
            threat_level,
            confidence,
            rule_id: rule_id.into(),
            span: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum EntryKind {
    Allowlist,
    Blocklist,
}

fn validate_entries(entries: &[String], kind: EntryKind) -> Result<(), PromptInjectionError> {
    for entry in entries {
        let stripped = entry.trim();
        if stripped.len() < MIN_LIST_ENTRY_LEN {
            return match kind {
                EntryKind::Allowlist => Err(PromptInjectionError::InvalidAllowlistEntry {
                    entry: entry.clone(),
                }),
                EntryKind::Blocklist => Err(PromptInjectionError::InvalidBlocklistEntry {
                    entry: entry.clone(),
                }),
            };
        }
    }
    Ok(())
}

fn compile_rules(
    prefix: &'static str,
    rules: &[(&'static str, ThreatLevel, f64, &'static str)],
) -> Result<Vec<CompiledRule>, PromptInjectionError> {
    rules
        .iter()
        .map(|(pattern, threat_level, confidence, name)| {
            Regex::new(pattern)
                .map(|regex| CompiledRule {
                    regex,
                    rule_id: format!("{prefix}:{name}"),
                    threat_level: *threat_level,
                    confidence: *confidence,
                })
                .map_err(|source| PromptInjectionError::InvalidBuiltInPattern { name, source })
        })
        .collect()
}

fn contains_decoded_malicious_keyword(lower: &str) -> bool {
    [
        "ignore previous",
        "ignore all previous",
        "reveal the system",
        "developer mode",
        "bypass safety",
        "disable safety",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn overlaps(left: (usize, usize), right: (usize, usize)) -> bool {
    left.0 < right.1 && right.0 < left.1
}

fn sha256_hex(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

fn sha256_prefix(text: &str) -> String {
    sha256_hex(text).chars().take(12).collect()
}

fn unix_ms_now() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default()
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

const DIRECT_RULES: &[(&str, ThreatLevel, f64, &str)] = &[
    (
        r"(?i)ignore\s+(all\s+)?previous\s+instructions",
        ThreatLevel::High,
        0.95,
        "ignore_previous_instructions",
    ),
    (
        r"(?i)\byou\s+are\s+now\b",
        ThreatLevel::High,
        0.85,
        "you_are_now",
    ),
    (r"(?i)new\s+role\s*:", ThreatLevel::High, 0.85, "new_role"),
    (
        r"(?i)forget\s+(everything|all|your)\b",
        ThreatLevel::High,
        0.85,
        "forget_context",
    ),
    (
        r"(?i)disregard\s+(all\s+)?(above|prior|previous)\b",
        ThreatLevel::High,
        0.85,
        "disregard_prior",
    ),
    (
        r"(?i)override\s+(previous\s+)?instructions",
        ThreatLevel::High,
        0.9,
        "override_instructions",
    ),
    (
        r"(?i)do\s+not\s+follow\s+(your|the)\s+(previous\s+)?instructions",
        ThreatLevel::High,
        0.9,
        "do_not_follow",
    ),
];

const DELIMITER_RULES: &[(&str, ThreatLevel, f64, &str)] = &[
    (
        r"(?m)^-{3,}\s*$",
        ThreatLevel::Medium,
        0.65,
        "dash_boundary",
    ),
    (
        r"(?m)^#{3,}\s*$",
        ThreatLevel::Medium,
        0.65,
        "hash_boundary",
    ),
    (
        r"(?m)^```\s*$",
        ThreatLevel::Medium,
        0.6,
        "code_fence_boundary",
    ),
    (r"(?i)END\s+SYSTEM", ThreatLevel::Medium, 0.75, "end_system"),
    (r"(?i)BEGIN\s+USER", ThreatLevel::Medium, 0.75, "begin_user"),
    (r"(?i)<\|im_start\|>", ThreatLevel::Medium, 0.8, "im_start"),
    (r"(?i)<\|im_end\|>", ThreatLevel::Medium, 0.8, "im_end"),
    (r"(?i)\[INST\]", ThreatLevel::Medium, 0.75, "inst_token"),
    (r"(?i)<<SYS>>", ThreatLevel::Medium, 0.75, "sys_token"),
    (
        r"(?i)</?(system|user|assistant)>",
        ThreatLevel::Medium,
        0.75,
        "role_tag",
    ),
    (
        r"(?i)<\|(system|user|assistant)\|>",
        ThreatLevel::Medium,
        0.75,
        "role_pipe_tag",
    ),
];

const ROLE_PLAY_RULES: &[(&str, ThreatLevel, f64, &str)] = &[
    (
        r"(?i)pretend\s+you\s+are\s+an?\s+unrestricted",
        ThreatLevel::High,
        0.85,
        "pretend_unrestricted",
    ),
    (
        r"(?i)act\s+as\s+if\s+you\s+have\s+no\s+restrictions",
        ThreatLevel::High,
        0.85,
        "act_no_restrictions",
    ),
    (
        r"(?i)enable\s+jailbreak\s+mode",
        ThreatLevel::High,
        0.9,
        "jailbreak_mode",
    ),
    (r"(?i)\bDAN\s+mode\b", ThreatLevel::High, 0.9, "dan_mode"),
    (
        r"(?i)developer\s+mode\s+override",
        ThreatLevel::High,
        0.85,
        "developer_mode",
    ),
    (
        r"(?i)bypass\s+all\s+safety\s+filters",
        ThreatLevel::High,
        0.9,
        "bypass_safety_filters",
    ),
];

const CONTEXT_RULES: &[(&str, ThreatLevel, f64, &str)] = &[
    (
        r"(?i)the\s+above\s+instructions\s+are\s+wrong",
        ThreatLevel::Medium,
        0.75,
        "above_wrong",
    ),
    (
        r"(?i)your\s+real\s+instructions\s+are",
        ThreatLevel::High,
        0.85,
        "real_instructions",
    ),
    (
        r"(?i)the\s+developer\s+told\s+me\s+to\s+tell\s+you",
        ThreatLevel::Medium,
        0.75,
        "developer_told_me",
    ),
    (
        r"(?i)secret\s+password\s+is\s+OVERRIDE",
        ThreatLevel::Medium,
        0.75,
        "secret_password_override",
    ),
];

const MULTI_TURN_RULES: &[(&str, ThreatLevel, f64, &str)] = &[
    (
        r"(?i)as\s+I\s+mentioned\s+before.*you\s+agreed",
        ThreatLevel::Medium,
        0.75,
        "mentioned_before_agreed",
    ),
    (
        r"(?i)you\s+already\s+said\s+yes",
        ThreatLevel::Medium,
        0.75,
        "already_said_yes",
    ),
    (
        r"(?i)continuing\s+from\s+where\s+you\s+unlocked",
        ThreatLevel::Medium,
        0.75,
        "continuing_unlocked",
    ),
    (
        r"(?i)you\s+previously\s+confirmed\s+you\s+would",
        ThreatLevel::Medium,
        0.75,
        "previously_confirmed",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_closed_result_is_critical() {
        let result = DetectionResult::fail_closed("boom");

        assert!(result.is_injection);
        assert_eq!(result.threat_level, ThreatLevel::Critical);
        assert_eq!(result.matched_patterns, vec!["detection_error"]);
    }
}
