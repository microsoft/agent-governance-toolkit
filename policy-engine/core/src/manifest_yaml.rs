// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bounded manifest YAML parsing retained by AGT.
//!
//! The policy runtime now lives in the `agent_control_spec` crate. That
//! crate exposes `Manifest::from_yaml_str` but not the resource bounded
//! `serde` seed AGT layers over it. The seed is generic input hardening
//! rather than contract semantics, so AGT keeps owning it instead of
//! forking the policy plane.

use agent_control_spec::policy::PolicyConfig;
use agent_control_spec::{JsonValue, Limits, Manifest, RuntimeError};
use serde::de::{DeserializeSeed, Deserializer, Error as DeError, MapAccess, SeqAccess, Visitor};
use serde_json::Map;
use std::fmt;

/// Upper bound on expanded manifest nodes. Guards against YAML anchor
/// expansion blowing up memory before the manifest is ever validated.
const MAX_MANIFEST_PARSE_NODES: usize = 100_000;

/// Manifest grammar versions accepted by the upstream engine.
pub use agent_control_spec::SUPPORTED_VERSIONS;

/// Legacy array form, derived from the upstream grammar rather than copied.
pub const SUPPORTED_MANIFEST_VERSIONS: [&str; 1] = [SUPPORTED_VERSIONS[0]];
const _: () = assert!(
    SUPPORTED_VERSIONS.len() == 1,
    "review the legacy array API when upstream accepts multiple manifest versions"
);

/// Manifest fields the pre-retarget engine implemented that
/// `agent-control-spec` 0.4.0-alpha.3 does not.
///
/// The upstream `RegoPolicyConfig::adapter_config`, `PolicyBinding::adapter_config`,
/// `AnnotatorConfig::fields` and `AnnotationConfig::fields` maps are open, so a
/// manifest declaring one of these keys deserializes and validates cleanly
/// while the feature it asks for is silently absent: an `llm` annotator with a
/// `system_prompt_file` or `system_prompt_url` runs with the default prompt,
/// and a rego policy with a `bundle_url` denies every request with
/// `runtime_error:policy_invocation_failed`. AGT rejects them instead. See
/// `docs/acs-retarget.md`, "Removed manifest fields".
pub const REMOVED_MANIFEST_FIELDS: [&str; 3] =
    ["bundle_url", "system_prompt_file", "system_prompt_url"];

/// Reject a manifest that declares any of [`REMOVED_MANIFEST_FIELDS`].
///
/// Checks every open map a manifest author can reach: each policy definition,
/// each annotator declaration, and each intervention point's policy binding
/// and annotation bindings, since a binding overlays its fields onto the
/// declaration. Cedar policies deny unknown fields upstream and cannot carry
/// them.
pub fn reject_removed_fields(manifest: &Manifest) -> Result<(), RuntimeError> {
    fn check(
        location: impl Fn() -> String,
        keys: impl Iterator<Item = impl AsRef<str>>,
    ) -> Result<(), RuntimeError> {
        for key in keys {
            let key = key.as_ref();
            if REMOVED_MANIFEST_FIELDS.contains(&key) {
                return Err(RuntimeError::ManifestInvalid(format!(
                    "{} declares '{key}', which the pre-retarget engine implemented and                      agent-control-spec {} does not; the field was removed in the retarget                      and is rejected rather than silently ignored. Inline the value or drop                      the field; see policy-engine/docs/acs-retarget.md, 'Removed manifest fields'",
                    location(),
                    agent_control_spec::SUPPORTED_VERSIONS[0]
                )));
            }
        }
        Ok(())
    }

    for (name, policy) in &manifest.policies {
        let adapter_config = match policy {
            PolicyConfig::Rego(config) => &config.adapter_config,
            PolicyConfig::Test(config) => &config.adapter_config,
            PolicyConfig::Custom(config) => &config.adapter_config,
            PolicyConfig::Cedar(_) => continue,
        };
        check(|| format!("policy '{name}'"), adapter_config.keys())?;
    }
    for (name, annotator) in &manifest.annotators {
        check(|| format!("annotator '{name}'"), annotator.fields.keys())?;
    }
    for (point, config) in &manifest.intervention_points {
        check(
            || format!("intervention point '{}' policy binding", point.as_str()),
            config.policy.adapter_config.keys(),
        )?;
        for (name, annotation) in &config.annotations {
            check(
                || {
                    format!(
                        "intervention point '{}' annotation '{name}'",
                        point.as_str()
                    )
                },
                annotation.fields.keys(),
            )?;
        }
    }
    Ok(())
}

/// The overlay-safe subset of manifest validation.
///
/// `agent_control_spec` carries only the strict `Manifest::validate`,
/// which over rejects fragments because it requires at least one
/// intervention point and resolves policy references across the whole
/// document. Deserializing catches structural and grammar errors; this
/// adds back the checks that are meaningful for a fragment and are
/// expressible over the public manifest surface.
pub fn validate_overlay(manifest: &Manifest) -> Result<(), RuntimeError> {
    let version = manifest.agent_control_specification_version.trim();
    if version.is_empty() {
        return Err(RuntimeError::ManifestInvalid(
            "agent_control_specification_version is required".to_string(),
        ));
    }
    if !SUPPORTED_VERSIONS.contains(&version) {
        return Err(RuntimeError::ManifestInvalid(format!(
            "unsupported agent_control_specification_version '{version}'; supported versions are {}",
            SUPPORTED_VERSIONS.join(", ")
        )));
    }
    for extends in &manifest.extends {
        // `ManifestExtends::reference()` is private in agent_control_spec.
        let reference = match extends {
            agent_control_spec::manifest::ManifestExtends::Reference(reference) => {
                reference.as_str()
            }
            agent_control_spec::manifest::ManifestExtends::Url(url) => url.url.as_str(),
        };
        if reference.trim().is_empty() {
            return Err(RuntimeError::ManifestInvalid(
                "extends entries must not be empty".to_string(),
            ));
        }
    }
    for policy_name in manifest.policies.keys() {
        if policy_name.trim().is_empty() {
            return Err(RuntimeError::ManifestInvalid(
                "policy ids must not be empty".to_string(),
            ));
        }
    }
    for annotator_name in manifest.annotators.keys() {
        if annotator_name.trim().is_empty() {
            return Err(RuntimeError::ManifestInvalid(
                "annotator names must not be empty".to_string(),
            ));
        }
    }
    reject_removed_fields(manifest)
}

pub fn parse_manifest_yaml_value(input: &str) -> Result<JsonValue, RuntimeError> {
    let limits = Limits::default();
    if input.len() > limits.max_merged_manifest_bytes {
        return Err(RuntimeError::ResourceLimitExceeded(format!(
            "manifest source size {} exceeds limit {}",
            input.len(),
            limits.max_merged_manifest_bytes
        )));
    }
    if input.trim().is_empty() {
        return Err(RuntimeError::ManifestInvalid(
            "manifest source must not be empty".to_string(),
        ));
    }
    let normalized = normalize_yaml_scalars(
        input,
        limits.max_policy_input_depth,
        MAX_MANIFEST_PARSE_NODES * 3,
    )
    .map_err(RuntimeError::from)?;
    let mut budget = ManifestValueBudget::new(limits);
    // Alias diagnostics can wrap the typed error. Use the structured budget report.
    let parser_limit = std::rc::Rc::new(std::cell::Cell::new(false));
    let reported_limit = std::rc::Rc::clone(&parser_limit);
    let parsed = serde_saphyr::with_deserializer_from_str_with_options(
        &normalized,
        serde_saphyr::options! {
            emit_comments: false,
            strict_booleans: true,
            reject_unsupported_tags: true,
            merge_keys: serde_saphyr::MergeKeyPolicy::AsOrdinary,
            with_snippet: false,
            budget: serde_saphyr::budget! {
                max_depth: limits.max_policy_input_depth,
                max_nodes: MAX_MANIFEST_PARSE_NODES,
                max_events: MAX_MANIFEST_PARSE_NODES * 3,
                max_total_scalar_bytes: limits.max_merged_manifest_bytes,
                max_recorded_anchor_bytes: limits.max_merged_manifest_bytes,
                max_recorded_anchor_events: MAX_MANIFEST_PARSE_NODES,
            },
        }
        .with_budget_report(move |report| {
            reported_limit.set(report.breached.is_some());
        }),
        |document| {
            BoundedJsonValueSeed {
                budget: &mut budget,
                depth: 0,
            }
            .deserialize(document)
        },
    );
    let value = match parsed {
        Ok(value) => value,
        Err(error) => {
            if let Some(detail) = budget.limit_error.take() {
                return Err(RuntimeError::ResourceLimitExceeded(detail));
            }
            if let serde_saphyr::Error::DuplicateMappingKey { key, .. } = &error {
                return Err(RuntimeError::ManifestInvalid(format!(
                    "duplicate manifest mapping key {}: {error}",
                    key.as_deref().unwrap_or("<unknown>")
                )));
            }
            if parser_limit.get()
                || matches!(
                    error,
                    serde_saphyr::Error::Budget { .. }
                        | serde_saphyr::Error::AliasReplayLimitExceeded { .. }
                        | serde_saphyr::Error::AliasExpansionLimitExceeded { .. }
                        | serde_saphyr::Error::AliasReplayStackDepthExceeded { .. }
                )
            {
                return Err(RuntimeError::ResourceLimitExceeded(error.to_string()));
            }
            return Err(RuntimeError::ManifestInvalid(error.to_string()));
        }
    };
    limits.validate_json_depth(&value, "manifest")?;
    let serialized = serde_json::to_vec(&value).map_err(|err| {
        RuntimeError::ManifestInvalid(format!("failed to serialize parsed manifest: {err}"))
    })?;
    if serialized.len() > limits.max_merged_manifest_bytes {
        return Err(RuntimeError::ResourceLimitExceeded(format!(
            "manifest serialized size {} exceeds limit {}",
            serialized.len(),
            limits.max_merged_manifest_bytes
        )));
    }
    Ok(value)
}

/// Failure while normalizing YAML scalar types before bounded deserialization.
#[derive(Debug)]
pub enum YamlScalarError {
    /// A parser error with its original source location.
    Scan(serde_saphyr::granit_parser::ScanError),
    /// A scalar outside the supported JSON-compatible YAML contract.
    Invalid(String),
    /// The event or nesting limit was exceeded.
    ResourceLimit(String),
}

impl YamlScalarError {
    /// One-based line and column when the scanner supplied a location.
    pub fn location(&self) -> Option<(u64, u64)> {
        match self {
            Self::Scan(error) => Some((
                error.marker().line() as u64,
                error.marker().col() as u64 + 1,
            )),
            Self::Invalid(_) | Self::ResourceLimit(_) => None,
        }
    }
}

impl fmt::Display for YamlScalarError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scan(error) => error.fmt(formatter),
            Self::Invalid(detail) | Self::ResourceLimit(detail) => formatter.write_str(detail),
        }
    }
}

impl std::error::Error for YamlScalarError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Scan(error) => Some(error),
            Self::Invalid(_) | Self::ResourceLimit(_) => None,
        }
    }
}

impl From<YamlScalarError> for RuntimeError {
    fn from(error: YamlScalarError) -> Self {
        match error {
            YamlScalarError::ResourceLimit(detail) => Self::ResourceLimitExceeded(detail),
            YamlScalarError::Scan(error)
                if matches!(
                    error.kind(),
                    serde_saphyr::granit_parser::ErrorKind::RecursionLimitExceeded
                ) =>
            {
                Self::ResourceLimitExceeded(error.to_string())
            }
            error => Self::ManifestInvalid(error.to_string()),
        }
    }
}

/// Preserve legacy numeric strings and YAML 1.2 boolean capitalization.
///
/// This shared pre-pass is used by manifest and agentmesh configuration parsing.
/// It preserves token structure and rejects unsupported scalar forms. Callers must
/// bound source bytes first and still deserialize with expanded-node/alias budgets.
pub fn normalize_yaml_scalars(
    input: &str,
    max_depth: usize,
    max_events: usize,
) -> Result<std::borrow::Cow<'_, str>, YamlScalarError> {
    use serde_saphyr::granit_parser::{self, Event, Parser, ScalarStyle};

    let parser = Parser::new_from_str_with_options(
        input,
        granit_parser::options! {
            emit_comments: false,
            flow_nesting_limit: max_depth,
            block_nesting_limit: max_depth,
        },
    );
    let mut output = String::new();
    let mut copied = 0;
    for (events, event) in parser.enumerate() {
        if events >= max_events {
            return Err(YamlScalarError::ResourceLimit(
                "YAML parser event limit exceeded".to_string(),
            ));
        }
        let (event, span) = event.map_err(YamlScalarError::Scan)?;
        let tag = match &event {
            Event::Scalar(_, _, _, tag)
            | Event::MappingStart(_, _, tag)
            | Event::SequenceStart(_, _, tag) => tag.as_ref(),
            _ => None,
        };
        if tag.is_some_and(|tag| tag.handle().is_empty() && tag.suffix() == "!") {
            return Err(YamlScalarError::Invalid(format!(
                "non-specific YAML tags are not supported at line {}, column {}",
                span.start.line(),
                span.start.col() + 1
            )));
        }
        let Event::Scalar(value, style, _, tag) = event else {
            continue;
        };
        let boolean_tag = tag
            .as_ref()
            .is_some_and(|tag| tag.is_yaml_core_schema_tag("bool"));
        let kind = tag.as_ref().and_then(|tag| tag.core_suffix());
        let string_tag = kind == Some("str");
        let integer_tag = kind == Some("int");
        let float_tag = kind == Some("float");
        let null_tag = kind == Some("null");
        let invalid = |message: &str| {
            YamlScalarError::Invalid(format!(
                "{message} at line {}, column {}",
                span.start.line(),
                span.start.col() + 1
            ))
        };
        if tag.is_some() && !boolean_tag && !string_tag && !integer_tag && !float_tag && !null_tag {
            return Err(invalid("unsupported YAML scalar tag"));
        }
        if style != ScalarStyle::Plain && (tag.is_none() || string_tag) {
            continue;
        }
        let boolean = if tag
            .as_ref()
            .is_none_or(|tag| tag.is_yaml_core_schema_tag("bool"))
        {
            match value.as_ref() {
                "true" | "True" | "TRUE" => Some("true"),
                "false" | "False" | "FALSE" => Some("false"),
                _ => None,
            }
        } else {
            None
        };
        if boolean_tag && boolean.is_none() {
            return Err(invalid("invalid YAML boolean"));
        }
        let mut explicit_scalar = None;
        if null_tag {
            if !matches!(value.as_ref(), "" | "~" | "null" | "Null" | "NULL") {
                return Err(invalid("invalid YAML null"));
            }
            explicit_scalar = Some("null".to_string());
        }
        if float_tag {
            let number = value
                .parse::<f64>()
                .map_err(|_| invalid("invalid YAML float"))?;
            if !number.is_finite() {
                return Err(invalid("YAML numbers must be finite"));
            }
            explicit_scalar =
                Some(serde_json::to_string(&number).map_err(|_| invalid("invalid YAML float"))?);
        }
        let mixed_keyword = (boolean.is_none()
            && (value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("false")))
            || (value.eq_ignore_ascii_case("null")
                && !matches!(value.as_ref(), "null" | "Null" | "NULL"));
        let unsigned = value.strip_prefix(['+', '-']).unwrap_or(&value);
        let leading_zero = unsigned.len() > 1
            && unsigned.starts_with('0')
            && unsigned.bytes().all(|byte| byte.is_ascii_digit());
        let (digits, radix) = if let Some(digits) = unsigned.strip_prefix("0x") {
            (digits, 16)
        } else if let Some(digits) = unsigned.strip_prefix("0o") {
            (digits, 8)
        } else if let Some(digits) = unsigned.strip_prefix("0b") {
            (digits, 2)
        } else {
            (unsigned, 10)
        };
        if !string_tag
            && !float_tag
            && !leading_zero
            && !digits.is_empty()
            && digits.chars().all(|ch| ch.is_digit(radix))
        {
            let magnitude = u64::from_str_radix(digits, radix).map_err(|_| {
                YamlScalarError::Invalid(
                    "YAML integer exceeds the supported 64-bit range".to_string(),
                )
            })?;
            if value.starts_with('-') && magnitude > (i64::MAX as u64) + 1 {
                return Err(YamlScalarError::Invalid(
                    "YAML integer exceeds the supported 64-bit range".to_string(),
                ));
            }
            if integer_tag {
                explicit_scalar = Some(if value.starts_with('-') {
                    format!("-{magnitude}")
                } else {
                    magnitude.to_string()
                });
            }
        }
        if integer_tag && explicit_scalar.is_none() {
            return Err(invalid("invalid YAML integer"));
        }
        let separated_number = unsigned.contains('_')
            && unsigned.starts_with(|ch: char| ch.is_ascii_digit() || ch == '.')
            && !unsigned.chars().any(char::is_whitespace);
        let legacy_prefix = [("0X", 16), ("0O", 8), ("0B", 2)]
            .iter()
            .any(|(prefix, radix)| {
                unsigned.strip_prefix(*prefix).is_some_and(|digits| {
                    !digits.is_empty() && digits.chars().all(|ch| ch.is_digit(*radix))
                })
            });
        if !leading_zero
            && !separated_number
            && !legacy_prefix
            && boolean.is_none()
            && !mixed_keyword
            && !string_tag
            && explicit_scalar.is_none()
        {
            continue;
        }
        let range = span.byte_range().ok_or_else(|| {
            YamlScalarError::Invalid("missing YAML scalar source range".to_string())
        })?;
        let block = matches!(style, ScalarStyle::Literal | ScalarStyle::Folded);
        let mut replacement_start = range.start;
        let mut prefix_start = copied;
        if tag.is_some() && !string_tag {
            let start = span
                .tag_start()
                .and_then(|marker| marker.byte_offset())
                .ok_or_else(|| {
                    YamlScalarError::Invalid("missing YAML tag source range".to_string())
                })?;
            let prefix = input.get(copied..start).ok_or_else(|| {
                YamlScalarError::Invalid("invalid YAML tag source range".to_string())
            })?;
            let tag_source = input.get(start..range.start).ok_or_else(|| {
                YamlScalarError::Invalid("invalid YAML tag source range".to_string())
            })?;
            let length = tag_source
                .find(char::is_whitespace)
                .unwrap_or(tag_source.len());
            output.push_str(prefix);
            output.extend(std::iter::repeat_n(' ', length));
            prefix_start = start + length;
        }
        if block {
            let mut cursor = prefix_start;
            loop {
                let remaining = input
                    .get(cursor..range.end)
                    .ok_or_else(|| invalid("invalid YAML block scalar range"))?;
                let ch = remaining
                    .chars()
                    .next()
                    .ok_or_else(|| invalid("missing YAML block scalar header"))?;
                match ch {
                    '|' | '>' => {
                        replacement_start = cursor;
                        break;
                    }
                    '#' => cursor += remaining.find('\n').unwrap_or(remaining.len()),
                    '&' => {
                        cursor += remaining
                            .find(char::is_whitespace)
                            .ok_or_else(|| invalid("invalid YAML block scalar properties"))?
                    }
                    ch if ch.is_whitespace() => cursor += ch.len_utf8(),
                    _ => return Err(invalid("invalid YAML block scalar header")),
                }
            }
        }
        let prefix = input.get(prefix_start..replacement_start).ok_or_else(|| {
            YamlScalarError::Invalid("invalid YAML scalar source range".to_string())
        })?;
        output.push_str(prefix);
        if string_tag && range.is_empty() {
            output.push(' ');
        }
        if let Some(explicit_scalar) = explicit_scalar {
            output.push_str(&explicit_scalar);
        } else if let Some(boolean) = boolean {
            output.push_str(boolean);
        } else {
            output.push_str(
                &serde_json::to_string(if string_tag && range.is_empty() {
                    ""
                } else {
                    value.as_ref()
                })
                .map_err(|error| YamlScalarError::Invalid(error.to_string()))?,
            );
        }
        if block {
            // Block spans consume separators before the next node; retain their layout.
            let replaced = input
                .get(replacement_start..range.end)
                .ok_or_else(|| invalid("invalid YAML block scalar range"))?;
            let tail = &replaced[replaced.trim_end_matches(char::is_whitespace).len()..];
            let removed_lines = replaced.bytes().filter(|byte| *byte == b'\n').count();
            let tail_lines = tail.bytes().filter(|byte| *byte == b'\n').count();
            output.extend(std::iter::repeat_n(
                '\n',
                removed_lines.saturating_sub(tail_lines),
            ));
            output.push_str(tail);
        }
        copied = range.end;
    }
    if copied == 0 {
        Ok(std::borrow::Cow::Borrowed(input))
    } else {
        output.push_str(&input[copied..]);
        Ok(std::borrow::Cow::Owned(output))
    }
}

/// Full manifest validation. Delegates to the `agent_control_spec` strict
/// validator once the bounded parser has accepted the source.
pub fn validate_manifest_yaml(input: &str) -> Result<(), RuntimeError> {
    let value = parse_manifest_yaml_value(input)?;
    let manifest: Manifest = serde_json::from_value(value)
        .map_err(|err| RuntimeError::ManifestInvalid(err.to_string()))?;
    reject_removed_fields(&manifest)?;
    manifest.validate()
}

/// Overlay validation for manifest fragments.
///
/// AGT's embedded engine had `Manifest::validate_overlay`, a relaxed check
/// for fragments that only become whole after `extends` resolution.
/// `agent_control_spec` 0.4.0-alpha.3 still exposes only the strict
/// `Manifest::validate`, which over rejects fragments because it requires
/// at least one intervention point and resolves policy references. Until
/// ACS grows an overlay entry point this deserializes the fragment, which
/// catches every structural and grammar error, and defers whole manifest
/// coherence to the post `extends` `validate` call the loader performs.
pub fn validate_manifest_overlay_yaml(input: &str) -> Result<(), RuntimeError> {
    let value = parse_manifest_yaml_value(input)?;
    let manifest: Manifest = serde_json::from_value(value)
        .map_err(|err| RuntimeError::ManifestInvalid(err.to_string()))?;
    validate_overlay(&manifest)
}

struct ManifestValueBudget {
    limits: Limits,
    nodes: usize,
    bytes: usize,
    limit_error: Option<String>,
}

impl ManifestValueBudget {
    fn new(limits: Limits) -> Self {
        Self {
            limits,
            nodes: 0,
            bytes: 0,
            limit_error: None,
        }
    }

    fn enter<E: DeError>(&mut self, depth: usize, bytes: usize) -> Result<(), E> {
        if depth > self.limits.max_policy_input_depth {
            let detail = format!(
                "manifest JSON nesting depth exceeds limit {}",
                self.limits.max_policy_input_depth
            );
            self.limit_error = Some(detail.clone());
            return Err(E::custom(detail));
        }
        self.nodes += 1;
        if self.nodes > MAX_MANIFEST_PARSE_NODES {
            let detail =
                format!("manifest expanded node count exceeds limit {MAX_MANIFEST_PARSE_NODES}");
            self.limit_error = Some(detail.clone());
            return Err(E::custom(detail));
        }
        self.add_bytes(bytes)
    }

    fn add_bytes<E: DeError>(&mut self, bytes: usize) -> Result<(), E> {
        self.bytes = self.bytes.saturating_add(bytes);
        if self.bytes > self.limits.max_merged_manifest_bytes {
            let detail = format!(
                "manifest expanded size exceeds limit {}",
                self.limits.max_merged_manifest_bytes
            );
            self.limit_error = Some(detail.clone());
            return Err(E::custom(detail));
        }
        Ok(())
    }
}

struct BoundedJsonValueSeed<'a> {
    budget: &'a mut ManifestValueBudget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for BoundedJsonValueSeed<'_> {
    type Value = JsonValue;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(BoundedJsonValueVisitor {
            budget: self.budget,
            depth: self.depth,
        })
    }
}

struct BoundedJsonValueVisitor<'a> {
    budget: &'a mut ManifestValueBudget,
    depth: usize,
}

impl<'de> Visitor<'de> for BoundedJsonValueVisitor<'_> {
    type Value = JsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON-compatible YAML value")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.budget.enter(self.depth, 4)?;
        Ok(JsonValue::Null)
    }

    fn visit_none<E>(self) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_unit()
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.budget.enter(self.depth, if value { 4 } else { 5 })?;
        Ok(JsonValue::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.budget.enter(self.depth, 20)?;
        Ok(JsonValue::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.budget.enter(self.depth, 20)?;
        Ok(JsonValue::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.budget.enter(self.depth, 24)?;
        serde_json::Number::from_f64(value)
            .map(JsonValue::Number)
            .ok_or_else(|| E::custom("manifest numbers must be finite"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.budget.enter(self.depth, json_string_size(value))?;
        Ok(JsonValue::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.budget.enter(self.depth, json_string_size(&value))?;
        Ok(JsonValue::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        self.budget.enter(self.depth, 2)?;
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(1024));
        while let Some(value) = sequence.next_element_seed(BoundedJsonValueSeed {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            if !values.is_empty() {
                self.budget.add_bytes(1)?;
            }
            values.push(value);
        }
        Ok(JsonValue::Array(values))
    }

    fn visit_map<A>(self, mut mapping: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        self.budget.enter(self.depth, 2)?;
        let mut values = Map::new();
        while let Some(key) = mapping.next_key_seed(JsonMapKeySeed)? {
            if values.contains_key(&key) {
                return Err(A::Error::custom(format!(
                    "duplicate manifest mapping key {key:?}"
                )));
            }
            if !values.is_empty() {
                self.budget.add_bytes(1)?;
            }
            self.budget.add_bytes(json_string_size(&key) + 1)?;
            let value = mapping.next_value_seed(BoundedJsonValueSeed {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(JsonValue::Object(values))
    }
}

struct JsonMapKeySeed;

impl<'de> DeserializeSeed<'de> for JsonMapKeySeed {
    type Value = String;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(JsonMapKeyVisitor)
    }
}

struct JsonMapKeyVisitor;

impl Visitor<'_> for JsonMapKeyVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a string manifest mapping key")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(value.to_string())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        Ok(value)
    }
}

fn json_string_size(value: &str) -> usize {
    serde_json::to_string(value)
        .map(|serialized| serialized.len())
        .unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::{
        reject_removed_fields, validate_manifest_overlay_yaml, validate_manifest_yaml,
        REMOVED_MANIFEST_FIELDS,
    };
    use agent_control_spec::Manifest;

    #[test]
    fn scalar_normalization_preserves_tagged_and_mixed_case_values() {
        let input = "values: [True, tRuE, !!bool TRUE, !!str TRUE]";
        let normalized = super::normalize_yaml_scalars(input, 64, 300_000).unwrap();
        assert_eq!(
            normalized,
            "values: [true, \"tRuE\",        true, !!str \"TRUE\"]"
        );
    }

    const VERSION: &str = "agent_control_specification_version: 0.4.0-alpha.1\n";

    fn llm_manifest(annotator_fields: &str) -> String {
        format!(
            "{VERSION}policies:\n  p:\n    type: test\nannotators:\n  judge:\n    type: llm\n\
             {annotator_fields}intervention_points:\n  input:\n    policy_target: $snap.input\n\
             \x20   policy:\n      id: p\n    annotations:\n      judge:\n        from: $target\n"
        )
    }

    fn rego_manifest(policy_fields: &str) -> String {
        format!(
            "{VERSION}policies:\n  p:\n    type: rego\n    query: data.acs.result\n\
             {policy_fields}intervention_points:\n  input:\n    policy_target: $snap.input\n\
             \x20   policy:\n      id: p\n"
        )
    }

    /// The six manifests the review probe showed `Manifest::from_yaml_str`
    /// accepting while the pinned engine had no implementation behind them.
    fn probe_manifests() -> Vec<(&'static str, String, &'static str)> {
        vec![
            (
                "llm annotator with a missing system_prompt_file",
                llm_manifest("    system_prompt_file: prompts/does-not-exist.txt\n"),
                "system_prompt_file",
            ),
            (
                "llm annotator with an inline prompt and an unpinned http system_prompt_url",
                llm_manifest(
                    "    system_prompt: inline\n    system_prompt_url:\n      url: http://prompts.example/p.txt\n",
                ),
                "system_prompt_url",
            ),
            (
                "llm annotator with a pinned https system_prompt_url",
                llm_manifest(&format!(
                    "    system_prompt_url:\n      url: https://prompts.example/p.txt\n      sha256: {}\n",
                    "a".repeat(64)
                )),
                "system_prompt_url",
            ),
            (
                "rego policy with a pinned https bundle_url",
                rego_manifest(&format!(
                    "    bundle_url:\n      url: https://bundles.example/b.tar.gz\n      sha256: {}\n",
                    "b".repeat(64)
                )),
                "bundle_url",
            ),
            (
                "rego policy with an unpinned http bundle_url",
                rego_manifest("    bundle_url:\n      url: http://bundles.example/b.tar.gz\n"),
                "bundle_url",
            ),
            (
                "rego policy with bundle and bundle_url together",
                rego_manifest(&format!(
                    "    bundle: ./policy\n    bundle_url:\n      url: https://bundles.example/b.tar.gz\n      sha256: {}\n",
                    "c".repeat(64)
                )),
                "bundle_url",
            ),
        ]
    }

    #[test]
    fn upstream_parser_retains_removed_fields_for_agt_validation() {
        // Parsing must retain these keys for AGT's rejection, even when newer
        // upstream semantic validation also rejects an invalid URL combination.
        for (label, manifest, field) in probe_manifests() {
            let parsed = Manifest::parse_yaml_str(&manifest)
                .unwrap_or_else(|error| panic!("{label}: upstream parse failed: {error}"));
            let error = reject_removed_fields(&parsed).expect_err("AGT rejects removed fields");
            assert!(error.detail().contains(field), "{label}: {error}");
        }
    }

    #[test]
    fn removed_fields_are_rejected_by_every_validation_entry_point() {
        for (label, manifest, field) in probe_manifests() {
            for (entry, result) in [
                ("validate_manifest_yaml", validate_manifest_yaml(&manifest)),
                (
                    "validate_manifest_overlay_yaml",
                    validate_manifest_overlay_yaml(&manifest),
                ),
                (
                    "reject_removed_fields",
                    reject_removed_fields(&Manifest::parse_yaml_str(&manifest).unwrap()),
                ),
            ] {
                let error = match result {
                    Ok(()) => panic!("{label}: {entry} accepted"),
                    Err(error) => error,
                };
                assert_eq!(
                    error.reason(),
                    "runtime_error:manifest_invalid",
                    "{label}: {entry}"
                );
                let detail = error.detail();
                assert!(
                    detail.contains(&format!("'{field}'")),
                    "{label}: {entry}: {detail}"
                );
                assert!(
                    detail.contains("docs/acs-retarget.md"),
                    "{label}: {entry}: {detail}"
                );
            }
        }
    }

    #[test]
    fn removed_fields_are_rejected_on_bindings_too() {
        // A binding overlays its fields onto the declaration, so the same
        // keys are reachable there.
        let annotation_binding = format!(
            "{VERSION}policies:\n  p:\n    type: test\nannotators:\n  judge:\n    type: llm\n\
             intervention_points:\n  input:\n    policy_target: $snap.input\n    policy:\n      id: p\n\
             \x20   annotations:\n      judge:\n        from: $target\n        system_prompt_file: x.txt\n"
        );
        let error = validate_manifest_yaml(&annotation_binding).unwrap_err();
        assert!(
            error.detail().starts_with(
                "intervention point 'input' annotation 'judge' declares 'system_prompt_file'"
            ),
            "{}",
            error.detail()
        );

        let policy_binding = format!(
            "{VERSION}policies:\n  p:\n    type: rego\n    query: data.acs.result\n\
             intervention_points:\n  input:\n    policy_target: $snap.input\n    policy:\n      id: p\n\
             \x20     bundle_url:\n        url: https://bundles.example/b.tar.gz\n        sha256: {}\n",
            "d".repeat(64)
        );
        let error = validate_manifest_yaml(&policy_binding).unwrap_err();
        assert!(
            error
                .detail()
                .starts_with("intervention point 'input' policy binding declares 'bundle_url'"),
            "{}",
            error.detail()
        );

        let custom_policy = format!(
            "{VERSION}policies:\n  p:\n    type: custom\n    adapter: mine\n    bundle_url: x\n\
             intervention_points:\n  input:\n    policy_target: $snap.input\n    policy:\n      id: p\n"
        );
        let error = validate_manifest_overlay_yaml(&custom_policy).unwrap_err();
        assert!(
            error
                .detail()
                .starts_with("policy 'p' declares 'bundle_url'"),
            "{}",
            error.detail()
        );
    }

    #[test]
    fn manifests_without_removed_fields_still_pass() {
        let inline_prompt = llm_manifest("    system_prompt: You are a judge.\n");
        validate_manifest_yaml(&inline_prompt).unwrap();
        validate_manifest_overlay_yaml(&inline_prompt).unwrap();
        let local_bundle = rego_manifest("    bundle: ./policy\n");
        validate_manifest_yaml(&local_bundle).unwrap();
        validate_manifest_overlay_yaml(&local_bundle).unwrap();
        assert_eq!(REMOVED_MANIFEST_FIELDS.len(), 3);
    }
}
