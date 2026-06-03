// AGT D1: the effects pipeline is sunset by `SPECIFICATION.md` §14.
// The module remains crate-private to keep the parsing and application
// helpers available for internal callers during the M2 transition; nothing
// in this module is part of the public surface. Dead-code warnings are
// suppressed because the runtime now drives transformations through the
// `Decision::Transform` path in `runtime::apply_transform`.
#![allow(dead_code)]

use crate::{paths::PathRoot, JsonPath, JsonValue, RuntimeError};
use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectType {
    Replace,
    Append,
    Prepend,
    Redact,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Effect {
    #[serde(rename = "type")]
    pub effect_type: EffectType,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<JsonValue>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spans: Vec<RedactionSpan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replacement: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RedactionSpan {
    pub start: usize,
    pub end: usize,
    pub replacement: String,
}

impl Effect {
    pub fn from_value(value: &JsonValue) -> Result<Self, RuntimeError> {
        let object = value
            .as_object()
            .ok_or_else(|| RuntimeError::EffectInvalid("effect must be an object".to_string()))?;
        let effect_type = object
            .get("type")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| RuntimeError::EffectInvalid("effect.type is required".to_string()))?;
        let path = object
            .get("path")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| RuntimeError::EffectInvalid("effect.path is required".to_string()))?;
        let parsed = JsonPath::parse_with_snapshot_alias(path)
            .map_err(|err| RuntimeError::EffectInvalid(format!("invalid effect path: {err}")))?;
        if parsed.root() != PathRoot::PolicyTarget {
            return Err(RuntimeError::EffectTargetForbidden(path.to_string()));
        }

        match effect_type {
            "replace" => Ok(Self {
                effect_type: EffectType::Replace,
                path: path.to_string(),
                value: Some(required_value(object, "replace")?),
                spans: Vec::new(),
                pattern: None,
                values: None,
                replacement: None,
            }),
            "append" => Ok(Self {
                effect_type: EffectType::Append,
                path: path.to_string(),
                value: Some(required_value(object, "append")?),
                spans: Vec::new(),
                pattern: None,
                values: None,
                replacement: None,
            }),
            "prepend" => Ok(Self {
                effect_type: EffectType::Prepend,
                path: path.to_string(),
                value: Some(required_value(object, "prepend")?),
                spans: Vec::new(),
                pattern: None,
                values: None,
                replacement: None,
            }),
            "redact" => {
                let redact = parse_redact(object)?;
                Ok(Self {
                    effect_type: EffectType::Redact,
                    path: path.to_string(),
                    value: None,
                    spans: redact.spans,
                    pattern: redact.pattern,
                    values: redact.values,
                    replacement: redact.replacement,
                })
            }
            other => Err(RuntimeError::EffectInvalid(format!(
                "unsupported effect type '{other}'"
            ))),
        }
    }
}

pub fn validate_and_maybe_apply_effects(
    policy_target: &JsonValue,
    effects: &[Effect],
    should_apply: bool,
) -> Result<Option<JsonValue>, RuntimeError> {
    if effects.is_empty() {
        return Ok(None);
    }

    let mut working = policy_target.clone();
    for effect in effects {
        apply_effect(&mut working, effect)?;
    }

    if should_apply {
        Ok(Some(working))
    } else {
        Ok(None)
    }
}

fn apply_effect(policy_target: &mut JsonValue, effect: &Effect) -> Result<(), RuntimeError> {
    let path = JsonPath::parse_with_snapshot_alias(&effect.path)
        .map_err(|err| RuntimeError::EffectInvalid(format!("invalid effect path: {err}")))?;
    if path.root() != PathRoot::PolicyTarget {
        return Err(RuntimeError::EffectTargetForbidden(effect.path.clone()));
    }
    let target = path
        .resolve_policy_target_mut(policy_target)
        .map_err(|err| match err {
            RuntimeError::EffectTargetForbidden(_) => err,
            _ => RuntimeError::EffectInvalid(err.to_string()),
        })?;

    match effect.effect_type {
        EffectType::Replace => {
            *target = effect.value.clone().unwrap_or(JsonValue::Null);
            Ok(())
        }
        EffectType::Append => append_or_prepend(target, effect.value.as_ref(), false),
        EffectType::Prepend => append_or_prepend(target, effect.value.as_ref(), true),
        EffectType::Redact => match target {
            JsonValue::String(value) => {
                let spans = redact_spans_for_value(value, effect)?;
                *value = apply_redactions(value, &spans)?;
                Ok(())
            }
            _ => Err(RuntimeError::EffectInvalid(format!(
                "redact target '{}' must be a string",
                effect.path
            ))),
        },
    }
}

fn append_or_prepend(
    target: &mut JsonValue,
    value: Option<&JsonValue>,
    prepend: bool,
) -> Result<(), RuntimeError> {
    let value =
        value.ok_or_else(|| RuntimeError::EffectInvalid("effect value missing".to_string()))?;
    match target {
        JsonValue::String(target_string) => {
            let value_string = value.as_str().ok_or_else(|| {
                RuntimeError::EffectInvalid(
                    "string append/prepend requires a string value".to_string(),
                )
            })?;
            if prepend {
                let mut next = value_string.to_string();
                next.push_str(target_string);
                *target_string = next;
            } else {
                target_string.push_str(value_string);
            }
            Ok(())
        }
        JsonValue::Array(items) => {
            if prepend {
                items.insert(0, value.clone());
            } else {
                items.push(value.clone());
            }
            Ok(())
        }
        _ => Err(RuntimeError::EffectInvalid(
            "append/prepend target must be a string or array".to_string(),
        )),
    }
}

fn apply_redactions(input: &str, spans: &[RedactionSpan]) -> Result<String, RuntimeError> {
    let chars: Vec<char> = input.chars().collect();
    let mut output = String::new();
    let mut last_end = 0usize;

    for span in spans {
        if span.start > span.end || span.end > chars.len() || span.start < last_end {
            return Err(RuntimeError::EffectInvalid(
                "redaction spans must be ordered, non-overlapping, and within bounds".to_string(),
            ));
        }
        for ch in &chars[last_end..span.start] {
            output.push(*ch);
        }
        output.push_str(&span.replacement);
        last_end = span.end;
    }

    for ch in &chars[last_end..] {
        output.push(*ch);
    }
    Ok(output)
}

fn required_value(
    object: &serde_json::Map<String, JsonValue>,
    effect_type: &str,
) -> Result<JsonValue, RuntimeError> {
    object
        .get("value")
        .cloned()
        .ok_or_else(|| RuntimeError::EffectInvalid(format!("{effect_type} effect requires value")))
}

const DEFAULT_REDACTION_REPLACEMENT: &str = "[REDACTED]";

struct ParsedRedact {
    spans: Vec<RedactionSpan>,
    pattern: Option<String>,
    values: Option<Vec<String>>,
    replacement: Option<String>,
}

fn parse_redact(object: &serde_json::Map<String, JsonValue>) -> Result<ParsedRedact, RuntimeError> {
    let form_count = ["pattern", "values", "spans"]
        .iter()
        .filter(|field| object.contains_key(**field))
        .count();
    if form_count != 1 {
        return Err(RuntimeError::EffectInvalid(
            "redact effect requires exactly one of pattern, values, or spans".to_string(),
        ));
    }

    let replacement = parse_replacement(object.get("replacement"))?;
    let pattern = match object.get("pattern") {
        Some(value) => {
            let pattern = value.as_str().ok_or_else(|| {
                RuntimeError::EffectInvalid("redact pattern must be a string".to_string())
            })?;
            Regex::new(pattern).map_err(|err| {
                RuntimeError::EffectInvalid(format!("invalid redact pattern: {err}"))
            })?;
            Some(pattern.to_string())
        }
        None => None,
    };
    let values = match object.get("values") {
        Some(value) => Some(parse_values(value)?),
        None => None,
    };
    let spans = match object.get("spans") {
        Some(value) => parse_spans(value)?,
        None => Vec::new(),
    };

    Ok(ParsedRedact {
        spans,
        pattern,
        values,
        replacement,
    })
}

fn parse_replacement(value: Option<&JsonValue>) -> Result<Option<String>, RuntimeError> {
    match value {
        None | Some(JsonValue::Null) => Ok(None),
        Some(JsonValue::String(replacement)) => Ok(Some(replacement.clone())),
        Some(_) => Err(RuntimeError::EffectInvalid(
            "redact replacement must be a string".to_string(),
        )),
    }
}

fn parse_values(value: &JsonValue) -> Result<Vec<String>, RuntimeError> {
    let values = value
        .as_array()
        .ok_or_else(|| RuntimeError::EffectInvalid("redact values must be an array".to_string()))?;
    values
        .iter()
        .map(|value| {
            value.as_str().map(str::to_string).ok_or_else(|| {
                RuntimeError::EffectInvalid("redact values must be strings".to_string())
            })
        })
        .collect()
}

fn parse_spans(value: &JsonValue) -> Result<Vec<RedactionSpan>, RuntimeError> {
    let spans = value
        .as_array()
        .ok_or_else(|| RuntimeError::EffectInvalid("redact spans must be an array".to_string()))?;
    spans
        .iter()
        .map(|span| {
            let object = span.as_object().ok_or_else(|| {
                RuntimeError::EffectInvalid("redaction span must be an object".to_string())
            })?;
            let start = object
                .get("start")
                .and_then(JsonValue::as_u64)
                .ok_or_else(|| RuntimeError::EffectInvalid("span.start is required".to_string()))?
                as usize;
            let end = object
                .get("end")
                .and_then(JsonValue::as_u64)
                .ok_or_else(|| RuntimeError::EffectInvalid("span.end is required".to_string()))?
                as usize;
            let replacement = object
                .get("replacement")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| {
                    RuntimeError::EffectInvalid("span.replacement is required".to_string())
                })?
                .to_string();
            Ok(RedactionSpan {
                start,
                end,
                replacement,
            })
        })
        .collect()
}

fn redact_spans_for_value(
    input: &str,
    effect: &Effect,
) -> Result<Vec<RedactionSpan>, RuntimeError> {
    let replacement = effect
        .replacement
        .as_deref()
        .unwrap_or(DEFAULT_REDACTION_REPLACEMENT);
    if let Some(pattern) = effect.pattern.as_deref() {
        let regex = Regex::new(pattern)
            .map_err(|err| RuntimeError::EffectInvalid(format!("invalid redact pattern: {err}")))?;
        return Ok(merge_byte_matches(
            input,
            regex_byte_matches(input, &regex),
            replacement,
        ));
    }
    if let Some(values) = effect.values.as_ref() {
        let matches = values
            .iter()
            .flat_map(|value| literal_byte_matches(input, value));
        return Ok(merge_byte_matches(input, matches, replacement));
    }
    Ok(effect.spans.clone())
}

fn regex_byte_matches(input: &str, regex: &Regex) -> Vec<(usize, usize)> {
    input
        .char_indices()
        .map(|(index, _)| index)
        .chain(std::iter::once(input.len()))
        .filter_map(|start| {
            let match_ = regex.find_at(input, start)?;
            (match_.start() == start && match_.start() != match_.end())
                .then_some((match_.start(), match_.end()))
        })
        .collect()
}

fn literal_byte_matches(input: &str, value: &str) -> Vec<(usize, usize)> {
    if value.is_empty() {
        return Vec::new();
    }

    let mut matches = Vec::new();
    let mut search_start = 0usize;
    while search_start <= input.len() {
        let Some(relative_start) = input[search_start..].find(value) else {
            break;
        };
        let start = search_start + relative_start;
        let end = start + value.len();
        matches.push((start, end));
        search_start = start
            + input[start..]
                .chars()
                .next()
                .map(char::len_utf8)
                .unwrap_or(1);
    }
    matches
}

fn merge_byte_matches(
    input: &str,
    matches: impl IntoIterator<Item = (usize, usize)>,
    replacement: &str,
) -> Vec<RedactionSpan> {
    let mut spans: Vec<RedactionSpan> = matches
        .into_iter()
        .filter(|(start, end)| start < end)
        .map(|(start, end)| RedactionSpan {
            start: byte_to_char_offset(input, start),
            end: byte_to_char_offset(input, end),
            replacement: replacement.to_string(),
        })
        .collect();
    spans.sort_by_key(|span| (span.start, span.end));

    let mut merged: Vec<RedactionSpan> = Vec::new();
    for span in spans {
        if let Some(last) = merged.last_mut() {
            if span.start <= last.end {
                last.end = last.end.max(span.end);
                continue;
            }
        }
        merged.push(span);
    }
    merged
}

fn byte_to_char_offset(input: &str, byte_offset: usize) -> usize {
    input[..byte_offset].chars().count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn effect(value: JsonValue) -> Effect {
        Effect::from_value(&value).expect("valid effect")
    }

    fn apply(target: JsonValue, effects: &[Effect]) -> Result<JsonValue, RuntimeError> {
        validate_and_maybe_apply_effects(&target, effects, true).map(|out| out.unwrap_or(target))
    }

    #[test]
    fn redaction_uses_character_offsets_not_bytes() {
        // The leading emoji is one `char` but four UTF-8 bytes; a byte-based
        // implementation would corrupt the string. Per spec spans are characters.
        let target = json!("\u{1f525}SECRET tail");
        let redact = effect(json!({
            "type": "redact",
            "path": "$policy_target",
            "spans": [{"start": 1, "end": 7, "replacement": "[X]"}],
        }));
        let out = apply(target, &[redact]).expect("redaction applies");
        assert_eq!(out, json!("\u{1f525}[X] tail"));
    }

    #[test]
    fn redaction_rejects_out_of_order_spans() {
        let target = json!("abcdef");
        let redact = effect(json!({
            "type": "redact",
            "path": "$policy_target",
            "spans": [
                {"start": 3, "end": 4, "replacement": "_"},
                {"start": 0, "end": 1, "replacement": "_"},
            ],
        }));
        let err = apply(target, &[redact]).expect_err("out-of-order fails closed");
        assert_eq!(err.reason(), "runtime_error:effect_invalid");
    }

    #[test]
    fn redaction_rejects_overlapping_spans() {
        let target = json!("abcdef");
        let redact = effect(json!({
            "type": "redact",
            "path": "$policy_target",
            "spans": [
                {"start": 0, "end": 3, "replacement": "_"},
                {"start": 2, "end": 4, "replacement": "_"},
            ],
        }));
        let err = apply(target, &[redact]).expect_err("overlap fails closed");
        assert_eq!(err.reason(), "runtime_error:effect_invalid");
    }

    #[test]
    fn redaction_rejects_span_out_of_bounds() {
        let target = json!("abc");
        let redact = effect(json!({
            "type": "redact",
            "path": "$policy_target",
            "spans": [{"start": 1, "end": 9, "replacement": "_"}],
        }));
        let err = apply(target, &[redact]).expect_err("out-of-bounds fails closed");
        assert_eq!(err.reason(), "runtime_error:effect_invalid");
    }

    #[test]
    fn redaction_allows_empty_span_as_insertion() {
        let target = json!("abc");
        let redact = effect(json!({
            "type": "redact",
            "path": "$policy_target",
            "spans": [{"start": 1, "end": 1, "replacement": "X"}],
        }));
        let out = apply(target, &[redact]).expect("insertion applies");
        assert_eq!(out, json!("aXbc"));
    }

    #[test]
    fn redact_non_string_target_fails_closed() {
        let target = json!({"value": 42});
        let redact = effect(json!({
            "type": "redact",
            "path": "$policy_target.value",
            "spans": [{"start": 0, "end": 1, "replacement": "_"}],
        }));
        let err = apply(target, &[redact]).expect_err("non-string redact fails closed");
        assert_eq!(err.reason(), "runtime_error:effect_invalid");
    }

    #[test]
    fn redaction_pattern_single_match_uses_default_replacement() {
        let target = json!("Contact jane@example.com today");
        let redact = effect(json!({
            "type": "redact",
            "path": "$policy_target",
            "pattern": "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}",
        }));
        let out = apply(target, &[redact]).expect("pattern redaction applies");
        assert_eq!(out, json!("Contact [REDACTED] today"));
    }

    #[test]
    fn redaction_pattern_multiple_matches_use_custom_replacement() {
        let target = json!("ids 123 and 4567");
        let redact = effect(json!({
            "type": "redact",
            "path": "$policy_target",
            "pattern": "\\d+",
            "replacement": "#",
        }));
        let out = apply(target, &[redact]).expect("pattern redaction applies");
        assert_eq!(out, json!("ids # and #"));
    }

    #[test]
    fn redaction_pattern_adjacent_matches_are_merged() {
        let target = json!("abc");
        let redact = effect(json!({
            "type": "redact",
            "path": "$policy_target",
            "pattern": "[ab]",
            "replacement": "X",
        }));
        let out = apply(target, &[redact]).expect("adjacent pattern matches merge");
        assert_eq!(out, json!("Xc"));
    }

    #[test]
    fn redaction_pattern_overlapping_matches_are_merged() {
        let target = json!("ababa end");
        let redact = effect(json!({
            "type": "redact",
            "path": "$policy_target",
            "pattern": "aba|bab",
            "replacement": "X",
        }));
        let out = apply(target, &[redact]).expect("overlapping pattern matches merge");
        assert_eq!(out, json!("X end"));
    }

    #[test]
    fn redaction_pattern_uses_character_offsets_for_unicode() {
        let target = json!("🔥 secret café tail");
        let redact = effect(json!({
            "type": "redact",
            "path": "$policy_target",
            "pattern": "café",
            "replacement": "[x]",
        }));
        let out = apply(target, &[redact]).expect("unicode pattern redaction applies");
        assert_eq!(out, json!("🔥 secret [x] tail"));
    }

    #[test]
    fn redaction_pattern_no_match_leaves_target_unchanged() {
        let target = json!("public text");
        let redact = effect(json!({
            "type": "redact",
            "path": "$policy_target",
            "pattern": "secret",
        }));
        let out = apply(target.clone(), &[redact]).expect("no-match redaction applies");
        assert_eq!(out, target);
    }

    #[test]
    fn redaction_values_single_match() {
        let target = json!("token abc123 ok");
        let redact = effect(json!({
            "type": "redact",
            "path": "$policy_target",
            "values": ["abc123"],
            "replacement": "[token]",
        }));
        let out = apply(target, &[redact]).expect("values redaction applies");
        assert_eq!(out, json!("token [token] ok"));
    }

    #[test]
    fn redaction_values_multiple_and_overlapping_matches_are_merged() {
        let target = json!("ababa end");
        let redact = effect(json!({
            "type": "redact",
            "path": "$policy_target",
            "values": ["aba", "bab"],
            "replacement": "X",
        }));
        let out = apply(target, &[redact]).expect("overlapping values merge");
        assert_eq!(out, json!("X end"));
    }

    #[test]
    fn redaction_values_repeated_matches() {
        let target = json!("one two one");
        let redact = effect(json!({
            "type": "redact",
            "path": "$policy_target",
            "values": ["one"],
            "replacement": "1",
        }));
        let out = apply(target, &[redact]).expect("repeated values redact");
        assert_eq!(out, json!("1 two 1"));
    }

    #[test]
    fn redaction_values_no_match_leaves_target_unchanged() {
        let target = json!("clear");
        let redact = effect(json!({
            "type": "redact",
            "path": "$policy_target",
            "values": ["secret"],
        }));
        let out = apply(target.clone(), &[redact]).expect("no-match values apply");
        assert_eq!(out, target);
    }

    #[test]
    fn redaction_values_skip_empty_values() {
        let target = json!("abc");
        let redact = effect(json!({
            "type": "redact",
            "path": "$policy_target",
            "values": [""],
        }));
        let out = apply(target.clone(), &[redact]).expect("empty values do not loop");
        assert_eq!(out, target);
    }

    #[test]
    fn redaction_requires_exactly_one_form() {
        let zero = Effect::from_value(&json!({
            "type": "redact",
            "path": "$policy_target",
        }))
        .expect_err("missing redaction form fails");
        assert_eq!(zero.reason(), "runtime_error:effect_invalid");
        assert_eq!(
            zero.detail(),
            "redact effect requires exactly one of pattern, values, or spans"
        );

        let multiple = Effect::from_value(&json!({
            "type": "redact",
            "path": "$policy_target",
            "pattern": "secret",
            "values": ["secret"],
        }))
        .expect_err("multiple redaction forms fail");
        assert_eq!(multiple.reason(), "runtime_error:effect_invalid");
        assert_eq!(
            multiple.detail(),
            "redact effect requires exactly one of pattern, values, or spans"
        );
    }

    #[test]
    fn redaction_rejects_bad_regex() {
        let err = Effect::from_value(&json!({
            "type": "redact",
            "path": "$policy_target",
            "pattern": "(",
        }))
        .expect_err("bad regex fails closed");
        assert_eq!(err.reason(), "runtime_error:effect_invalid");
        assert!(err.detail().starts_with("invalid redact pattern:"));
    }

    #[test]
    fn redaction_pattern_skips_zero_width_matches() {
        let target = json!("abc");
        let redact = effect(json!({
            "type": "redact",
            "path": "$policy_target",
            "pattern": "\\b",
            "replacement": "X",
        }));
        let out = apply(target.clone(), &[redact]).expect("zero-width matches do not loop");
        assert_eq!(out, target);
    }

    #[test]
    fn append_and_prepend_on_string_and_array() {
        let appended = apply(
            json!("base"),
            &[effect(
                json!({"type": "append", "path": "$policy_target", "value": "-tail"}),
            )],
        )
        .expect("append applies");
        assert_eq!(appended, json!("base-tail"));

        let prepended = apply(
            json!(["b", "c"]),
            &[effect(
                json!({"type": "prepend", "path": "$policy_target", "value": "a"}),
            )],
        )
        .expect("prepend applies");
        assert_eq!(prepended, json!(["a", "b", "c"]));
    }

    #[test]
    fn effect_targeting_non_policy_target_is_forbidden() {
        let err = Effect::from_value(&json!({
            "type": "replace",
            "path": "$snap.text",
            "value": "x",
        }))
        .expect_err("effects may only target the policy target");
        assert_eq!(err.reason(), "runtime_error:effect_target_forbidden");
    }

    #[test]
    fn multiple_effects_apply_in_order() {
        let out = apply(
            json!("secret"),
            &[
                effect(json!({
                    "type": "redact",
                    "path": "$policy_target",
                    "spans": [{"start": 0, "end": 6, "replacement": "[R]"}],
                })),
                effect(json!({"type": "append", "path": "$policy_target", "value": "!"})),
            ],
        )
        .expect("chain applies");
        assert_eq!(out, json!("[R]!"));
    }
}
