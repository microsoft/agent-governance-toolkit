// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Parser-independent policy values. YAML policies use the JSON data model:
//! string mapping keys, finite numbers, booleans, null, arrays and objects.

pub use serde_json::Value;
/// A nested policy mapping.
pub type Mapping = serde_json::Map<String, Value>;
/// Context supplied to policy evaluation and protocol extractors.
pub type Context = std::collections::HashMap<String, Value>;

/// A YAML configuration error, including a source location when available.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct YamlError(#[source] YamlErrorSource);

#[derive(Debug, thiserror::Error)]
enum YamlErrorSource {
    #[error("{0}")]
    Deserialize(#[source] Box<serde_saphyr::Error>),
    #[error("{0}")]
    Tokenize(#[source] serde_saphyr::granit_parser::ScanError),
}

impl YamlError {
    /// One-based line and column, if the parser supplied a location.
    pub fn location(&self) -> Option<(u64, u64)> {
        match &self.0 {
            YamlErrorSource::Deserialize(error) => {
                error.location().map(|loc| (loc.line(), loc.column()))
            }
            YamlErrorSource::Tokenize(error) => Some((
                error.marker().line() as u64,
                error.marker().col() as u64 + 1,
            )),
        }
    }
}

impl From<serde_saphyr::Error> for YamlError {
    fn from(error: serde_saphyr::Error) -> Self {
        Self(YamlErrorSource::Deserialize(Box::new(error)))
    }
}

pub(crate) const MAX_YAML_BYTES: usize = 1_048_576;

pub(crate) fn from_yaml<T: serde::de::DeserializeOwned>(input: &str) -> Result<T, YamlError> {
    if input.len() > MAX_YAML_BYTES {
        return Err(serde::de::Error::custom(
            "YAML configuration exceeds 1048576 bytes",
        ));
    }
    let normalized = preserve_scalar_types(input)?;
    let value: serde_json::Value = serde_saphyr::from_str_with_options(
        &normalized,
        serde_saphyr::options! {
            strict_booleans: true,
            no_schema: true,
            reject_unsupported_tags: true,
            merge_keys: serde_saphyr::MergeKeyPolicy::AsOrdinary,
            with_snippet: false,
            budget: serde_saphyr::budget! {
                max_depth: 64,
                max_nodes: 100_000,
                max_events: 300_000,
                max_total_scalar_bytes: MAX_YAML_BYTES,
                max_recorded_anchor_bytes: MAX_YAML_BYTES,
                max_recorded_anchor_events: 100_000,
            },
        },
    )
    .map_err(YamlError::from)?;
    serde_json::from_value(value).map_err(<YamlError as serde::de::Error>::custom)
}

// Resolve scalar types before strict JSON decoding so numeric limits cannot coerce strings.
fn preserve_scalar_types(input: &str) -> Result<std::borrow::Cow<'_, str>, YamlError> {
    use serde::de::Error;
    use serde_saphyr::granit_parser::{self, Event, Parser, ScalarStyle};

    let parser = Parser::new_from_str_with_options(
        input,
        granit_parser::options! {
            emit_comments: false,
            flow_nesting_limit: 64,
            block_nesting_limit: 64,
        },
    );
    let mut output = String::new();
    let mut copied = 0;
    for (events, event) in parser.enumerate() {
        if events >= 300_000 {
            return Err(YamlError::custom("YAML parser event limit exceeded"));
        }
        let (event, span) = event.map_err(|error| YamlError(YamlErrorSource::Tokenize(error)))?;
        let Event::Scalar(value, style, _, tag) = event else {
            continue;
        };
        let boolean_tag = tag
            .as_ref()
            .is_some_and(|tag| tag.is_yaml_core_schema_tag("bool"));
        if style != ScalarStyle::Plain && !boolean_tag {
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
        if tag.is_some() && boolean.is_none() {
            continue;
        }
        let mixed_boolean = boolean.is_none()
            && (value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("false"));
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
        if !leading_zero && !digits.is_empty() && digits.chars().all(|ch| ch.is_digit(radix)) {
            let magnitude = u64::from_str_radix(digits, radix).map_err(|_| {
                YamlError::custom("YAML integer exceeds the supported 64-bit range")
            })?;
            if value.starts_with('-') && magnitude > (i64::MAX as u64) + 1 {
                return Err(YamlError::custom(
                    "YAML integer exceeds the supported 64-bit range",
                ));
            }
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
            && !mixed_boolean
        {
            continue;
        }
        let range = span
            .byte_range()
            .ok_or_else(|| YamlError::custom("missing YAML scalar source range"))?;
        let mut prefix_start = copied;
        if boolean_tag {
            let start = span
                .tag_start()
                .and_then(|marker| marker.byte_offset())
                .ok_or_else(|| YamlError::custom("missing YAML tag source range"))?;
            let prefix = input
                .get(copied..start)
                .ok_or_else(|| YamlError::custom("invalid YAML tag source range"))?;
            let tag_source = input
                .get(start..range.start)
                .ok_or_else(|| YamlError::custom("invalid YAML tag source range"))?;
            let length = tag_source
                .find(char::is_whitespace)
                .unwrap_or(tag_source.len());
            output.push_str(prefix);
            output.extend(std::iter::repeat_n(' ', length));
            prefix_start = start + length;
        }
        let prefix = input
            .get(prefix_start..range.start)
            .ok_or_else(|| YamlError::custom("invalid YAML scalar source range"))?;
        output.push_str(prefix);
        if let Some(boolean) = boolean {
            output.push_str(boolean);
        } else {
            output.push_str(&serde_json::to_string(value.as_ref()).map_err(YamlError::custom)?);
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

impl serde::de::Error for YamlError {
    fn custom<T: std::fmt::Display>(message: T) -> Self {
        Self::from(<serde_saphyr::Error as serde::de::Error>::custom(message))
    }
}

pub(crate) fn read_yaml(path: impl AsRef<std::path::Path>) -> std::io::Result<String> {
    use std::io::Read;
    let mut input = String::new();
    std::fs::File::open(path)?
        .take(MAX_YAML_BYTES as u64 + 1)
        .read_to_string(&mut input)?;
    if input.len() > MAX_YAML_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "YAML configuration exceeds 1048576 bytes",
        ));
    }
    Ok(input)
}
