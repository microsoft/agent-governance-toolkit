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
    Normalize(#[source] agent_control_specification::YamlScalarError),
}

impl YamlError {
    /// One-based line and column, if the parser supplied a location.
    pub fn location(&self) -> Option<(u64, u64)> {
        match &self.0 {
            YamlErrorSource::Deserialize(error) => {
                error.location().map(|loc| (loc.line(), loc.column()))
            }
            YamlErrorSource::Normalize(error) => error.location(),
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
    let normalized = agent_control_specification::normalize_yaml_scalars(input, 64, 300_000)
        .map_err(|error| YamlError(YamlErrorSource::Normalize(error)))?;
    let value: serde_json::Value = serde_saphyr::from_str_with_options(
        &normalized,
        serde_saphyr::options! {
            emit_comments: false,
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
    T::deserialize(ConfigValue(value)).map_err(<YamlError as serde::de::Error>::custom)
}

// JSON's default struct decoder accepts positional arrays. Configuration structs
// must be mappings, including structs inside sequences, options and enum payloads.
struct ConfigValue(Value);

impl<'de> serde::de::IntoDeserializer<'de, serde_json::Error> for ConfigValue {
    type Deserializer = Self;

    fn into_deserializer(self) -> Self {
        self
    }
}

impl<'de> serde::Deserializer<'de> for ConfigValue {
    type Error = serde_json::Error;

    fn deserialize_any<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        use serde::de::value::{MapDeserializer, SeqDeserializer};
        match self.0 {
            Value::Array(values) => {
                SeqDeserializer::new(values.into_iter().map(ConfigValue)).deserialize_any(visitor)
            }
            Value::Object(values) => MapDeserializer::new(
                values
                    .into_iter()
                    .map(|(key, value)| (key, ConfigValue(value))),
            )
            .deserialize_any(visitor),
            value => value.deserialize_any(visitor),
        }
    }

    fn deserialize_map<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        if self.0.is_object() {
            self.deserialize_any(visitor)
        } else {
            self.0.deserialize_map(visitor)
        }
    }

    fn deserialize_struct<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.deserialize_map(visitor)
    }

    fn deserialize_option<V: serde::de::Visitor<'de>>(
        self,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        if self.0.is_null() {
            visitor.visit_none()
        } else {
            visitor.visit_some(self)
        }
    }

    fn deserialize_newtype_struct<V: serde::de::Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_enum<V: serde::de::Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        use serde::de::value::{MapAccessDeserializer, MapDeserializer};
        match self.0 {
            Value::Object(values) if values.len() == 1 => {
                MapAccessDeserializer::new(MapDeserializer::new(
                    values
                        .into_iter()
                        .map(|(key, value)| (key, ConfigValue(value))),
                ))
                .deserialize_enum(name, variants, visitor)
            }
            value => value.deserialize_enum(name, variants, visitor),
        }
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf unit unit_struct seq tuple tuple_struct identifier ignored_any
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
