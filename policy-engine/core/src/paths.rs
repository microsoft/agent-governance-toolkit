use crate::{constants::policy_input as pi_key, JsonValue, RuntimeError};
use std::{fmt, num::ParseIntError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathRoot {
    Snap,
    Pi,
    PolicyTarget,
    Tool,
}

impl PathRoot {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Snap => "$snap",
            Self::Pi => "$pi",
            Self::PolicyTarget => "$policy_target",
            Self::Tool => "$tool",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSegment {
    Field(String),
    Index(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonPath {
    original: String,
    root: PathRoot,
    segments: Vec<PathSegment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathParseError {
    Empty,
    MissingRoot,
    UnknownRoot,
    InvalidSyntax(String),
    NegativeIndex,
    InvalidIndex,
    InvalidLiteral(String),
}

impl fmt::Display for PathParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("path is empty"),
            Self::MissingRoot => f.write_str("path must start with an explicit root"),
            Self::UnknownRoot => f.write_str("unknown path root"),
            Self::InvalidSyntax(detail) => write!(f, "invalid path syntax: {detail}"),
            Self::NegativeIndex => f.write_str("negative indices are unsupported"),
            Self::InvalidIndex => f.write_str("invalid array index"),
            Self::InvalidLiteral(detail) => write!(f, "invalid bracket literal: {detail}"),
        }
    }
}

impl std::error::Error for PathParseError {}

impl JsonPath {
    pub fn parse(input: &str) -> Result<Self, PathParseError> {
        if input.is_empty() {
            return Err(PathParseError::Empty);
        }
        if !input.starts_with('$') {
            return Err(PathParseError::MissingRoot);
        }

        let (root, mut index) = parse_root(input)?;
        let mut segments = Vec::new();
        let bytes = input.as_bytes();

        while index < input.len() {
            match bytes[index] {
                b'.' => {
                    index += 1;
                    let start = index;
                    while index < input.len() {
                        let b = bytes[index];
                        if b == b'.' || b == b'[' {
                            break;
                        }
                        if b == b']' {
                            return Err(PathParseError::InvalidSyntax(
                                "']' is only valid inside bracket notation".to_string(),
                            ));
                        }
                        let ch = input[index..].chars().next().ok_or_else(|| {
                            PathParseError::InvalidSyntax("unexpected end".to_string())
                        })?;
                        index += ch.len_utf8();
                    }
                    if start == index {
                        return Err(PathParseError::InvalidSyntax(
                            "dot field segment is empty".to_string(),
                        ));
                    }
                    segments.push(PathSegment::Field(input[start..index].to_string()));
                }
                b'[' => {
                    index += 1;
                    if index >= input.len() {
                        return Err(PathParseError::InvalidSyntax(
                            "unclosed bracket".to_string(),
                        ));
                    }
                    if bytes[index] == b'"' {
                        let literal_start = index;
                        index += 1;
                        let mut escaped = false;
                        let mut closed = false;
                        while index < input.len() {
                            let b = bytes[index];
                            if escaped {
                                escaped = false;
                                index += 1;
                                continue;
                            }
                            match b {
                                b'\\' => {
                                    escaped = true;
                                    index += 1;
                                }
                                b'"' => {
                                    index += 1;
                                    closed = true;
                                    break;
                                }
                                _ => index += 1,
                            }
                        }
                        if !closed {
                            return Err(PathParseError::InvalidLiteral(
                                "unterminated string".to_string(),
                            ));
                        }
                        let literal: String = serde_json::from_str(&input[literal_start..index])
                            .map_err(|err| PathParseError::InvalidLiteral(err.to_string()))?;
                        if index >= input.len() || bytes[index] != b']' {
                            return Err(PathParseError::InvalidSyntax(
                                "bracket literal must close with ']'".to_string(),
                            ));
                        }
                        index += 1;
                        segments.push(PathSegment::Field(literal));
                    } else {
                        if bytes[index] == b'-' {
                            return Err(PathParseError::NegativeIndex);
                        }
                        let start = index;
                        while index < input.len() && bytes[index].is_ascii_digit() {
                            index += 1;
                        }
                        if start == index {
                            return Err(PathParseError::InvalidIndex);
                        }
                        if index >= input.len() || bytes[index] != b']' {
                            return Err(PathParseError::InvalidSyntax(
                                "array index must close with ']'".to_string(),
                            ));
                        }
                        let parsed = input[start..index]
                            .parse::<usize>()
                            .map_err(|_: ParseIntError| PathParseError::InvalidIndex)?;
                        index += 1;
                        segments.push(PathSegment::Index(parsed));
                    }
                }
                _ => {
                    return Err(PathParseError::InvalidSyntax(format!(
                        "unexpected byte at offset {index}"
                    )))
                }
            }
        }

        Ok(Self {
            original: input.to_string(),
            root,
            segments,
        })
    }

    pub fn parse_with_snapshot_alias(input: &str) -> Result<Self, PathParseError> {
        let normalized = normalize_snapshot_alias(input);
        Self::parse(&normalized)
    }

    pub fn root(&self) -> PathRoot {
        self.root
    }

    pub fn original(&self) -> &str {
        &self.original
    }

    pub fn segments(&self) -> &[PathSegment] {
        &self.segments
    }

    pub fn references_pi_annotations(&self) -> bool {
        self.root == PathRoot::Pi
            && matches!(self.segments.first(), Some(PathSegment::Field(field)) if field == pi_key::ANNOTATIONS)
    }

    pub fn resolve(&self, env: &PathEnv<'_>) -> Result<JsonValue, RuntimeError> {
        let mut current = env.root_value(self.root).ok_or_else(|| {
            RuntimeError::PathMissing(format!(
                "root {} not available for {}",
                self.root.as_str(),
                self.original
            ))
        })?;

        for segment in &self.segments {
            match segment {
                PathSegment::Field(field) => match current {
                    JsonValue::Object(map) => {
                        current = map
                            .get(field)
                            .ok_or_else(|| RuntimeError::PathMissing(self.original.clone()))?;
                    }

                    _ => return Err(RuntimeError::PathTypeMismatch(self.original.clone())),
                },
                PathSegment::Index(index) => match current {
                    JsonValue::Array(values) => {
                        current = values
                            .get(*index)
                            .ok_or_else(|| RuntimeError::PathMissing(self.original.clone()))?;
                    }
                    _ => return Err(RuntimeError::PathTypeMismatch(self.original.clone())),
                },
            }
        }

        Ok(current.clone())
    }

    pub fn resolve_policy_target_mut<'a>(
        &self,
        policy_target: &'a mut JsonValue,
    ) -> Result<&'a mut JsonValue, RuntimeError> {
        if self.root != PathRoot::PolicyTarget {
            return Err(RuntimeError::EffectTargetForbidden(self.original.clone()));
        }

        let mut current = policy_target;
        for segment in &self.segments {
            match segment {
                PathSegment::Field(field) => match current {
                    JsonValue::Object(map) => {
                        current = map
                            .get_mut(field)
                            .ok_or_else(|| RuntimeError::PathMissing(self.original.clone()))?;
                    }
                    _ => return Err(RuntimeError::PathTypeMismatch(self.original.clone())),
                },
                PathSegment::Index(index) => match current {
                    JsonValue::Array(values) => {
                        current = values
                            .get_mut(*index)
                            .ok_or_else(|| RuntimeError::PathMissing(self.original.clone()))?;
                    }
                    _ => return Err(RuntimeError::PathTypeMismatch(self.original.clone())),
                },
            }
        }
        Ok(current)
    }
}

fn normalize_snapshot_alias(input: &str) -> String {
    if input == "$" {
        "$snap".to_string()
    } else if let Some(rest) = input.strip_prefix("$.") {
        format!("$snap.{rest}")
    } else {
        input.to_string()
    }
}

fn parse_root(input: &str) -> Result<(PathRoot, usize), PathParseError> {
    let roots = [
        ("$policy_target", PathRoot::PolicyTarget),
        ("$snap", PathRoot::Snap),
        ("$tool", PathRoot::Tool),
        ("$pi", PathRoot::Pi),
    ];

    for (literal, root) in roots {
        if input.starts_with(literal) {
            let next = input.as_bytes().get(literal.len()).copied();
            if matches!(next, None | Some(b'.') | Some(b'[')) {
                return Ok((root, literal.len()));
            }
        }
    }

    Err(PathParseError::UnknownRoot)
}

#[derive(Debug, Default, Clone, Copy)]
pub struct PathEnv<'a> {
    pub snap: Option<&'a JsonValue>,
    pub pi: Option<&'a JsonValue>,
    pub policy_target: Option<&'a JsonValue>,
    pub tool: Option<&'a JsonValue>,
}

impl<'a> PathEnv<'a> {
    pub fn with_snap(snapshot: &'a JsonValue) -> Self {
        Self {
            snap: Some(snapshot),
            ..Self::default()
        }
    }

    pub fn with_pi(policy_input: &'a JsonValue) -> Self {
        Self {
            pi: Some(policy_input),
            ..Self::default()
        }
    }

    pub fn with_pi_and_snap(policy_input: &'a JsonValue, snapshot: &'a JsonValue) -> Self {
        Self {
            snap: Some(snapshot),
            pi: Some(policy_input),
            ..Self::default()
        }
    }

    fn root_value(&self, root: PathRoot) -> Option<&'a JsonValue> {
        match root {
            PathRoot::Snap => self.snap,
            PathRoot::Pi => self.pi,
            PathRoot::PolicyTarget => self.policy_target.or_else(|| {
                self.pi
                    .and_then(|pi| pi.get(pi_key::POLICY_TARGET))
                    .and_then(|policy_target| policy_target.get(pi_key::VALUE))
            }),
            PathRoot::Tool => self
                .tool
                .or_else(|| self.pi.and_then(|pi| pi.get(pi_key::TOOL))),
        }
    }
}
