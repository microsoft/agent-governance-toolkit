use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InterventionPoint {
    AgentStartup,
    Input,
    PreModelCall,
    PostModelCall,
    PreToolCall,
    PostToolCall,
    Output,
    AgentShutdown,
}

impl InterventionPoint {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AgentStartup => "agent_startup",
            Self::Input => "input",
            Self::PreModelCall => "pre_model_call",
            Self::PostModelCall => "post_model_call",
            Self::PreToolCall => "pre_tool_call",
            Self::PostToolCall => "post_tool_call",
            Self::Output => "output",
            Self::AgentShutdown => "agent_shutdown",
        }
    }

    pub fn is_tool_intervention_point(self) -> bool {
        matches!(self, Self::PreToolCall | Self::PostToolCall)
    }
}

impl fmt::Display for InterventionPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for InterventionPoint {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "agent_startup" => Ok(Self::AgentStartup),
            "input" => Ok(Self::Input),
            "pre_model_call" => Ok(Self::PreModelCall),
            "post_model_call" => Ok(Self::PostModelCall),
            "pre_tool_call" => Ok(Self::PreToolCall),
            "post_tool_call" => Ok(Self::PostToolCall),
            "output" => Ok(Self::Output),
            "agent_shutdown" => Ok(Self::AgentShutdown),
            other => Err(format!("unknown intervention_point '{other}'")),
        }
    }
}

impl Serialize for InterventionPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for InterventionPoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EnforcementMode {
    Enforce,
    EvaluateOnly,
}

impl EnforcementMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enforce => "enforce",
            Self::EvaluateOnly => "evaluate_only",
        }
    }
}

impl FromStr for EnforcementMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "enforce" => Ok(Self::Enforce),
            "evaluate_only" => Ok(Self::EvaluateOnly),
            other => Err(format!("unknown enforcement mode '{other}'")),
        }
    }
}

impl Serialize for EnforcementMode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for EnforcementMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}
