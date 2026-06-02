use serde::{Deserialize, Serialize};

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum PerfTelemetry {
    #[default]
    Off,
    External,
    Full,
}

impl PerfTelemetry {
    pub const fn emit_external_events(self) -> bool {
        !matches!(self, Self::Off)
    }

    pub const fn emit_stage_events(self) -> bool {
        matches!(self, Self::Full)
    }

    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::External => 1,
            Self::Full => 2,
        }
    }

    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Off),
            1 => Some(Self::External),
            2 => Some(Self::Full),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_off() {
        assert_eq!(PerfTelemetry::default(), PerfTelemetry::Off);
    }

    #[test]
    fn wire_roundtrips() {
        for level in [
            PerfTelemetry::Off,
            PerfTelemetry::External,
            PerfTelemetry::Full,
        ] {
            assert_eq!(PerfTelemetry::from_u8(level.as_u8()), Some(level));
        }
        assert_eq!(PerfTelemetry::from_u8(3), None);
        assert_eq!(PerfTelemetry::from_u8(255), None);
    }

    #[test]
    fn gating_matches_contract() {
        assert!(!PerfTelemetry::Off.emit_external_events());
        assert!(!PerfTelemetry::Off.emit_stage_events());
        assert!(PerfTelemetry::External.emit_external_events());
        assert!(!PerfTelemetry::External.emit_stage_events());
        assert!(PerfTelemetry::Full.emit_external_events());
        assert!(PerfTelemetry::Full.emit_stage_events());
    }
}
