use crate::{InterventionPoint, InterventionPointResult, JsonValue};
use std::{error::Error, fmt};

#[derive(Debug, Clone, PartialEq)]
pub struct AgentControlBlocked {
    pub intervention_point: InterventionPoint,
    pub intervention_point_result: Box<InterventionPointResult>,
}

impl AgentControlBlocked {
    pub fn new(
        intervention_point: InterventionPoint,
        intervention_point_result: InterventionPointResult,
    ) -> Self {
        Self {
            intervention_point,
            intervention_point_result: Box::new(intervention_point_result),
        }
    }
}

impl fmt::Display for AgentControlBlocked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Agent Control blocked at {} with decision {}",
            self.intervention_point, self.intervention_point_result.verdict.decision
        )?;
        if let Some(reason) = &self.intervention_point_result.verdict.reason {
            write!(f, ": {reason}")?;
        }
        Ok(())
    }
}

impl Error for AgentControlBlocked {}

/// Raised when an approval resolver suspends an `escalate` verdict for deferred approval.
///
/// This is a terminal unwinding signal for the current call. The enforcing
/// methods do not resume automatically; resumption is owned by the host using
/// `handle`. A suspension at a `post_*` intervention point does not undo an
/// already-executed action, so a host resuming from such a point must deliver
/// the already-produced result rather than re-executing the guarded operation.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentControlSuspended {
    pub intervention_point: InterventionPoint,
    pub intervention_point_result: Box<InterventionPointResult>,
    pub handle: Option<JsonValue>,
}

impl AgentControlSuspended {
    pub fn new(
        intervention_point: InterventionPoint,
        intervention_point_result: InterventionPointResult,
        handle: Option<JsonValue>,
    ) -> Self {
        Self {
            intervention_point,
            intervention_point_result: Box::new(intervention_point_result),
            handle,
        }
    }
}

impl fmt::Display for AgentControlSuspended {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Agent Control suspended at {} pending approval",
            self.intervention_point
        )?;
        if let Some(reason) = &self.intervention_point_result.verdict.reason {
            write!(f, ": {reason}")?;
        }
        Ok(())
    }
}

impl Error for AgentControlSuspended {}

/// A policy-driven interruption raised by the enforcing wrappers.
///
/// Distinguishes a block (`deny` or unapproved `escalate`) from an approval
/// suspension so callers can tell the two apart.
#[derive(Debug, Clone, PartialEq)]
pub enum AgentControlInterruption {
    Blocked(AgentControlBlocked),
    Suspended(AgentControlSuspended),
}

impl AgentControlInterruption {
    /// The intervention point whose verdict triggered this interruption.
    pub fn intervention_point(&self) -> InterventionPoint {
        match self {
            Self::Blocked(blocked) => blocked.intervention_point,
            Self::Suspended(suspended) => suspended.intervention_point,
        }
    }

    /// The intervention-point result that triggered this interruption.
    pub fn intervention_point_result(&self) -> &InterventionPointResult {
        match self {
            Self::Blocked(blocked) => &blocked.intervention_point_result,
            Self::Suspended(suspended) => &suspended.intervention_point_result,
        }
    }
}

impl From<AgentControlBlocked> for AgentControlInterruption {
    fn from(value: AgentControlBlocked) -> Self {
        Self::Blocked(value)
    }
}

impl From<AgentControlSuspended> for AgentControlInterruption {
    fn from(value: AgentControlSuspended) -> Self {
        Self::Suspended(value)
    }
}

impl fmt::Display for AgentControlInterruption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blocked(blocked) => blocked.fmt(f),
            Self::Suspended(suspended) => suspended.fmt(f),
        }
    }
}

impl Error for AgentControlInterruption {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Blocked(blocked) => Some(blocked),
            Self::Suspended(suspended) => Some(suspended),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum AgentControlError<E> {
    Blocked(AgentControlBlocked),
    Suspended(AgentControlSuspended),
    Execute(E),
}

impl<E> From<AgentControlBlocked> for AgentControlError<E> {
    fn from(value: AgentControlBlocked) -> Self {
        Self::Blocked(value)
    }
}

impl<E> From<AgentControlSuspended> for AgentControlError<E> {
    fn from(value: AgentControlSuspended) -> Self {
        Self::Suspended(value)
    }
}

impl<E> From<AgentControlInterruption> for AgentControlError<E> {
    fn from(value: AgentControlInterruption) -> Self {
        match value {
            AgentControlInterruption::Blocked(blocked) => Self::Blocked(blocked),
            AgentControlInterruption::Suspended(suspended) => Self::Suspended(suspended),
        }
    }
}

impl<E: fmt::Display> fmt::Display for AgentControlError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blocked(blocked) => blocked.fmt(f),
            Self::Suspended(suspended) => suspended.fmt(f),
            Self::Execute(error) => write!(f, "host execution failed: {error}"),
        }
    }
}

impl<E: Error + 'static> Error for AgentControlError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Blocked(blocked) => Some(blocked),
            Self::Suspended(suspended) => Some(suspended),
            Self::Execute(error) => Some(error),
        }
    }
}
