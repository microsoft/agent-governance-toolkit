// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Clock and nonce seams for deterministic security testing.

use crate::mcp::error::McpError;
use rand::{distributions::Alphanumeric, Rng};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

/// Time source abstraction used by security-sensitive components.
pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
}

/// Production clock backed by the operating system.
#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Deterministic test clock with manual advancement.
#[derive(Debug)]
pub struct FixedClock {
    wall_time: Mutex<SystemTime>,
}

impl FixedClock {
    /// Create a fixed clock anchored at the provided wall time.
    pub fn new(wall_time: SystemTime) -> Self {
        Self {
            wall_time: Mutex::new(wall_time),
        }
    }

    /// Advance the fixed clock.
    pub fn advance(&self, delta: Duration) -> Result<(), McpError> {
        let mut wall_time = self
            .wall_time
            .lock()
            .map_err(|_| McpError::store("clock", "fixed clock wall-time lock poisoned"))?;
        *wall_time = wall_time
            .checked_add(delta)
            .ok_or(McpError::InvalidConfig("clock overflow"))?;
        Ok(())
    }
}

impl Clock for FixedClock {
    fn now(&self) -> SystemTime {
        match self.wall_time.lock() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }
}

/// Nonce generation seam for testability.
pub trait NonceGenerator: Send + Sync {
    fn generate(&self) -> Result<String, McpError>;
}

/// Production nonce generator backed by random alphanumeric bytes.
#[derive(Debug, Default)]
pub struct SystemNonceGenerator;

impl NonceGenerator for SystemNonceGenerator {
    fn generate(&self) -> Result<String, McpError> {
        let nonce = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();
        Ok(nonce)
    }
}

/// Deterministic nonce generator for tests.
#[derive(Debug, Default)]
pub struct DeterministicNonceGenerator {
    values: Mutex<VecDeque<String>>,
}

impl DeterministicNonceGenerator {
    /// Create a deterministic generator from a fixed sequence.
    pub fn from_values(values: Vec<String>) -> Self {
        Self {
            values: Mutex::new(values.into()),
        }
    }
}

impl NonceGenerator for DeterministicNonceGenerator {
    fn generate(&self) -> Result<String, McpError> {
        let mut values = self
            .values
            .lock()
            .map_err(|_| McpError::store("nonce", "deterministic nonce lock poisoned"))?;
        values
            .pop_front()
            .ok_or_else(|| McpError::NonceGeneration("no nonce values remaining".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_clock_advances() {
        let clock = FixedClock::new(SystemTime::UNIX_EPOCH);
        let start = clock.now();
        clock.advance(Duration::from_secs(5)).unwrap();
        assert_eq!(clock.now().duration_since(start).unwrap().as_secs(), 5);
    }

    #[test]
    fn deterministic_nonce_generator_uses_queue() {
        let generator = DeterministicNonceGenerator::from_values(vec!["a".into(), "b".into()]);
        assert_eq!(generator.generate().unwrap(), "a");
        assert_eq!(generator.generate().unwrap(), "b");
    }
}
