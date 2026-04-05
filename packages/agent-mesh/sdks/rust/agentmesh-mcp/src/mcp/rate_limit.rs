// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Sliding-window rate limiting for MCP traffic.

use crate::mcp::clock::Clock;
use crate::mcp::error::McpError;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Sliding-window decision for an MCP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpSlidingWindowDecision {
    pub allowed: bool,
    pub remaining: usize,
    pub retry_after_secs: u64,
}

/// Rate-limit store seam.
pub trait McpRateLimitStore: Send + Sync {
    fn check_and_record(
        &self,
        key: &str,
        now_secs: u64,
        max_requests: usize,
        window_secs: u64,
    ) -> Result<McpSlidingWindowDecision, McpError>;
}

/// In-memory rate-limit store.
#[derive(Debug, Default)]
pub struct InMemoryRateLimitStore {
    windows: Mutex<HashMap<String, Vec<u64>>>,
}

impl McpRateLimitStore for InMemoryRateLimitStore {
    fn check_and_record(
        &self,
        key: &str,
        now_secs: u64,
        max_requests: usize,
        window_secs: u64,
    ) -> Result<McpSlidingWindowDecision, McpError> {
        let mut windows = self
            .windows
            .lock()
            .map_err(|_| McpError::store("rate_limit", "rate-limit store lock poisoned"))?;
        let events = windows.entry(key.to_string()).or_default();
        events.retain(|event_secs| now_secs.saturating_sub(*event_secs) < window_secs);
        if events.len() >= max_requests {
            let retry_after_secs = retry_after_secs(now_secs, events[0], window_secs);
            return Ok(McpSlidingWindowDecision {
                allowed: false,
                remaining: 0,
                retry_after_secs,
            });
        }
        events.push(now_secs);
        Ok(McpSlidingWindowDecision {
            allowed: true,
            remaining: max_requests.saturating_sub(events.len()),
            retry_after_secs: 0,
        })
    }
}

/// Per-agent sliding-window limiter for MCP traffic.
#[derive(Clone)]
pub struct McpSlidingRateLimiter {
    max_requests: usize,
    window: Duration,
    clock: Arc<dyn Clock>,
    store: Arc<dyn McpRateLimitStore>,
}

impl McpSlidingRateLimiter {
    pub fn new(
        max_requests: usize,
        window: Duration,
        clock: Arc<dyn Clock>,
        store: Arc<dyn McpRateLimitStore>,
    ) -> Result<Self, McpError> {
        if max_requests == 0 || window.is_zero() {
            return Err(McpError::InvalidConfig(
                "rate limiter requires max_requests > 0 and window > 0",
            ));
        }
        Ok(Self {
            max_requests,
            window,
            clock,
            store,
        })
    }

    pub fn check(&self, agent_id: &str) -> Result<McpSlidingWindowDecision, McpError> {
        self.store.check_and_record(
            agent_id,
            unix_secs(self.clock.now())?,
            self.max_requests,
            self.window.as_secs(),
        )
    }
}

fn retry_after_secs(now_secs: u64, oldest_secs: u64, window_secs: u64) -> u64 {
    let elapsed = now_secs.saturating_sub(oldest_secs);
    if elapsed >= window_secs {
        return 0;
    }
    window_secs - elapsed
}

fn unix_secs(time: SystemTime) -> Result<u64, McpError> {
    Ok(time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| McpError::AccessDenied {
            reason: "system clock before unix epoch".to_string(),
        })?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::clock::FixedClock;
    use std::time::SystemTime;

    #[test]
    fn allows_until_window_is_full() {
        let clock = Arc::new(FixedClock::new(SystemTime::UNIX_EPOCH));
        let limiter = McpSlidingRateLimiter::new(
            2,
            Duration::from_secs(60),
            clock.clone(),
            Arc::new(InMemoryRateLimitStore::default()),
        )
        .unwrap();
        assert!(limiter.check("agent").unwrap().allowed);
        assert!(limiter.check("agent").unwrap().allowed);
        assert!(!limiter.check("agent").unwrap().allowed);
    }

    #[test]
    fn window_recovers_after_time_passes() {
        let clock = Arc::new(FixedClock::new(SystemTime::UNIX_EPOCH));
        let limiter = McpSlidingRateLimiter::new(
            1,
            Duration::from_secs(10),
            clock.clone(),
            Arc::new(InMemoryRateLimitStore::default()),
        )
        .unwrap();
        assert!(limiter.check("agent").unwrap().allowed);
        clock.advance(Duration::from_secs(11)).unwrap();
        assert!(limiter.check("agent").unwrap().allowed);
    }
}
