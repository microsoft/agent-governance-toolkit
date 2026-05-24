// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Structured CLI error with an associated process exit code.
//!
//! Exit-code contract:
//! - `0` success
//! - `1` fail-closed operational error (invalid policy, malformed file, IO, not found)
//! - `2` argument/input-usage error (clap parse errors, or invalid `check` input)

use std::fmt;

/// A fail-closed CLI error. Carries a human-readable message and the process
/// exit code to use. Every operational failure maps to exit code 1.
#[derive(Debug)]
pub struct CliError {
    message: String,
    code: i32,
}

impl CliError {
    /// An operational failure that maps to exit code 1.
    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: 1,
        }
    }

    /// An argument/input-usage error that maps to exit code 2 (e.g. invalid
    /// `check --input` JSON), distinct from an operational failure or a policy deny.
    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: 2,
        }
    }

    /// The process exit code associated with this error.
    pub fn exit_code(&self) -> i32 {
        self.code
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CliError {}
