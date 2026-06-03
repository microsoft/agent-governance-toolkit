//! Reference annotator dispatchers for Agent Control Specification.
//!
//! These dispatchers now live in the core crate behind its `default-dispatchers`
//! feature so they can back the zero-config FFI defaults. This crate is a thin
//! re-export shim that preserves the historical
//! `agent_control_specification_annotators` import surface.

pub use agent_control_specification_core::dispatchers::bundled;
pub use agent_control_specification_core::dispatchers::*;
