//! Bundled reference dispatchers for Agent Control Specification.
//!
//! The core defines the annotator contract but leaves execution to hosts. This
//! module provides small synchronous reference dispatchers for HTTP endpoints,
//! generic classifiers, and OpenAI-compatible LLM judges. It is gated behind the
//! `default-dispatchers` feature so the pure deterministic core carries no
//! networking dependency unless a host opts in. These dispatchers back the
//! zero-config defaults surfaced through the FFI builder.

pub mod bundled;
mod classifier;
mod constants;
mod default;
mod endpoint;
mod http;
mod llm;
mod resolve;

pub use bundled::{
    fold_score_verdict, BundledClassifierProvider, ClassifierVerdict, HttpTransport,
    ResolvedClassifierConfig, StubHttpTransport, TransportRequest, TransportResponse,
    UreqHttpTransport,
};
pub use classifier::ClassifierAnnotator;
pub use default::DefaultAnnotatorDispatcher;
pub use endpoint::EndpointAnnotator;
pub use llm::LlmAnnotator;

use crate::AnnotatorDispatcher;
use crate::{Limits, Manifest};
#[cfg(feature = "opa")]
use crate::{OpaPolicyDispatcher, OpaRegoRunner, PolicyDispatcher, RuntimeError};
use std::sync::Arc;

/// The bundled native annotator dispatcher used as the zero-config default. It
/// routes each annotator to the matching reference dispatcher based on its
/// declared `type`, reading endpoint configuration from the manifest. It is
/// bound to the `limits` the caller passes, used for dispatch time fetches, and
/// to the manifest `url_sourced` provenance, so a bundled `llm` annotator on an
/// untrusted URL sourced manifest never falls back to a host environment
/// credential, including a provider default credential variable. Credentials
/// must be supplied inline. A file sourced manifest keeps the historical
/// behavior. Every host surface MUST build the annotator dispatcher through this
/// function so the provenance is never dropped. The FFI builder
/// (`acs_builder_set_url_fetch_limits`) and the Rust SDK
/// (`from_url_with_limits`) let a host pass tightened URL fetch limits here.
pub fn default_annotator_dispatcher_for(
    manifest: &Manifest,
    limits: Limits,
) -> Arc<dyn AnnotatorDispatcher> {
    Arc::new(DefaultAnnotatorDispatcher::with_limits_and_source(
        limits,
        manifest.url_sourced,
    ))
}

/// The bundled native OPA policy dispatcher used as the zero-config default. The
/// dispatch time `bundle_url` fetch uses `Limits::default()`; a host that
/// tightened its URL fetch limits builds through `default_policy_dispatcher_with_limits`
/// instead, which the FFI builder and Rust SDK wire from the host configured limits.
///
/// Fails closed if the manifest declares a non-Rego policy because the default
/// dispatcher only evaluates Rego. OPA process failures happen during
/// evaluation and are normalized by the runtime to fail-closed verdicts.
///
/// AGT M2.S5 D7: gated behind the `opa` feature. Hosts that build the core
/// without `opa` MUST register their own `PolicyDispatcher` explicitly; the
/// FFI builder surfaces a clear error in that configuration.
#[cfg(feature = "opa")]
pub fn default_policy_dispatcher(
    manifest: &Manifest,
) -> Result<Arc<dyn PolicyDispatcher>, RuntimeError> {
    default_policy_dispatcher_with_limits(manifest, Limits::default())
}

/// The bundled native OPA policy dispatcher bound to the host effective `limits`,
/// so a `bundle_url` fetch on a file sourced manifest honors the configured body
/// size, timeout, and redirect caps. `default_policy_dispatcher` passes
/// `Limits::default()`; a host that tightened its limits builds the dispatcher
/// through this function instead. Fails closed on a non-Rego policy, as above.
#[cfg(feature = "opa")]
pub fn default_policy_dispatcher_with_limits(
    manifest: &Manifest,
    limits: Limits,
) -> Result<Arc<dyn PolicyDispatcher>, RuntimeError> {
    for (name, policy) in &manifest.policies {
        let engine = policy.engine_type();
        if engine != "rego" {
            return Err(RuntimeError::PolicyInvocationFailed(format!(
                "default policy dispatcher supports only Rego policies; policy '{name}' uses engine '{engine}'"
            )));
        }
    }
    Ok(Arc::new(OpaPolicyDispatcher::with_runner(
        OpaRegoRunner::from_environment().with_limits(limits),
    )))
}
