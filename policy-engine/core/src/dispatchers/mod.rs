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
use crate::Limits;
#[cfg(feature = "opa")]
use crate::{Manifest, OpaPolicyDispatcher, OpaRegoRunner, PolicyDispatcher, RuntimeError};
use std::sync::Arc;

/// The bundled native annotator dispatcher used as the zero-config default. It
/// routes each annotator to the matching reference dispatcher based on its
/// declared `type`, reading endpoint configuration from the manifest.
pub fn default_annotator_dispatcher() -> Arc<dyn AnnotatorDispatcher> {
    default_annotator_dispatcher_with_limits(Limits::default())
}

/// The zero-config annotator dispatcher bound to the host effective `Limits`, so
/// a bundled `llm` annotator honors them on its dispatch-time `system_prompt_url`
/// fetch (body size, timeout, redirects). `default_annotator_dispatcher` uses the
/// default limits; a host with tightened limits builds the dispatcher here.
pub fn default_annotator_dispatcher_with_limits(limits: Limits) -> Arc<dyn AnnotatorDispatcher> {
    Arc::new(DefaultAnnotatorDispatcher::with_limits(limits))
}

/// The bundled native OPA policy dispatcher used as the zero-config default.
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

/// The zero-config OPA policy dispatcher bound to the host effective `Limits`, so
/// a `bundle_url` fetch honors them. `default_policy_dispatcher` uses the default
/// limits; a host with tightened limits builds the dispatcher here.
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
