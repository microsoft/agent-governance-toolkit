// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// AGT stock drift gate, Cedar mirror of `policy/lib/drift.rego`. The Rego
// library issues a `warn` verdict when the host annotator score
// `context.annotations.drift_score` crosses the configured threshold.
// Cedar has no native `warn` decision, so this library emits the AGT
// `warn` verdict through the cedar advice channel per D3.3. The
// `@advice` annotation carries the cedar advice JSON payload described
// in `policy-engine/spec/schema/cedar_advice.schema.json`; the cedar
// dispatcher validates the payload and translates it into a warn
// verdict.
//
// The threshold sits on the resource entity attribute `drift_threshold`
// supplied by the host via the policy `entities_path` (D3.1). The
// drift score is an integer in this Cedar mirror because Cedar long
// values are integer typed and Cedar cannot compare floats with the
// `>=` operator without a decimal conversion. Hosts SHOULD scale their
// drift score to an integer range (for example 0..100) before placing
// it on the snapshot for the Cedar policy. Authors who require float
// thresholds stay on the Rego library `data.agt.drift`.
//
// This permit policy MUST be composed with at least one baseline
// permit (for example the one in `agt_default.cedar`) for the action
// to be allowed. Used in isolation it relies on Cedar's implicit deny
// when the drift threshold is not crossed, which the host SHOULD
// compose against the other AGT gates.

@advice("{\"verdict\":\"warn\",\"reason\":\"drift_detected\"}")
@id("agt.drift.warn")
permit (
  principal,
  action,
  resource
) when {
  context has annotations &&
  context.annotations has drift_score &&
  resource has drift_threshold &&
  context.annotations.drift_score >= resource.drift_threshold
};
