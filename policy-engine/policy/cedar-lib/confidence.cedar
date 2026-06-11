// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// AGT stock confidence gate, Cedar mirror of `policy/lib/confidence.rego`.
// The Rego library denies the action with reason
// `confidence_below_threshold` when the host annotator score
// `context.annotations.confidence.score` falls under the configured
// minimum. The threshold sits on the resource entity attribute
// `min_confidence` supplied by the host via the policy `entities_path`
// (D3.1).
//
// Cedar limit. Cedar long values are integer typed. The Rego library
// accepts a 0..1 float score. Hosts using the Cedar mirror SHOULD scale
// the confidence score to an integer range (for example 0..100) before
// placing it on the snapshot, and SHOULD set the threshold on the same
// scale. Authors who need float precision stay on the Rego library
// `data.agt.confidence`.

@id("confidence_below_threshold")
forbid (
  principal,
  action,
  resource
) when {
  resource has min_confidence &&
  context has annotations &&
  context.annotations has confidence &&
  context.annotations.confidence has score &&
  context.annotations.confidence.score < resource.min_confidence
};
