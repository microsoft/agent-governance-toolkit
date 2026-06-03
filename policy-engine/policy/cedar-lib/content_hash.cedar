// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// AGT stock tool content-hash gate, Cedar mirror of
// `policy/lib/content_hash.rego`. The Rego library forbids the tool
// invocation when the manifest declared `tool.content_hash` and the
// observed `snapshot.tool_call.content_hash` do not agree. In the Cedar
// model the declared hash sits on the resource entity attribute
// `content_hash` and the observed hash flows through
// `context.tool_call.content_hash` per AGT-SNAPSHOT-1.0.md section 2.5.
//
// The host loads the resource entity with the manifest declared hash via
// the policy `entities_path` (D3.1) on the entity matching the resource
// UID built by D3.2 (`Tool::"<name>"`).
//
// Per the Rego semantics this policy distinguishes the two failure modes:
// the manifest declared a hash but the snapshot omitted one, and both are
// present but disagree. Both surface the same AGT deny reason
// `tool_content_hash_mismatch` because the dispatcher uses the policy
// `@id` as the reason string per D3.3.

@id("tool_content_hash_mismatch")
forbid (
  principal,
  action,
  resource
) when {
  resource has content_hash &&
  context has tool_call &&
  context.tool_call has content_hash &&
  resource.content_hash != context.tool_call.content_hash
};

@id("tool_content_hash_mismatch_observed_missing")
forbid (
  principal,
  action,
  resource
) when {
  resource has content_hash &&
  context has tool_call &&
  !(context.tool_call has content_hash)
};
