// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// AGT stock egress gate, Cedar mirror of `policy/lib/egress.rego`. The
// Rego library parses a URL out of `snapshot.tool_call.args.url` and
// compares the extracted host against `tool.security_labels` with
// `glob.match` semantics. Cedar has no URL parser, no host extractor, no
// glob, and no string substring operator, so this library forbids the
// action only when a bare host or domain is already projected into the
// snapshot at one of two well known paths, and only when the host appears
// verbatim in the resource entity attribute `security_labels`.
//
// Cedar limit. The Cedar policy cannot parse a URL string. Authors who
// want to gate on a URL value run an annotator that extracts the host
// into `context.annotations.egress.destination` before policy
// evaluation, or have the host SDK project the bare host into
// `context.tool_call.args.host` or `context.tool_call.args.domain`.
// Authors who need glob style host patterns (`*.example.com`) or
// scheme aware URL parsing stay on the Rego library `data.agt.egress`.
//
// The resource entity attribute `security_labels` MUST be a set of
// strings naming the exact allowed hosts. The host loads this set via
// the policy `entities_path` (D3.1) on the entity matching the resource
// UID built by D3.2.

@id("egress_destination_not_allowed")
forbid (
  principal,
  action,
  resource
) when {
  resource has security_labels &&
  context has tool_call &&
  context.tool_call has args &&
  context.tool_call.args has host &&
  !(resource.security_labels.contains(context.tool_call.args.host))
};

@id("egress_destination_not_allowed_domain")
forbid (
  principal,
  action,
  resource
) when {
  resource has security_labels &&
  context has tool_call &&
  context.tool_call has args &&
  context.tool_call.args has domain &&
  !(resource.security_labels.contains(context.tool_call.args.domain))
};

@id("egress_destination_not_allowed_annotation")
forbid (
  principal,
  action,
  resource
) when {
  resource has security_labels &&
  context has annotations &&
  context.annotations has egress &&
  context.annotations.egress has destination &&
  !(resource.security_labels.contains(context.annotations.egress.destination))
};
