// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// AGT stock pattern gate, Cedar mirror of `policy/lib/patterns.rego`. The
// Rego library uses RE2 to detect PII tokens (SSN, email, credit card,
// phone, secrets) anywhere in a string. Cedar has no regex engine and only
// exposes the `like` operator with `*` wildcards, so this library can only
// approximate three of the five Rego patterns and only as substring
// matchers with bounded specificity.
//
// Cedar limit. The Cedar `like` operator cannot enforce digit counts or
// case folding. The patterns below detect a structural signature only.
// Authors who need true regex stay on the Rego library
// `data.agt.patterns`. The Rego library remains canonical for PII
// detection.
//
// Source paths. The Rego library is parameterised over the text to scan.
// The Cedar mirror scans the host-visible snapshot fields:
// `context.input.body` at the `input` intervention point and
// `context.response.content` at the `output` intervention point. Authors
// who need to scan other fields write their own `forbid` policy following
// the shape below.

@id("pii_email_pattern_in_input")
forbid (
  principal,
  action,
  resource
) when {
  context has input &&
  context.input has body &&
  context.input.body like "*@*.*"
};

@id("pii_email_pattern_in_output")
forbid (
  principal,
  action,
  resource
) when {
  context has response &&
  context.response has content &&
  context.response.content like "*@*.*"
};

@id("pii_ssn_pattern_in_input")
forbid (
  principal,
  action,
  resource
) when {
  context has input &&
  context.input has body &&
  context.input.body like "*-*-*"
};

@id("pii_ssn_pattern_in_output")
forbid (
  principal,
  action,
  resource
) when {
  context has response &&
  context.response has content &&
  context.response.content like "*-*-*"
};

@id("pii_credit_card_pattern_in_input")
forbid (
  principal,
  action,
  resource
) when {
  context has input &&
  context.input has body &&
  context.input.body like "*-*-*-*"
};

@id("pii_credit_card_pattern_in_output")
forbid (
  principal,
  action,
  resource
) when {
  context has response &&
  context.response has content &&
  context.response.content like "*-*-*-*"
};
