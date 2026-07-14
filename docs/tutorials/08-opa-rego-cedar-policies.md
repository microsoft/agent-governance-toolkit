---
title: Rego and Cedar in ACS
last_reviewed: 2026-07-11
owner: docs-team
---

# Rego and Cedar in ACS

ACS manifests declare Rego and Cedar policies under `policies`.

Rego policies reference a bundle and query. Cedar policies use the native
inline policy set or file fields defined by the manifest schema. Bind the
policy identifier at one or more intervention points.

See the [manifest schema](../../policy-engine/spec/schema/manifest.schema.json)
and [ACS specification](../../policy-engine/spec/SPECIFICATION.md).
