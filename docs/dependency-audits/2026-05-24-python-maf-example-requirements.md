---
title: Python MAF Example Requirements Refresh
last_reviewed: 2026-05-24
owner: docs-team
---

# Python MAF Example Requirements Refresh

## Which Dependencies Changed And Why

- The following example lockfiles changed:
  - `examples/maf-integration/01-loan-processing/python/requirements.txt`
  - `examples/maf-integration/02-customer-service/python/requirements.txt`
  - `examples/maf-integration/03-healthcare/python/requirements.txt`
  - `examples/maf-integration/04-it-helpdesk/python/requirements.txt`
  - `examples/maf-integration/05-devops-deploy/python/requirements.txt`
- Each file now pins the published `agent-framework==1.5.0` package for the
  real Microsoft Agent Framework runtime used by the refactored Python
  walkthroughs.
- The old split dependency shape using both `agent-framework==1.2.0` and
  `agent-framework-openai==1.2.0` was removed because the examples now target
  the current published package shape and do not need the separate OpenAI
  package entry.

## Security Advisory Relevance

- No CVE-specific remediation is claimed by this change.
- The dependency refresh is driven by using the real MAF runtime in the Python
  examples, not by a reported security advisory.
- The affected files are example-local `requirements.txt` lockfiles and do not
  change the core repository dependency graph outside those runnable examples.

## Breaking Change Risk Assessment

- Risk is low and scoped to the Python MAF examples under `examples/`.
- The examples were updated in the same PR to match the new dependency shape and
  now execute through real `Agent.run(...)` flows using the published package.
- The main compatibility consideration is that anyone rerunning older local
  environments for these examples must reinstall from the updated
  `requirements.txt` files.
