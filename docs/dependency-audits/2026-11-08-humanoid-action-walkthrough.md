---
title: Dependency audit for the humanoid action walkthrough
last_reviewed: 2026-11-08
owner: carloshvp
---

# Dependency audit for the humanoid action walkthrough

## Which dependencies changed and why

The [walkthrough lockfile](../../examples/humanoid-action-governed/requirements.txt)
pins 20 Python distributions. Pydantic with email validation, PyYAML,
cryptography, httpx and python-dateutil support the local AgentMesh imports.
The example uses rfc8785 to serialize signed records. The revised lock drops
PyNaCl, PyJWT, rich, structlog, agentrust-trace, opentelemetry-api and their
unused transitive dependencies.

Cryptography's CPython dependency cffi moves from 2.1.1 to 2.0.0. That release
carries an MIT license accepted by the dependency review configuration.
PyPI declares PSF-2.0 for the retained typing-extensions 4.16.0 pin. GitHub
dependency review reports a compound license expression for the same pin.

## Security advisory relevance

Certifi moves from 2026.7.22 to 2026.10.23 to pick up the fix for
GHSA-6q48-6c7w-9gw2. All locked releases cleared the seven-day release age
check on 2026-11-08. The PyPI vulnerability scan found no known advisories
for the revised pins.

## Breaking change risk assessment

The lock applies only to this example. Its dependencies install in a fresh
Python 3.11 environment, and the tests exercise approval, signature
verification, replay and altered evidence. The example uses simulated inputs
and runs without external services after setup.
