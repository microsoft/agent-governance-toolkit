# Security Audits

This directory contains security audit documents required by the
`ci/security-audit-required.sh` CI gate.

When a PR touches core security surfaces (policy engine, identity, trust,
encryption, execution rings, kill switch), it **must** include a dated
audit document here.

## File naming

```
YYYY-MM-DD-<short-description>.md
```

## Required sections

1. **What changed and why** — brief description of the capability change
2. **Threat model impact** — new attack surfaces, mitigations applied
3. **Test coverage** — what tests validate the security-relevant behavior

## Inspiration

This practice is adapted from [AzureClaw's Phase 0 CI gates](https://github.com/Azure/azureclaw),
which require a security audit doc for every capability-introducing change.
