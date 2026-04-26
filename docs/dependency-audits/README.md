# Dependency Audits

This directory contains dependency audit documents required by the
`ci/vendored-patch-audit.sh` CI gate.

When a PR changes lockfiles (`requirements.txt`, `Cargo.lock`,
`package-lock.json`, `go.sum`, `packages.lock.json`, etc.) or vendored
content, it **must** include a dated audit document here.

## File naming

```
YYYY-MM-DD-<short-description>.md
```

## Required sections

1. **Which dependencies changed and why**
2. **Security advisory relevance** (CVE numbers if applicable)
3. **Breaking change risk assessment**
