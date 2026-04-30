# AI-assisted contributions to security-sensitive code

This document provides guidance for contributors using AI development tools when
working on security-sensitive areas of the Agent Governance Toolkit. It supplements
the AI contribution policy in [CONTRIBUTING.md](../../CONTRIBUTING.md).

## Scope

Security-sensitive areas include, but are not limited to:

- **Cryptographic implementations**: key generation, signing, verification, hashing,
  certificate handling, trust chain validation
- **Authentication and authorization**: identity verification, credential management,
  token handling, access control, capability gating
- **Input validation and sanitization**: prompt injection detection, allowlist/blocklist
  logic, content filtering, boundary enforcement
- **Policy enforcement**: sandbox controls, kill switches, budget enforcement,
  compliance gates, governance rules
- **Supply chain tooling**: dependency auditing, package publishing, CI/CD pipeline
  security, ESRP configuration

## Requirements for AI-assisted security changes

All requirements from CONTRIBUTING.md apply. The following additional requirements
apply to security-sensitive code:

### 1. Independent validation of AI-generated tests

AI-generated tests for AI-generated implementations risk circular validation: the
tests may only confirm that the implementation does what the AI intended, not what
is actually correct. For security-sensitive changes:

- Write at least one test case by hand that validates the security property
  independently of how the implementation works.
- Include negative tests: inputs that must be rejected, operations that must fail,
  boundaries that must hold.
- If the change fixes a vulnerability, include a regression test that reproduces
  the original attack vector.

### 2. No secrets or sensitive data in AI tool prompts

Do not include the following in prompts to AI tools:

- Private keys, certificates, or signing credentials
- API tokens, connection strings, or service account credentials
- Internal infrastructure details (Key Vault names, tenant IDs, subscription IDs)
- Customer data or PII
- Vulnerability details before public disclosure

### 3. Review AI output for common security anti-patterns

AI tools may generate code that appears correct but introduces subtle vulnerabilities.
Watch for:

- **Hallucinated package names**: AI may suggest packages that do not exist or are
  name-squatted. Verify every dependency against the official registry before adding it.
- **Deprecated cryptographic algorithms**: MD5, SHA-1 for integrity, DES, RC4, RSA
  with small key sizes. Use the algorithms already established in the codebase.
- **Insecure defaults**: `verify=False` on TLS connections, `shell=True` in subprocess
  calls, overly permissive CORS or file permissions, disabled certificate validation.
- **Timing-unsafe comparisons**: using `==` instead of `hmac.compare_digest()` for
  secret comparison.
- **Incomplete input validation**: AI may validate the happy path but miss edge cases
  like empty strings, Unicode normalization attacks, or IEEE 754 special values.
- **Allowlist/blocklist ordering errors**: as seen in the PR #1613 fix, the order in
  which allowlists and blocklists are evaluated matters for security. Ensure
  fail-closed behavior.

### 4. Cryptographic code review checklist

For changes to cryptographic code, verify:

- [ ] No custom cryptographic primitives are introduced (use established libraries)
- [ ] Key sizes meet current standards (RSA >= 2048, ECDSA >= P-256, AES >= 128)
- [ ] Random number generation uses `secrets` module or OS-level CSPRNG, not `random`
- [ ] Certificates are validated against a trust store, not accepted blindly
- [ ] Signature verification uses constant-time comparison

### 5. Sandbox and isolation changes

For changes to sandbox controls, capability isolation, or kill switches:

- [ ] The change cannot be bypassed by malformed input (see CostGuard advisory)
- [ ] State mutations are thread-safe under concurrent access
- [ ] Kill switches fail closed: if the enforcement mechanism errors, the operation
  is denied, not permitted
- [ ] Resource limits cannot be set to negative, NaN, or Infinity values

## Maintainer review expectations

Security-sensitive PRs receive heightened review regardless of how they were produced.
Maintainers may:

- Request the contributor explain the security properties the change preserves
- Ask for additional test cases covering adversarial inputs
- Require a second maintainer review for changes to core security primitives
- Run additional static analysis or fuzzing before merge

## Reporting security issues

If you discover a security vulnerability while using AI tools on this codebase,
follow the reporting process in [SECURITY.md](../../SECURITY.md). Do not disclose
vulnerability details in public issues, PRs, or AI tool conversations.
