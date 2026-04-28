# OWASP Top 10 for LLM Applications — Coverage Mapping

> **Disclaimer**: This document is an internal self-assessment mapping, NOT a validated certification or third-party audit. It documents how the toolkit's capabilities align with the referenced standard. Organizations must perform their own compliance assessments with qualified auditors.


**Mapping Version:** 1.0
**OWASP Reference:** [OWASP Top 10 for LLM Applications (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
**Toolkit Version:** v1.1.0
**Last Updated:** April 2026

> **Edition note:** This mapping uses the risk categories from the [OWASP Top 10 for
> LLM Applications v1.1 (2023)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
> as specified in [Issue #697](https://github.com/microsoft/agent-governance-toolkit/issues/697).
> The 2025 revision renumbers several risks (e.g., Sensitive Information Disclosure
> moved from LLM06 to LLM02), renames others (Model Theft → Unbounded Consumption,
> Overreliance → Misinformation), and introduces two new categories: **System Prompt
> Leakage (LLM07)** and **Vector and Embedding Weaknesses (LLM08)**. Coverage notes
> for the new 2025 categories are included at the end of this document.

---

## Executive Summary

The toolkit contains detection mechanisms for 9 of 10 LLM risks. However, 6 of 10
share a structural gap where detection modules exist as standalone utilities but are
not wired into the `BaseIntegration` enforcement lifecycle. A single integration
effort — adding optional auto-wiring controlled by `GovernancePolicy` flags — would
close gaps across multiple risks simultaneously. The strongest enforcement is in
plugin/tool security (MCPGateway) and execution privilege control (rings, kill switch).
The widest gaps are in output sanitization and sensitive data protection.

---

## Coverage Summary

| # | OWASP Risk | Coverage | Key Mechanism | Key Gap |
|---|-----------|----------|---------------|---------|
| LLM01 | Prompt Injection | Partial | 6 regex pattern groups + base64 decoding + MCP tool scanning | Regex-only; no semantic detection; opt-in, not default-wired |
| LLM02 | Insecure Output Handling | Partial | AST-based Python code validation + drift detection | `post_execute()` never blocks; Python-only; no text output sanitization |
| LLM03 | Training Data Poisoning | Partial | MemoryGuard for runtime memory stores | Training pipeline out of scope; MemoryGuard not wired into adapters |
| LLM04 | Model Denial of Service | Partial | Token/call/timeout limits + concurrency semaphore + circuit breakers | TokenBudgetTracker advisory-only; RateLimiter not wired; no payload size limits |
| LLM05 | Supply Chain Vulnerabilities | Partial | SBOM + Ed25519 signing + MCP fingerprinting + ContentHashInterceptor | SupplyChainGuard reporting-only; signing opt-in |
| LLM06 | Sensitive Information Disclosure | Partial | PII patterns in MCP gateway + secret detection in codegen + egress policy | Only 2 PII patterns; no output text filtering; audit-log PII minimization remains incomplete |
| LLM07 | Insecure Plugin Design | Partial | MCPGateway 5-stage pipeline + rug-pull detection + schema abuse scanning | JSON Schema composition ($ref/oneOf) unexamined; gateway and scanner disconnected |
| LLM08 | Excessive Agency | Partial | Execution rings + kill switch + rogue detection + scope guard | Kill switch manual-only; detection modules advisory, not auto-wired to enforcement |
| LLM09 | Overreliance | Partial | Drift detection + confidence threshold + adversarial evaluator | No fact-checking; confidence attribute never provided by frameworks |
| LLM10 | Model Theft | Gap | N/A | Out of scope — toolkit wraps LLM APIs, does not host models |

**Result: 0 fully mitigated, 9 partially covered, 1 out-of-scope gap.**

---

## Methodology

This mapping was produced using a structured multi-perspective analysis with
independent redundancy at each stage:

1. **Discovery**: Two independent code scans of all 4 packages, producing
   file:line citations for mitigations against each risk. Disagreements between
   scans flagged for deeper investigation.
2. **Adversarial validation**: Every claimed mitigation subjected to bypass
   testing. Scope boundaries assessed for each gap.
3. **Compliance audit**: All findings cross-validated for citation accuracy,
   evidence completeness, and missed sub-risks.
4. **Strategic review**: Defense-in-depth assessment and enterprise readiness
   evaluation.

Evidence standard: line-level code citations + adversarial bypass testing.

---

## Cross-Cutting Finding: Detection Without Enforcement

Six of ten risks share a structural pattern: detection mechanisms exist as standalone utilities but are not wired into the `BaseIntegration` lifecycle. Specifically:

| Module | What it does | What it doesn't do |
|--------|-------------|-------------------|
| `PromptInjectionDetector` | Scans text for injection patterns | Not called by any adapter's `pre_execute()` |
| `TokenBudgetTracker` | Tracks token usage, fires warning callbacks | Never blocks execution; `is_exceeded` flag unchecked |
| `RateLimiter` | Token-bucket rate limiting with `allow()` | Not wired into any adapter or interceptor |
| `BoundedSemaphore` | Concurrency limiter with backpressure | Not integrated into `BaseIntegration.pre_execute()` |
| `ScopeGuard` | Evaluates file/line count scope | Returns advisory strings; nothing checks the decision |
| `SupplyChainGuard` | Scans for supply chain risks | Returns findings; no blocking pipeline |
| `MCPSecurityScanner` | Detects tool poisoning, rug pulls, schema abuse | Results not consumed by MCPGateway decisions |
| `post_execute()` | Computes drift scores, emits events | Always returns `(True, None)` — never blocks |

**Note:** These assessments apply to the `BaseIntegration` path used by most
adapters. The MAF (Microsoft Agent Framework) adapter provides enforcement wiring
for rogue detection, governance policy, and ring enforcement via its
`FunctionMiddleware` pipeline — but this covers only the Semantic Kernel
integration path.

**Recommendation:** A unified integration effort — adding optional auto-wiring in
`BaseIntegration.__init__()` controlled by `GovernancePolicy` flags — would close
gaps across LLM01, LLM02, LLM04, LLM06, and LLM07 simultaneously. Recommended
interceptor ordering: rate limiting first, then scope guard, then content
inspection (to avoid expensive regex on requests that would be rate-limited
anyway).

---

## Detailed Mapping

### LLM01: Prompt Injection

> *Attackers manipulate LLM behavior through crafted inputs that override system instructions, either directly or via poisoned external content.*

**Coverage: Partial**

**Mitigations:**

- `PromptInjectionDetector` — `prompt_injection.py:147-197` — 6 compiled regex pattern groups covering direct overrides, delimiters, role-play/jailbreak, context manipulation, multi-turn escalation, and encoding attacks. Configurable sensitivity (strict/balanced/permissive).
- Base64 payload decoding — `prompt_injection.py:548-563` — Decodes base64 candidates and checks for suspicious keywords (ignore, override, system, password, exec, eval, import os).
- Canary token detection — `prompt_injection.py:595-612` — Detects system prompt leakage via planted canary strings. CRITICAL threat level, confidence=1.0.
- MCP tool description scanning — `mcp_security.py:557-603` — Reuses `PromptInjectionDetector` on MCP tool descriptions to catch injection embedded in tool metadata.
- `ConversationGuardian` — `conversation_guardian.py:83-107` — Evasion resistance via `normalize_text()` with homoglyph/leetspeak/zero-width stripping.
- LlamaFirewall integration — `llamafirewall.py:63-98` — Chains Meta's LlamaFirewall with Agent OS detection in 4 modes (CHAIN_BOTH, VOTE_MAJORITY, etc.). Graceful fallback when LlamaFirewall not installed.
- Blocked patterns — `base.py:153` — Supports substring, regex, and glob pattern blocking on tool arguments.
- Fail-closed — `prompt_injection.py:358-373` — Detection errors result in CRITICAL threat level with `is_injection=True`.

**Coverage Boundaries:**

| Technique Category | Covered | Notes |
|--------------------|---------|-------|
| Direct English-language overrides | Yes | 6 compiled regex pattern groups match known phrases |
| Base64-encoded payloads | Yes | Decoded and inspected for suspicious keywords |
| Canary token leakage | Yes | Planted canary strings detected at CRITICAL level |
| Semantically equivalent paraphrasing | No | Regex patterns match literal phrases, not semantic intent |
| Non-English injections | No | All patterns are English-only; no multilingual normalization |
| Indirect injection via tool output | No | Detector screens input only; tool results are not scanned |
| URL encoding / ROT13 applied | No | Only base64 and hex/unicode escape sequences covered |
| Allowlist configuration abuse | No | `DetectionConfig.allowlist` (line 123) lacks input validation (see #744) |

**Recommendations:**

- Wire `PromptInjectionDetector` into `BaseIntegration.pre_execute()` via a `GovernancePolicy.prompt_injection_detection` flag (default: True for regex).
- Document LlamaFirewall integration as the recommended ML-based upgrade path for semantic detection (covers paraphrasing and multilingual attacks).
- Share `ConversationGuardian`'s `normalize_text()` homoglyph/evasion logic with `PromptInjectionDetector`.
- Add allowlist validation (minimum length, format constraints) to prevent overly broad entries from disabling detection.

---

### LLM02: Insecure Output Handling

> *Insufficient validation or sanitization of LLM outputs before passing them to downstream components, potentially enabling XSS, SSRF, or code execution.*

**Coverage: Partial**

**Mitigations:**

- `CodeSecurityValidator` — `secure_codegen.py:179-237` — AST-based validation of LLM-generated Python code. Detects dangerous imports (17 modules), dangerous calls (22+ functions), shell injection (`shell=True`), SQL injection (string formatting), path traversal (`../`), and hardcoded secrets (5 patterns).
- Code sanitization — `secure_codegen.py:384-393` — Comments out dangerous lines in generated code.
- Secure code templates — `secure_codegen.py:401-526` — Pre-vetted templates for HTTP clients, file reads, SQL queries, and subprocess calls.
- `GuardrailsKernel` — `guardrails_adapter.py:1-80` — Bridge to Guardrails AI validators for input and output validation with BLOCK/WARN/FIX actions.
- Drift detection — `base.py:977-1038` — Computes semantic drift score between baseline and actual output using `SequenceMatcher`. Emits `DRIFT_DETECTED` event when threshold exceeded.

**Coverage Boundaries:**

| Technique Category | Covered | Notes |
|--------------------|---------|-------|
| Python code validation (AST) | Yes | 17 dangerous imports, 22+ dangerous calls, shell/SQL injection, path traversal, secrets |
| Drift detection on outputs | Partial | `post_execute()` emits `DRIFT_DETECTED` events but always returns `(True, None)` — advisory only |
| Non-Python code validation | No | `secure_codegen.py:193` raises `ValueError` for any language other than Python |
| Natural language output filtering | No | No text output sanitization exists for PII, secrets, or sensitive data in prose |
| HTML/XSS output encoding | No | No escaping or encoding for outputs rendered in web UIs |

**Recommendations:**

- Add `GovernancePolicy.block_on_drift: bool = False` and honor it in `post_execute()` (1-line change + policy flag).
- Ship a basic `OutputSanitizer` that scans tool outputs for the dangerous patterns already defined in `mcp_gateway.py`.
- Document that multi-language code validation requires CodeShield integration (available via LlamaFirewall's `scan_code()`).

---

### LLM03: Training Data Poisoning

> *Manipulation of training data to introduce vulnerabilities, biases, or backdoors into the model.*

**Coverage: Partial**

**Mitigations:**

- `MemoryGuard` — `memory_guard.py:186-242` — Guards agent runtime memory stores (RAG, episodic, working memory) against poisoning. Pre-write validation checks for injection patterns (7 regex), code injection (6 regex), excessive special characters (>30% threshold), and Unicode bidi/homoglyph manipulation.
- Hash integrity — `memory_guard.py:244-259` — SHA-256 hash comparison for tamper detection on stored entries.
- Batch scanning — `memory_guard.py:261-295` — Integrity + content scanning of existing memory entries.
- Write audit trail — `memory_guard.py:220-241` — Every write attempt logged with timestamp, source, content hash, and allow/deny decision.
- Fail-closed — `memory_guard.py:199-210` — Validation errors block the write.

**Adversarial Validation:**

Training pipeline data poisoning is architecturally out of scope — the toolkit does not manage model training, fine-tuning, or dataset curation. `MemoryGuard` addresses the runtime variant: poisoning of RAG stores, episodic memory, and working context that influence agent behavior at inference time.

**Recommendations:**

- Wire `MemoryGuard.validate_write()` into adapters that manage agent memory/context.
- Document the scope boundary: "Training pipeline data poisoning is out of scope. Runtime memory and context poisoning (RAG injection, episodic memory tampering) is addressed by MemoryGuard."

---

### LLM04: Model Denial of Service

> *Resource-intensive queries that consume excessive compute, degrade availability, or increase costs.*

**Coverage: Partial**

**Mitigations:**

- Token limits — `base.py:150` — `GovernancePolicy.max_tokens` (default 4096). Validated as positive integer on construction.
- Tool call limits — `base.py:151` — `GovernancePolicy.max_tool_calls` (default 10). Enforced by `PolicyInterceptor` (line 705-709).
- Timeout — `base.py:155` — `GovernancePolicy.timeout_seconds` (default 300s). Checked in `pre_execute` (line 944).
- Concurrency limits — `base.py:805-859` — `BoundedSemaphore` with backpressure. Rejects requests when capacity exhausted.
- MCPGateway rate limiting — `mcp_gateway.py:219-225` — Per-agent call budget enforcement. Manual reset methods exist (`reset_agent` at line 292, `reset_all` at line 296) but no automatic time-window reset.
- `RateLimiter` — `rate_limiter.py:93-101` — Token-bucket algorithm, thread-safe with `threading.Lock`. Returns `False` when budget exhausted.
- `RingBreachDetector` — `breach_detector.py:68-99` — Sliding-window call-rate analysis with severity thresholds. Per-agent circuit breaker trips on HIGH/CRITICAL.

**Coverage Boundaries:**

| Technique Category | Covered | Notes |
|--------------------|---------|-------|
| Tool call count limits | Yes | `PolicyInterceptor` enforces `max_tool_calls` per session (line 705-709) |
| MCPGateway call budget | Yes | Per-agent budget enforcement; manual reset methods exist but no automatic time-window reset |
| Token budget tracking | Partial | `TokenBudgetTracker` tracks usage and fires warnings but never blocks execution |
| Token-bucket rate limiting | No (unwired) | `RateLimiter` has correct algorithm but is not imported by any adapter or interceptor |
| Concurrency limiting | No (unwired) | `BoundedSemaphore` exists but is not integrated into `BaseIntegration.pre_execute()` |
| Payload size validation | No | No input size limits; arbitrarily large parameters are serialized and processed |

**Recommendations:**

- Wire `RateLimiter` and `TokenBudgetTracker` into `BaseIntegration` with blocking behavior controlled by policy flags (`block_on_budget_exceeded`, `block_on_rate_limit`).
- Add `GovernancePolicy.max_input_length` as a coarse payload size guard.
- Add automatic time-window reset to MCPGateway's call counter.
- Note: prompt-length validation relative to model context windows is model-serving scope, not governance scope.

---

### LLM05: Supply Chain Vulnerabilities

> *Vulnerabilities in third-party components, pre-trained models, or data pipelines used by LLM applications.*

**Coverage: Partial**

**Mitigations:**

- `SupplyChainGuard` — `supply_chain.py:72-79` — Detects freshly published packages (<7 days), unpinned versions, and typosquatting (SequenceMatcher ratio >0.85).
- SBOM generation — `sbom.py:46+` — SPDX 2.3 format with SHA-256 hashing and dependency tracking.
- Artifact signing — `signing.py:18-33` — Ed25519 signing with `cryptography` library. Fail-closed when library missing (raises `ImportError`).
- MCP tool fingerprinting — `mcp_security.py:367-454` — SHA-256 fingerprints of tool definitions with change detection via `check_rug_pull()`.
- MCP typosquatting — `mcp_security.py:683-741` — Levenshtein distance check (<=2 edits) for tool name impersonation.
- `ContentHashInterceptor` — `base.py:714-782` — SHA-256 content hashing of tool callables. Strict mode blocks unregistered tools.
- CI workflows — `dependency-review.yml`, `codeql.yml`, `scorecard.yml`, `sbom.yml` — Automated dependency audit, CodeQL scanning, OpenSSF Scorecard, SBOM generation.

**Coverage Boundaries:**

| Technique Category | Covered | Notes |
|--------------------|---------|-------|
| Dependency metadata scanning | Partial | `SupplyChainGuard` produces findings but has no blocking pipeline — reporting only |
| Artifact signing | Partial | Ed25519 signing is fail-closed when library missing, but signing itself is opt-in |
| Tool integrity verification | Partial | `ContentHashInterceptor` is fail-closed but requires cooperative adapter to set `content_hash` metadata |
| CI-level scanning | Yes | dependency-review, CodeQL, OpenSSF Scorecard, SBOM generation workflows active |
| MCP tool fingerprinting | Yes | SHA-256 fingerprints with rug-pull change detection |

**Recommendations:**

- Connect `SupplyChainGuard` findings to a blocking pipeline (e.g., raise on CRITICAL severity findings).
- Make `ContentHashInterceptor` hash computation automatic on tool registration, rather than requiring adapter cooperation.
- Add SLSA provenance attestation generation.

---

### LLM06: Sensitive Information Disclosure

> *LLM applications revealing confidential data, PII, or proprietary information through their outputs or logs.*

**Coverage: Partial**

**Mitigations:**

- PII patterns — `mcp_gateway.py:34-42` — Built-in regex for SSN (`\b\d{3}-\d{2}-\d{4}\b`) and credit card numbers in tool parameters. Returns `(False, reason)` on match.
- Blocked patterns — `base.py:695-701` — `PolicyInterceptor.intercept()` checks `blocked_patterns` against tool arguments.
- Secret detection — `secure_codegen.py:346-360` — 5 regex patterns for API keys, passwords, tokens, AWS keys, private keys in generated code. CRITICAL severity.
- Egress policy — `egress_policy.py:113-139` — Domain-level egress filtering with first-match-wins and default-deny.
- Canary leak detection — `prompt_injection.py:595-612` — Detects system prompt canary tokens in user input.

**Coverage Boundaries:**

| Technique Category | Covered | Notes |
|--------------------|---------|-------|
| SSN / credit card in tool parameters | Yes | Regex patterns in `mcp_gateway.py:34-42` block matching arguments |
| Other PII (email, phone, address) | No | Only 2 PII patterns implemented |
| Sensitive data in LLM text output | No | Blocked patterns check tool arguments only, not LLM response text |
| Audit log parameter redaction | No | `mcp_gateway.py:165` stores raw `parameters=params` with no redaction (see below) |

**Audit Log Disclosure (elevated finding):** The audit trail is the single most
reliable disclosure vector because it is always active when `log_all_calls=True`
(the default). Every tool call's full parameters — including any PII, credentials,
or tokens passed as arguments — are stored verbatim in `AuditEntry` and exposed
via `logger.info()`. This means the toolkit's own security logging is a data leak
pathway. This finding warrants priority remediation.

**Recommendations:**

- **Priority:** Add `GovernancePolicy.redact_audit_pii: bool = False` for pattern-based redaction of `AuditEntry.parameters` before persistence.
- Expand default PII patterns to cover the OWASP-recommended set (email, phone, IP address, JWT tokens).
- Apply the same pattern scanning to LLM outputs via `post_execute()` or a new output interceptor.
- Document integration path for external DLP services as an advanced configuration.

---

### LLM07: Insecure Plugin Design

> *Plugins or tools that accept untrusted input without adequate validation, enabling injection, privilege escalation, or data exfiltration.*

**Coverage: Partial**

**Mitigations:**

- MCPGateway 5-stage pipeline — `mcp_gateway.py:134-251` — Deny-list, allow-list, parameter sanitization (policy + built-in patterns), rate limiting, human-in-the-loop approval. Fail-closed on errors.
- Tool definition scanning — `mcp_security.py:300-331` — Comprehensive scan for hidden instructions, description injection, schema abuse, and cross-server attacks.
- Rug-pull detection — `mcp_security.py:413-454` — SHA-256 fingerprinting of tool definitions with change detection.
- Schema abuse detection — `mcp_security.py:605-681` — Flags overly permissive schemas, suspicious field names (`system_prompt`, `webhook`, `callback_url`), instruction-bearing defaults.
- `ContentHashInterceptor` — `base.py:714-782` — SHA-256 integrity verification of tool callables. Strict mode blocks unregistered tools.
- RBAC — `rbac.py:88-92` — 4-role access control with action-level permissions.
- Human approval — `mcp_gateway.py:231-249` — Sensitive tools require explicit human approval via configurable callback. Fails closed on callback errors.

**Coverage Boundaries:**

| Technique Category | Covered | Notes |
|--------------------|---------|-------|
| Tool allow/deny lists | Yes | MCPGateway 5-stage pipeline with fail-closed error handling |
| Parameter pattern matching | Yes | `json.dumps()` flattens nested structures; regex catches patterns regardless of depth |
| Unicode-normalized parameters | No | `mcp_gateway.py:39` regex matches ASCII semicolons only; fullwidth Unicode variants not normalized |
| JSON Schema composition ($ref/oneOf) | No | `_check_schema_abuse()` inspects top-level properties only; composition keywords unresolved |
| Runtime rug-pull detection | No | `check_rug_pull()` runs at scan-time; MCPGateway does not invoke scanner at execution time |
| Human-in-the-loop for sensitive tools | Yes | Configurable approval callback with fail-closed behavior |

**Recommendations:**

- Integrate `MCPSecurityScanner` results into `MCPGateway` decisions (connect scan-time detection to execution-time enforcement).
- Add JSON Schema composition keyword resolution ($ref, oneOf, allOf, anyOf) to `_check_schema_abuse()`.
- Apply Unicode normalization (NFKC) to tool parameters before pattern matching.

---

### LLM08: Excessive Agency

> *LLM agents taking actions beyond their intended scope, including excessive autonomy, permissions, or functionality.*

**Coverage: Partial**

**Mitigations:**

- Execution rings — `enforcer.py:47-88` — 4-tier privilege model (Ring 0-3). Ring 0 always denied in Public Preview. Agent ring derived from trust score.
- Ring enforcement — `enforcer.py:94-97` — `should_demote()` checks trust score drops.
- Kill switch — `kill_switch.py:86-118` — Immediate agent termination with 6 kill reasons and saga step compensation.
- `RogueDetectionMiddleware` — `maf_adapter.py:416-501` — Raises `MiddlewareTermination` when `quarantine_recommended=True`. **Only enforcement point that auto-blocks.**
- Breach detector — `breach_detector.py:104-178` — Sliding-window frequency analysis with severity classification and internal circuit breaker.
- Rogue agent detection — `rogue_detector.py:276-374` — Composite risk scoring from frequency z-score, entropy deviation, and capability profile violations.
- Tool allowlist — `base.py:689-693` — `PolicyInterceptor` blocks tools not in `allowed_tools`.
- Max tool calls — `base.py:705-709` — Hard limit per session.
- Human approval — `base.py:682-685` — `require_human_approval` halts all tool calls pending review.
- Scope guard — `scope_guard.py:139-249` — File/line count limits with PASS/SOFT_FAIL/HARD_FAIL decisions.
- Escalation quorum — `escalation.py:1-80` — M-of-N approval for sensitive actions with timeout and default-deny.

**Coverage Boundaries:**

| Technique Category | Covered | Notes |
|--------------------|---------|-------|
| Tool allowlist enforcement | Yes | `PolicyInterceptor` blocks tools not in `allowed_tools` (line 689-693) |
| Max tool calls per session | Yes | Hard limit enforced at line 705-709 |
| Human approval gates | Yes | `require_human_approval` halts all tool calls pending review |
| Rogue detection → auto-block (MAF path) | Yes | `RogueDetectionMiddleware` raises `MiddlewareTermination` (MAF adapter only) |
| Rogue detection → auto-block (other paths) | No | Standalone `RogueAgentDetector` sets `quarantine_recommended` but takes no enforcement action |
| Kill switch auto-trigger | No | Exactly 1 call site: CLI handler at `session_commands.py:120`; no detection system invokes it |
| ScopeGuard enforcement | No | Returns advisory `ScopeEvaluation`; no production code checks the decision |

**Recommendations:**

- Ship an optional `RogueEnforcementBridge` that connects `RogueAgentDetector.assess()` to `KillSwitch.kill()` with configurable risk thresholds.
- Wire `ScopeGuard` evaluation results into a `ToolCallInterceptor` that blocks on HARD_FAIL.
- The separation between detection and enforcement is architecturally intentional (operators control enforcement policy), but the toolkit should provide the wiring as opt-in rather than requiring custom glue code.

---

### LLM09: Overreliance

> *Uncritical acceptance of LLM outputs without verification, leading to misinformation, security vulnerabilities, or faulty decisions.*

**Coverage: Partial**

**Mitigations:**

- Drift detection — `base.py:977-1038` — `SequenceMatcher`-based drift scoring between baseline and actual output. Emits `DRIFT_DETECTED` event when threshold exceeded.
- Confidence threshold — `base.py:964-973` — `GovernancePolicy.confidence_threshold` (default 0.8) gates actions below minimum confidence.
- Adversarial evaluator — `_adversarial_impl.py:120-191` — Runs 8 built-in attack vectors against governance interceptor. Produces per-category risk scores. Testing utility, not runtime enforcement.
- Dry-run mode — `dry_run.py:63-104` — Shadow-mode evaluation that records what would happen without blocking.
- Trust scoring — `agentmesh/reward/scoring.py:1-100` — 5-dimensional scoring (policy compliance, resource efficiency, output quality, security posture, collaboration health) with exponential moving average.

**Coverage Boundaries:**

| Technique Category | Covered | Notes |
|--------------------|---------|-------|
| Drift detection (same agent) | Partial | `post_execute()` computes scores and emits events but never blocks (returns `(True, None)` always) |
| Confidence threshold gating | No (dead code) | `base.py:966` uses `getattr(input_data, 'confidence', None)` — no framework adapter populates this attribute |
| Cascading hallucination (cross-agent) | No | Drift detection is per-agent; no cross-agent hallucination propagation detection |
| Factual accuracy verification | No | No fact-checking, grounding, or retrieval verification — application-layer concern |
| Adversarial governance testing | Yes | `AdversarialEvaluator` runs 8 attack vectors against interceptor (testing utility, not runtime) |

**Recommendations:**

- Document the scope boundary: "The toolkit detects behavioral anomalies that correlate with overreliance (drift, trust decay) but does not verify factual accuracy. Fact-checking and grounding are application-layer concerns."
- Make drift detection block-capable via `GovernancePolicy.block_on_drift` flag.
- Explore cross-agent drift correlation for multi-agent deployments.

---

### LLM10: Model Theft

> *Unauthorized access to, copying, or extraction of proprietary LLM models through API queries, side channels, or direct access.*

**Coverage: Gap (Out of Scope)**

The toolkit wraps LLM API clients. It does not host models, manage model weights, or control model serving infrastructure. Model theft prevention requires controls at the inference/serving layer, which is architecturally outside this toolkit's domain.

**Indirect mitigations:**

- Rate limiting via `RateLimiter` — limits query volume that could be used for extraction-via-distillation.
- Audit logging of all tool calls — forensic trail for detecting suspicious query patterns.
- `RogueAgentDetector` frequency analysis — detects high-volume systematic querying that could indicate extraction attempts.

These are defense-in-depth signals, not primary mitigations.

**Recommendations:**

- Document as out of scope with indirect mitigations cited.
- Recommend model-serving-layer protections: API key rotation, model endpoint access logging, output watermarking, extraction query detection.

---

## Relationship to OWASP Agentic Top 10

This document covers the **OWASP Top 10 for LLM Applications (2025)** — risks specific to LLM-powered applications. The toolkit also maps against the **OWASP Top 10 for Agentic Applications (2026)** in [`docs/OWASP-COMPLIANCE.md`](../OWASP-COMPLIANCE.md), which covers agent-specific risks (goal hijack, rogue agents, cascading failures, etc.).

Several risks overlap between the two lists:

| LLM Risk | Agentic Risk | Overlap |
|----------|-------------|---------|
| LLM01 Prompt Injection | ASI-01 Agent Goal Hijack | Prompt injection is one vector for goal hijacking |
| LLM05 Supply Chain | ASI-04 Supply Chain | Same risk, different framing |
| LLM07 Insecure Plugin | ASI-02 Tool Misuse | Plugin security is a subset of tool governance |
| LLM08 Excessive Agency | ASI-10 Rogue Agents | Excessive agency can manifest as rogue behavior |

The Agentic Top 10 mapping uses a different evidence standard (capability presence)
than this document (verified enforcement + adversarial bypass testing). A similar
adversarial validation of the Agentic Top 10 would likely surface comparable
detection-without-enforcement gaps.

---

## OWASP 2025 Edition: New Risk Categories

The 2025 revision of the OWASP Top 10 for LLM Applications introduces two new
categories not present in the 2023 edition. Preliminary coverage notes:

### LLM07 (2025): System Prompt Leakage

> *Unauthorized disclosure of system prompts that reveal internal logic, security
> controls, or sensitive configuration.*

**Coverage: Partial**

The toolkit's canary token detection (`prompt_injection.py:595-612`) catches
system prompt leakage when canary strings appear in user-visible output.
`MemoryGuard` protects policy-controlled context (`vfs://{agent_id}/policy/*`)
as read-only. However, there is no dedicated system prompt protection mechanism —
no prompt encryption, no output scanning for known system prompt fragments, and
no monitoring for extraction attempts (repeated probing queries designed to
elicit system instructions).

### LLM08 (2025): Vector and Embedding Weaknesses

> *Vulnerabilities in RAG pipelines where embeddings, vector stores, or retrieval
> mechanisms are manipulated to inject malicious content or poison context.*

**Coverage: Partial**

`MemoryGuard` (`memory_guard.py:186-295`) validates writes to agent memory stores
(including RAG stores) with injection pattern detection, hash integrity, and
content scanning. This addresses write-path poisoning. However, there is no
read-path validation — poisoned content that was written before `MemoryGuard`
was deployed, or content poisoned at the embedding/indexing layer, would not be
detected at retrieval time. No embedding-level integrity verification exists.
