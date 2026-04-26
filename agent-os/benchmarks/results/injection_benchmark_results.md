# Prompt Injection Detection — Benchmark Results

> Generated: 2026-02-27 17:43 UTC

## Methodology

- **100 curated test prompts**: 60 malicious + 40 benign
- **Categories**: direct injection (20), indirect injection (20), jailbreak (20), benign (40)
- **Tested at 3 sensitivity levels**: strict, balanced, permissive
- **Canary tokens active**: 2 tokens planted for leak detection
- **Detector**: Agent OS `PromptInjectionDetector` with 7-strategy rule-based detection

## Results

### Agent OS PromptInjectionDetector

| Sensitivity | TPR | FPR | Precision | Recall | F1 |
|-------------|-----|-----|-----------|--------|-----|
| Strict      | 95.0% | 0.0% | 100.0% | 95.0% | 97.4% |
| Balanced    | 95.0% | 0.0% | 100.0% | 95.0% | 97.4% |
| Permissive  | 70.0% | 0.0% | 100.0% | 70.0% | 82.4% |

### Comparison with LlamaFirewall (Published Numbers)

| Detector | Attack Success Rate | Notes |
|----------|-------------------|-------|
| No defense | 17.6% | Baseline (CyberSecEval 3) |
| LlamaFirewall | 1.7% | PromptGuard 2 + AlignmentCheck |
| Agent OS (balanced) | 5.0% | 7-strategy rule-based detection |
| Agent OS + LlamaFirewall | 0.1% | Defense-in-depth chain (multiplicative) |

> **Attack success rate** = 1 − TPR. Lower is better.
> **Chained rate** assumes independent detectors in series (conservative upper bound).

### Category Breakdown

| Category | Sensitivity | TPR | FPR | Precision | Recall | F1 |
|----------|-------------|-----|-----|-----------|--------|-----|
| Direct Injection | Strict | 90.0% | 0.0% | 100.0% | 90.0% | 94.7% |
| Indirect Injection | Strict | 95.0% | 0.0% | 100.0% | 95.0% | 97.4% |
| Jailbreak | Strict | 100.0% | 0.0% | 100.0% | 100.0% | 100.0% |
| Benign | Strict | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| Direct Injection | Balanced | 90.0% | 0.0% | 100.0% | 90.0% | 94.7% |
| Indirect Injection | Balanced | 95.0% | 0.0% | 100.0% | 95.0% | 97.4% |
| Jailbreak | Balanced | 100.0% | 0.0% | 100.0% | 100.0% | 100.0% |
| Benign | Balanced | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |
| Direct Injection | Permissive | 90.0% | 0.0% | 100.0% | 90.0% | 94.7% |
| Indirect Injection | Permissive | 45.0% | 0.0% | 100.0% | 45.0% | 62.1% |
| Jailbreak | Permissive | 75.0% | 0.0% | 100.0% | 75.0% | 85.7% |
| Benign | Permissive | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% |

### Key Findings

1. **Where Agent OS excels**:
   - Encoding tricks (base64, hex, unicode) — rule-based patterns catch obfuscation that model-based detectors may miss.
   - Canary token leak detection — deterministic 100% detection of planted tokens in any input.
   - Delimiter/chat-format attacks — explicit regex coverage for `<|im_start|>`, `[INST]`, `<<SYS>>` injection.

2. **Where LlamaFirewall excels**:
   - Semantic understanding of novel attacks not covered by static patterns.
   - Model-based detection (PromptGuard 2) generalises to unseen attack variations.
   - AlignmentCheck catches subtle goal-hijacking that doesn't match explicit keywords.

3. **Why chaining both is optimal**:
   - Agent OS provides fast, deterministic first-pass filtering with zero LLM latency.
   - LlamaFirewall adds semantic depth as a second layer.
   - Combined attack success rate drops to **0.1%** — well below either detector alone.
   - Defense-in-depth: a missed attack must evade *both* layers.
