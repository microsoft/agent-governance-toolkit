---
title: "Security audit: HIPAA healthcare identifier detection"
last_reviewed: 2026-09-26
owner: agt-maintainers
---

# Security Audit: HIPAA Healthcare Identifier Detection

**Date:** 2026-09-26  
**Scope:** Python Agent OS credential and data-classification detection  
**Pull request:** microsoft/agent-governance-toolkit#3754

## What changed

This change adds and refines contextual detection for healthcare-related
identifiers in the Python Agent OS implementation.

The changes include:

- Shared contextual detection for Medical Record Numbers (MRN).
- Contextual detection for Health Plan IDs.
- Separate contextual detection for National Provider Identifiers (NPI).
- Luhn validation for NPI values.
- Explicit separation between PHI patterns and non-PHI healthcare identifiers.
- Shared MRN semantics between `credential_redactor.py` and
  `policies/data_classification.py`.
- Tests covering positive matches, invalid values, cue boundaries,
  classification behavior, and detection ordering.

MRN and Health Plan IDs are treated as PHI. NPI is treated as a separate
non-PHI healthcare identifier because it identifies providers and is publicly
available through NPPES.

## Security rationale

The purpose of this change is to improve detection precision and reduce both
under-detection and over-detection when untrusted text is processed by Agent OS
components.

The shared MRN definition prevents different security-sensitive components from
classifying the same input inconsistently. Contextual cues, separator
requirements, bounded lengths, digit requirements, and NPI Luhn validation
reduce false positives while preserving detection of valid healthcare
identifiers.

## Threat model impact

The affected components process text that may originate from model output,
tool responses, external APIs, audit payloads, or other untrusted sources.

Relevant threats include:

1. **Under-detection of PHI**
   - An attacker or malformed upstream system could provide a patient-linked
     identifier in a format accepted by one component but missed by another.
   - Mitigation: one shared MRN definition is used by both data classification
     and credential detection.

2. **False positives and over-redaction**
   - Generic words or arbitrary alphanumeric values could be incorrectly
     treated as healthcare identifiers.
   - Mitigation: contextual cues, required separators, bounded value lengths,
     and digit requirements.

3. **Incorrect NPI classification**
   - Treating provider identifiers as patient PHI could cause incorrect policy
     decisions or unnecessary redaction.
   - Mitigation: NPI is kept outside `PHI_PATTERNS` and represented as a
     separate healthcare-identifier category.

4. **Invalid NPI acceptance**
   - Arbitrary numeric values could be reported as NPIs.
   - Mitigation: contextual matching combined with Luhn validation.

5. **Detection inconsistency**
   - Different regex definitions could produce different classification results
     depending on which subsystem processes the input.
   - Mitigation: `MEDICAL_RECORD_NUMBER_REGEX` is the canonical MRN definition.

No new network access, credential storage, authorization bypass, or code
execution surface is introduced by this change.

## Security-relevant testing

The tests cover:

- Valid numeric and alphanumeric MRN values.
- `MRN` and `medical record` contextual cues.
- Missing separators before letter-initial values.
- Alphabetic-only invalid values.
- Values outside the supported length.
- Valid and invalid NPI values.
- Luhn validation behavior.
- Health Plan ID detection.
- PHI versus non-PHI healthcare-identifier classification.
- Agreement between `detect_phi()` and
  `CredentialRedactor.find_pii_matches()`.
- Existing PII/PHI detection behavior and match ordering.

## Validation results

- `pytest tests/test_hipaa_patterns.py -q`
  - Result: `47 passed`
- `pytest tests/test_credential_redactor.py tests/test_data_classification.py -q`
  - Result: hit the known Windows environment limit in the adversarial setup
    case with `ValueError: the environment variable is longer than 32767 characters`
- `pytest tests/test_credential_redactor.py tests/test_data_classification.py -q -k "not trailing_lookahead_patterns_handle_adversarial_input_quickly"`
  - Result: `180 passed, 4 deselected`
- `python -m ruff check src/agent_os/hipaa_patterns.py src/agent_os/policies/data_classification.py tests/test_hipaa_patterns.py tests/test_data_classification.py`
  - Result: passed
- `python -m ruff format --check src/agent_os/hipaa_patterns.py src/agent_os/policies/data_classification.py tests/test_hipaa_patterns.py tests/test_data_classification.py`
  - Result: passed
