# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for the shared ``PII_PATTERNS`` constant (issue #2635).

The dashed-only SSN regex (``\\b\\d{3}-\\d{2}-\\d{4}\\b``) that used to be
duplicated across each framework adapter was trivially bypassed by SSNs
formatted with spaces, dots, or no separator at all.  This module guards
two invariants going forward:

1. The shared SSN regex in :mod:`agent_os.integrations.base` matches every
   common separator variant (dash, space, dot, none).
2. Every framework adapter (LangChain, AutoGen, CrewAI, Bedrock) imports
   ``PII_PATTERNS`` from :mod:`agent_os.integrations.base` and exercises
   the same regex objects, so future adapters cannot silently drift back
   to a private copy.

For the two adapters whose PII enforcement path can be exercised without
optional third-party SDKs, we also drive a live boundary test through the
real call site to verify the broadened SSN regex actually blocks every
variant end-to-end.
"""

from __future__ import annotations

import pytest

from agent_os.integrations import base as _base
from agent_os.integrations import (
    autogen_adapter,
    bedrock_adapter,
    crewai_adapter,
    langchain_adapter,
)
from agent_os.integrations.base import PII_PATTERNS, GovernancePolicy

# The four separator variants the broadened SSN regex must catch.  The
# corresponding negative cases live next to each variant so future
# regressions cannot silently drop coverage.
_SSN_VARIANTS = (
    "123-45-6789",
    "123 45 6789",
    "123.45.6789",
    "123456789",
)

_SSN_NON_MATCHES = (
    "",
    "no digits in dashed positions",
    "12-345-6789",      # wrong group sizes
    "1234-56-7890",     # wrong group sizes
    "no digits at all",
)


# ── Shared regex behaviour ────────────────────────────────────────────

def _ssn_pattern():
    """Return the SSN regex from the shared ``PII_PATTERNS`` tuple."""
    # SSN is the first pattern by construction in base.PII_PATTERNS.
    return PII_PATTERNS[0]


@pytest.mark.parametrize("variant", _SSN_VARIANTS)
def test_shared_ssn_regex_matches_each_separator(variant: str) -> None:
    """SSN regex must catch dash, space, dot, and no-separator variants."""
    ssn = _ssn_pattern()
    assert ssn.search(variant) is not None, (
        f"shared SSN regex {ssn.pattern!r} failed to match variant {variant!r}"
    )


@pytest.mark.parametrize("variant", _SSN_VARIANTS)
def test_shared_ssn_regex_matches_variant_in_sentence(variant: str) -> None:
    """SSN regex must catch each variant when embedded in larger text."""
    text = f"customer ssn {variant} on file"
    ssn = _ssn_pattern()
    assert ssn.search(text) is not None


@pytest.mark.parametrize("non_match", _SSN_NON_MATCHES)
def test_shared_ssn_regex_rejects_obvious_non_ssn(non_match: str) -> None:
    """Sanity check that the broadened regex still rejects clear non-SSNs."""
    ssn = _ssn_pattern()
    assert ssn.search(non_match) is None, (
        f"shared SSN regex {ssn.pattern!r} unexpectedly matched {non_match!r}"
    )


def test_shared_pii_patterns_is_immutable_tuple() -> None:
    """The shared constant is a tuple so adapters cannot mutate it in place."""
    assert isinstance(PII_PATTERNS, tuple)


def test_shared_email_pattern_still_matches() -> None:
    """The email pattern survived the consolidation."""
    assert any(p.search("alice@example.com") for p in PII_PATTERNS)


def test_shared_credit_card_pattern_still_matches() -> None:
    """Bedrock's credit-card pattern was promoted to the shared list."""
    # Valid-looking Visa-style PAN (16 digits, leading 4).
    assert any(p.search("card 4111111111111111 on file") for p in PII_PATTERNS)


def test_shared_secret_pattern_still_matches() -> None:
    """The secrets pattern survived the consolidation."""
    assert any(p.search("api_key=sk-deadbeef1234") for p in PII_PATTERNS)


# ── Consolidation guard: every adapter sees the same shared object ────
#
# We can't simply assert ``adapter.PII_PATTERNS is _base.PII_PATTERNS``
# because the adapters use a local-import-rebind pattern that some
# linters discourage.  Instead, each adapter is verified through the
# code path that actually consumes the constant — see the behavioural
# tests below for ``bedrock_adapter._scan_pii`` and
# ``langchain_adapter.LangChainKernel._validate_memory_write``.  Below,
# we exercise the same invariant directly via ``sys.modules`` lookup so
# the test still fails fast if a future adapter quietly drops the import.

def _adapter_uses_shared_pii_patterns(adapter_module) -> bool:
    """Return True iff ``adapter_module`` imports ``PII_PATTERNS`` from base."""
    return getattr(adapter_module, "PII_PATTERNS", None) is PII_PATTERNS


def test_langchain_adapter_imports_shared_pii_patterns() -> None:
    assert _adapter_uses_shared_pii_patterns(langchain_adapter)


def test_autogen_adapter_imports_shared_pii_patterns() -> None:
    assert _adapter_uses_shared_pii_patterns(autogen_adapter)


def test_crewai_adapter_imports_shared_pii_patterns() -> None:
    assert _adapter_uses_shared_pii_patterns(crewai_adapter)


def test_bedrock_adapter_imports_shared_pii_patterns() -> None:
    assert _adapter_uses_shared_pii_patterns(bedrock_adapter)


def test_bedrock_legacy_pii_re_alias_still_points_to_shared_object() -> None:
    """Back-compat alias keeps existing imports of ``_PII_RE`` working."""
    assert bedrock_adapter._PII_RE is _base.PII_PATTERNS


# ── Behavioural boundary tests through real enforcement paths ─────────

@pytest.mark.parametrize("variant", _SSN_VARIANTS)
def test_bedrock_scan_pii_blocks_every_ssn_variant(variant: str) -> None:
    """``bedrock_adapter._scan_pii`` reports the SSN regex for every variant."""
    matches = bedrock_adapter._scan_pii(f"customer ssn {variant} on file")
    ssn_pattern_str = _ssn_pattern().pattern
    assert ssn_pattern_str in matches, (
        f"bedrock._scan_pii did not report the shared SSN regex for variant "
        f"{variant!r}; got {matches!r}"
    )


@pytest.mark.parametrize("variant", _SSN_VARIANTS)
def test_langchain_memory_write_blocks_every_ssn_variant(variant: str) -> None:
    """``LangChainKernel._validate_memory_write`` raises for every variant.

    ``LangChainKernel`` only requires a :class:`GovernancePolicy` to
    instantiate — no LangChain SDK is needed for this code path — so we
    can drive the real PII enforcement path directly.

    Note: ``langchain_adapter`` redefines ``PolicyViolationError`` as a
    module-local class that shadows the canonical exception, so the
    boundary test catches that adapter-local class (matching how the
    existing adapter test suite asserts against it).
    """
    kernel = langchain_adapter.LangChainKernel(policy=GovernancePolicy())
    inputs = {"question": f"my ssn is {variant}"}
    outputs = {"answer": ""}

    with pytest.raises(langchain_adapter.PolicyViolationError) as exc_info:
        kernel._validate_memory_write(inputs, outputs, ctx=None)

    # The raised error names the matched PII pattern, which must be the
    # shared SSN regex.  Substring check keeps the assertion robust against
    # message-format tweaks.
    assert _ssn_pattern().pattern in str(exc_info.value)

