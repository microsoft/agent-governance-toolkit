# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for credential redaction helpers."""

# Fixture credentials, not repo vocabulary. ``AKIAIOSFODNN`` opens AWS's own
# documentation example key ID, ``TOOSHORT`` is the below-the-length-floor token
# that must stay unredacted, and ``Rpbjpvc`` is a camel-case fragment cspell
# extracts from the base64 Basic-auth fixture. Declared at the top by
# convention, not by necessity: ``cspell:ignore`` scopes to the whole document,
# so it covers a word that appears above it too.
# cspell:ignore AKIAIOSFODNN TOOSHORT Rpbjpvc

from __future__ import annotations

import time

import pytest

from agent_os.credential_redactor import CredentialRedactor, REDACTED_PLACEHOLDER


def _fake_github_token(prefix: str) -> str:
    return f"{prefix}_FAKEFORTESTING000000000000000000"


# Fake Google API key built by concatenation so the contiguous literal never
# appears in source (avoids secret-scanner false positives on a test value).
_FAKE_GOOGLE_KEY = "AIza" + "SyD1234567890abcdefghijklmnopqrstuv"

# AWS's own documentation example access key ID -- deterministic and clearly fake.
_FAKE_AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"


def _fake_pem_block(label: str) -> str:
    return (
        f"-----BEGIN {label}-----\n"
        "VGhpcyBpcyBub3QgYSByZWFsIGtleS4=\n"
        "QWxsIHZhbHVlcyBhcmUgZmFrZSBmb3IgdGVzdGluZy4=\n"
        f"-----END {label}-----"
    )


@pytest.mark.parametrize(
    ("input_text", "expected_type"),
    [
        ("key=sk-test_abcdefghijklmnopqrstuvwxyz", "OpenAI API key"),
        ("token=ghp_FAKEFORTESTING000000000000000000", "GitHub token"),
        ("aws=AKIAIOSFODNN7EXAMPLE", "AWS access key"),
        ("AccountKey=abc123def456ghi789jkl012mno345pqr678stu901vw==", "Azure key"),
        (
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
            "Bearer token",
        ),
        ("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----", "PEM private key"),
        ("Server=db;Password=supersecret;", "Connection string secret"),
        ("https://user:pass123@example.com/resource", "Basic auth secret"),
        ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature", "JWT"),
        ("api_key=super-secret-value", "Generic API secret"),
    ],
)
def test_detects_and_redacts_supported_credential_types(input_text: str, expected_type: str):
    redacted = CredentialRedactor.redact(input_text)
    detected = CredentialRedactor.detect_credential_types(input_text)

    assert REDACTED_PLACEHOLDER in redacted
    assert expected_type in detected
    assert CredentialRedactor.contains_credentials(input_text) is True


def test_redact_dictionary_alias_redacts_nested_values():
    payload = {
        "headers": {
            "authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
        },
        "items": [
            "safe value",
            "api_key=secret-value",
        ],
    }

    redacted = CredentialRedactor.redact_dictionary(payload)

    assert redacted["headers"]["authorization"] == REDACTED_PLACEHOLDER
    assert redacted["items"][0] == "safe value"
    assert redacted["items"][1] == REDACTED_PLACEHOLDER


def test_clean_values_remain_unchanged():
    payload = {
        "message": "hello world",
        "list": ["one", "two"],
    }

    assert CredentialRedactor.redact("hello world") == "hello world"
    assert CredentialRedactor.redact_data_structure(payload) == payload
    assert CredentialRedactor.contains_credentials("hello world") is False


def test_incomplete_pem_header_is_not_treated_as_full_key():
    text = "-----BEGIN RSA PRIVATE KEY-----\nmissing footer"

    assert CredentialRedactor.redact(text) == text
    assert CredentialRedactor.contains_credentials(text) is False


@pytest.mark.parametrize(
    "label",
    [
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "DSA PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "PRIVATE KEY",
    ],
)
def test_redacts_full_rfc7468_private_key_blocks(label: str):
    pem_block = _fake_pem_block(label)
    text = f"before\n{pem_block}\nafter"

    redacted = CredentialRedactor.redact(text)
    matches = CredentialRedactor.find_matches(text)

    assert redacted == f"before\n{REDACTED_PLACEHOLDER}\nafter"
    assert any(match.name == "PEM private key" and match.matched_text == pem_block for match in matches)


@pytest.mark.parametrize(
    "text",
    [
        _fake_pem_block("PUBLIC KEY"),
        "-----BEGIN RSA PRIVATE KEY-----\nZmFrZQ==\n-----END EC PRIVATE KEY-----",
        "BEGIN RSA PRIVATE KEY\nZmFrZQ==\nEND RSA PRIVATE KEY",
    ],
)
def test_does_not_redact_non_private_or_malformed_pem_blocks(text: str):
    assert CredentialRedactor.redact(text) == text
    assert CredentialRedactor.contains_credentials(text) is False


@pytest.mark.parametrize(
    "token",
    [
        _fake_github_token("ghp"),
        _fake_github_token("ghs"),
        _fake_github_token("gho"),
        _fake_github_token("ghu"),
        _fake_github_token("ghr"),
        "github_pat_FAKE_FOR_TESTING_0000000000000000000000",
    ],
)
def test_redacts_supported_github_token_prefixes(token: str):
    text = f"token {token} end"

    redacted = CredentialRedactor.redact(text)

    assert redacted == f"token {REDACTED_PLACEHOLDER} end"
    assert "GitHub token" in CredentialRedactor.detect_credential_types(text)


@pytest.mark.parametrize(
    "prefix", ["ghp", "ghs", "gho", "ghu", "ghr"],
)
def test_redacts_classic_github_token_with_trailing_underscore(prefix: str):
    """A trailing "_" ends a classic token; it does not disqualify it.

    A row asserting the opposite used to live in the false-positive table
    below, which encoded the leak as intended behaviour: the classic body class
    stops at "_", so a token followed by "_" is a complete token followed by a
    separator -- exactly the ``_old`` / ``_backup`` annotation this pattern has
    to survive.
    """
    token = _fake_github_token(prefix)

    assert CredentialRedactor.redact(f"{token}_") == f"{REDACTED_PLACEHOLDER}_"
    assert "GitHub token" in CredentialRedactor.detect_credential_types(f"{token}_")


@pytest.mark.parametrize(
    "text",
    [
        f"x{_fake_github_token('ghp')}",
        "gho_short",
        "github_pat_short",
        "notgithub_pat_FAKE_FOR_TESTING_0000000000000000000000",
    ],
)
def test_github_token_boundaries_and_lengths_avoid_false_positives(text: str):
    assert CredentialRedactor.redact(text) == text
    assert CredentialRedactor.contains_credentials(text) is False


def test_redaction_is_idempotent():
    text = (
        f"first {_fake_github_token('ghp')} "
        f"second {_fake_pem_block('EC PRIVATE KEY')} "
        "third key=sk-FAKEFORTESTING000000000000000000"
    )

    once = CredentialRedactor.redact(text)
    twice = CredentialRedactor.redact(once)

    assert once == twice
    assert once.count(REDACTED_PLACEHOLDER) == 3


def test_private_key_pattern_handles_adversarial_input_quickly():
    text = "-----BEGIN RSA PRIVATE KEY-----\n" + ("A" * 100_000)

    start = time.perf_counter()
    redacted = CredentialRedactor.redact(text)
    elapsed = time.perf_counter() - start

    assert redacted == text
    assert elapsed < 1.0


# AWS's own documentation example secret — deterministic and clearly fake.
_FAKE_AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Realistic-length clearly-fake Azure SAS signature. Real Azure sig values are
# base64(HMAC-SHA256) = 44 chars (longer URL-encoded); the detector requires
# this realistic floor so short incidental "sig=" params are not flagged.
_FAKE_SAS_SIG = "abcDEF0123ghiJKL4567mnoPQR89stuVWX%2Fyz01%3D2345"


@pytest.mark.parametrize(
    ("input_text", "expected_type"),
    [
        (f"aws_secret_access_key = {_FAKE_AWS_SECRET}", "AWS secret access key"),
        (f"aws-secret-access-key: {_FAKE_AWS_SECRET}", "AWS secret access key"),
        (f'"AWS Secret Access Key":"{_FAKE_AWS_SECRET}"', "AWS secret access key"),
        (
            "https://a.blob.core.windows.net/c/b?sv=2021-08-06&ss=b&srt=o"
            f"&sp=rwd&se=2025-01-01T00:00:00Z&sig={_FAKE_SAS_SIG}",
            "Azure SAS token",
        ),
        (
            # SAS query parameters are not ordered; sig may appear before sv.
            f"https://a.blob.core.windows.net/c/b?sig={_FAKE_SAS_SIG}"
            "&sv=2021-08-06&sp=r",
            "Azure SAS token",
        ),
        ("xoxb-FAKE-not-a-real-slack-token-00", "Slack token"),
        ("xapp-FAKE-not-a-real-slack-token-00", "Slack token"),
        (_FAKE_GOOGLE_KEY, "Google API key"),
        ("stripe=sk_live_FakeTestKey0000", "Stripe secret key"),
        ("rk_test_FakeTestKey0000", "Stripe secret key"),
    ],
)
def test_detects_and_redacts_newly_covered_secret_classes(input_text: str, expected_type: str):
    redacted = CredentialRedactor.redact(input_text)
    detected = CredentialRedactor.detect_credential_types(input_text)

    assert REDACTED_PLACEHOLDER in redacted
    assert expected_type in detected
    assert CredentialRedactor.contains_credentials(input_text) is True


def test_aws_secret_value_is_fully_removed():
    text = f"aws_secret_access_key = {_FAKE_AWS_SECRET}"

    assert _FAKE_AWS_SECRET not in CredentialRedactor.redact(text)


def test_azure_sas_signature_is_removed():
    url = (
        "https://a.blob.core.windows.net/c/b?sv=2021-08-06&ss=b&srt=o"
        f"&sp=rwd&se=2025-01-01T00:00:00Z&sig={_FAKE_SAS_SIG}"
    )

    redacted = CredentialRedactor.redact(url)

    assert "sig=" not in redacted
    assert _FAKE_SAS_SIG not in redacted
    # The non-secret base path survives.
    assert redacted.startswith("https://a.blob.core.windows.net/c/b?")


def test_azure_sas_detected_regardless_of_parameter_order():
    # SAS query parameters are order-independent; a token with sig before sv
    # must still be detected and redacted (regression: an sv-anchored pattern
    # missed this and the signature leaked).
    url = (
        f"https://a.blob.core.windows.net/c/b?sig={_FAKE_SAS_SIG}"
        "&sv=2021-08-06&sp=r"
    )

    assert CredentialRedactor.contains_credentials(url) is True
    assert _FAKE_SAS_SIG not in CredentialRedactor.redact(url)


def test_azure_sas_pattern_has_no_quadratic_backtracking():
    # Repeated non-matching markers must not trigger super-linear scanning
    # (regression: a lazy cross-parameter gap scanned to end from each marker).
    text = "&".join(["sv=2021-08-06"] * 5000)

    start = time.perf_counter()
    CredentialRedactor.redact(text)
    elapsed = time.perf_counter() - start

    assert elapsed < 1.0


def test_slack_token_fully_redacted_when_followed_by_word_char():
    # Regression: the "-" in the token class let a trailing word boundary
    # backtrack and redact only a prefix, leaking the final secret segment.
    secret_tail = "abcdefghijklmnopqrstuvwx"
    text = f"slack=xoxb-111111111111-222222222222-{secret_tail}_rotated"

    redacted = CredentialRedactor.redact(text)

    assert secret_tail not in redacted


def test_bare_sig_query_param_without_sas_context_is_not_flagged():
    # A short "sig=" that is not an Azure SAS token must not false-positive.
    text = "https://example.com/callback?sig=abcdefghijklmnopqrstuvwxyz123456"

    assert CredentialRedactor.contains_credentials(text) is False
    assert CredentialRedactor.redact(text) == text


def test_detection_and_redaction_agree_on_adjacent_anchored_secrets():
    # Regression: sequential subn on a mutating string let the greedy OpenAI
    # pattern consume the "aws_secret_access_key" anchor of a following pattern,
    # so redaction removed less than detection reported and the secret survived.
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    text = "sk-abcDEF012345678901234567890-aws_secret_access_key=" + secret

    detected = CredentialRedactor.detect_credential_types(text)
    redacted = CredentialRedactor.redact(text)

    assert "AWS secret access key" in detected
    assert secret not in redacted
    assert CredentialRedactor.contains_credentials(redacted) is False


@pytest.mark.parametrize(
    "text",
    [
        "session_sk-abcdefghijklmnopqrstuvwx0123",
        "prefix_ghp_FAKEFORTESTING000000000000000000",
        "x_xoxb-FAKE-not-a-real-slack-token",
        "svc_" + _FAKE_GOOGLE_KEY,
        "env_sk_live_FakeTestKey0000",
        "db_password=Hunter2xyz",
    ],
)
def test_detects_secret_glued_to_preceding_word_character(text: str):
    # Regression: a leading \b treats "_" as a word character, so a secret glued
    # directly after "_" was missed. The (?<![A-Za-z0-9]) anchor detects it.
    assert CredentialRedactor.contains_credentials(text) is True
    assert REDACTED_PLACEHOLDER in CredentialRedactor.redact(text)


@pytest.mark.parametrize(
    "text",
    [
        "basketball-court-schedule-1234567",
        "the disk-usage-report is ready",
        "a risky-business-plan draft",
        "the tokenizer=fast setting is nice",
    ],
)
def test_loosened_anchor_does_not_match_inside_words(text: str):
    # The (?<![A-Za-z0-9]) anchor still refuses to match a secret prefix that is
    # embedded in an alphanumeric word (e.g. the "sk-" inside "disk-").
    assert CredentialRedactor.contains_credentials(text) is False
    assert CredentialRedactor.redact(text) == text


# A base64 Basic-auth value; the credential is the whole encoded pair.
_FAKE_BASIC_B64 = "YWxhZGRpbjpvcGVuc2VzYW1l"


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        # AKIA... is fixed-length, so the engine has no shorter match to back off
        # to and the whole pattern fails -- the key is not redacted at all.
        (f"{_FAKE_AWS_ACCESS_KEY}_old", _FAKE_AWS_ACCESS_KEY),
        (f"AWS_ACCESS_KEY_ID_OLD={_FAKE_AWS_ACCESS_KEY}_deprecated", _FAKE_AWS_ACCESS_KEY),
        (f'{{"{_FAKE_AWS_ACCESS_KEY}_backup": "unused"}}', _FAKE_AWS_ACCESS_KEY),
        # Google keys are fixed-length too. No `key=` prefix here: that would be
        # caught by the keyword-anchored "Generic API secret" pattern instead, and
        # the case would pass without exercising the Google pattern at all.
        (f"rotate {_FAKE_GOOGLE_KEY}_v2 today", _FAKE_GOOGLE_KEY),
        # Stripe's value class excludes "_", so {10,} cannot absorb the suffix.
        ("stripe=sk_live_FakeTestKey0000_rotated", "sk_live_FakeTestKey0000"),
        # The classic GitHub token had the same class/assertion disagreement
        # about "_" that this change fixes elsewhere: its body class stops at
        # "_" while the shared trailing assertion excluded "_" as well, so the
        # whole token leaked. All five classic prefixes share the one pattern.
        (f"{_fake_github_token('ghp')}_old", _fake_github_token("ghp")),
        (f"{_fake_github_token('gho')}_rotated", _fake_github_token("gho")),
        (
            f'{{"{_fake_github_token("ghu")}_backup": "unused"}}',
            _fake_github_token("ghu"),
        ),
        # Both Basic-auth alternatives kept \b on the *left* edge, the very case
        # the lookbehind was introduced for everywhere else.
        (f"auth_Basic {_FAKE_BASIC_B64}", _FAKE_BASIC_B64),
        ("url_https://user:pass123@example.com/resource", "pass123"),
    ],
)
def test_redacts_secret_glued_to_a_following_word_character(text: str, secret: str):
    """A key annotated in place must still be redacted.

    Rotation notes are how secrets actually appear in the text a host scans:
    `AKIA..._old`, `sk_live_..._rotated`, a JSON key suffixed `_backup`. A
    trailing `\\b` after a value class that excludes `_` cannot match these,
    and because the value length is fixed (or `_`-free) there is no shorter
    match ending on a word boundary for the engine to fall back to. The result
    was not a truncated redaction but no redaction at all.
    """
    assert CredentialRedactor.contains_credentials(text) is True
    assert secret not in CredentialRedactor.redact(text)


@pytest.mark.parametrize(
    "text",
    [
        # Glued on the left: still an alphanumeric word, still not a secret.
        f"x{_FAKE_AWS_ACCESS_KEY}",
        f"prefix{_FAKE_GOOGLE_KEY}",
        # One character too long for a fixed-length key: not that key.
        f"{_FAKE_AWS_ACCESS_KEY}X",
        f"{_FAKE_AWS_ACCESS_KEY}1",
        f"{_FAKE_GOOGLE_KEY}9",
        # Below the length floor.
        "sk_live_short",
        "Basic short",
        # A URL with no userinfo.
        "https://example.com/path",
        # A classic GitHub token glued on the left is still an alphanumeric word.
        # No right-edge row here: the body is {20,}, so one more alphanumeric is
        # a longer valid token rather than a false positive -- unlike the
        # fixed-length keys above.
        f"x{_fake_github_token('ghp')}",
        "ghp_TOOSHORT",
    ],
)
def test_trailing_anchor_does_not_widen_the_match(text: str):
    # Replacing the trailing \b with (?![A-Za-z0-9]) must not make the patterns
    # accept more: an alphanumeric character on either side still disqualifies.
    assert CredentialRedactor.contains_credentials(text) is False
    assert CredentialRedactor.redact(text) == text


def test_scan_and_redact_reports_types_without_raw_secret():
    secret = "xoxb-FAKE-not-a-real-slack-token-00"
    redacted, types = CredentialRedactor.scan_and_redact(f"token {secret}")

    assert REDACTED_PLACEHOLDER in redacted
    assert secret not in redacted
    assert types == ["Slack token"]
    # The returned metadata must never carry the raw secret value.
    assert all(secret not in name for name in types)


def test_scan_and_redact_empty_input():
    assert CredentialRedactor.scan_and_redact(None) == ("", [])
    assert CredentialRedactor.scan_and_redact("") == ("", [])
