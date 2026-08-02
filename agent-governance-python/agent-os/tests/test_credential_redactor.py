# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for credential redaction helpers."""

# Fake passwords and a deliberately non-matching keyword, used only as fixtures
# below. ``topsecret=`` is the negative case for the ``(?<![A-Za-z0-9])``
# lookbehind, so it has to be spelled as one word to be the fixture it is.
# cspell:ignore efgh cdefgh topsecret

from __future__ import annotations

import json
import time

import pytest

from agent_os.credential_redactor import CredentialRedactor, REDACTED_PLACEHOLDER


def _fake_github_token(prefix: str) -> str:
    return f"{prefix}_FAKEFORTESTING000000000000000000"


# Fake Google API key built by concatenation so the contiguous literal never
# appears in source (avoids secret-scanner false positives on a test value).
_FAKE_GOOGLE_KEY = "AIza" + "SyD1234567890abcdefghijklmnopqrstuv"


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
    # The anchor keyword survives; only the value is replaced. "secret-value"
    # is what had to disappear, and the reader still learns which field it was.
    assert redacted["items"][1] == f"api_key={REDACTED_PLACEHOLDER}"
    assert "secret-value" not in redacted["items"][1]


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
    "text",
    [
        f"x{_fake_github_token('ghp')}",
        f"{_fake_github_token('ghs')}_",
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


# A clearly-fake secret value long enough to clear every pattern's length floor.
_FAKE_SECRET_VALUE = "hunter22-not-a-real-secret"


@pytest.mark.parametrize(
    ("keyword", "expected_type"),
    [
        ("api_key", "Generic API secret"),
        ("api-key", "Generic API secret"),
        ("apikey", "Generic API secret"),
        ("client_secret", "Generic API secret"),
        ("secret", "Generic API secret"),
        ("token", "Generic API secret"),
        ("password", "Connection string secret"),
        ("pwd", "Connection string secret"),
        ("passphrase", "Connection string secret"),
    ],
)
def test_detects_keyword_secrets_in_the_json_spelling(keyword: str, expected_type: str):
    r"""JSON is the wire format for MCP tool output, so it is the shape that matters.

    In `"api_key": "value"` the closing quote of the key sits between the keyword
    and the colon. A pattern that runs the keyword straight into `\s*[:=]` matches
    the bare `api_key=value` form and misses the quoted one entirely, which is
    the form a tool response, a config file, and a log line all use.
    """
    text = '{"' + keyword + '": "' + _FAKE_SECRET_VALUE + '"}'

    redacted = CredentialRedactor.redact(text)

    assert _FAKE_SECRET_VALUE not in redacted
    assert expected_type in CredentialRedactor.detect_credential_types(text)


@pytest.mark.parametrize(
    "text_template",
    [
        '{{"api_key": "{value}"}}',
        '{{"api_key":"{value}"}}',
        "api_key={value}",
        "api_key: {value}",
        "api_key = '{value}'",
        'api_key: "{value}"',
    ],
)
def test_one_secret_is_found_in_every_spelling(text_template: str):
    """The same secret, however the surrounding syntax quotes it."""
    text = text_template.format(value=_FAKE_SECRET_VALUE)

    assert _FAKE_SECRET_VALUE not in CredentialRedactor.redact(text)


@pytest.mark.parametrize(
    "text_template",
    [
        "token={value}",
        "api_key={value}",
        '{{"token": "{value}"}}',
        "api_key = '{value}'",
    ],
)
def test_a_digit_only_secret_is_found_in_every_string_spelling(text_template: str):
    """Quoting or an ``=`` makes a digit run a string, so it is a secret.

    The literal guard exists so ``{"token": 12345678}`` -- a JSON integer, an ID
    or an expiry -- is not read as a credential. Applying it to every spelling
    alike instead made the *same* digit-only secret redact in one and leak in
    another: ``token="12345678"`` was redacted while ``token=12345678`` was not.
    An environment variable, a connection string and a query string have no
    number type, so a digit run there is a digit-only secret.
    """
    text = text_template.format(value="1234567890123")

    assert "1234567890123" not in CredentialRedactor.redact(text)


def test_an_unterminated_quote_still_redacts():
    """A truncated log line must not be the way a secret survives.

    The bare branch takes an *optional* opening quote rather than excluding one.
    Excluding it meant a value whose closing quote never arrived matched no
    branch at all and leaked in full.
    """
    text = 'api_key="' + _FAKE_SECRET_VALUE

    assert _FAKE_SECRET_VALUE not in CredentialRedactor.redact(text)


def test_a_stray_quote_does_not_swallow_the_following_lines():
    """A quoted value ends at its line: a JSON string cannot hold a raw newline.

    Without ``\\n`` excluded from the quoted classes, an unclosed quote ran on to
    the next quote anywhere later in the buffer and redacted the intervening log
    lines as if they were one secret.
    """
    text = 'api_key="' + _FAKE_SECRET_VALUE + '\nkeep one\nkeep two "quoted"\n'

    redacted = CredentialRedactor.redact(text)

    assert _FAKE_SECRET_VALUE not in redacted
    assert "keep one" in redacted
    assert 'keep two "quoted"' in redacted


def test_redaction_of_a_json_secret_leaves_the_other_fields_intact():
    """The match must stop at the value, not swallow the rest of the object."""
    text = '{"user": "alice", "api_key": "' + _FAKE_SECRET_VALUE + '", "region": "eu-west-1"}'

    redacted = CredentialRedactor.redact(text)

    assert _FAKE_SECRET_VALUE not in redacted
    assert '"user": "alice"' in redacted
    assert '"region": "eu-west-1"' in redacted


def test_detects_azure_account_key_in_the_json_spelling():
    key = "abc123def456ghi789jkl012mno345pqr678stu901vw=="
    text = '{"AccountKey": "' + key + '"}'

    redacted = CredentialRedactor.redact(text)

    # Assert the full value, padding included. Checking the value minus its
    # trailing "==" passes even when the match stops short of the padding, which
    # is exactly the partial-redaction bug a boundary change can reintroduce.
    assert key not in redacted
    assert redacted == '{"AccountKey": "' + REDACTED_PLACEHOLDER + '"}'
    assert "Azure key" in CredentialRedactor.detect_credential_types(text)


@pytest.mark.parametrize(
    "text",
    [
        # Below every value-length floor.
        '{"api_key": "abc"}',
        '{"token": ""}',
        # Prose that mentions a keyword without assigning anything.
        "the token is rotated weekly",
        "rotate the password before Friday",
        # The keyword must not match as the tail of a longer word. This is the
        # `(?<![A-Za-z0-9])` lookbehind's job: drop it and `topsecret=` matches.
        "topsecret=abcdefghijkl",
        # A separator with nothing after it.
        '{"password":}',
        # "secret" and "token" name plenty of non-secret fields, and the length
        # floors are what keep the ordinary ones out -- not a guard on the shape
        # of the value, which whoever writes the value could satisfy on purpose.
        # ``false``, ``true``, ``null`` and ``none`` are all under the 6-character
        # generic floor. A *number* is not exempt: see
        # ``test_a_value_is_not_exempted_by_its_shape``.
        '{"secret": false}',
        '{"secret": false, "keep": 1}',
        '{"token": true}',
        '{"secret": null}',
        '{"expires_token": -1}',
        "token: null",
        # ``:`` is also Python's annotation separator. The connection-string
        # floor of 4 exists for ``Password=1234``, but with ``:`` it let a
        # function signature match and redacted the tail of the line.
        "def authenticate_user(username: str, password: str):",
        "def f(self, token: str) -> None:",
        "    api_key: str",
    ],
)
def test_keyword_patterns_still_avoid_false_positives(text: str):
    assert CredentialRedactor.redact(text) == text
    assert CredentialRedactor.contains_credentials(text) is False


@pytest.mark.parametrize(
    "text",
    [
        # An unexpanded reference names a credential rather than containing one,
        # so exempting it reads as harmless. It is not, on this path: the value
        # arrives from the far side of the MCP boundary, so a tool that wants a
        # secret past the gate only has to wrap it in the exempt shape. Every one
        # of these carries a real secret in a shape an earlier revision of this
        # patch treated as a reference and skipped entirely.
        "password=${DB_PASS:-" + _FAKE_SECRET_VALUE + "}",
        "api_key=%" + _FAKE_SECRET_VALUE + "%",
        'api_key: "{{ ' + _FAKE_SECRET_VALUE + ' }}"',
        # Shaping the value works the same way: a bare number was exempt as a
        # non-credential, and a numeric password or account id is a credential.
        "token: 738291046512",
        "password=1234567890123456",
    ],
)
def test_a_value_is_not_exempted_by_its_shape(text: str):
    redacted = CredentialRedactor.redact(text)

    assert redacted != text
    assert _FAKE_SECRET_VALUE not in redacted
    assert CredentialRedactor.contains_credentials(text) is True


@pytest.mark.parametrize(
    "text",
    [
        # The cost of dropping that exemption, stated rather than hidden: a
        # reference with no secret in it is redacted too. Over-redaction is the
        # direction this module has to fail in -- a reader loses the variable
        # name, and nothing leaks.
        '"API_KEY": "${MCP_API_KEY}"',
        "api_key=${MY_KEY}",
        "password=%DB_PASS%",
        "Password=${DB_PASS};Server=db",
    ],
)
def test_an_unexpanded_reference_is_redacted_too(text: str):
    assert CredentialRedactor.redact(text) != text


@pytest.mark.parametrize(
    "text",
    [
        'api_key: "${MCP_API_KEY}' + _FAKE_SECRET_VALUE + '"',
        'api_key: "prefix${X}' + _FAKE_SECRET_VALUE + '"',
        'api_key: "{not-a-reference-' + _FAKE_SECRET_VALUE + '"',
        "Password=${DB_PASS},suffix",
        "Password=${DB_PASS}}real",
        "password: ${DB_PASS},tail",
    ],
)
def test_a_reference_prefix_does_not_hide_a_real_secret(text: str):
    redacted = CredentialRedactor.redact(text)

    assert _FAKE_SECRET_VALUE not in redacted
    assert redacted != text


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # A bare value in a JSON or YAML flow mapping runs up to the delimiter
        # that closes it, and taking the delimiter into the redaction turns a
        # redaction into a parse failure. The value is what gets redacted; the
        # delimiter stays.
        ('{"password": hunter2xyz}', '{"password": ' + REDACTED_PLACEHOLDER + "}"),
        (
            '{"password": hunter2xyz, "keep": 1}',
            '{"password": ' + REDACTED_PLACEHOLDER + ', "keep": 1}',
        ),
        ("[api_key=abcdefghijkl]", f"[api_key={REDACTED_PLACEHOLDER}]"),
        # A value that *contains* one of those characters keeps all of it. This
        # is why the delimiter is excluded from the value's last character only:
        # excluding it from the value class throughout made the value end early,
        # fall under the length floor, and leak in full -- both of these are
        # redacted on ``main`` and passed through on an earlier revision here.
        ("token=ab,cdefghijkl", f"token={REDACTED_PLACEHOLDER}"),
        ('{"token": "ab,cdefghijkl"}', '{"token": "' + REDACTED_PLACEHOLDER + '"}'),
        # A connection string separates fields with ``;`` only, so here the brace
        # is an ordinary password character and the password is four long. The
        # same keyword has to give the brace back in the JSON spelling above, so
        # ending on a delimiter is a fallback, not an alternative of equal rank.
        ("Password=abc}", f"Password={REDACTED_PLACEHOLDER}"),
        ("Password=ab,c;Server=db", f"Password={REDACTED_PLACEHOLDER};Server=db"),
    ],
)
def test_a_structural_delimiter_is_not_redacted_with_the_value(text: str, expected: str):
    assert CredentialRedactor.redact(text) == expected


# ── redaction replaces the value, not the key ─────────────────


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            '{"api_key": "' + _FAKE_SECRET_VALUE + '", "keep": 1}',
            '{"api_key": "' + REDACTED_PLACEHOLDER + '", "keep": 1}',
        ),
        (
            '{"password": "hunter2xyz", "keep": 1}',
            '{"password": "' + REDACTED_PLACEHOLDER + '", "keep": 1}',
        ),
        (
            "{'client_secret': '" + _FAKE_SECRET_VALUE + "'}",
            "{'client_secret': '" + REDACTED_PLACEHOLDER + "'}",
        ),
        # The key=value spelling keeps working the same way.
        ("password=hunter2xyz;Server=db", f"password={REDACTED_PLACEHOLDER};Server=db"),
        (
            "api_key=" + _FAKE_SECRET_VALUE,
            f"api_key={REDACTED_PLACEHOLDER}",
        ),
        # A quoted value may contain the delimiters a bare one stops at.
        (
            '{"api_key": "with,comma;inside!!"}',
            '{"api_key": "' + REDACTED_PLACEHOLDER + '"}',
        ),
        # A connection-string password is delimited by ``;``, so an apostrophe
        # inside it is an ordinary password character. Excluding quotes from the
        # bare branch made the whole assignment unmatchable when the apostrophe
        # came early enough to leave fewer than 4 characters before it, and
        # redacted only the head when it came later -- the tail leaked.
        (
            "Password=ab'cdefgh;Server=db",
            f"Password={REDACTED_PLACEHOLDER};Server=db",
        ),
        (
            "Password=abcd'efgh",
            f"Password={REDACTED_PLACEHOLDER}",
        ),
        (
            "Password=ab'cdefgh",
            f"Password={REDACTED_PLACEHOLDER}",
        ),
        # A digit-only password is still a password. The literal guard rejects
        # a bare number, but it has to reject it as a *value*, i.e. only where
        # the number is the whole value -- and its terminator set has to admit
        # every delimiter the value class stops at, not just some of them.
        (
            "Password=12345678",
            f"Password={REDACTED_PLACEHOLDER}",
        ),
        (
            "Password=12345678;Server=db",
            f"Password={REDACTED_PLACEHOLDER};Server=db",
        ),
        # Letting a connection-string password contain ``,`` and ``}`` must not
        # let an *unquoted* one consume the delimiter that closes the structure
        # it sits in -- that turns a redaction back into a parse failure, which
        # is the thing the secret-only span exists to prevent.
        (
            '{"password": hunter2xyz, "keep": 1}',
            '{"password": ' + REDACTED_PLACEHOLDER + ', "keep": 1}',
        ),
        (
            "{password: hunter2xyz}",
            "{password: " + REDACTED_PLACEHOLDER + "}",
        ),
    ],
)
def test_keyword_redaction_replaces_only_the_value(text: str, expected: str):
    """The keyword locates the secret; it is not itself sensitive.

    Replacing the whole match took the key and separator with it, so
    ``{"api_key": "S", "keep": 1}`` became ``{"[REDACTED]", "keep": 1}``. The
    secret was gone, but the output was no longer parseable JSON -- anything
    downstream that re-parses sanitized MCP output saw a redaction as a parse
    failure.
    """
    assert CredentialRedactor.redact(text) == expected


def test_redacted_json_still_parses():
    text = (
        '{"user": "alice", "api_key": "' + _FAKE_SECRET_VALUE + '", '
        '"password": "hunter2xyz", "visible_secret": false, "retries": 3}'
    )

    parsed = json.loads(CredentialRedactor.redact(text))

    assert parsed["api_key"] == REDACTED_PLACEHOLDER
    assert parsed["password"] == REDACTED_PLACEHOLDER
    assert parsed["user"] == "alice"
    assert parsed["retries"] == 3
    # A visibility flag is not a secret and must survive as a real boolean.
    assert parsed["visible_secret"] is False


def test_reported_span_is_the_secret_not_the_pair():
    # find_matches drives redaction, so the span it reports has to be the
    # value alone; matched_text must not carry the key either.
    text = '{"api_key": "' + _FAKE_SECRET_VALUE + '"}'

    matches = [m for m in CredentialRedactor.find_matches(text) if "API" in m.name]

    assert matches, "the generic keyword pattern should match"
    match = matches[0]
    assert match.matched_text == _FAKE_SECRET_VALUE
    assert text[match.start : match.end] == _FAKE_SECRET_VALUE
