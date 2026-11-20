"""Tests for PII pattern false positive fixes (#4582).

These cases previously matched as PII but should not:
- Bare digit runs matching US phone numbers (e.g. build 1234567890)
- Arbitrary 16-digit groups matching credit cards (e.g. order IDs)
- Five-part version strings matching IPv4 (e.g. 1.2.3.4.5)
"""

import pytest

from agent_os.credential_redactor import CredentialRedactor, _passes_luhn


class TestIPv4FalsePositives:
    """IPv4 pattern should not match inside longer dotted sequences."""

    def test_five_part_version_not_matched(self):
        matches = CredentialRedactor.find_pii_matches("version 1.2.3.4.5 released")
        ipv4_matches = [m for m in matches if m.name == "IPv4 address"]
        assert ipv4_matches == []

    def test_real_ipv4_still_matched(self):
        matches = CredentialRedactor.find_pii_matches("server at 10.0.0.5 is healthy")
        ipv4_matches = [m for m in matches if m.name == "IPv4 address"]
        assert len(ipv4_matches) == 1
        assert ipv4_matches[0].matched_text == "10.0.0.5"

    def test_private_ip_in_log_matched(self):
        matches = CredentialRedactor.find_pii_matches("Container started at 172.17.0.2:8080")
        ipv4_matches = [m for m in matches if m.name == "IPv4 address"]
        assert len(ipv4_matches) == 1

    def test_loopback_matched(self):
        matches = CredentialRedactor.find_pii_matches("listening on 127.0.0.1")
        ipv4_matches = [m for m in matches if m.name == "IPv4 address"]
        assert len(ipv4_matches) == 1

    def test_ip_after_from_still_matched(self):
        """Reviewer requirement: 'from 172.17.0.2' must still detect the IP."""
        matches = CredentialRedactor.find_pii_matches("copied from 172.17.0.2")
        ipv4_matches = [m for m in matches if m.name == "IPv4 address"]
        assert len(ipv4_matches) == 1

    def test_ip_after_to_still_matched(self):
        """Reviewer requirement: 'ssh to 10.0.0.5' must still detect the IP."""
        matches = CredentialRedactor.find_pii_matches("ssh to 10.0.0.5")
        ipv4_matches = [m for m in matches if m.name == "IPv4 address"]
        assert len(ipv4_matches) == 1


class TestPhoneFalsePositives:
    """US phone pattern should not match bare 10-digit runs."""

    def test_bare_digits_not_matched(self):
        matches = CredentialRedactor.find_pii_matches(
            "Release v3.5.0 build 1234567890 finished"
        )
        phone_matches = [m for m in matches if m.name == "US phone number"]
        assert phone_matches == []

    def test_tracking_number_not_matched(self):
        matches = CredentialRedactor.find_pii_matches("tracking: 9876543210")
        phone_matches = [m for m in matches if m.name == "US phone number"]
        assert phone_matches == []

    def test_real_phone_with_dashes_matched(self):
        matches = CredentialRedactor.find_pii_matches("Call 555-123-4567 for support")
        phone_matches = [m for m in matches if m.name == "US phone number"]
        assert len(phone_matches) == 1

    def test_real_phone_with_parens_matched(self):
        matches = CredentialRedactor.find_pii_matches("Call (555) 123-4567")
        phone_matches = [m for m in matches if m.name == "US phone number"]
        assert len(phone_matches) == 1

    def test_real_phone_with_dots_matched(self):
        matches = CredentialRedactor.find_pii_matches("Fax: 555.123.4567")
        phone_matches = [m for m in matches if m.name == "US phone number"]
        assert len(phone_matches) == 1

    def test_international_format_matched(self):
        matches = CredentialRedactor.find_pii_matches("Call +1-555-123-4567")
        phone_matches = [m for m in matches if m.name == "US phone number"]
        assert len(phone_matches) == 1


class TestCreditCardFalsePositives:
    """Credit card pattern should reject Luhn-invalid sequences."""

    def test_order_id_not_matched(self):
        matches = CredentialRedactor.find_pii_matches(
            "Order 1234567890123456 confirmed"
        )
        cc_matches = [m for m in matches if m.name == "Credit card number"]
        assert cc_matches == []

    def test_order_id_with_spaces_not_matched(self):
        matches = CredentialRedactor.find_pii_matches(
            "Order 1234 5678 9012 3456 confirmed"
        )
        cc_matches = [m for m in matches if m.name == "Credit card number"]
        assert cc_matches == []

    def test_luhn_valid_card_with_spaces_matched(self):
        matches = CredentialRedactor.find_pii_matches("card: 4111 1111 1111 1111")
        cc_matches = [m for m in matches if m.name == "Credit card number"]
        assert len(cc_matches) == 1

    def test_luhn_valid_card_bare_matched(self):
        """Reviewer requirement: bare 16-digit Luhn-valid PAN must be detected."""
        matches = CredentialRedactor.find_pii_matches("card: 4111111111111111")
        cc_matches = [m for m in matches if m.name == "Credit card number"]
        assert len(cc_matches) == 1

    def test_luhn_valid_mastercard_matched(self):
        matches = CredentialRedactor.find_pii_matches("pay with 5500-0000-0000-0004")
        cc_matches = [m for m in matches if m.name == "Credit card number"]
        assert len(cc_matches) == 1


class TestLuhnFunction:
    """Unit tests for the Luhn checksum helper."""

    def test_visa_test_number(self):
        assert _passes_luhn("4111111111111111") is True

    def test_mastercard_test_number(self):
        assert _passes_luhn("5500000000000004") is True

    def test_arbitrary_digits_fail(self):
        assert _passes_luhn("1234567890123456") is False

    def test_order_id_digits_fail(self):
        assert _passes_luhn("1234567890123456") is False

    def test_too_short(self):
        assert _passes_luhn("123456") is False

    def test_non_digits(self):
        assert _passes_luhn("abcdefghijklmnop") is False


class TestBenignPayloadsPassGateway:
    """End-to-end: benign payloads should produce exact expected PII names."""

    def test_plain_ok_no_pii(self):
        matches = CredentialRedactor.find_pii_matches("status: ok")
        assert [m.name for m in matches] == []

    def test_build_number_no_phone(self):
        matches = CredentialRedactor.find_pii_matches(
            "Release v3.5.0 build 1234567890 finished"
        )
        assert "US phone number" not in {m.name for m in matches}

    def test_order_id_no_credit_card(self):
        matches = CredentialRedactor.find_pii_matches(
            "Order 1234 5678 9012 3456 confirmed"
        )
        assert "Credit card number" not in {m.name for m in matches}

    def test_five_part_version_no_ipv4(self):
        matches = CredentialRedactor.find_pii_matches("version 1.2.3.4.5 released")
        assert "IPv4 address" not in {m.name for m in matches}
