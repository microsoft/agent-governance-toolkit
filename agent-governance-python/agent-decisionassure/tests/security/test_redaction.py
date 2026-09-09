import pytest
from src.agent_decisionassure.security import redact, RedactionConfig


def test_redact_string_ssn():
    text = "My SSN is 123-45-6789 and my email is test@example.com"
    result = redact(text)
    assert "[REDACTED SSN]" in result
    assert "123-45-6789" not in result
    assert "[REDACTED EMAIL]" in result
    assert "test@example.com" not in result


def test_redact_dict():
    data = {"user": "alice", "ssn": "123-45-6789", "credit_card": "4111-1111-1111-1111"}
    result = redact(data)
    assert result["user"] == "alice"
    assert result["ssn"] == "[REDACTED SSN]"
    assert result["credit_card"] == "[REDACTED CREDIT CARD]"


def test_redact_list():
    data = ["alice", "123-45-6789", "bob"]
    result = redact(data)
    assert result[0] == "alice"
    assert result[1] == "[REDACTED SSN]"
    assert result[2] == "bob"


def test_redact_nested():
    data = {
        "user": {"name": "alice", "ssn": "123-45-6789"},
        "messages": ["hi", "my ssn is 123-45-6789"]
    }
    result = redact(data)
    assert result["user"]["name"] == "alice"
    assert result["user"]["ssn"] == "[REDACTED SSN]"
    assert "[REDACTED SSN]" in result["messages"][1]


def test_redact_custom_pattern():
    config = RedactionConfig(redact_custom_patterns=[r"\bSECRET-\d+\b"])
    text = "My token is SECRET-1234"
    result = redact(text, config)
    assert result == "My token is [REDACTED CUSTOM]"
