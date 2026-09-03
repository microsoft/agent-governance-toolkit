from decisionassure_impact.security.redaction import redact
def test_secret_values_are_redacted(): assert redact({"token":"value", "ok":"safe"}) == {"token":"[REDACTED]", "ok":"safe"}
