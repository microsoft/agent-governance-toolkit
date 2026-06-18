import pytest
from src.capability_ontology import OntologyMatcher, DEFAULT_ONTOLOGY

def test_ontology_has_patterns():
    assert len(DEFAULT_ONTOLOGY.patterns) > 0
    assert len(DEFAULT_ONTOLOGY.patterns) >= 12

def test_match_credential_exfiltration():
    matcher = OntologyMatcher()
    action_types = {"read_database", "read_credentials", "export_data"}
    result = matcher.match(action_types)
    assert result["pattern"] is not None
    assert result["pattern"].capability_id == "credential_exfiltration"
    assert result["confidence"] == 1.0

def test_get_all_capability_names():
    matcher = OntologyMatcher()
    names = matcher.get_capability_names()
    assert "Credential Exfiltration" in names
    assert "Privilege Escalation" in names