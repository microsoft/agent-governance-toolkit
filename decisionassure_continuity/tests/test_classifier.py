import pytest
from src.capability_classifier import CapabilityClassifier

def test_classification_credential_exfiltration():
    classifier = CapabilityClassifier()
    actions = [
        {"agent": "alice", "action": "read_database"},
        {"agent": "bob", "action": "read_credentials"},
        {"agent": "charlie", "action": "export_data"}
    ]
    result = classifier.classify(actions)
    assert result["classification"] == "credential_exfiltration"
    assert result["confidence"] >= 0.8

def test_classification_privilege_escalation():
    classifier = CapabilityClassifier()
    actions = [
        {"agent": "david", "action": "grant_permission"},
        {"agent": "eve", "action": "write_config"},
        {"agent": "frank", "action": "delete_logs"}
    ]
    result = classifier.classify(actions)
    assert result["classification"] == "privilege_escalation"
    assert result["confidence"] >= 0.8

def test_classification_unknown():
    classifier = CapabilityClassifier()
    actions = [
        {"agent": "grace", "action": "read_database"},
        {"agent": "heidi", "action": "read_database"}
    ]
    result = classifier.classify(actions)
    assert result["classification"] == "unknown"
    assert result["confidence"] == 0.0

def test_classification_partial_match():
    classifier = CapabilityClassifier(threshold=0.5)
    actions = [
        {"agent": "alice", "action": "read_database"},
        {"agent": "bob", "action": "export_data"}
    ]
    result = classifier.classify(actions)
    # Should match "data_exfiltration" because it has read_database and export_data
    assert result["classification"] == "data_exfiltration"
    assert result["confidence"] >= 0.5