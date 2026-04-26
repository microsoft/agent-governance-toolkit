# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test script for OpenAgent Definition (OAD) metadata system.
Tests the core components and functionality of agent metadata manifests.
"""

import json
import os
import tempfile
import sys

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent_metadata import (
    AgentMetadata,
    AgentMetadataManager,
    Capability,
    Constraint,
    IOContract,
    TrustScore,
    create_default_manifest
)


def test_capability():
    """Test Capability dataclass."""
    print("Testing Capability...")
    
    cap = Capability(
        name="math",
        description="Can do math",
        tags=["math", "calculations"],
        version="1.0"
    )
    
    assert cap.name == "math"
    assert cap.description == "Can do math"
    assert "math" in cap.tags
    assert cap.version == "1.0"
    
    # Test to_dict
    cap_dict = cap.to_dict()
    assert isinstance(cap_dict, dict)
    assert cap_dict["name"] == "math"
    
    print("✓ Capability works")


def test_constraint():
    """Test Constraint dataclass."""
    print("Testing Constraint...")
    
    con = Constraint(
        type="resource",
        description="No internet access",
        severity="high"
    )
    
    assert con.type == "resource"
    assert con.description == "No internet access"
    assert con.severity == "high"
    
    # Test to_dict
    con_dict = con.to_dict()
    assert isinstance(con_dict, dict)
    assert con_dict["type"] == "resource"
    
    print("✓ Constraint works")


def test_io_contract():
    """Test IOContract dataclass."""
    print("Testing IOContract...")
    
    io = IOContract(
        input_schema={"type": "string"},
        output_schema={"type": "string"},
        examples=[{"input": "test", "output": "result"}]
    )
    
    assert io.input_schema == {"type": "string"}
    assert io.output_schema == {"type": "string"}
    assert len(io.examples) == 1
    
    # Test to_dict
    io_dict = io.to_dict()
    assert isinstance(io_dict, dict)
    assert io_dict["input_schema"]["type"] == "string"
    
    print("✓ IOContract works")


def test_trust_score():
    """Test TrustScore dataclass."""
    print("Testing TrustScore...")
    
    score = TrustScore(
        success_rate=0.95,
        avg_latency_ms=1200.0,
        total_executions=100,
        metrics={"compilation_rate": 0.97}
    )
    
    assert score.success_rate == 0.95
    assert score.avg_latency_ms == 1200.0
    assert score.total_executions == 100
    assert score.metrics["compilation_rate"] == 0.97
    assert score.last_updated is not None
    
    # Test to_dict
    score_dict = score.to_dict()
    assert isinstance(score_dict, dict)
    assert score_dict["success_rate"] == 0.95
    
    print("✓ TrustScore works")


def test_agent_metadata_creation():
    """Test AgentMetadata creation and methods."""
    print("Testing AgentMetadata creation...")
    
    metadata = AgentMetadata(
        agent_id="test-agent",
        name="Test Agent",
        version="1.0.0",
        description="A test agent"
    )
    
    assert metadata.agent_id == "test-agent"
    assert metadata.name == "Test Agent"
    assert metadata.version == "1.0.0"
    assert len(metadata.capabilities) == 0
    assert len(metadata.constraints) == 0
    
    print("✓ AgentMetadata creation works")


def test_add_capability():
    """Test adding capabilities to metadata."""
    print("Testing add_capability...")
    
    metadata = AgentMetadata(
        agent_id="test-agent",
        name="Test Agent",
        version="1.0.0",
        description="A test agent"
    )
    
    metadata.add_capability(
        name="math",
        description="Can do math",
        tags=["math"],
        version="1.0"
    )
    
    assert len(metadata.capabilities) == 1
    assert metadata.capabilities[0].name == "math"
    
    print("✓ add_capability works")


def test_add_constraint():
    """Test adding constraints to metadata."""
    print("Testing add_constraint...")
    
    metadata = AgentMetadata(
        agent_id="test-agent",
        name="Test Agent",
        version="1.0.0",
        description="A test agent"
    )
    
    metadata.add_constraint(
        type="resource",
        description="No internet",
        severity="high"
    )
    
    assert len(metadata.constraints) == 1
    assert metadata.constraints[0].type == "resource"
    
    print("✓ add_constraint works")


def test_set_io_contract():
    """Test setting IO contract."""
    print("Testing set_io_contract...")
    
    metadata = AgentMetadata(
        agent_id="test-agent",
        name="Test Agent",
        version="1.0.0",
        description="A test agent"
    )
    
    metadata.set_io_contract(
        input_schema={"type": "string"},
        output_schema={"type": "string"},
        examples=[{"input": "test", "output": "result"}]
    )
    
    assert metadata.io_contract is not None
    assert metadata.io_contract.input_schema["type"] == "string"
    assert len(metadata.io_contract.examples) == 1
    
    print("✓ set_io_contract works")


def test_set_trust_score():
    """Test setting trust score."""
    print("Testing set_trust_score...")
    
    metadata = AgentMetadata(
        agent_id="test-agent",
        name="Test Agent",
        version="1.0.0",
        description="A test agent"
    )
    
    metadata.set_trust_score(
        success_rate=0.95,
        avg_latency_ms=1200.0,
        total_executions=100
    )
    
    assert metadata.trust_score is not None
    assert metadata.trust_score.success_rate == 0.95
    assert metadata.trust_score.total_executions == 100
    
    print("✓ set_trust_score works")


def test_update_trust_score():
    """Test updating trust score with new executions."""
    print("Testing update_trust_score...")
    
    metadata = AgentMetadata(
        agent_id="test-agent",
        name="Test Agent",
        version="1.0.0",
        description="A test agent"
    )
    
    # Initialize trust score
    metadata.set_trust_score(success_rate=0.5, total_executions=2)
    
    # Update with successful execution
    metadata.update_trust_score(success=True, latency_ms=1000.0)
    
    assert metadata.trust_score.total_executions == 3
    assert metadata.trust_score.success_rate > 0.5  # Should increase
    assert metadata.trust_score.avg_latency_ms == 1000.0
    
    # Update with failed execution
    metadata.update_trust_score(success=False, latency_ms=2000.0)
    
    assert metadata.trust_score.total_executions == 4
    # Weighted average: (1000*3 + 2000*1)/4 = 1250
    assert metadata.trust_score.avg_latency_ms == 1250.0
    
    print("✓ update_trust_score works")


def test_to_dict_and_from_dict():
    """Test serialization and deserialization."""
    print("Testing to_dict and from_dict...")
    
    # Create metadata with all components
    metadata = AgentMetadata(
        agent_id="test-agent",
        name="Test Agent",
        version="1.0.0",
        description="A test agent"
    )
    
    metadata.add_capability("math", "Can do math", tags=["math"])
    metadata.add_constraint("resource", "No internet", severity="high")
    metadata.set_io_contract(
        input_schema={"type": "string"},
        output_schema={"type": "string"}
    )
    metadata.set_trust_score(success_rate=0.95, total_executions=100)
    
    # Convert to dict
    data = metadata.to_dict()
    assert isinstance(data, dict)
    assert data["agent_id"] == "test-agent"
    assert len(data["capabilities"]) == 1
    assert len(data["constraints"]) == 1
    assert data["io_contract"] is not None
    assert data["trust_score"] is not None
    
    # Convert back from dict
    metadata2 = AgentMetadata.from_dict(data)
    assert metadata2.agent_id == metadata.agent_id
    assert metadata2.name == metadata.name
    assert len(metadata2.capabilities) == len(metadata.capabilities)
    assert len(metadata2.constraints) == len(metadata.constraints)
    
    print("✓ to_dict and from_dict work")


def test_to_json_and_from_json():
    """Test JSON serialization."""
    print("Testing to_json and from_json...")
    
    metadata = AgentMetadata(
        agent_id="test-agent",
        name="Test Agent",
        version="1.0.0",
        description="A test agent"
    )
    
    metadata.add_capability("math", "Can do math")
    
    # Convert to JSON
    json_str = metadata.to_json()
    assert isinstance(json_str, str)
    
    # Parse JSON
    parsed = json.loads(json_str)
    assert parsed["agent_id"] == "test-agent"
    
    # Convert back from JSON
    metadata2 = AgentMetadata.from_json(json_str)
    assert metadata2.agent_id == metadata.agent_id
    
    print("✓ to_json and from_json work")


def test_metadata_manager_creation():
    """Test AgentMetadataManager creation."""
    print("Testing AgentMetadataManager creation...")
    
    test_file = os.path.join(tempfile.gettempdir(), 'test_manifest.json')
    
    # Remove if exists
    if os.path.exists(test_file):
        os.remove(test_file)
    
    try:
        manager = AgentMetadataManager(test_file)
        assert manager.manifest_file == test_file
        assert manager.metadata is None
        
        print("✓ AgentMetadataManager creation works")
    finally:
        if os.path.exists(test_file):
            os.remove(test_file)


def test_create_and_save_manifest():
    """Test creating and saving a manifest."""
    print("Testing create_manifest and save_manifest...")
    
    test_file = os.path.join(tempfile.gettempdir(), 'test_manifest.json')
    
    # Remove if exists
    if os.path.exists(test_file):
        os.remove(test_file)
    
    try:
        manager = AgentMetadataManager(test_file)
        
        # Create manifest
        metadata = manager.create_manifest(
            agent_id="test-agent",
            name="Test Agent",
            version="1.0.0",
            description="A test agent"
        )
        
        assert metadata is not None
        assert manager.metadata == metadata
        
        # Add some data
        metadata.add_capability("math", "Can do math")
        
        # Save manifest
        success = manager.save_manifest(metadata)
        assert success is True
        assert os.path.exists(test_file)
        
        print("✓ create_manifest and save_manifest work")
    finally:
        if os.path.exists(test_file):
            os.remove(test_file)


def test_load_manifest():
    """Test loading a manifest."""
    print("Testing load_manifest...")
    
    test_file = os.path.join(tempfile.gettempdir(), 'test_manifest.json')
    
    # Remove if exists
    if os.path.exists(test_file):
        os.remove(test_file)
    
    try:
        # Create and save a manifest
        manager1 = AgentMetadataManager(test_file)
        metadata1 = manager1.create_manifest(
            agent_id="test-agent",
            name="Test Agent",
            version="1.0.0",
            description="A test agent"
        )
        metadata1.add_capability("math", "Can do math")
        manager1.save_manifest(metadata1)
        
        # Load with a new manager
        manager2 = AgentMetadataManager(test_file)
        metadata2 = manager2.load_manifest()
        
        assert metadata2 is not None
        assert metadata2.agent_id == "test-agent"
        assert len(metadata2.capabilities) == 1
        
        print("✓ load_manifest works")
    finally:
        if os.path.exists(test_file):
            os.remove(test_file)


def test_get_manifest():
    """Test get_manifest method."""
    print("Testing get_manifest...")
    
    test_file = os.path.join(tempfile.gettempdir(), 'test_manifest.json')
    
    # Remove if exists
    if os.path.exists(test_file):
        os.remove(test_file)
    
    try:
        # Create and save a manifest
        manager = AgentMetadataManager(test_file)
        metadata1 = manager.create_manifest(
            agent_id="test-agent",
            name="Test Agent",
            version="1.0.0",
            description="A test agent"
        )
        manager.save_manifest(metadata1)
        
        # Create new manager and get manifest (should auto-load)
        manager2 = AgentMetadataManager(test_file)
        metadata2 = manager2.get_manifest()
        
        assert metadata2 is not None
        assert metadata2.agent_id == "test-agent"
        
        print("✓ get_manifest works")
    finally:
        if os.path.exists(test_file):
            os.remove(test_file)


def test_publish_manifest():
    """Test publish_manifest method."""
    print("Testing publish_manifest...")
    
    manager = AgentMetadataManager()
    metadata = manager.create_manifest(
        agent_id="test-agent",
        name="Test Agent",
        version="1.0.0",
        description="A test agent"
    )
    
    result = manager.publish_manifest()
    
    assert result["status"] == "published"
    assert result["manifest"]["agent_id"] == "test-agent"
    assert "published_at" in result
    
    print("✓ publish_manifest works")


def test_validate_compatibility():
    """Test validate_compatibility method."""
    print("Testing validate_compatibility...")
    
    # Create two metadata manifests
    manager1 = AgentMetadataManager()
    metadata1 = manager1.create_manifest(
        agent_id="agent1",
        name="Agent 1",
        version="1.0.0",
        description="First agent"
    )
    metadata1.add_constraint("resource", "High severity issue", severity="high")
    
    metadata2 = AgentMetadata(
        agent_id="agent2",
        name="Agent 2",
        version="1.0.0",
        description="Second agent"
    )
    
    result = manager1.validate_compatibility(metadata2)
    
    assert isinstance(result, dict)
    assert "compatible" in result
    assert "warnings" in result
    assert "errors" in result
    
    print("✓ validate_compatibility works")


def test_create_default_manifest():
    """Test create_default_manifest helper function."""
    print("Testing create_default_manifest...")
    
    metadata = create_default_manifest()
    
    assert metadata.agent_id == "self-evolving-agent"
    assert metadata.name == "Self-Evolving Agent"
    assert metadata.version == "1.0.0"
    assert len(metadata.capabilities) > 0
    assert len(metadata.constraints) > 0
    assert metadata.io_contract is not None
    assert metadata.trust_score is not None
    
    # Check specific capabilities
    capability_names = [cap.name for cap in metadata.capabilities]
    assert "mathematical_calculations" in capability_names
    assert "self_improvement" in capability_names
    
    # Check specific constraints
    constraint_types = [con.type for con in metadata.constraints]
    assert "resource" in constraint_types
    assert "security" in constraint_types
    
    print("✓ create_default_manifest works")


def run_all_tests():
    """Run all tests."""
    print("="*60)
    print("Testing OpenAgent Definition (OAD) Metadata System")
    print("="*60)
    print()
    
    tests = [
        test_capability,
        test_constraint,
        test_io_contract,
        test_trust_score,
        test_agent_metadata_creation,
        test_add_capability,
        test_add_constraint,
        test_set_io_contract,
        test_set_trust_score,
        test_update_trust_score,
        test_to_dict_and_from_dict,
        test_to_json_and_from_json,
        test_metadata_manager_creation,
        test_create_and_save_manifest,
        test_load_manifest,
        test_get_manifest,
        test_publish_manifest,
        test_validate_compatibility,
        test_create_default_manifest,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"✗ Test failed: {test.__name__}")
            print(f"  Error: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ Test error: {test.__name__}")
            print(f"  Error: {e}")
            failed += 1
        print()
    
    print("="*60)
    print(f"Tests completed: {passed} passed, {failed} failed")
    print("="*60)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)
