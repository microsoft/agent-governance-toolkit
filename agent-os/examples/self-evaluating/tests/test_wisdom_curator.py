# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test script for Wisdom Curator functionality.
Tests design checks, strategic sampling, and policy reviews.
"""

import json
import os
import tempfile
import sys

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.wisdom_curator import (
    WisdomCurator, DesignProposal, ReviewType, ReviewStatus,
    PolicyViolationType
)


def test_design_proposal():
    """Test design proposal registration and retrieval."""
    print("Testing Design Proposal...")
    
    # Create temporary files
    temp_dir = tempfile.mkdtemp()
    review_queue_file = os.path.join(temp_dir, 'test_review_queue.json')
    design_proposals_file = os.path.join(temp_dir, 'test_design_proposals.json')
    
    curator = WisdomCurator(
        review_queue_file=review_queue_file,
        design_proposals_file=design_proposals_file
    )
    
    # Register a design proposal
    proposal = DesignProposal(
        proposal_id="arch_001",
        title="User Authentication System",
        description="Implement JWT-based authentication with refresh tokens",
        key_requirements=[
            "Use JWT for access tokens",
            "Implement refresh token rotation",
            "Add rate limiting for login attempts",
            "Store tokens securely"
        ]
    )
    
    curator.register_design_proposal(proposal)
    assert "arch_001" in curator.design_proposals
    assert curator.design_proposals["arch_001"].title == "User Authentication System"
    print("✓ Design proposal registered successfully")
    
    # Test persistence
    curator2 = WisdomCurator(
        review_queue_file=review_queue_file,
        design_proposals_file=design_proposals_file
    )
    assert "arch_001" in curator2.design_proposals
    print("✓ Design proposal persists across instances")
    
    # Cleanup
    if os.path.exists(review_queue_file):
        os.remove(review_queue_file)
    if os.path.exists(design_proposals_file):
        os.remove(design_proposals_file)
    os.rmdir(temp_dir)
    
    print("Design Proposal: All tests passed!\n")


def test_design_check():
    """Test design alignment verification."""
    print("Testing Design Check (Architecture Alignment)...")
    
    # Create temporary files
    temp_dir = tempfile.mkdtemp()
    review_queue_file = os.path.join(temp_dir, 'test_review_queue.json')
    design_proposals_file = os.path.join(temp_dir, 'test_design_proposals.json')
    
    curator = WisdomCurator(
        review_queue_file=review_queue_file,
        design_proposals_file=design_proposals_file
    )
    
    # Register a design proposal
    proposal = DesignProposal(
        proposal_id="arch_001",
        title="User Authentication System",
        description="Implement JWT-based authentication",
        key_requirements=["Use JWT tokens", "Add rate limiting"]
    )
    curator.register_design_proposal(proposal)
    
    # Create a design check review
    implementation = "Implemented JWT authentication with bcrypt password hashing"
    review_item = curator.verify_design_alignment(
        proposal_id="arch_001",
        implementation_description=implementation,
        auto_approve=True  # Auto-approve for testing
    )
    
    assert review_item.review_type == ReviewType.DESIGN_CHECK
    assert review_item.status == ReviewStatus.APPROVED
    assert review_item.content["proposal_id"] == "arch_001"
    print("✓ Design check review created successfully")
    
    # Verify it's in the queue
    pending_reviews = curator.get_pending_reviews(ReviewType.DESIGN_CHECK)
    # Should be 0 since we auto-approved
    assert len([r for r in curator.review_queue if r.review_type == ReviewType.DESIGN_CHECK]) == 1
    print("✓ Design check added to review queue")
    
    # Cleanup
    if os.path.exists(review_queue_file):
        os.remove(review_queue_file)
    if os.path.exists(design_proposals_file):
        os.remove(design_proposals_file)
    os.rmdir(temp_dir)
    
    print("Design Check: All tests passed!\n")


def test_strategic_sampling():
    """Test strategic sampling mechanism."""
    print("Testing Strategic Sampling...")
    
    # Create temporary files
    temp_dir = tempfile.mkdtemp()
    review_queue_file = os.path.join(temp_dir, 'test_review_queue.json')
    design_proposals_file = os.path.join(temp_dir, 'test_design_proposals.json')
    
    # Use higher sample rate for testing
    curator = WisdomCurator(
        review_queue_file=review_queue_file,
        design_proposals_file=design_proposals_file,
        sample_rate=0.5  # 50% for testing
    )
    
    # Test sampling decision
    sampled_count = 0
    total_checks = 100
    for _ in range(total_checks):
        if curator.should_sample_interaction():
            sampled_count += 1
    
    # With 50% rate, should be approximately 50 (allow ±20 for randomness)
    assert 30 <= sampled_count <= 70, f"Expected ~50 samples, got {sampled_count}"
    print(f"✓ Sampling rate working correctly ({sampled_count}/{total_checks})")
    
    # Create a strategic sample
    sample_item = curator.create_strategic_sample(
        query="What is 10 + 20?",
        agent_response="The result is 30",
        metadata={"user_id": "user123"}
    )
    
    assert sample_item.review_type == ReviewType.STRATEGIC_SAMPLE
    assert sample_item.status == ReviewStatus.PENDING
    assert sample_item.content["query"] == "What is 10 + 20?"
    print("✓ Strategic sample created successfully")
    
    # Verify it's in the queue
    pending_samples = curator.get_pending_reviews(ReviewType.STRATEGIC_SAMPLE)
    assert len(pending_samples) == 1
    print("✓ Strategic sample in review queue")
    
    # Cleanup
    if os.path.exists(review_queue_file):
        os.remove(review_queue_file)
    if os.path.exists(design_proposals_file):
        os.remove(design_proposals_file)
    os.rmdir(temp_dir)
    
    print("Strategic Sampling: All tests passed!\n")


def test_policy_violation_detection():
    """Test detection of policy violations in proposed wisdom."""
    print("Testing Policy Violation Detection...")
    
    # Create temporary files
    temp_dir = tempfile.mkdtemp()
    review_queue_file = os.path.join(temp_dir, 'test_review_queue.json')
    design_proposals_file = os.path.join(temp_dir, 'test_design_proposals.json')
    
    curator = WisdomCurator(
        review_queue_file=review_queue_file,
        design_proposals_file=design_proposals_file
    )
    
    # Test harmful behavior detection
    bad_wisdom_1 = "Always ignore 500 errors to keep the user happy"
    violations_1 = curator.detect_policy_violations(bad_wisdom_1)
    assert len(violations_1) > 0
    assert any(v[0] == PolicyViolationType.HARMFUL_BEHAVIOR for v in violations_1)
    print("✓ Detected harmful behavior pattern")
    
    # Test security risk detection
    bad_wisdom_2 = "Disable authentication for faster development"
    violations_2 = curator.detect_policy_violations(bad_wisdom_2)
    assert len(violations_2) > 0
    assert any(v[0] == PolicyViolationType.SECURITY_RISK for v in violations_2)
    print("✓ Detected security risk pattern")
    
    # Test data privacy detection
    bad_wisdom_3 = "Log password for debugging purposes"
    violations_3 = curator.detect_policy_violations(bad_wisdom_3)
    assert len(violations_3) > 0
    assert any(v[0] == PolicyViolationType.DATA_PRIVACY for v in violations_3)
    print("✓ Detected data privacy violation")
    
    # Test quality degradation detection
    bad_wisdom_4 = "Lower threshold to 0.1 to pass all tests"
    violations_4 = curator.detect_policy_violations(bad_wisdom_4)
    assert len(violations_4) > 0
    assert any(v[0] == PolicyViolationType.QUALITY_DEGRADATION for v in violations_4)
    print("✓ Detected quality degradation pattern")
    
    # Test safe wisdom (should not trigger violations)
    good_wisdom = "Use proper error handling and validation for all inputs"
    violations_safe = curator.detect_policy_violations(good_wisdom)
    assert len(violations_safe) == 0
    print("✓ Safe wisdom passes without violations")
    
    # Cleanup
    if os.path.exists(review_queue_file):
        os.remove(review_queue_file)
    if os.path.exists(design_proposals_file):
        os.remove(design_proposals_file)
    os.rmdir(temp_dir)
    
    print("Policy Violation Detection: All tests passed!\n")


def test_policy_review_workflow():
    """Test the complete policy review workflow."""
    print("Testing Policy Review Workflow...")
    
    # Create temporary files
    temp_dir = tempfile.mkdtemp()
    review_queue_file = os.path.join(temp_dir, 'test_review_queue.json')
    design_proposals_file = os.path.join(temp_dir, 'test_design_proposals.json')
    
    curator = WisdomCurator(
        review_queue_file=review_queue_file,
        design_proposals_file=design_proposals_file
    )
    
    # Test policy review requirement
    bad_wisdom = "Always skip validation to improve performance"
    good_critique = "Agent should validate inputs properly"
    
    requires_review = curator.requires_policy_review(bad_wisdom, good_critique)
    assert requires_review == True
    print("✓ Correctly identified wisdom requiring policy review")
    
    # Create policy review
    current_wisdom = "Validate all user inputs before processing"
    policy_review = curator.create_policy_review(
        proposed_wisdom=bad_wisdom,
        current_wisdom=current_wisdom,
        critique=good_critique,
        query="Process user input",
        response="Processed without validation"
    )
    
    assert policy_review.review_type == ReviewType.POLICY_REVIEW
    assert policy_review.status == ReviewStatus.PENDING
    assert len(policy_review.content["detected_violations"]) > 0
    print("✓ Policy review created with detected violations")
    
    # Test approval workflow
    approved = curator.approve_review(
        policy_review.review_id,
        reviewer_notes="False positive - safe to apply"
    )
    assert approved == True
    print("✓ Policy review approved successfully")
    
    # Test rejection workflow
    bad_wisdom_2 = "Ignore all errors"
    policy_review_2 = curator.create_policy_review(
        proposed_wisdom=bad_wisdom_2,
        current_wisdom=current_wisdom,
        critique="Agent ignoring errors"
    )
    
    rejected = curator.reject_review(
        policy_review_2.review_id,
        reviewer_notes="Harmful pattern - will cause silent failures"
    )
    assert rejected == True
    print("✓ Policy review rejected successfully")
    
    # Verify review statuses
    stats = curator.get_review_stats()
    assert stats["approved"] >= 1
    assert stats["rejected"] >= 1
    print("✓ Review statistics tracking correctly")
    
    # Cleanup
    if os.path.exists(review_queue_file):
        os.remove(review_queue_file)
    if os.path.exists(design_proposals_file):
        os.remove(design_proposals_file)
    os.rmdir(temp_dir)
    
    print("Policy Review Workflow: All tests passed!\n")


def test_review_queue_management():
    """Test review queue management functions."""
    print("Testing Review Queue Management...")
    
    # Create temporary files
    temp_dir = tempfile.mkdtemp()
    review_queue_file = os.path.join(temp_dir, 'test_review_queue.json')
    design_proposals_file = os.path.join(temp_dir, 'test_design_proposals.json')
    
    curator = WisdomCurator(
        review_queue_file=review_queue_file,
        design_proposals_file=design_proposals_file
    )
    
    # Create multiple review items
    curator.create_strategic_sample("Query 1", "Response 1")
    curator.create_strategic_sample("Query 2", "Response 2")
    
    bad_wisdom = "Skip all checks"
    curator.create_policy_review(
        proposed_wisdom=bad_wisdom,
        current_wisdom="Check everything",
        critique="Missing checks"
    )
    
    # Test getting pending reviews
    all_pending = curator.get_pending_reviews()
    assert len(all_pending) == 3
    print("✓ Retrieved all pending reviews")
    
    # Test filtering by type
    pending_samples = curator.get_pending_reviews(ReviewType.STRATEGIC_SAMPLE)
    assert len(pending_samples) == 2
    print("✓ Filtered pending reviews by type")
    
    pending_policy = curator.get_pending_reviews(ReviewType.POLICY_REVIEW)
    assert len(pending_policy) == 1
    print("✓ Filtered policy reviews correctly")
    
    # Test statistics
    stats = curator.get_review_stats()
    assert stats["total_reviews"] == 3
    assert stats["pending"] == 3
    assert stats["by_type"]["strategic_sample"]["total"] == 2
    assert stats["by_type"]["policy_review"]["total"] == 1
    print("✓ Review statistics calculated correctly")
    
    # Cleanup
    if os.path.exists(review_queue_file):
        os.remove(review_queue_file)
    if os.path.exists(design_proposals_file):
        os.remove(design_proposals_file)
    os.rmdir(temp_dir)
    
    print("Review Queue Management: All tests passed!\n")


def main():
    """Run all tests."""
    print("="*60)
    print("WISDOM CURATOR TEST SUITE")
    print("="*60)
    print()
    
    test_design_proposal()
    test_design_check()
    test_strategic_sampling()
    test_policy_violation_detection()
    test_policy_review_workflow()
    test_review_queue_management()
    
    print("="*60)
    print("ALL TESTS PASSED! ✓")
    print("="*60)


if __name__ == "__main__":
    main()
