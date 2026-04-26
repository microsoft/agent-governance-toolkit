# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example demonstrating the Wisdom Curator system.

This shows the three key components:
1. Design Check: Verify implementation matches architectural proposals
2. Strategic Sample: Random sampling for quality checks
3. Policy Review: Human approval for wisdom updates

Run this to see the Wisdom Curator in action!
"""

import os
import sys

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.wisdom_curator import WisdomCurator, DesignProposal, ReviewType


def print_section(title):
    """Print a section header."""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)


def demo_design_check():
    """Demonstrate the Design Check feature."""
    print_section("1. DESIGN CHECK: Architecture Alignment Verification")
    
    print("\nThe Old World:")
    print("  'I need to check if they used the right variable names.'")
    print("\nThe New World:")
    print("  'Did this implementation match the Architectural Design Proposal?'")
    
    curator = WisdomCurator()
    
    # Register a design proposal
    print("\n📋 Registering Design Proposal...")
    proposal = DesignProposal(
        proposal_id="auth_system_v1",
        title="User Authentication System",
        description="Implement secure JWT-based authentication with refresh tokens",
        key_requirements=[
            "Use JWT for access tokens (15-minute expiry)",
            "Implement refresh token rotation",
            "Add rate limiting (5 attempts per minute)",
            "Store refresh tokens securely with encryption"
        ]
    )
    curator.register_design_proposal(proposal)
    print(f"✓ Registered: {proposal.title}")
    print(f"  Requirements: {len(proposal.key_requirements)} key requirements")
    
    # Create a design check review
    print("\n🔍 Creating Design Check Review...")
    implementation = """
    Implemented JWT authentication with:
    - Access tokens with 15-minute expiry
    - Refresh token rotation on each use
    - Rate limiting using Redis (5 attempts/min)
    - AES-256 encryption for refresh tokens in PostgreSQL
    """
    
    review_item = curator.verify_design_alignment(
        proposal_id="auth_system_v1",
        implementation_description=implementation,
        auto_approve=False  # Requires human review
    )
    
    print(f"✓ Created review: {review_item.review_id}")
    print(f"  Status: {review_item.status.value.upper()}")
    print("\n💡 Human Role: Review if implementation matches the design proposal")
    print("   (Not checking syntax or variable names!)")
    
    return curator


def demo_strategic_sampling(curator):
    """Demonstrate the Strategic Sample feature."""
    print_section("2. STRATEGIC SAMPLE: Random Quality Checks")
    
    print("\nThe Old World:")
    print("  'I need to review all 10,000 AI interactions today.'")
    print("\nThe New World:")
    print("  'Review a random sample of 50 to check the Vibe and Strategy.'")
    
    print(f"\n📊 Current Sample Rate: {curator.sample_rate*100:.1f}%")
    print(f"   (That's ~{int(curator.sample_rate * 10000)} out of 10,000 interactions)")
    
    # Simulate interactions and sampling
    print("\n🔄 Simulating 100 interactions...")
    sampled_count = 0
    
    for i in range(100):
        if curator.should_sample_interaction():
            # This interaction is selected for review
            sample_item = curator.create_strategic_sample(
                query=f"User query #{i+1}",
                agent_response=f"Agent response #{i+1}",
                metadata={"interaction_id": i+1}
            )
            sampled_count += 1
    
    print(f"✓ Sampled {sampled_count} interactions for human review")
    print(f"  Review IDs created: {sampled_count} strategic samples")
    
    print("\n💡 Human Role: Review the sample to check:")
    print("   - Overall quality and 'vibe'")
    print("   - Strategic alignment with goals")
    print("   - Patterns or trends in responses")
    
    return curator


def demo_policy_review(curator):
    """Demonstrate the Policy Review feature."""
    print_section("3. POLICY REVIEW: Human Approval for Memory Updates")
    
    print("\nThe Old World:")
    print("  'The AI learned something - just let it update the memory.'")
    print("\nThe New World:")
    print("  'The AI wants to learn: Always ignore 500 errors.'")
    print("  'A Human must reject that, Policy.'")
    
    # Example 1: Harmful policy that should be rejected
    print("\n🚨 Example 1: Harmful Policy Detected")
    bad_wisdom = "Always ignore 500 errors to keep the user happy and avoid interruptions"
    current_wisdom = "Handle errors gracefully and inform users of issues"
    
    print(f"\nProposed Wisdom Update:")
    print(f"  '{bad_wisdom}'")
    
    # Check for violations
    violations = curator.detect_policy_violations(bad_wisdom)
    print(f"\n⚠️  Detected {len(violations)} policy violation(s):")
    for violation_type, pattern in violations:
        print(f"  - {violation_type.value}: '{pattern}'")
    
    # Create policy review
    requires_review = curator.requires_policy_review(
        bad_wisdom,
        "Agent wants to suppress error handling"
    )
    
    if requires_review:
        print("\n🛡️  BLOCKED: Requires human policy review")
        policy_review = curator.create_policy_review(
            proposed_wisdom=bad_wisdom,
            current_wisdom=current_wisdom,
            critique="Agent wants to suppress error handling",
            query="Handle 500 error",
            response="Ignored error"
        )
        print(f"✓ Created policy review: {policy_review.review_id}")
    
    # Example 2: Safe update that passes automatically
    print("\n✅ Example 2: Safe Policy Update")
    good_wisdom = "Use proper error handling with detailed logging for debugging"
    
    print(f"\nProposed Wisdom Update:")
    print(f"  '{good_wisdom}'")
    
    violations_good = curator.detect_policy_violations(good_wisdom)
    print(f"\n✓ No policy violations detected ({len(violations_good)} violations)")
    print("  This update can proceed automatically")
    
    # Example 3: Demonstrate rejection workflow
    print("\n❌ Example 3: Human Rejects Harmful Update")
    print("\nHuman Reviewer Decision:")
    print("  Status: REJECTED")
    print("  Reason: 'Ignoring errors will cause silent failures'")
    
    # Get the policy review we created
    pending_policy_reviews = curator.get_pending_reviews(ReviewType.POLICY_REVIEW)
    if pending_policy_reviews:
        review_to_reject = pending_policy_reviews[0]
        curator.reject_review(
            review_to_reject.review_id,
            reviewer_notes="Harmful pattern - will cause silent failures and poor UX"
        )
        print("✓ Wisdom update rejected - Agent will NOT learn this lesson")
    
    print("\n💡 Human Role: Act as Wisdom Curator")
    print("   - Not fixing grammar or syntax")
    print("   - Approving knowledge that aligns with policy")
    print("   - Rejecting harmful or misaligned lessons")
    
    return curator


def demo_review_dashboard(curator):
    """Display the review dashboard."""
    print_section("WISDOM CURATOR DASHBOARD")
    
    stats = curator.get_review_stats()
    
    print("\n📊 Overall Statistics:")
    print(f"  Total Reviews: {stats['total_reviews']}")
    print(f"  Pending: {stats['pending']}")
    print(f"  Approved: {stats['approved']}")
    print(f"  Rejected: {stats['rejected']}")
    
    print("\n📋 By Review Type:")
    for review_type, type_stats in stats['by_type'].items():
        print(f"\n  {review_type.upper()}:")
        print(f"    Total: {type_stats['total']}")
        print(f"    Pending: {type_stats['pending']}")
        print(f"    Approved: {type_stats['approved']}")
        print(f"    Rejected: {type_stats['rejected']}")
    
    print(f"\n🎯 Configuration:")
    print(f"  Sample Rate: {stats['sample_rate']*100:.1f}%")
    print(f"  Design Proposals: {stats['design_proposals']}")
    
    print("\n💡 Next Steps for Humans:")
    print("  1. Review pending design checks")
    print("  2. Examine strategic samples for quality")
    print("  3. Approve or reject policy reviews")


def main():
    """Run the complete Wisdom Curator demo."""
    print("="*70)
    print("  WISDOM CURATOR DEMO")
    print("  Reviewing Design, Not Syntax")
    print("="*70)
    
    print("\n🎯 The Shift:")
    print("  From: Line-by-line code review (syntax, variables, semicolons)")
    print("  To: High-level strategic verification (design, policy, alignment)")
    
    # Run demos
    curator = demo_design_check()
    curator = demo_strategic_sampling(curator)
    curator = demo_policy_review(curator)
    demo_review_dashboard(curator)
    
    print("\n" + "="*70)
    print("  DEMO COMPLETE")
    print("="*70)
    
    print("\n✨ Key Takeaways:")
    print("  1. Humans verify DESIGN alignment, not syntax")
    print("  2. Strategic SAMPLING replaces exhaustive review")
    print("  3. POLICY review prevents harmful memory updates")
    print("\n🎓 We stop being Editors (fixing grammar)")
    print("   We become Curators (approving knowledge)")
    
    # Show files created
    print("\n📁 Review Files Created:")
    if os.path.exists("curator_review_queue.json"):
        print("  ✓ curator_review_queue.json - Review queue")
    if os.path.exists("design_proposals.json"):
        print("  ✓ design_proposals.json - Design proposals")
    
    print("\n💡 To inspect reviews, check the files above")
    print("   Or use curator.get_pending_reviews() in your code")


if __name__ == "__main__":
    main()
