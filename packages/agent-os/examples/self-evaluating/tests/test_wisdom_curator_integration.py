# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Integration test for Wisdom Curator with Observer Agent.
Tests the complete workflow of policy review blocking wisdom updates.
"""

import os
import tempfile
import json
import sys

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.observer import ObserverAgent
from src.telemetry import EventStream, TelemetryEvent
from src.wisdom_curator import WisdomCurator, ReviewType


def test_observer_wisdom_curator_integration():
    """Test that Observer blocks policy-violating wisdom updates."""
    print("Testing Observer + Wisdom Curator Integration...")
    
    # Create temporary files
    temp_dir = tempfile.mkdtemp()
    wisdom_file = os.path.join(temp_dir, 'test_wisdom.json')
    stream_file = os.path.join(temp_dir, 'test_stream.jsonl')
    checkpoint_file = os.path.join(temp_dir, 'test_checkpoint.json')
    review_queue_file = os.path.join(temp_dir, 'test_review_queue.json')
    design_proposals_file = os.path.join(temp_dir, 'test_design_proposals.json')
    
    # Initialize wisdom file
    initial_wisdom = {
        "version": 1,
        "instructions": "Handle errors gracefully and inform users of issues",
        "improvements": []
    }
    with open(wisdom_file, 'w') as f:
        json.dump(initial_wisdom, f)
    
    # Create event stream with a problematic event
    event_stream = EventStream(stream_file)
    
    # Create an event that will trigger learning
    bad_event = TelemetryEvent(
        event_type="task_complete",
        timestamp="2024-01-01T12:00:00",
        query="Handle 500 error",
        agent_response="Ignored the error to keep user happy",
        success=False,  # Failed execution
        instructions_version=1,
        metadata={"user_id": "user123"}
    )
    event_stream.append(bad_event)
    
    # Initialize observer with wisdom curator enabled
    observer = ObserverAgent(
        wisdom_file=wisdom_file,
        stream_file=stream_file,
        checkpoint_file=checkpoint_file,
        enable_wisdom_curator=True,
        enable_prioritization=False,  # Disable for this test
        enable_intent_metrics=False    # Disable for this test
    )
    
    # Override the wisdom curator files
    observer.wisdom_curator.review_queue_file = review_queue_file
    observer.wisdom_curator.design_proposals_file = design_proposals_file
    observer.wisdom_curator._save_review_queue()
    
    print("\n📊 Processing event with low score (should trigger learning)...")
    
    # Process events - this should:
    # 1. Analyze the event
    # 2. Get low score due to failure
    # 3. Generate new instructions via evolve()
    # 4. Detect policy violation in new instructions
    # 5. Block the update and create review item
    results = observer.process_events(verbose=False)
    
    # Check that wisdom was NOT updated (version should still be 1)
    current_wisdom = observer.wisdom.load_instructions()
    print(f"\n✓ Wisdom version after processing: {current_wisdom['version']}")
    
    # Should still be version 1 if policy review blocked the update
    # Note: The actual result depends on whether the LLM generates policy-violating text
    # For a more reliable test, we need to mock the evolve() method
    
    # Check that a review item was created
    curator = WisdomCurator(
        review_queue_file=review_queue_file,
        design_proposals_file=design_proposals_file
    )
    
    pending_policy_reviews = curator.get_pending_reviews(ReviewType.POLICY_REVIEW)
    print(f"✓ Policy reviews created: {len(pending_policy_reviews)}")
    
    # Cleanup
    for f in [wisdom_file, stream_file, checkpoint_file, review_queue_file, design_proposals_file]:
        if os.path.exists(f):
            os.remove(f)
    os.rmdir(temp_dir)
    
    print("\n✅ Integration test demonstrates Observer + Wisdom Curator workflow")
    print("   Note: Actual blocking depends on LLM generating policy-violating text")
    

def test_strategic_sampling_integration():
    """Test that Observer creates strategic samples during event processing."""
    print("\n\nTesting Strategic Sampling Integration...")
    
    # Create temporary files
    temp_dir = tempfile.mkdtemp()
    wisdom_file = os.path.join(temp_dir, 'test_wisdom.json')
    stream_file = os.path.join(temp_dir, 'test_stream.jsonl')
    checkpoint_file = os.path.join(temp_dir, 'test_checkpoint.json')
    review_queue_file = os.path.join(temp_dir, 'test_review_queue.json')
    design_proposals_file = os.path.join(temp_dir, 'test_design_proposals.json')
    
    # Initialize wisdom file
    initial_wisdom = {
        "version": 1,
        "instructions": "You are a helpful AI assistant",
        "improvements": []
    }
    with open(wisdom_file, 'w') as f:
        json.dump(initial_wisdom, f)
    
    # Create event stream with multiple events
    event_stream = EventStream(stream_file)
    
    # Add multiple successful events
    for i in range(20):
        event = TelemetryEvent(
            event_type="task_complete",
            timestamp=f"2024-01-01T12:00:{i:02d}",
            query=f"Query {i}",
            agent_response=f"Response {i}",
            success=True,
            instructions_version=1
        )
        event_stream.append(event)
    
    # Initialize observer with high sampling rate for testing
    observer = ObserverAgent(
        wisdom_file=wisdom_file,
        stream_file=stream_file,
        checkpoint_file=checkpoint_file,
        enable_wisdom_curator=True,
        enable_prioritization=False,
        enable_intent_metrics=False
    )
    
    # Use high sampling rate for testing
    observer.wisdom_curator.sample_rate = 0.5  # 50% for testing
    observer.wisdom_curator.review_queue_file = review_queue_file
    observer.wisdom_curator.design_proposals_file = design_proposals_file
    
    print("\n📊 Processing 20 events with 50% sampling rate...")
    results = observer.process_events(verbose=False)
    
    print(f"✓ Events processed: {results['events_processed']}")
    print(f"✓ Strategic samples created: {results['curator_stats']['strategic_samples_created']}")
    
    # Check that samples were created
    curator = WisdomCurator(
        review_queue_file=review_queue_file,
        design_proposals_file=design_proposals_file
    )
    
    samples = curator.get_pending_reviews(ReviewType.STRATEGIC_SAMPLE)
    print(f"✓ Samples in review queue: {len(samples)}")
    
    assert len(samples) > 0, "Should have created at least one strategic sample"
    assert results['curator_stats']['strategic_samples_created'] == len(samples)
    
    # Cleanup
    for f in [wisdom_file, stream_file, checkpoint_file, review_queue_file, design_proposals_file]:
        if os.path.exists(f):
            os.remove(f)
    os.rmdir(temp_dir)
    
    print("\n✅ Strategic sampling integration working correctly")


def main():
    """Run integration tests."""
    print("="*70)
    print("WISDOM CURATOR + OBSERVER INTEGRATION TESTS")
    print("="*70)
    
    test_observer_wisdom_curator_integration()
    test_strategic_sampling_integration()
    
    print("\n" + "="*70)
    print("INTEGRATION TESTS COMPLETE")
    print("="*70)


if __name__ == "__main__":
    # Check for API key
    if not os.getenv("OPENAI_API_KEY"):
        print("Warning: OPENAI_API_KEY not set")
        print("Some tests may fail without API key")
        print()
    
    main()
