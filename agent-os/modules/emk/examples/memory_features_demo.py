# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example: Memory Decay & Negative Memory Features

This example demonstrates:
1. Memory Decay & Compression (Sleep Cycle): Summarizing old episodes into semantic rules
2. Negative Memory (Anti-Patterns): Tracking failures and successful patterns
"""

from datetime import datetime, timezone, timedelta
from emk import Episode, FileAdapter, MemoryCompressor

# Initialize storage
store = FileAdapter("demo_episodes.jsonl")
compressor = MemoryCompressor(
    store=store,
    age_threshold_days=7,
    rules_filepath="demo_semantic_rules.jsonl"
)

print("=" * 80)
print("EMK Demo: Memory Decay & Negative Memory")
print("=" * 80)

# Part 1: Store some successful episodes
print("\n1. Storing successful episodes...")
for i in range(3):
    episode = Episode(
        goal=f"Query user data from database",
        action=f"SELECT * FROM users WHERE id={i}",
        result="Success - Retrieved 1 row",
        reflection="Query was efficient and completed in 45ms",
        metadata={"query_time_ms": 45, "user_id": str(i)}
    )
    store.store(episode)
    print(f"  ✓ Stored successful episode {i+1}")

# Part 2: Store some failure episodes (anti-patterns)
print("\n2. Storing failure episodes (anti-patterns)...")
for i in range(2):
    failed_episode = Episode(
        goal="Query user data from external API",
        action=f"GET https://api.example.com/users/{i}",
        result="Failed - Connection timeout",
        reflection="Network request timed out after 30 seconds",
        metadata={"is_failure": True, "failure_reason": "Connection timeout", "user_id": str(i)}
    )
    store.store(failed_episode)
    print(f"  ✗ Stored failure episode {i+1}")

# Part 3: Retrieve successful patterns and failures separately
print("\n3. Retrieving patterns...")

successes = store.retrieve_successes(limit=10)
print(f"  ✓ Found {len(successes)} successful patterns")

failures = store.retrieve_failures(limit=10)
print(f"  ✗ Found {len(failures)} failure patterns (anti-patterns)")

# Part 4: Retrieve both to make informed decisions
print("\n4. Comprehensive pattern analysis...")
patterns = store.retrieve_with_anti_patterns(limit=10)
print(f"  Total patterns:")
print(f"    - Successes: {len(patterns['successes'])}")
print(f"    - Failures: {len(patterns['failures'])}")

# Show what works and what doesn't
print("\n  What WORKS:")
for ep in patterns['successes'][:2]:
    print(f"    ✓ {ep.goal} → {ep.result}")

print("\n  What DOESN'T work (DO NOT TOUCH):")
for ep in patterns['failures']:
    print(f"    ✗ {ep.goal} → {ep.result}")
    print(f"      Reason: {ep.metadata.get('failure_reason', 'Unknown')}")

# Part 5: Memory Compression - Create old episodes
print("\n5. Creating old episodes for compression demo...")
old_time = datetime.now(timezone.utc) - timedelta(days=10)

for i in range(5):
    old_episode = Episode(
        goal="Process batch job",
        action=f"Run ETL pipeline for batch {i}",
        result="Completed successfully",
        reflection="Pipeline processed 1000 records",
        timestamp=old_time,
        metadata={"records_processed": 1000, "batch_id": i}
    )
    store.store(old_episode)
print(f"  ✓ Created 5 old episodes")

# Part 6: Run sleep cycle compression (dry run first)
print("\n6. Running sleep cycle compression (dry run)...")
dry_result = compressor.compress_old_episodes(dry_run=True)
print(f"  Dry run results:")
print(f"    - Old episodes found: {dry_result['old_episodes']}")
print(f"    - Would compress: {dry_result['compressed_count']} episodes")
print(f"    - Would create: {dry_result['rules_created']} semantic rules")

# Part 7: Actual compression
print("\n7. Running actual compression...")
result = compressor.compress_old_episodes(dry_run=False)
print(f"  Compression complete:")
print(f"    - Compressed: {result['compressed_count']} episodes")
print(f"    - Created: {result['rules_created']} semantic rules")

# Part 8: Retrieve semantic rules
print("\n8. Retrieving semantic rules...")
rules = compressor.retrieve_rules(limit=10)
print(f"  Found {len(rules)} semantic rules:")
for i, rule in enumerate(rules, 1):
    print(f"\n  Rule {i}:")
    print(f"    Knowledge: {rule.rule}")
    print(f"    Confidence: {rule.confidence:.2f}")
    print(f"    Source episodes: {len(rule.source_episode_ids)}")
    if rule.metadata:
        print(f"    Metadata: {rule.metadata}")

# Part 9: Using mark_as_failure helper
print("\n9. Using mark_as_failure helper...")
normal_episode = Episode(
    goal="Deploy application",
    action="Run deployment script",
    result="Deployment failed",
    reflection="Container failed to start"
)
failed_episode = normal_episode.mark_as_failure(reason="Docker image not found")
print(f"  ✓ Marked episode as failure: {failed_episode.is_failure()}")
print(f"    Failure reason: {failed_episode.metadata['failure_reason']}")

print("\n" + "=" * 80)
print("Demo complete! Key takeaways:")
print("=" * 80)
print("1. Memory Decay: Old episodes are compressed into semantic rules")
print("   → Reduces storage and retrieval costs")
print("   → Preserves knowledge without raw logs")
print("")
print("2. Negative Memory: Failures are explicitly tracked")
print("   → Agents can query 'What works' AND 'What failed'")
print("   → Prunes search space by avoiding known failures")
print("   → DO NOT TOUCH patterns prevent repeated mistakes")
print("")
print("3. Scale by Subtraction: Less context, more knowledge")
print("   → No infinite context windows needed")
print("   → Efficient memory management")
print("=" * 80)

# Cleanup
import os
if os.path.exists("demo_episodes.jsonl"):
    os.remove("demo_episodes.jsonl")
if os.path.exists("demo_semantic_rules.jsonl"):
    os.remove("demo_semantic_rules.jsonl")
print("\n✓ Cleanup complete")
