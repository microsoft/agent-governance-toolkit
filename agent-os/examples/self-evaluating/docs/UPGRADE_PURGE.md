# Upgrade Purge Strategy: Active Wisdom Lifecycle Management

## Overview

The Upgrade Purge Strategy is an active lifecycle management system for the wisdom database. It treats "Wisdom" like a high-performance cache rather than a cold storage archive. The key insight: **lessons are often just band-aids for a model's weaknesses**, and when you upgrade the base model, many of those band-aids become redundant.

## Philosophy

### The Problem
- AI models continuously improve (GPT-3.5 → GPT-4 → GPT-4.5, etc.)
- Each upgrade fixes many of the model's previous weaknesses
- Lessons learned to compensate for old weaknesses become obsolete
- Without lifecycle management, the wisdom database grows forever with stale lessons

### The Solution: Upgrade Purge
When upgrading the underlying model:
1. **Audit**: Take the "Failure Scenarios" that generated old lessons
2. **Test**: Run them against the New Model without the extra context
3. **Purge**: If the New Model solves it natively, DELETE the old lesson
4. **Result**: Database gets smaller and more specialized over time

## Benefits

### 1. **Leaner Database**
- Removes redundant lessons automatically
- Keeps only edge cases the new model can't handle
- More efficient use of context window

### 2. **Self-Maintaining**
- No manual cleanup required
- Automatically adapts to model improvements
- Continuous refinement over time

### 3. **Better Signal-to-Noise**
- Only specialized lessons remain
- Clearer guidance for the agent
- Faster context loading

### 4. **Cost Efficiency**
- Smaller context = lower token costs
- Faster inference times
- More maintainable system

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              NORMAL OPERATION (Learning)                │
├─────────────────────────────────────────────────────────┤
│  Agent encounters failures → Learns lessons             │
│  Wisdom database grows: 10 → 30 → 50 lessons            │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│           MODEL UPGRADE (Purge Trigger)                 │
├─────────────────────────────────────────────────────────┤
│  You: "I'm upgrading from GPT-3.5 to GPT-4"           │
│  System: "Let me audit your wisdom database..."         │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│               AUDIT PHASE                               │
├─────────────────────────────────────────────────────────┤
│  For each lesson in database:                           │
│    1. Extract the original failure scenario             │
│    2. Test against GPT-4 WITHOUT the lesson             │
│    3. Score the new model's performance                 │
│                                                         │
│  Results:                                               │
│    ✅ Lesson 1: Score 0.9 → REDUNDANT (can purge)     │
│    ✅ Lesson 2: Score 0.85 → REDUNDANT (can purge)    │
│    ⚠️  Lesson 3: Score 0.6 → CRITICAL (keep it)       │
└─────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│               PURGE PHASE                               │
├─────────────────────────────────────────────────────────┤
│  Delete redundant lessons (1, 2)                        │
│  Keep critical lessons (3)                              │
│  Update wisdom database                                 │
│  Record purge in history                                │
│                                                         │
│  Result: 50 lessons → 20 lessons (60% reduction) ✅     │
└─────────────────────────────────────────────────────────┘
```

## Usage

### Basic Usage

```python
from model_upgrade import ModelUpgradeManager

# Initialize the upgrade manager
manager = ModelUpgradeManager()

# Define baseline instructions for the new model
baseline_instructions = """You are a helpful AI assistant. Your goal is to 
provide accurate and useful responses to user queries. You have access to 
tools that you can use to help answer questions. Always think step-by-step 
and provide clear, concise answers."""

# Perform upgrade audit and purge
report = manager.perform_upgrade(
    new_model="gpt-4o",              # The new model you're upgrading to
    baseline_instructions=baseline_instructions,
    score_threshold=0.8,              # Threshold for "solved natively"
    auto_purge=True,                  # Automatically purge redundant lessons
    verbose=True                      # Show detailed progress
)

# Review results
print(f"Purged: {report['purge_results']['purged_count']} lessons")
print(f"Remaining: {report['purge_results']['remaining_count']} lessons")
```

### Step-by-Step (Manual Review)

```python
# Step 1: Audit only (review before purging)
audit_results = manager.audit_wisdom_database(
    new_model="gpt-4o",
    baseline_instructions=baseline_instructions,
    score_threshold=0.8,
    verbose=True
)

# Step 2: Review recommendations
print(f"Redundant lessons: {len(audit_results['redundant_lessons'])}")
print(f"Critical lessons: {len(audit_results['critical_lessons'])}")

# Step 3: Manually purge after review
purge_results = manager.purge_redundant_lessons(
    audit_results=audit_results,
    verbose=True
)
```

## Integration with Existing Components

### 1. Memory System (agent.py)
The `MemorySystem` now stores query and response alongside each improvement:

```python
memory.update_instructions(
    new_instructions="...",
    critique="...",
    query="What is 15 * 24?",        # Original query that failed
    response="Let me calculate..."    # Agent's failed response
)
```

This context is essential for the audit phase to test scenarios.

### 2. Observer Agent (observer.py)
The `ObserverAgent` automatically captures this context during learning:

```python
self.wisdom.update_instructions(
    new_instructions,
    analysis["critique"],
    query=event.query,                # From telemetry
    response=event.agent_response     # From telemetry
)
```

### 3. Prioritization Framework (prioritization.py)
The upgrade purge also cleans up the prioritization framework's safety corrections, removing corrections that are no longer needed.

## Upgrade Tracking

The system maintains an upgrade log (`model_upgrade_log.json`) that tracks:
- When upgrades occurred
- Which model was used
- How many lessons were purged
- Historical reduction over time

```json
{
  "current_model": "gpt-4o",
  "upgrades": [
    {
      "timestamp": "2024-01-15T10:30:00",
      "new_model": "gpt-4o",
      "purged_count": 30,
      "remaining_count": 20
    }
  ]
}
```

## Configuration

### Score Threshold
The `score_threshold` parameter (default: 0.8) determines when a lesson is considered redundant:
- **Lower threshold (0.6)**: More aggressive purging, keeps fewer lessons
- **Higher threshold (0.9)**: More conservative, keeps more lessons
- **Recommended**: 0.8 (80% quality threshold)

### Baseline Instructions
Provide clear, concise baseline instructions that represent the new model's foundation. These should NOT include specific lessons - just the core agent behavior.

## Example Timeline

### Month 1: Initial Learning (GPT-3.5)
- Start: 0 lessons
- Learn from failures: +50 lessons
- End: 50 lessons

### Month 3: Continued Learning (GPT-3.5)
- Start: 50 lessons
- Learn from failures: +30 lessons
- End: 80 lessons

### Month 6: Upgrade to GPT-4
- Start: 80 lessons
- **Audit**: Test all lessons against GPT-4
- **Purge**: Remove 40 redundant lessons
- End: 40 lessons ✅ (50% reduction)

### Month 9: Continued Learning (GPT-4)
- Start: 40 lessons
- Learn from failures: +15 lessons
- End: 55 lessons

### Month 12: Upgrade to GPT-4.5
- Start: 55 lessons
- **Audit**: Test all lessons against GPT-4.5
- **Purge**: Remove 30 redundant lessons
- End: 25 lessons ✅ (45% reduction)

**Key Insight**: The database continuously refines itself, maintaining only the most specialized edge cases.

## Best Practices

### 1. **Upgrade After Model Changes**
Run the upgrade purge whenever you change your base model (even minor version updates).

### 2. **Review Before Purging**
For production systems, use `auto_purge=False` initially to review audit results before purging.

### 3. **Backup Before Upgrading**
Keep a backup of `system_instructions.json` before running the purge, just in case.

### 4. **Monitor Purge History**
Track the `purge_history` in your wisdom database to understand lifecycle trends.

### 5. **Adjust Threshold Based on Criticality**
- **Non-critical systems**: Use lower threshold (0.7) for aggressive purging
- **Critical systems**: Use higher threshold (0.9) to be conservative

## Testing

Run the test suite to validate the upgrade purge functionality:

```bash
python test_model_upgrade.py
```

Try the example demonstration:

```bash
python example_upgrade_purge.py
```

## Advanced: Custom Evaluation

You can customize the evaluation logic by subclassing `ModelUpgradeManager`:

```python
class CustomUpgradeManager(ModelUpgradeManager):
    def _evaluate_response(self, query: str, agent_response: str) -> float:
        # Custom evaluation logic
        # Return score 0.0 - 1.0
        pass
```

## Troubleshooting

### "No lessons to purge"
This is normal if:
- The new model isn't significantly better
- Your lessons are already specialized
- Threshold is too high

### "All lessons marked as redundant"
This suggests:
- New model is much better
- Threshold might be too low
- Lessons were too generic

### "Audit takes too long"
Audit time scales with:
- Number of lessons
- Model response time
- Network latency

Consider batching or caching evaluations for large databases.

## Future Enhancements

Potential improvements to the upgrade purge strategy:

1. **Semantic Similarity**: Use embeddings to detect similar failure patterns
2. **Batch Processing**: Test multiple scenarios in parallel
3. **A/B Testing**: Compare new model with/without lessons
4. **Cost Analysis**: Calculate cost savings from purging
5. **Automatic Triggers**: Auto-detect model upgrades and suggest purges

## References

- [README.md](README.md) - Main documentation
- [ARCHITECTURE_DECOUPLED.md](ARCHITECTURE_DECOUPLED.md) - Decoupled architecture
- [PRIORITIZATION_FRAMEWORK.md](PRIORITIZATION_FRAMEWORK.md) - Context prioritization
- [model_upgrade.py](model_upgrade.py) - Implementation source code
- [test_model_upgrade.py](test_model_upgrade.py) - Test suite
- [example_upgrade_purge.py](example_upgrade_purge.py) - Usage example

---

**Remember**: Treat your wisdom database like a high-performance cache, not a cold storage archive. Purge regularly to keep it lean, focused, and effective!
