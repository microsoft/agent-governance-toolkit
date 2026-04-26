# Intent Detection and Intent-Based Evaluation

## The Problem: Engagement is Often Failure

In productivity tools, a single success metric doesn't work:

**The Trapped User Scenario:**
- User asks: "How do I reset my password?"
- 20 turns later, they're still talking to the bot
- They are not "engaged" — they are **trapped**
- High engagement = FAILURE

**The Creative Conversation Scenario:**
- User asks: "Help me design a microservices architecture"
- 20 turns of deep exploration
- This is a valuable brainstorming session
- High engagement = SUCCESS

**Key Insight:** We cannot use a single metric for success. We must detect Intent in the first interaction.

## Solution: Intent-Based Evaluation

### Intent Types

#### 1. Troubleshooting (Short-Lived Intent)

**Characteristics:**
- User has a specific problem
- Wants quick resolution
- Examples: "How do I reset my password?", "Why isn't this working?", "Fix this error"

**Success Metric:** Time-to-Resolution
- **Success:** Resolved in ≤ 3 turns
- **Failure:** > 3 turns means user is trapped, not engaged

**Reasoning:**
- Users want to get unstuck and move on
- Every additional turn is friction
- 20 turns = trapped in a support loop

#### 2. Brainstorming (Long-Lived Intent)

**Characteristics:**
- User wants to explore ideas
- Open-ended discussion
- Examples: "Help me design a system", "Let's explore approaches", "What are the trade-offs?"

**Success Metric:** Depth of Context
- **Success:** ≥ 5 turns with rich discussion
- **Failure:** Too short means we failed to be creative enough

**Reasoning:**
- Users want deep exploration
- Short conversations miss opportunities
- 2 turns = insufficient creative depth

## Architecture

### 1. Intent Detection

The `IntentDetector` class analyzes the first user query to determine intent:

```python
from intent_detection import IntentDetector

detector = IntentDetector()
result = detector.detect_intent("How do I reset my password?")
# Result: {"intent": "troubleshooting", "confidence": 0.95, "reasoning": "..."}
```

**Detection Process:**
1. User's first query is sent to LLM
2. LLM classifies as "troubleshooting" or "brainstorming"
3. Returns intent type, confidence score, and reasoning
4. Intent is stored in telemetry for the entire conversation

### 2. Conversation Tracking

The system tracks multi-turn conversations:

```python
# Turn 1: Intent detected
doer.run(
    query="How do I reset my password?",
    conversation_id="conv-123",
    turn_number=1  # Intent detected here
)

# Turn 2+: Same conversation
doer.run(
    query="I tried that, still not working",
    conversation_id="conv-123",
    turn_number=2  # Same intent used
)
```

**Key Features:**
- `conversation_id`: Groups related turns together
- `turn_number`: Tracks position in conversation (1-indexed)
- `intent_type`: Set on first turn, inherited by subsequent turns
- `intent_confidence`: Confidence in the detected intent

### 3. Intent-Based Evaluation

The `ObserverAgent` evaluates conversations using intent-specific metrics:

```python
from observer import ObserverAgent

observer = ObserverAgent()
evaluation = observer.evaluate_conversation_by_intent("conv-123")

# For troubleshooting:
# {"success": False, "turn_count": 5, "reasoning": "User trapped..."}

# For brainstorming:
# {"success": True, "turn_count": 10, "depth_score": 0.8, "reasoning": "..."}
```

**Evaluation Process:**
1. Observer collects all events for a conversation
2. Retrieves intent from first turn
3. Applies intent-specific success criteria
4. Returns evaluation with success/failure status

### 4. Metrics

#### Troubleshooting Metrics

```python
from intent_detection import IntentMetrics

# Quick resolution = SUCCESS
result = IntentMetrics.evaluate_troubleshooting(turn_count=2, resolved=True)
# {"success": True, "metric": "time_to_resolution", ...}

# User trapped = FAILURE
result = IntentMetrics.evaluate_troubleshooting(turn_count=5, resolved=True)
# {"success": False, "reasoning": "User trapped in conversation..."}
```

**Thresholds:**
- Max acceptable turns: 3
- > 3 turns = Trapped user (failure)

#### Brainstorming Metrics

```python
# Deep exploration = SUCCESS
result = IntentMetrics.evaluate_brainstorming(
    turn_count=10,
    context_depth_score=0.8
)
# {"success": True, "metric": "depth_of_context", ...}

# Too short = FAILURE
result = IntentMetrics.evaluate_brainstorming(
    turn_count=2,
    context_depth_score=0.5
)
# {"success": False, "reasoning": "Too short, failed to be creative..."}
```

**Thresholds:**
- Min acceptable turns: 5
- Min acceptable depth: 0.6 (on scale of 0-1)
- Too few turns or low depth = Failed to engage creatively

**Context Depth Calculation:**
- Analyzes conversation history
- Considers response length, diversity of topics
- Returns score 0-1 (0 = shallow, 1 = deep)

## Usage

### Basic Example

```python
from agent import DoerAgent
from observer import ObserverAgent
import uuid

# Initialize
doer = DoerAgent()
conversation_id = str(uuid.uuid4())

# Multi-turn conversation
doer.run("How do I reset my password?", conversation_id=conversation_id, turn_number=1)
doer.run("Thanks!", conversation_id=conversation_id, turn_number=2)

# Evaluate
observer = ObserverAgent()
observer.process_events()  # Applies intent-based evaluation
```

### Running the Demo

```bash
python example_intent_detection.py
```

This demonstrates:
1. Troubleshooting with quick resolution (SUCCESS)
2. Troubleshooting with user trapped (FAILURE)
3. Brainstorming with deep exploration (SUCCESS)
4. Brainstorming that's too shallow (FAILURE)

### Running Tests

```bash
python test_intent_detection.py
```

Tests the intent detection system without requiring API keys.

## Configuration

Environment variables (in `.env`):

```bash
# Model for intent detection (optional, defaults to gpt-4o-mini)
INTENT_MODEL=gpt-4o-mini
```

## Benefits

1. **Accurate Success Measurement**
   - Different intents have different success criteria
   - No more false positives from "engaged" trapped users

2. **Better Learning**
   - Observer learns from intent-specific failures
   - Troubleshooting: "Resolve faster"
   - Brainstorming: "Go deeper"

3. **Prevents Misinterpretation**
   - 20-turn troubleshooting = FAILURE (trapped)
   - 20-turn brainstorming = SUCCESS (engaged)

4. **Automatic Detection**
   - Intent detected from first interaction
   - No manual labeling required
   - Works with any query type

## Implementation Details

### Telemetry Schema

```json
{
  "event_type": "task_complete",
  "timestamp": "2024-01-01T12:00:00",
  "query": "How do I reset my password?",
  "agent_response": "...",
  "conversation_id": "conv-123",
  "turn_number": 1,
  "intent_type": "troubleshooting",
  "intent_confidence": 0.95
}
```

### Observer Output

```
Intent-Based Evaluation Statistics:
  🔧 Troubleshooting Conversations: 2
     ❌ Failed (>3 turns): 1
  💡 Brainstorming Conversations: 2
     ❌ Failed (too shallow): 1
```

## Files

- `intent_detection.py`: Core intent detection and metrics
- `example_intent_detection.py`: Demo script
- `test_intent_detection.py`: Test suite
- `INTENT_DETECTION.md`: This documentation

## Future Enhancements

Potential improvements:
1. More intent types (research, comparison, tutorial)
2. Dynamic threshold adjustment based on domain
3. Intent confidence thresholds
4. Intent transition detection (troubleshooting → brainstorming)
5. Per-user intent patterns

## References

- Main README: [README.md](README.md)
- Agent Architecture: [ARCHITECTURE.md](ARCHITECTURE.md)
- Decoupled Architecture: [ARCHITECTURE_DECOUPLED.md](ARCHITECTURE_DECOUPLED.md)
