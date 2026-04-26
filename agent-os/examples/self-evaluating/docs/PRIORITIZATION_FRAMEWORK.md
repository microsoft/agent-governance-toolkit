# Prioritization Framework

## Overview

The Prioritization Framework is a Graph RAG-inspired system that sits between the wisdom database and the agent. It ranks retrieved context based on a hierarchy of needs, ensuring the agent receives not just context, but a **ranked strategy** for execution.

## Three-Layer Hierarchy

### 1. Safety Layer (Highest Priority) 🔴
**"Have we failed at this exact task recently?"**

- Tracks recent failures and their corrections
- Injects critical warnings with high urgency
- Prevents repeating past mistakes
- Time-windowed (default: 7 days)
- User-specific or global corrections

**Example:**
```
⚠️ CRITICAL SAFETY WARNINGS (Highest Priority)
1. [WARNING] Task similar to 'calculate mathematical expression' failed recently 
   (2x in last 168h). Issue: Agent calculated mentally instead of using calculator 
   tool. MUST DO: MUST explicitly use the calculate() tool for any mathematical operations
```

### 2. Personalization Layer (Medium Priority) 🟡
**"Does this specific user have preferred constraints?"**

- Stores user-specific preferences
- Learns from user feedback over time
- Priority-ranked within layer (1-10 scale)
- Customizes agent behavior per user

**Example:**
```
## USER PREFERENCES (Important)
You must respect these user-specific constraints:
1. [output_format] Always provide responses in JSON format → JSON
2. [verbosity] Keep responses brief and to the point → concise
```

### 3. Global Wisdom Layer (Low Priority) 🟢
**"What is the generic best practice?"**

- Base system instructions from wisdom database
- Generic best practices
- Foundation for all responses
- Continuously evolved through traditional learning

**Example:**
```
You are a helpful AI assistant with access to tools. Your goal is to provide 
accurate and useful responses to user queries.
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    User Query                           │
└───────────────────┬─────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│            Prioritization Framework                     │
│  ┌───────────────────────────────────────────────────┐ │
│  │  1. Safety Layer (Highest Priority)              │ │
│  │     - Recent failures for this task              │ │
│  │     - User-specific corrections                  │ │
│  │     - Time-windowed (7 days default)             │ │
│  └───────────────────────────────────────────────────┘ │
│                        │                                │
│  ┌───────────────────────────────────────────────────┐ │
│  │  2. Personalization Layer (Medium Priority)      │ │
│  │     - User preferences                           │ │
│  │     - Priority-ranked (1-10)                     │ │
│  │     - Learned from feedback                      │ │
│  └───────────────────────────────────────────────────┘ │
│                        │                                │
│  ┌───────────────────────────────────────────────────┐ │
│  │  3. Global Wisdom Layer (Low Priority)           │ │
│  │     - Base system instructions                   │ │
│  │     - Generic best practices                     │ │
│  │     - Evolved from traditional learning          │ │
│  └───────────────────────────────────────────────────┘ │
└───────────────────┬─────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│            Prioritized Context                          │
│  "I must solve X, but I must specifically avoid Y       │
│   because I failed at it last time for this user."      │
└───────────────────┬─────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│                 Agent Execution                         │
└─────────────────────────────────────────────────────────┘
```

## Integration Points

### DoerAgent Integration
```python
from agent import DoerAgent

# Initialize with prioritization
doer = DoerAgent(enable_prioritization=True)

# Execute with user context
result = doer.run(
    query="What is 25 * 4?",
    user_id="alice",  # For personalization
    verbose=True
)
```

### ObserverAgent Integration
```python
from observer import ObserverAgent

# Initialize with prioritization
observer = ObserverAgent(enable_prioritization=True)

# Process events - automatically learns:
# 1. Safety corrections from failures
# 2. User preferences from feedback
results = observer.process_events(verbose=True)
```

## Data Structures

### SafetyCorrection
Represents a correction for a past failure.

```python
@dataclass
class SafetyCorrection:
    task_pattern: str           # Pattern of task that failed
    failure_description: str    # What went wrong
    correction: str            # How to avoid this failure
    timestamp: str             # When this failure occurred
    user_id: Optional[str]     # User who experienced failure
    occurrences: int           # Number of times this occurred
```

### UserPreference
Represents a user-specific preference or constraint.

```python
@dataclass
class UserPreference:
    user_id: str               # User identifier
    preference_key: str        # Type (e.g., "output_format")
    preference_value: str      # Value (e.g., "JSON")
    description: str           # Human-readable description
    priority: int              # Priority level (1-10)
    timestamp: str             # When preference was learned
```

### PrioritizedContext
Container for the three-layer context.

```python
@dataclass
class PrioritizedContext:
    safety_items: List[str]           # High priority warnings
    personalization_items: List[str]  # Medium priority preferences
    global_wisdom: str                # Low priority base instructions
    
    def build_system_prompt() -> str:
        # Builds system prompt with proper layering
```

## Storage

### Files Created
- `safety_corrections.json` - Safety layer database
- `user_preferences.json` - Personalization layer database
- `system_instructions.json` - Global wisdom layer (existing)

### Safety Corrections Database
```json
{
  "corrections": [
    {
      "task_pattern": "calculate mathematical expression",
      "failure_description": "Agent calculated mentally",
      "correction": "MUST use calculate() tool",
      "timestamp": "2024-01-01T12:00:00",
      "user_id": "alice",
      "occurrences": 2
    }
  ],
  "last_updated": "2024-01-01T12:30:00"
}
```

### User Preferences Database
```json
{
  "preferences": {
    "alice": [
      {
        "user_id": "alice",
        "preference_key": "output_format",
        "preference_value": "JSON",
        "description": "Always use JSON format",
        "priority": 9,
        "timestamp": "2024-01-01T12:00:00"
      }
    ]
  },
  "last_updated": "2024-01-01T12:30:00"
}
```

## API Reference

### PrioritizationFramework

Main class for prioritization.

#### Initialization
```python
framework = PrioritizationFramework(
    safety_db_file="safety_corrections.json",
    preferences_db_file="user_preferences.json",
    failure_window_hours=168  # 7 days
)
```

#### Methods

**get_prioritized_context()**
```python
context = framework.get_prioritized_context(
    query="What is 25 * 4?",
    global_wisdom="You are a helpful assistant.",
    user_id="alice",
    verbose=True
)
# Returns: PrioritizedContext
```

**add_safety_correction()**
```python
framework.add_safety_correction(
    task_pattern="calculate math",
    failure_description="Didn't use tool",
    correction="Must use calculate() tool",
    user_id="alice"
)
```

**add_user_preference()**
```python
framework.add_user_preference(
    user_id="alice",
    preference_key="output_format",
    preference_value="JSON",
    description="Use JSON format",
    priority=9
)
```

**learn_from_failure()**
```python
framework.learn_from_failure(
    query="What is 5 + 5?",
    critique="Agent should use calculator tool",
    user_id="alice",
    verbose=True
)
```

**learn_user_preference()**
```python
framework.learn_user_preference(
    user_id="alice",
    query="Give me data",
    user_feedback="Please use JSON format",
    verbose=True
)
```

**get_stats()**
```python
stats = framework.get_stats()
# Returns:
# {
#     "total_safety_corrections": 5,
#     "recent_safety_corrections": 3,
#     "total_users_with_preferences": 2,
#     "total_preferences": 7,
#     "failure_window_hours": 168
# }
```

## Learning Mechanisms

### Automatic Safety Learning
When ObserverAgent detects a failure (score < threshold):
1. Extracts failure pattern from query
2. Extracts correction from critique
3. Stores in safety corrections database
4. Auto-injected for similar future queries

### Automatic Preference Learning
When user provides feedback:
1. Detects common preference patterns:
   - "JSON format" → output_format preference
   - "concise" → verbosity preference
   - "use calculator" → tool_preference
2. Stores with priority ranking
3. Applied to all future queries for that user

## Configuration

### Environment Variables
```bash
# Existing variables
OPENAI_API_KEY=sk-...
AGENT_MODEL=gpt-4o-mini
REFLECTION_MODEL=gpt-4o-mini
EVOLUTION_MODEL=gpt-4o-mini
SCORE_THRESHOLD=0.8

# Prioritization settings (optional)
FAILURE_WINDOW_HOURS=168  # Default: 7 days
```

### Disabling Prioritization
```python
# Disable in DoerAgent
doer = DoerAgent(enable_prioritization=False)

# Disable in ObserverAgent
observer = ObserverAgent(enable_prioritization=False)
```

## Examples

### Example 1: Math Query with Safety Warning
```python
# User alice has failed on math queries before
framework = PrioritizationFramework()

context = framework.get_prioritized_context(
    query="What is 15 * 24 + 50?",
    global_wisdom="You are a helpful assistant.",
    user_id="alice"
)

prompt = context.build_system_prompt()
# Result includes:
# - Safety warning about using calculator tool (HIGHEST priority)
# - Alice's preferences for JSON output (MEDIUM priority)
# - Base instructions (LOW priority)
```

### Example 2: Learning from Failure
```python
observer = ObserverAgent(enable_prioritization=True)

# Processes telemetry event where agent failed
# Automatically:
# 1. Extracts failure pattern
# 2. Creates safety correction
# 3. Stores for future injection

results = observer.process_events()
```

### Example 3: User Feedback Learning
```python
doer = DoerAgent(enable_prioritization=True)

result = doer.run(
    query="Give me the weather data",
    user_id="bob",
    user_feedback="Please always use JSON format for data"
)

# Observer will later process this feedback and:
# 1. Extract preference: output_format=JSON
# 2. Store for user bob
# 3. Apply to all bob's future queries
```

## Benefits

1. **Prevents Recurring Failures**: Safety layer ensures past mistakes aren't repeated
2. **Personalized Experience**: Each user gets customized agent behavior
3. **Contextual Awareness**: Agent knows what to avoid and what user prefers
4. **Automatic Learning**: No manual configuration needed
5. **Priority-Based**: Critical information is most visible to the agent
6. **Scalable**: Efficient storage and retrieval with time-windowing

## Testing

Run prioritization tests:
```bash
python test_prioritization.py
```

Run integration demo:
```bash
python example_prioritization.py
```

## Future Enhancements

1. **Graph RAG Integration**: Use actual graph structure to understand relationships between tasks
2. **Semantic Matching**: Use embeddings for better task pattern matching
3. **LLM-based Extraction**: Use LLM to extract structured failure info and preferences
4. **Multi-modal Preferences**: Support preferences beyond text (e.g., code style, visual preferences)
5. **Preference Conflicts**: Handle conflicting preferences with resolution strategies
6. **A/B Testing**: Test different prioritization strategies
7. **Distributed Storage**: Scale to database backend for production use

## Implementation Notes

### Why This Approach?

1. **Inspired by Graph RAG**: While not a full graph implementation, the prioritization framework captures the spirit of understanding relationships (task→failure→correction, user→preference→constraint)

2. **Three-Layer Design**: Matches human cognitive hierarchy:
   - Safety (survival): "What must I avoid?"
   - Social (personalization): "What does this person want?"
   - Knowledge (wisdom): "What generally works?"

3. **Time-Windowed Safety**: Recent failures are more relevant than old ones

4. **Priority-Ranked Preferences**: Not all preferences are equally important

5. **Automatic Learning**: Framework learns from both failures and feedback without manual intervention

### Performance Considerations

- **Time Complexity**: O(n) for safety correction matching (where n = number of corrections in window)
- **Space Complexity**: Bounded by time window for safety corrections
- **Storage**: JSON-based for simplicity; can be replaced with database for scale
- **Caching**: Framework loads databases on init; consider adding caching for high-throughput scenarios

## License

MIT
