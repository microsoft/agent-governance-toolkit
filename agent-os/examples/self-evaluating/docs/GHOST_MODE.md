# Ghost Mode (Passive Observation) - The Observer Daemon Pattern

## Overview

Ghost Mode implements the "No UI" paradigm where the Interface Layer sits in the background, consuming signal streams silently and only surfacing when it has high-confidence value. This is the Observer Daemon Pattern: **invisible until indispensable**.

## The Problem with "Destination" UIs

**The Old World:** "The user must explicitly ask for help."

Users must:
- Navigate to a website or app
- Type their question
- Wait for response
- Context switch from their current task

This interrupts workflow and creates friction.

## The New World: Ghost Mode

**Ghost Mode:** A background daemon that:
1. Sits silently in the background (no UI)
2. Consumes signal streams passively
3. Runs dry-run analysis without taking action
4. Only surfaces when confidence is high
5. Learns user behavior patterns over time

### The Three Core Principles

1. **The Setup**: The Interface Layer sits in the background (Ghost Mode)
2. **The Loop**: It consumes the signal stream silently. It sends data to the Agent with a "Dry Run" flag
3. **The Trigger**: It only surfaces when it has high-confidence value

### The Key Insight

> The future interface isn't a "Destination" (a website). It is a Daemon (a background process). It is invisible until it is indispensable.

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Ghost Mode System                         │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐        ┌──────────────┐                   │
│  │  Application │───────>│ Signal Stream│                   │
│  │   Signals    │        │   (Passive)  │                   │
│  └──────────────┘        └──────┬───────┘                   │
│                                 │                             │
│                                 ▼                             │
│                    ┌────────────────────┐                    │
│                    │ GhostModeObserver  │                    │
│                    │   (Background)     │                    │
│                    └─────────┬──────────┘                    │
│                              │                                │
│                    ┌─────────┴──────────┐                   │
│                    │                     │                   │
│                    ▼                     ▼                   │
│         ┌──────────────────┐  ┌──────────────────┐         │
│         │ Dry Run Analysis │  │  Context Shadow   │         │
│         │ (No Actions)     │  │ (Learn Patterns)  │         │
│         └─────────┬────────┘  └──────────────────┘         │
│                   │                                          │
│                   ▼                                          │
│         ┌──────────────────┐                                │
│         │ Confidence Score │                                │
│         │   (0.0 - 1.0)    │                                │
│         └─────────┬────────┘                                │
│                   │                                          │
│              Is confidence                                   │
│              >= threshold?                                   │
│                   │                                          │
│         ┌─────────┴─────────┐                               │
│         │                   │                                │
│     YES │               NO  │                                │
│         ▼                   ▼                                │
│   ┌──────────┐      ┌──────────┐                           │
│   │ SURFACE  │      │  SILENT  │                           │
│   │(Callback)│      │  (Skip)  │                           │
│   └──────────┘      └──────────┘                           │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Key Classes

#### 1. `GhostModeObserver`

The background daemon that observes without interfering.

```python
observer = GhostModeObserver(
    confidence_threshold=0.7,  # Only surface if confidence >= 0.7
    surfacing_callback=my_callback  # What to do when surfacing
)

# Start the daemon (runs in background thread)
observer.start_observing(poll_interval=1.0)

# Application generates signals (non-blocking)
observer.observe_signal({
    "type": "file_change",
    "data": {"file_path": "/config/secrets.yaml", "change_type": "modified"}
})

# Daemon processes silently in background...
# Surfaces only when confident

# Stop when done
observer.stop_observing()
```

#### 2. `ContextShadow`

The "Cookies of the Real World" - secure local storage of user behavior patterns.

```python
shadow = ContextShadow(user_id="user123")

# Learn a workflow pattern
pattern = BehaviorPattern(
    pattern_id="expense_filing",
    name="Weekly Expense Filing",
    trigger="open_expense_form",
    steps=["Open form", "Attach receipt", "Fill amount", "Submit"],
    frequency=1,
    last_seen="2024-01-01T16:00:00",
    confidence=0.7
)
shadow.learn_pattern(pattern)

# Query learned patterns
patterns = shadow.query_patterns(
    trigger="open_expense_form",
    min_confidence=0.5
)

# Get statistics
stats = shadow.get_stats()
print(f"Learned {stats['total_patterns']} patterns")
```

#### 3. `ObservationResult`

Result of passive observation with confidence scoring.

```python
result = ObservationResult(
    timestamp="2024-01-01T12:00:00",
    signal_type="file_change",
    observation="Security-sensitive file modified",
    confidence=0.95,  # High confidence
    should_surface=True,
    recommendation="Review security implications"
)

# Check confidence level
level = result.get_confidence_level()  # ConfidenceLevel.CRITICAL
```

## Confidence Levels

Ghost Mode uses confidence scoring to decide when to surface:

| Level | Range | Behavior | Example |
|-------|-------|----------|---------|
| **LOW** | < 0.5 | Don't surface, stay silent | Regular file save |
| **MEDIUM** | 0.5-0.7 | Maybe surface (context dependent) | Test file modified |
| **HIGH** | 0.7-0.9 | Probably surface | Security file changed |
| **CRITICAL** | > 0.9 | Always surface | System error detected |

### Confidence Calculation Factors

1. **Signal Clarity**: Do we have all required fields?
2. **Pattern Match**: Have we seen this workflow before?
3. **Analysis Quality**: Did we extract meaningful insights?
4. **Urgency Indicators**: Security keywords, error levels, etc.

## Dry Run Mode

Ghost Mode analyzes signals without taking action. This is critical for:

- **Safety**: Never interferes with user workflow
- **Learning**: Builds understanding without risk
- **Testing**: What would happen if we acted?

```python
# Signal comes in
signal = {
    "type": "log_stream",
    "data": {"level": "ERROR", "message": "Database timeout"}
}

# Observer processes in dry-run mode:
# 1. What happened? → "Error detected"
# 2. How confident are we? → 0.9 (high)
# 3. Should we surface? → Yes
# 4. What to recommend? → "Investigate error in logs"

# No action taken, just analysis
```

## Integration Examples

### Example 1: IDE Integration

```python
from ghost_mode import GhostModeObserver

def show_notification(observation):
    """Show IDE notification when Ghost Mode surfaces."""
    ide.show_notification(
        title="Ghost Mode Alert",
        message=observation.observation,
        actions=[observation.recommendation] if observation.recommendation else []
    )

# Setup observer
observer = GhostModeObserver(
    confidence_threshold=0.7,
    surfacing_callback=show_notification
)
observer.start_observing()

# Hook into IDE events
ide.on_file_change(lambda event: observer.observe_signal({
    "type": "file_change",
    "data": event
}))

ide.on_error(lambda error: observer.observe_signal({
    "type": "log_stream",
    "data": {"level": "ERROR", "message": error.message}
}))
```

### Example 2: Browser Extension

```python
from ghost_mode import GhostModeObserver, ContextShadow

# Learn user workflows on specific websites
shadow = ContextShadow(user_id=browser.user_id)
observer = GhostModeObserver(context_shadow=shadow)

observer.start_observing()

# Observe user actions
browser.on_dom_event(lambda event: observer.observe_signal({
    "type": "user_action",
    "data": {
        "action": event.type,
        "sequence": browser.get_recent_actions()
    }
}))

# When pattern is recognized, offer to auto-complete
def suggest_completion(observation):
    if observation.recommendation:
        browser.show_suggestion(observation.recommendation)

observer.surfacing_callback = suggest_completion
```

### Example 3: CLI Tool

```python
from ghost_mode import GhostModeObserver
import subprocess

observer = GhostModeObserver(confidence_threshold=0.8)
observer.start_observing()

# Monitor command execution
def run_command(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    # Observe the execution
    observer.observe_signal({
        "type": "command_execution",
        "data": {
            "command": cmd,
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    })
    
    return result

# Ghost Mode learns command patterns and surfaces warnings
# for potentially dangerous commands
```

## Benefits

1. **No Context Switching**: Users stay in their workflow
2. **Proactive Assistance**: System offers help before being asked
3. **Privacy Preserving**: Learns locally, doesn't send data
4. **Non-Intrusive**: Only surfaces when highly confident
5. **Continuous Learning**: Gets smarter over time without explicit training

## Testing

Run the test suite:
```bash
python test_ghost_mode.py
```

Run the demonstration:
```bash
python example_ghost_mode.py
```

## Use Cases

### 1. Security Monitoring

```python
# Automatically detect and alert on security-sensitive operations
observer.observe_signal({
    "type": "file_change",
    "data": {
        "file_path": "/etc/passwd",
        "change_type": "modified"
    }
})
# → High confidence, surfaces: "Critical system file modified"
```

### 2. Workflow Completion

```python
# Learn user's expense filing workflow
# Next time they start, suggest remaining steps
shadow.learn_pattern(expense_workflow)
# → Later: "You usually attach receipt next, would you like help?"
```

### 3. Error Prevention

```python
# Detect patterns that lead to errors
observer.observe_signal({
    "type": "user_action",
    "data": {
        "action": "deploy_without_tests",
        "context": {"branch": "main"}
    }
})
# → High confidence: "This usually causes errors. Run tests first?"
```

### 4. Performance Optimization

```python
# Learn when user performs expensive operations
# Suggest alternatives or caching
observer.observe_signal({
    "type": "database_query",
    "data": {
        "query": "SELECT * FROM large_table",
        "execution_time": 30000  # 30 seconds
    }
})
# → "This query is slow. Consider adding an index?"
```

## 🚀 Startup Opportunity: The "Context Shadow"

A lightweight desktop/browser daemon that securely "shadows" an employee, learning their specific workflows (e.g., "How they file expenses"). It builds a local "Behavior Model" that can be queried by other Agents.

### Value Proposition

- **For Users**: Proactive assistance without asking
- **For Companies**: Capture institutional knowledge automatically
- **For Developers**: Standard API to query user behavior patterns

### Technical Approach

```python
# The daemon runs 24/7 in the background
shadow_daemon = ContextShadow(user_id=employee.id)
observer = GhostModeObserver(context_shadow=shadow_daemon)

# It learns from everything the user does
observer.observe_signal(user_action)

# Other agents can query the learned patterns
patterns = shadow_daemon.query_patterns(
    trigger="expense_filing",
    min_confidence=0.7
)

# "This user files expenses on Fridays at 4pm with these steps..."
```

### Privacy & Security

- All data stored locally on user's device
- Encrypted at rest
- User controls what's shared
- Can query patterns without exposing raw data
- GDPR compliant by design

## Key Takeaways

1. **👻 Ghost Mode** is invisible until indispensable
2. **🧠 Context Shadow** learns user workflows securely
3. **🎯 Confidence-based surfacing** prevents noise
4. **🔄 Dry-run mode** analyzes without interfering
5. **💡 Proactive assistance** without explicit requests

The future isn't about better chatbots. It's about systems that understand you without you having to explain yourself.

---

## API Reference

### GhostModeObserver

```python
class GhostModeObserver:
    def __init__(
        self,
        context_shadow: Optional[ContextShadow] = None,
        confidence_threshold: float = 0.7,
        surfacing_callback: Optional[Callable[[ObservationResult], None]] = None
    )
    
    def start_observing(self, poll_interval: float = 1.0) -> None
    def stop_observing(self) -> None
    def observe_signal(self, signal: Dict[str, Any]) -> None
    def get_stats(self) -> Dict[str, Any]
    def get_recent_observations(self, limit: int = 10) -> List[ObservationResult]
```

### ContextShadow

```python
class ContextShadow:
    def __init__(
        self,
        storage_file: str = "behavior_model.json",
        user_id: Optional[str] = None
    )
    
    def learn_pattern(self, pattern: BehaviorPattern) -> None
    def query_patterns(
        self,
        trigger: Optional[str] = None,
        min_confidence: float = 0.5,
        reload: bool = False
    ) -> List[BehaviorPattern]
    def get_pattern(self, pattern_id: str) -> Optional[BehaviorPattern]
    def get_stats(self) -> Dict[str, Any]
```

### BehaviorPattern

```python
@dataclass
class BehaviorPattern:
    pattern_id: str
    name: str
    description: str
    trigger: str
    steps: List[str]
    frequency: int
    last_seen: str
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
```

### ObservationResult

```python
@dataclass
class ObservationResult:
    timestamp: str
    signal_type: str
    observation: str
    confidence: float
    should_surface: bool
    recommendation: Optional[str] = None
    dry_run_result: Optional[Dict[str, Any]] = None
    context: Dict[str, Any] = field(default_factory=dict)
    
    def get_confidence_level(self) -> ConfidenceLevel
    def to_dict(self) -> Dict[str, Any]
```
