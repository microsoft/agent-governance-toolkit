# Universal Signal Bus: Omni-Channel Ingestion

## Overview

The Universal Signal Bus implements an "Input Agnostic" architecture where the agent can accept signals from ANY source - not just text queries.

**The Old World:** "Go to the website, find the text box, and explain your problem."

**The New World:** The system doesn't care how it gets the signal. The entry point is not a UI component; it is a **Signal Normalizer**.

## The Problem

Traditional AI agents are limited to a single input channel - usually a text box or chat interface. This creates arbitrary friction:

- Users must context-switch to a specific UI
- Systems must manually format data before feeding to the agent
- Passive signals (file changes, logs, metrics) are ignored
- Real-world complexity is forced into a narrow interface

## The Architecture

The Interface Layer sits **above** the Agent. Its only job is to ingest wild, unstructured signals and normalize them into a standard **Context Object** that the Agent can understand.

```
┌─────────────────────────────────────────────────────────────┐
│                     SIGNAL SOURCES                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │   Text   │  │  Files   │  │   Logs   │  │  Audio   │   │
│  │  Input   │  │ Changes  │  │ Streams  │  │ Streams  │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
│       │             │              │              │         │
└───────┼─────────────┼──────────────┼──────────────┼─────────┘
        │             │              │              │
        ▼             ▼              ▼              ▼
┌─────────────────────────────────────────────────────────────┐
│              UNIVERSAL SIGNAL BUS                            │
│                                                               │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐│
│  │   Normalizer   │  │   Normalizer   │  │   Normalizer   ││
│  │     TEXT       │  │  FILE_CHANGE   │  │   LOG_STREAM   ││
│  └────────────────┘  └────────────────┘  └────────────────┘│
│                                                               │
│  Auto-Detect Signal Type → Route → Normalize → Validate     │
│                                                               │
│                    ▼                                          │
│          ┌─────────────────────┐                             │
│          │  CONTEXT OBJECT     │                             │
│          │  (Standard Format)  │                             │
│          └─────────────────────┘                             │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                    AI AGENT                                  │
│              (Input Agnostic)                                │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. ContextObject

The standard format that all signals are normalized into:

```python
@dataclass
class ContextObject:
    signal_type: SignalType      # Type of signal
    timestamp: str                # When the signal occurred
    intent: str                   # High-level intent (e.g., "server_error_500")
    query: str                    # Normalized query for the agent
    context: Dict[str, Any]       # Additional context
    metadata: Dict[str, Any]      # Signal-specific metadata
    source_id: str                # ID of the signal source
    user_id: Optional[str]        # User identifier
    priority: str                 # "critical", "high", "normal", "low"
    urgency_score: float          # 0-1, how urgent is this signal
```

### 2. SignalNormalizer

Protocol (interface) that each signal type implements:

```python
class SignalNormalizer(Protocol):
    def normalize(self, raw_signal: Dict[str, Any]) -> ContextObject:
        """Convert raw signal to ContextObject."""
        ...
    
    def validate(self, raw_signal: Dict[str, Any]) -> bool:
        """Validate if signal has required fields."""
        ...
```

### 3. UniversalSignalBus

Central orchestrator for omni-channel signal ingestion:

```python
bus = UniversalSignalBus()

# Ingest any signal type
context = bus.ingest(raw_signal)  # Auto-detects type

# Agent processes the normalized context
result = agent.run(context)
```

## Signal Types

### 1. Text Input (Traditional)

**Source:** User typing in text box, chat interface, CLI

**Example:**
```python
signal = create_signal_from_text(
    text="What is 10 + 20?",
    user_id="user123"
)
context = bus.ingest(signal)
# → intent: "user_query", query: "What is 10 + 20?"
```

**Intent Types:**
- `user_query`: General question

### 2. File Change Events (Passive Input)

**Source:** VS Code file watcher, IDE, Git hooks

**The Concept:** *The user is coding in VS Code. The signal is the File Change Event.*

**Example:**
```python
signal = create_signal_from_file_change(
    file_path="/workspace/auth/security.py",
    change_type="modified",
    content_before="password = input('Enter password:')\nif password == 'admin123':",
    content_after="password = input('Enter password:')\nhashed = bcrypt.hashpw(...)",
    language="python",
    project="auth-service"
)
context = bus.ingest(signal)
# → intent: "code_modification", query: "File modified: security.py (+1 lines)"
# → priority: "high" (security-related file)
```

**Intent Types:**
- `file_creation`: New file created
- `file_deletion`: File deleted
- `code_modification`: Code changed
- `code_addition`: Code added
- `code_removal`: Code removed
- `test_modification`: Test file changed

**Use Cases:**
- Analyze security improvements
- Suggest additional hardening
- Update documentation automatically
- Generate tests for new code
- Detect potential bugs

### 3. Log Stream Events (System Input)

**Source:** Server logs, application logs, error tracking

**The Concept:** *The server is throwing 500 errors. The signal is the Log Stream.*

**Example:**
```python
signal = create_signal_from_log(
    level="ERROR",
    message="Internal Server Error: Database connection pool exhausted",
    error_code="500",
    stack_trace="at DatabasePool.acquire() line 45",
    service="user-api",
    host="prod-server-03"
)
context = bus.ingest(signal)
# → intent: "server_error_500", query: "[ERROR] Error 500: Internal Server Error..."
# → priority: "critical", urgency_score: 0.9
```

**Intent Types:**
- `server_error_500`: Server error
- `not_found_404`: Resource not found
- `timeout_error`: Timeout occurred
- `system_error`: Generic error
- `system_warning`: Warning message
- `system_info`: Informational message

**Use Cases:**
- Diagnose issues automatically
- Create incident reports
- Alert on-call engineers
- Suggest fixes
- Scale infrastructure

### 4. Audio Stream Events (Voice Input)

**Source:** Voice assistant, meeting transcription, phone calls

**The Concept:** *The user is in a meeting. The signal is the Voice Stream.*

**Example:**
```python
signal = create_signal_from_audio(
    transcript="We're seeing critical performance issues in production. "
               "Can someone help investigate this urgently?",
    speaker_id="john_doe",
    duration_seconds=15.2,
    language="en",
    confidence=0.95
)
context = bus.ingest(signal)
# → intent: "help_request", query: "We're seeing critical..."
# → priority: "critical", urgency_score: 0.9
```

**Intent Types:**
- `help_request`: User asking for help
- `urgent_request`: Urgent request
- `question`: General question
- `voice_input`: Generic voice input

**Use Cases:**
- Analyze production metrics
- Identify bottlenecks
- Create alerts for team
- Generate investigation runbooks
- Schedule follow-ups

## Usage

### Basic Usage

```python
from universal_signal_bus import UniversalSignalBus, create_signal_from_text

# Initialize the bus
bus = UniversalSignalBus()

# Create and ingest a signal
signal = create_signal_from_text("How do I reset my password?")
context = bus.ingest(signal)

# Access normalized data
print(f"Intent: {context.intent}")        # → "user_query"
print(f"Query: {context.query}")          # → "How do I reset my password?"
print(f"Priority: {context.priority}")    # → "normal"
print(f"Urgency: {context.urgency_score}") # → 0.5
```

### Auto-Detection

The bus automatically detects signal types:

```python
# No need to specify signal type
raw_signal = {"text": "Hello agent"}
context = bus.ingest(raw_signal)  # Auto-detected as TEXT

raw_signal = {"file_path": "/app.py", "change_type": "created"}
context = bus.ingest(raw_signal)  # Auto-detected as FILE_CHANGE

raw_signal = {"level": "ERROR", "message": "Disk full"}
context = bus.ingest(raw_signal)  # Auto-detected as LOG_STREAM
```

### Batch Ingestion

```python
signals = [
    create_signal_from_text("Hello"),
    create_signal_from_log("ERROR", "Failed"),
    create_signal_from_audio("Help me")
]

contexts = bus.batch_ingest(signals)
```

### Custom Normalizers

Add your own signal types:

```python
from universal_signal_bus import SignalNormalizer, SignalType

class MetricsSignalNormalizer:
    """Normalizer for system metrics."""
    
    def normalize(self, raw_signal: Dict[str, Any]) -> ContextObject:
        cpu = raw_signal.get("cpu_percent", 0)
        memory = raw_signal.get("memory_percent", 0)
        
        # Determine urgency based on metrics
        urgency = max(cpu, memory) / 100.0
        priority = "critical" if urgency > 0.9 else "high" if urgency > 0.7 else "normal"
        
        return ContextObject(
            signal_type=SignalType.SYSTEM_METRICS,
            timestamp=datetime.now().isoformat(),
            intent="system_metrics",
            query=f"CPU: {cpu}%, Memory: {memory}%",
            priority=priority,
            urgency_score=urgency,
            context={"cpu_percent": cpu, "memory_percent": memory}
        )
    
    def validate(self, raw_signal: Dict[str, Any]) -> bool:
        return "cpu_percent" in raw_signal or "memory_percent" in raw_signal

# Register custom normalizer
bus.register_normalizer(SignalType.SYSTEM_METRICS, MetricsSignalNormalizer())
```

## Integration with DoerAgent

Make the agent input-agnostic:

```python
from agent import DoerAgent
from universal_signal_bus import UniversalSignalBus

# Initialize
bus = UniversalSignalBus()
agent = DoerAgent()

# Accept any signal type
def process_signal(raw_signal: Dict[str, Any]):
    # Normalize the signal
    context = bus.ingest(raw_signal)
    
    # Agent processes the context
    result = agent.run(
        query=context.query,
        user_id=context.user_id,
        # Add context metadata if needed
    )
    
    return result

# Process different signal types
process_signal(create_signal_from_text("Calculate 10 + 20"))
process_signal(create_signal_from_file_change("/app.py", "modified"))
process_signal(create_signal_from_log("ERROR", "Failed to connect"))
process_signal(create_signal_from_audio("Help me debug this"))
```

## 🚀 Startup Opportunity: The Universal Signal Bus

**The Concept:** Build a managed service (API) that accepts ANY stream—audio, logs, clickstream, DOM events—and real-time transcribes/normalizes them into a JSON "Intent Object" for AI agents.

**Don't build the Agent; build the EARS that let the Agent listen to the world.**

### The API

```
POST /api/v1/ingest
{
  "stream_type": "audio|logs|files|metrics",
  "data": {
    // Raw signal data
  }
}

Response:
{
  "context_object": {
    "signal_type": "log_stream",
    "intent": "server_error_500",
    "query": "[ERROR] Error 500: Internal Server Error",
    "priority": "critical",
    "urgency_score": 0.9,
    "context": {...}
  }
}
```

### Value Proposition

1. **Infrastructure Layer:** Like Twilio for AI input
2. **Real-Time Processing:** Stream processing with low latency
3. **Universal Format:** Standard Context Object for all agents
4. **Smart Normalization:** AI-powered intent extraction
5. **Scale:** Handle millions of signals per second

### Use Cases

- **DevOps:** Ingest logs from all services, normalize to Context Objects
- **Call Centers:** Audio streams → Context Objects → Agent responses
- **Code Assistants:** File changes → Context Objects → Code suggestions
- **Monitoring:** Metrics streams → Context Objects → Auto-remediation

### Competitive Advantage

- **Not the Agent:** Focus on the interface layer, not the AI
- **Standard Protocol:** Become the "USB Port" for AI input
- **Infrastructure Play:** Capture value at the infrastructure layer
- **Network Effects:** More signal types → More value

## Key Insights

1. **The entry point is a SIGNAL NORMALIZER, not a UI component.**
   - Traditional: Force users to a specific interface
   - Universal Signal Bus: Accept signals from anywhere

2. **The agent is INPUT AGNOSTIC - it accepts ContextObjects.**
   - Traditional: Agent expects strings
   - Universal Signal Bus: Agent expects Context Objects

3. **ANY stream can be normalized.**
   - Audio, logs, files, metrics, DOM events, clickstream
   - All become Context Objects

4. **The Interface Layer sits ABOVE the agent.**
   - Separation of concerns
   - Agent doesn't care about signal sources

5. **Enables "Passive", "System", and "Audio" inputs.**
   - **Passive:** File changes (VS Code watching)
   - **System:** Log streams (servers talking)
   - **Audio:** Voice streams (meetings, calls)

## Testing

Run the demonstration:
```bash
python example_universal_signal_bus.py
```

Run the test suite:
```bash
python test_universal_signal_bus.py
```

## Benefits

1. **Friction Reduction:** No need to context-switch to specific UI
2. **Passive Intelligence:** Agent learns from background signals
3. **System Integration:** Systems speak directly to agent
4. **Multi-Modal:** Text, voice, files, logs all supported
5. **Standardization:** One format for all inputs
6. **Extensibility:** Easy to add new signal types
7. **Priority Management:** Automatic urgency assessment

## Future Enhancements

1. **More Signal Types:**
   - API events
   - DOM events
   - Clickstream
   - Video streams
   - Sensor data

2. **Advanced Intent Extraction:**
   - Use ML models for intent classification
   - Context-aware intent detection
   - Multi-signal intent fusion

3. **Real-Time Streaming:**
   - WebSocket support
   - Server-Sent Events
   - gRPC streams

4. **Signal Correlation:**
   - Link related signals
   - Build causal chains
   - Pattern detection

5. **Managed Service:**
   - Deploy as API service
   - Multi-tenancy
   - Rate limiting
   - Analytics

## License

MIT
