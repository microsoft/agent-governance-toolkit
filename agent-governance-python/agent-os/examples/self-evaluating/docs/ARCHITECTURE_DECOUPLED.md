# Architecture and Flow

## System Overview

The Self-Evolving Agent now supports two modes of operation:

1. **Decoupled Mode (Recommended)**: Separates execution from learning for low-latency operation
2. **Legacy Mode**: Traditional synchronous self-improvement loop (for backward compatibility)

## Decoupled Architecture

The decoupled architecture separates the "Doer" (execution) from the "Observer" (learning) to achieve:
- Low runtime latency (Doer doesn't wait for learning)
- Persistent learning (Observer builds wisdom over time)
- Scalability (Observer can process events in batch)
- Flexibility (Different models for execution vs. learning)

### Component Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                     EXECUTION PHASE                             │
│                  (Synchronous - Low Latency)                    │
├────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐         ┌─────────────────┐                 │
│  │  DoerAgent   │ ─READ─► │ Wisdom Database │                 │
│  │              │         │  (Read-Only)    │                 │
│  └──────┬───────┘         └─────────────────┘                 │
│         │                                                       │
│         │ EMIT                                                  │
│         ▼                                                       │
│  ┌──────────────┐                                              │
│  │ Event Stream │                                              │
│  │ (telemetry)  │                                              │
│  └──────────────┘                                              │
└────────────────────────────────────────────────────────────────┘

                          ▼ (Asynchronous)

┌────────────────────────────────────────────────────────────────┐
│                     LEARNING PHASE                              │
│                  (Asynchronous - Offline)                       │
├────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────┐      ┌──────────────────┐               │
│  │  ObserverAgent   │◄CONSUME│  Event Stream  │               │
│  │  (Shadow Learner)│      │   (telemetry)   │               │
│  └────────┬─────────┘      └──────────────────┘               │
│           │                                                     │
│           │ ANALYZE → REFLECT → EVOLVE                         │
│           │                                                     │
│           ▼                                                     │
│  ┌─────────────────┐                                           │
│  │ Wisdom Database │                                           │
│  │  (Read-Write)   │                                           │
│  └─────────────────┘                                           │
└────────────────────────────────────────────────────────────────┘
```

### Data Structures

**Wisdom Database** (`system_instructions.json`):
```json
{
  "version": 2,
  "instructions": "Current system prompt text",
  "improvements": [
    {
      "version": 2,
      "timestamp": "2024-01-01T12:00:00",
      "critique": "What was learned from failure"
    }
  ]
}
```

**Event Stream** (`telemetry_events.jsonl`):
```jsonl
{"event_type":"task_start","timestamp":"2024-01-01T12:00:00","query":"...","instructions_version":1}
{"event_type":"task_complete","timestamp":"2024-01-01T12:00:01","query":"...","agent_response":"...","success":true,"instructions_version":1}
```

## Execution Flow

### Decoupled Mode Flow

#### Phase 1: Execution (DoerAgent - Synchronous)

```
USER REQUEST
     │
     ▼
┌─────────────────┐
│  DoerAgent.run()│
└────────┬────────┘
         │
         ├──► 1. Load wisdom (read-only)
         │
         ├──► 2. ACT: Execute query with LLM
         │       • Use current system instructions
         │       • Access to tools
         │       • Generate response
         │
         ├──► 3. EMIT: Send telemetry
         │       • Emit "task_start" event
         │       • Emit "task_complete" event
         │       • Include query, response, version
         │
         └──► Return response immediately
              (NO reflection, NO learning)
```

**Key Point**: Doer returns immediately without waiting for evaluation or learning.

#### Phase 2: Learning (ObserverAgent - Asynchronous)

```
SCHEDULED/TRIGGERED
     │
     ▼
┌──────────────────────┐
│ObserverAgent.process │
└──────────┬───────────┘
           │
           ├──► 1. READ: Consume unprocessed events
           │       • Read from event stream
           │       • Track checkpoint
           │
           ├──► 2. ANALYZE: For each execution trace
           │       │
           │       ├──► REFLECT: Evaluate response
           │       │       • Call reflection LLM
           │       │       • Get score (0-1) + critique
           │       │
           │       └──► If score < threshold:
           │               │
           │               └──► EVOLVE: Improve wisdom
           │                      • Call evolution LLM
           │                      • Generate new instructions
           │                      • Update wisdom database
           │                      • Increment version
           │
           └──► 3. CHECKPOINT: Save progress
                  • Update last processed timestamp
                  • Track lessons learned
```

**Key Point**: Observer runs independently, can be scheduled, and doesn't block execution.

### Comparison: Decoupled vs Legacy Mode

| Aspect | Decoupled Mode | Legacy Mode |
|--------|---------------|-------------|
| **Execution Latency** | Low (1 LLM call) | High (1-3 iterations, 3-9 LLM calls) |
| **Learning** | Asynchronous, offline | Synchronous, during execution |
| **Retries** | None (learn from telemetry) | Up to 3 immediate retries |
| **User Wait Time** | Just execution | Execution + reflection + evolution |
| **Scalability** | High (batch processing) | Low (per-request) |
| **Models** | Can use different models | Same model for all |

## Component Details

### 1. DoerAgent (Synchronous Executor)

**Purpose**: Execute tasks quickly with read-only wisdom access

**Key Methods**:
- `act(query)` → Execute query with current wisdom
- `run(query)` → Main execution loop with telemetry emission

**Characteristics**:
- Read-only access to wisdom database
- No reflection or evaluation
- No learning or evolution
- Emits telemetry events
- Returns immediately

### 2. ObserverAgent (Asynchronous Learner)

**Purpose**: Learn from execution traces offline

**Key Methods**:
- `reflect(query, response)` → Evaluate response quality (score + critique)
- `evolve(critique, query, response)` → Generate improved instructions
- `analyze_trace(event)` → Analyze single execution
- `learn_from_analysis(analysis)` → Update wisdom database
- `process_events()` → Main learning loop

**Characteristics**:
- Read-write access to wisdom database
- Consumes telemetry stream
- Performs reflection and evolution
- Can use more powerful models
- Checkpoint-based progress tracking
- Runs independently of execution

### 3. EventStream (Telemetry System)

**Purpose**: Capture and persist execution traces

**Key Methods**:
- `emit(event)` → Append event to stream
- `read_all()` → Read all events
- `read_unprocessed(timestamp)` → Read events after checkpoint
- `get_last_timestamp()` → Get most recent event timestamp

**Characteristics**:
- Append-only JSONL format
- Simple file-based storage
- Supports batch reading
- Checkpoint-based tracking

### 4. TelemetryEvent (Event Data)

**Event Types**:
- `task_start`: Query initiated
- `task_complete`: Execution finished
- `user_feedback`: Optional user input

**Fields**:
- `event_type`, `timestamp`, `query`
- `agent_response`, `success`, `user_feedback`
- `instructions_version`, `metadata`

### 5. MemorySystem (Wisdom Database)

**Purpose**: Persist learned knowledge

**Key Methods**:
- `load_instructions()` → Load from JSON
- `save_instructions()` → Persist to JSON
- `get_system_prompt()` → Get current instructions
- `update_instructions(new, critique)` → Evolve with versioning

## Legacy Mode Architecture

For backward compatibility, the original `SelfEvolvingAgent` is preserved:

```
START (SelfEvolvingAgent.run)
  │
  ├──► Attempt 1
  │      ├──► ACT: Execute query
  │      ├──► REFLECT: Evaluate (score + critique)
  │      ├──► If score >= threshold: SUCCESS
  │      └──► If score < threshold: EVOLVE → Attempt 2
  │
  ├──► Attempt 2 (with evolved instructions)
  │      └──► [Same flow]
  │
  └──► Attempt 3 (if needed)
         └──► Return best result
```

## Configuration

Environment variables:
- `OPENAI_API_KEY`: Your OpenAI API key (required)
- `AGENT_MODEL`: Model for execution (default: gpt-4o-mini)
- `REFLECTION_MODEL`: Model for reflection (default: gpt-4o-mini)
- `EVOLUTION_MODEL`: Model for evolution (default: gpt-4o-mini)
- `SCORE_THRESHOLD`: Learning threshold (default: 0.8)
- `MAX_RETRIES`: Legacy mode retries (default: 3)

## Usage Patterns

### Pattern 1: Continuous Execution + Scheduled Learning

```python
# Web server or API - fast responses
doer = DoerAgent()
response = doer.run(user_query)  # Returns immediately
return response

# Cron job or background worker - learns offline
observer = ObserverAgent()
observer.process_events()  # Batch process telemetry
```

### Pattern 2: Immediate Feedback Loop (Legacy)

```python
# All-in-one synchronous mode
agent = SelfEvolvingAgent()
results = agent.run(query)  # Includes reflection + evolution
```

## Key Design Principles

1. **Separation of Concerns**: Execution separate from learning
2. **Low Latency**: Critical path has minimal overhead
3. **Persistent Memory**: Wisdom accumulates over time
4. **Scalability**: Learning can be batched and scheduled
5. **Flexibility**: Different models/resources for different phases
6. **Backward Compatible**: Legacy mode still available
7. **Observable**: Full audit trail via telemetry

## Extension Points

The system can be extended by:

1. **Different Storage**: Replace file-based storage with database
2. **Event Processors**: Add custom analyzers for telemetry
3. **Learning Strategies**: Implement alternative learning algorithms
4. **Model Selection**: Use different models based on criteria
5. **Tools**: Add more capabilities to AgentTools
6. **Feedback Loop**: Incorporate user feedback into learning
7. **Distributed**: Run multiple observers for parallel processing
