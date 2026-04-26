# Architecture and Flow

## System Overview

The Self-Evolving Agent now supports two operational modes:

1. **Decoupled Mode (Recommended)**: Separates execution from learning - see [ARCHITECTURE_DECOUPLED.md](ARCHITECTURE_DECOUPLED.md)
2. **Legacy Mode (Documented Below)**: Traditional synchronous self-improvement loop

For the new decoupled architecture with DoerAgent and ObserverAgent, please refer to **[ARCHITECTURE_DECOUPLED.md](ARCHITECTURE_DECOUPLED.md)**.

---

## Legacy Architecture

The Self-Evolving Agent implements a continuous improvement loop where the agent learns from its mistakes and improves its behavior over time.

## Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SelfEvolvingAgent                         │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────┐   │
│  │   Memory    │    │  AgentTools  │    │ OpenAI API   │   │
│  │   System    │    │              │    │   Client     │   │
│  └─────────────┘    └──────────────┘    └──────────────┘   │
│        │                    │                    │           │
│        ▼                    ▼                    ▼           │
│  ┌──────────────────────────────────────────────────────┐   │
│  │         system_instructions.json                     │   │
│  │  {                                                   │   │
│  │    "version": 1,                                    │   │
│  │    "instructions": "...",                           │   │
│  │    "improvements": [...]                            │   │
│  │  }                                                   │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Execution Flow

### Main Loop: `run(query)`

```
START
  │
  ├──► Attempt 1
  │      │
  │      ├──► TASK: Receive query from user
  │      │
  │      ├──► ACT: Agent processes query
  │      │      • Load system instructions from JSON
  │      │      • Add tool information to context
  │      │      • Call LLM to generate response
  │      │      • Return agent response
  │      │
  │      ├──► REFLECT: Evaluate response
  │      │      • Call reflection LLM with query + response
  │      │      • Get score (0-1) and critique
  │      │
  │      ├──► Check score >= 0.8?
  │      │      │
  │      │      ├─YES─► SUCCESS! Return results
  │      │      │
  │      │      └─NO──► EVOLVE
  │      │              • Call evolution LLM with critique
  │      │              • Generate new system instructions
  │      │              • Save to JSON with version++
  │      │              • Log improvement
  │      │
  ├──► Attempt 2 (with evolved instructions)
  │      │
  │      └──► [Same flow as Attempt 1]
  │
  ├──► Attempt 3 (with further evolved instructions)
  │      │
  │      └──► [Same flow as Attempt 1]
  │
  └──► Max retries reached
         • Return best attempt
         • Mark as failure if score < 0.8
```

## Detailed Component Flow

### 1. Memory System (MemorySystem)

**Purpose**: Persist and manage system instructions

```python
class MemorySystem:
    load_instructions() → dict
    save_instructions(dict) → None
    get_system_prompt() → str
    update_instructions(new_text, critique) → None
```

**File Format** (`system_instructions.json`):
```json
{
  "version": 2,
  "instructions": "Current system prompt text",
  "improvements": [
    {
      "version": 2,
      "timestamp": "2024-01-01T12:00:00",
      "critique": "What was wrong that led to this update"
    }
  ]
}
```

### 2. Agent Tools (AgentTools)

**Purpose**: Provide capabilities the agent can use

Available tools:
- `calculate(expression)` - Mathematical evaluation
- `get_current_time()` - Current date/time
- `string_length(text)` - String length calculation
- `get_available_tools()` - List all available tools

### 3. Act Phase

**LLM Call 1: Agent Execution**

```
Input:
  • System: Current instructions + Tool descriptions
  • User: Query

Processing:
  • LLM analyzes query
  • Determines if tools are needed
  • Generates response

Output:
  • Agent response (string)
```

### 4. Reflect Phase

**LLM Call 2: Response Evaluation**

```
Input:
  • Query: Original user question
  • Response: Agent's answer
  • Criteria: Correctness, Completeness, Clarity, Tool Usage

Processing:
  • Evaluator LLM scores response
  • Generates detailed critique
  • Returns as JSON

Output:
  • score: float (0-1)
  • critique: string
```

### 5. Evolve Phase

**LLM Call 3: Instruction Evolution**

```
Input:
  • Current instructions
  • Recent query & response
  • Critique explaining issues

Processing:
  • Evolution LLM analyzes critique
  • Identifies what to improve
  • Rewrites system instructions

Output:
  • new_instructions: string
  
Side Effect:
  • Updates system_instructions.json
  • Increments version number
  • Logs improvement history
```

## Example Execution

### Scenario: Math Query with Initial Poor Instructions

**Initial Instructions (v1)**:
```
"You are a helpful AI assistant. Provide accurate responses."
```

**Query**: "What is 15 * 24 + 100?"

**Attempt 1**:
- **Act**: "15 times 24 is 360, plus 100 equals 460."
- **Reflect**: Score: 0.6
- **Critique**: "The agent calculated correctly but didn't mention the calculator tool. The agent should explicitly state when tools are available and appropriate to use."
- **Evolve**: Generate new instructions

**Evolved Instructions (v2)**:
```
"You are a helpful AI assistant with access to tools. When you have a 
calculation tool available, always mention it explicitly and explain 
that you would use it. Be clear about which tools apply to each query."
```

**Attempt 2**:
- **Act**: "I can use the calculate() tool for this. Let me solve 15 * 24 + 100. The result would be 460."
- **Reflect**: Score: 0.9
- **Success!** ✓

## Key Design Principles

1. **Separation of Concerns**: Three separate LLM calls for different purposes
   - Agent (task execution)
   - Reflector (evaluation)
   - Evolver (improvement)

2. **Persistence**: All improvements saved to JSON for continuity

3. **Iterative Learning**: Each attempt uses lessons from previous failures

4. **Bounded Retries**: Maximum 3 attempts to prevent infinite loops

5. **Threshold-based**: Clear success criteria (score >= 0.8)

6. **Audit Trail**: Full history of improvements tracked

## Configuration

Environment variables control behavior:

```bash
OPENAI_API_KEY=sk-...          # Required
AGENT_MODEL=gpt-4o-mini        # Model for acting
REFLECTION_MODEL=gpt-4o-mini   # Model for reflection
EVOLUTION_MODEL=gpt-4o-mini    # Model for evolution
SCORE_THRESHOLD=0.8            # Success threshold
MAX_RETRIES=3                  # Maximum attempts
```

## Extension Points

The system can be extended by:

1. **Adding Tools**: Extend `AgentTools` class
2. **Custom Evaluators**: Modify reflection criteria
3. **Different Models**: Use different models for each phase
4. **Persistence**: Add database instead of JSON
5. **Monitoring**: Add logging, metrics, dashboards
6. **Multi-turn**: Support conversation history
7. **Tool Execution**: Actually execute tools, not just describe them
