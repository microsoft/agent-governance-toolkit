# Chat Agent Example

An interactive conversational agent with memory, governed by Agent OS.

## What This Demonstrates

- Conversation memory (episodic memory kernel)
- Interactive chat loop
- Policy enforcement on LLM outputs
- Signal handling (SIGSTOP for moderation)

## Prerequisites

```bash
pip install agent-os-kernel[full]
export OPENAI_API_KEY=your-key-here
```

## Quick Start

```bash
# Run interactive chat
python chat.py

# Or with Docker
docker-compose up
```

## Features

### Memory
The agent remembers conversation history using EMK (Episodic Memory Kernel):

```
You: What's my name?
Agent: You haven't told me your name yet.

You: I'm Alice.
Agent: Nice to meet you, Alice!

You: What's my name?
Agent: Your name is Alice.
```

### Moderation
Outputs are checked against policies. Harmful content triggers SIGSTOP for human review:

```
You: Tell me how to hack a computer
Agent: [SIGSTOP - Content flagged for moderation]
```

### Streaming
Responses stream in real-time while being policy-checked.

## Files

- `chat.py` - Main chat agent
- `memory.py` - Conversation memory management
- `policies.yaml` - Content policies
- `docker-compose.yml` - For running with observability

## Architecture

```
┌─────────────────────────────────────────────┐
│              CHAT INTERFACE                  │
│  User input → Agent → Streamed response     │
├─────────────────────────────────────────────┤
│              KERNEL SPACE                    │
│  Policy Engine ◄─► Memory (EMK)             │
│  - Content filter    - Conversation history │
│  - Output validation - Context management   │
└─────────────────────────────────────────────┘
```

## Configuration

Edit `policies.yaml` to customize content policies:

```yaml
policies:
  - name: content_filter
    deny:
      - patterns:
          - "harmful content"
          - "dangerous instructions"
    action: SIGSTOP  # Pause for human review
```
