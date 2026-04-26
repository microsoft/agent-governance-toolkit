# Tool-Using Agent Example

An agent that uses safe, kernel-governed tools to accomplish tasks.

## What This Demonstrates

- Using pre-built safe tools (HTTP, file reader, calculator)
- Tool registration with ATR (Agent Tool Registry)
- Policy enforcement on tool operations
- Multi-step task execution

## Prerequisites

```bash
pip install agent-os-kernel[full]
export OPENAI_API_KEY=your-key-here
```

## Quick Start

```bash
# Run the agent
python agent.py

# Or run a specific task
python agent.py --task "Calculate 15% tip on $84.50"
```

## Available Tools

| Tool | Description | Example |
|------|-------------|---------|
| `calculate` | Safe math operations | `2 + 2 * 3` → `8` |
| `http_get` | Fetch data from URLs | Fetch API data |
| `read_file` | Read files from sandbox | Read config files |
| `parse_json` | Parse JSON safely | Parse API responses |
| `datetime_now` | Get current time | Timezone-aware |
| `text_analyze` | Analyze text | Word count, etc. |

## Example Tasks

### Math
```
Task: What is 15% of $84.50?
Agent: I'll calculate that for you.
→ Using tool: calculate("84.50 * 0.15")
Result: $12.68
```

### Web Lookup
```
Task: Get the current weather for Seattle
Agent: I'll fetch weather data.
→ Using tool: http_get("https://api.weather.gov/...")
Result: Currently 54°F and cloudy in Seattle.
```

### File Analysis
```
Task: Summarize the document in data/report.txt
Agent: I'll read and analyze that file.
→ Using tool: read_file("data/report.txt")
→ Using tool: text_analyze(content)
Result: The document has 500 words and discusses...
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     AGENT LAYER                              │
│  Task → LLM decides which tool → Execute → Response         │
├─────────────────────────────────────────────────────────────┤
│                    TOOL REGISTRY (ATR)                       │
│  calculate | http_get | read_file | parse_json | ...        │
├─────────────────────────────────────────────────────────────┤
│                     KERNEL SPACE                             │
│  Policy Engine checks every tool call before execution       │
│  - Rate limits on HTTP                                       │
│  - Sandbox enforcement on file reads                         │
│  - Expression validation on calculator                       │
└─────────────────────────────────────────────────────────────┘
```

## Configuration

### Tool Restrictions (config.yaml)

```yaml
tools:
  http:
    allowed_domains:
      - "api.github.com"
      - "api.weather.gov"
    rate_limit: 10  # per minute
  
  files:
    sandbox_paths:
      - "./data"
    allowed_extensions:
      - ".txt"
      - ".json"
      - ".md"
```

## Files

- `agent.py` - Main tool-using agent
- `tools.py` - Tool configuration
- `config.yaml` - Tool restrictions
- `data/` - Sandboxed data directory
