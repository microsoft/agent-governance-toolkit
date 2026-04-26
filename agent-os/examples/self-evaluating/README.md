# Self-Evolving Agent Framework

A comprehensive, production-ready framework for building self-improving AI agents with advanced features including polymorphic output, universal signal bus, agent brokerage, orchestration, constraint engineering, and more.

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Copy environment file and add your OpenAI API key
cp .env.example .env

# Run basic tests (no API key required)
python tests/test_agent.py

# Run a simple example (requires API key)
python examples/example.py
```

📖 **New to the framework?** Start with our [Getting Started Guide](docs/GETTING_STARTED.md)

## 📁 Project Structure

```
├── src/                    # Core framework modules
│   ├── agent.py           # Main agent implementation
│   ├── observer.py        # Asynchronous learning
│   ├── telemetry.py       # Event tracking
│   ├── polymorphic_output.py      # Adaptive rendering
│   ├── universal_signal_bus.py    # Omni-channel input
│   └── ...                        # 17+ modules
├── tests/                  # Comprehensive test suite
├── examples/               # Usage examples & samples
├── docs/                   # Detailed documentation
├── README.md              # This file
├── setup.py               # Package installation
└── requirements.txt       # Dependencies
```

## ✨ Key Features

- **Polymorphic Output (Adaptive Rendering)**: The "Just-in-Time UI" where agents determine response modality based on context
  - **Output Modality Detection**: Automatically chooses the right format (text, widget, chart, table, etc.)
  - **Scenario A (Data)**: Backend telemetry → Dashboard widget (not chat)
  - **Scenario B (Code)**: IDE typing → Ghost text (not popup)
  - **Generative UI Engine**: SDK that renders React/Flutter components from JSON
  - **Text Fallback**: Backward compatible with plain text systems
  - **Context-Aware**: IDE gets ghost text, monitoring gets widgets, chat gets text
  - Key insight: "If input can be anything, output must be anything"
  - Startup opportunity: "Generative UI Engine SDK" - stop hard-coding screens, render them dynamically
  - See [POLYMORPHIC_OUTPUT.md](docs/POLYMORPHIC_OUTPUT.md) for detailed documentation
- **Universal Signal Bus (Omni-Channel Ingestion)**: The "Input Agnostic" architecture for AI
  - **Signal Normalizer**: Entry point is NOT a UI - it's a signal normalizer
  - **File Change Events**: Passive input from VS Code/IDE file watchers
  - **Log Streams**: System input from server logs and error streams
  - **Audio Streams**: Voice input from meetings and conversations
  - **Auto-Detection**: Smart signal type detection from raw data
  - **Standard Context Object**: All signals normalized to same format
  - Key insight: "The entry point is NOT a UI component; it is a Signal Normalizer"
  - Startup opportunity: "Universal Signal Bus as a Service" - the managed API for AI input
  - See [UNIVERSAL_SIGNAL_BUS.md](docs/UNIVERSAL_SIGNAL_BUS.md) for detailed documentation
- **Agent Brokerage Layer - The API Economy**: Utility-based pricing and micro-payments for specialized agents
  - **Agent Marketplace**: Registry where agents publish capabilities and pricing
  - **Agent Bidding**: Agents compete on cost, speed, and quality for each task
  - **Micro-Payments**: Pay per API call, not monthly subscriptions
  - **Dynamic Selection**: Orchestrator selects best agent based on user constraints
  - **Usage Tracking**: Real-time cost and performance monitoring
  - Key insight: "The Old World: Subscribe for $20/month. The New World: Pay $0.01 for 10 seconds."
  - Startup opportunity: "Agent Marketplace as a Service" - the AWS Marketplace for AI agents
  - See [AGENT_BROKERAGE.md](docs/AGENT_BROKERAGE.md) for detailed documentation
- **OpenAgent Definition (OAD) - The "USB Port" for AI**: Standard interface definition language for AI agents
  - **Capabilities**: What the agent CAN do (e.g., "I can write Python 3.9 code")
  - **Constraints**: What the agent WON'T/CAN'T do (e.g., "I have no internet access")
  - **IO Contract**: Standard input/output specification (like OpenAPI/Swagger)
  - **Trust Score**: Real performance metrics (success rate, latency, executions)
  - **Agent Discovery**: Find and compare agents in a marketplace
  - **Agent Composition**: Validate compatibility and build pipelines
  - Key insight: "This is the USB Port moment for AI. The startup that defines the Standard Agent Protocol wins the platform war."
  - See [OPENAGENT_DEFINITION.md](docs/OPENAGENT_DEFINITION.md) for detailed documentation
- **Orchestration Layer (Deterministic Workflows)**: Rigid state machine that manages probabilistic AI workers
  - **The Orchestrator**: Deterministic state machine (not a fuzzy AI manager)
  - **Hub & Spoke Pattern**: Workers never talk to each other directly - they report to the Hub
  - **Transformer Middleware**: Manages data flow between probabilistic workers
  - **Pre-built Pipelines**: Product Manager → Coder → Reviewer workflows
  - Key insight: "The Brain (AI) is probabilistic, but the Skeleton (Orchestrator) is deterministic"
  - Startup opportunity: "Orchestration-as-a-Service" - define a goal, service spins up the correct pipeline
  - See [ORCHESTRATION.md](docs/ORCHESTRATION.md) for detailed documentation
- **Constraint Engineering (The Logic Firewall)**: Deterministic safety layer that intercepts AI plans before execution
  - **Brain (LLM)**: Generates creative plans with high temperature
  - **Firewall (Constraint Engine)**: Deterministic Python validation layer
  - **Hand (Executor)**: Only executes if firewall approves
  - **SQL Injection Prevention**: Blocks DROP TABLE, DELETE WHERE 1=1, and injection patterns
  - **File Operation Safety**: Protects system directories and blocks dangerous commands
  - **Cost Limits**: Enforces per-action cost thresholds
  - **Domain Restrictions**: Whitelists for email domains and API endpoints
  - **Rate Limiting**: Prevents excessive action execution
  - Key insight: "The Human builds the walls; the AI plays inside them"
  - See [CONSTRAINT_ENGINEERING.md](docs/CONSTRAINT_ENGINEERING.md) for detailed documentation
- **Evaluation Engineering (The New TDD)**: Write evaluation suites instead of implementation code
  - **Golden Datasets**: Define quality through 50+ test cases with expected outputs
  - **Scoring Rubrics**: Multi-dimensional evaluation (correctness + tone + safety)
  - **Eval-DD**: Evaluation-Driven Development - write the exam, let AI iterate until it passes
  - Key insight: "If correct but rude, score 5/10" - quality is multi-dimensional
  - The "Source Code" is the Evaluation Suite that constrains the AI
  - See [EVALUATION_ENGINEERING.md](docs/EVALUATION_ENGINEERING.md) for detailed documentation
- **Wisdom Curator**: Human-in-the-loop review for high-level strategic verification
  - **Design Check**: Verify implementation matches architectural proposals (not syntax!)
  - **Strategic Sample**: Review random samples (50 out of 10,000) for quality/vibe
  - **Policy Review**: Human approval prevents harmful wisdom updates (e.g., "ignore all errors")
  - Shifts human role from Editor (fixing grammar) to Curator (approving knowledge)
  - Automatic policy violation detection for safety, security, privacy, and quality
  - See [WISDOM_CURATOR.md](docs/WISDOM_CURATOR.md) for detailed documentation
- **Automated Circuit Breaker**: Real-time rollout management with deterministic metrics
  - **The Probe**: Gradual rollout (1% → 5% → 20% → 100%)
  - **The Watchdog**: Real-time monitoring of Task Completion Rate and Latency
  - **Auto-Scale**: Automatic advancement when metrics hold
  - **Auto-Rollback**: Immediate revert when metrics degrade
  - Replaces "Old World" manual A/B testing with "New World" automated controls
  - See [CIRCUIT_BREAKER.md](docs/CIRCUIT_BREAKER.md) for detailed documentation
- **Intent Detection**: Smart evaluation based on conversation type
  - **Troubleshooting Intent**: Success = Quick resolution (≤3 turns)
  - **Brainstorming Intent**: Success = Deep exploration (≥5 turns)
  - Key insight: "Engagement is often Failure" — a 20-turn password reset means the user is trapped, not engaged
  - Automatically detects intent from first interaction
  - Applies appropriate metrics for each conversation type
  - See [INTENT_DETECTION.md](docs/INTENT_DETECTION.md) for detailed documentation
- **Silent Signals**: Implicit feedback mechanism that captures user friction
  - **Undo Signal** (Critical Failure): User reverses agent action (Ctrl+Z, revert) 
  - **Abandonment Signal** (Loss): User stops responding mid-workflow
  - **Acceptance Signal** (Success): User moves to next task without follow-up
  - Eliminates blind spot of relying solely on explicit feedback
  - Learns from what users DO, not just what they SAY
  - See [SILENT_SIGNALS.md](docs/SILENT_SIGNALS.md) for detailed documentation
- **Ghost Mode (Passive Observation)**: The Observer Daemon Pattern - invisible until indispensable
  - **Background Processing**: Daemon runs silently consuming signal streams
  - **Dry Run Analysis**: Analyzes signals without taking action
  - **Confidence-Based Surfacing**: Only surfaces when highly confident
  - **Context Shadow**: Learns user behavior patterns locally and securely
  - **Behavior Model**: Local storage of workflows that can be queried by agents
  - Key insight: "The future interface isn't a Destination (website). It is a Daemon (background process)."
  - Startup opportunity: "Context Shadow" - the "Cookies" of the real world for secure user context storage
  - See [GHOST_MODE.md](docs/GHOST_MODE.md) for detailed documentation
- **Decoupled Execution/Learning**: Low-latency execution with offline learning
- **Upgrade Purge Strategy**: Active lifecycle management for wisdom database
  - Automatically removes lessons when upgrading models
  - Keeps database lean and specialized
  - Treats wisdom like a high-performance cache
- **Prioritization Framework**: Graph RAG-inspired three-layer context ranking system
  - Safety Layer: Prevents repeating recent failures
  - Personalization Layer: User-specific preferences and constraints
  - Global Wisdom Layer: Generic best practices
- **Telemetry System**: Event stream for capturing execution traces
- **Wisdom Database**: Persistent knowledge stored in `system_instructions.json`
- **Tool System**: Simple tools for calculations, time, and string operations
- **Reflection System**: Automatic evaluation of agent responses
- **Evolution System**: Automatic improvement of system instructions
- **Backward Compatible**: Legacy synchronous mode still available


## Installation

### Option 1: Install as Package (Recommended)
```bash
# Clone the repository
git clone https://github.com/microsoft/agent-governance-toolkit.git
cd self-evaluating-agent-sample

# Install in editable mode
pip install -e .

# Set up environment
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY
```

### Option 2: Install Dependencies Only
```bash
pip install -r requirements.txt

# Set up environment
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY
```

## Quick Examples

### Example 1: Basic Agent Usage
```bash
python examples/example.py
```

### Example 2: Full Stack Agent (Comprehensive Integration)
```bash
python examples/sample_full_stack_agent.py
```

This demonstrates integration of:
- Universal Signal Bus (omni-channel input)
- DoerAgent (task execution)
- Polymorphic Output (adaptive rendering)
- Generative UI Engine (dynamic UI)
- Telemetry (event tracking)

### Example 3: Monitoring Agent (Real-World Scenario)
```bash
python examples/sample_monitoring_agent.py
```

This shows a production monitoring agent with:
- Ghost Mode passive observation
- Log stream ingestion
- Confidence-based alerting
- Dashboard widget rendering

## Usage
# Edit .env and add your OPENAI_API_KEY
```

## Usage

### Polymorphic Output (Adaptive Rendering)

Run the polymorphic output demonstration:
```bash
python example_polymorphic_output.py
```

This demonstrates:
1. **Scenario A (Data)**: Backend telemetry → Dashboard widget (not chat message)
2. **Scenario B (Code)**: IDE typing → Ghost text (not popup)
3. **Scenario C (Analysis)**: SQL results → Interactive table (not text dump)
4. **Scenario D (Monitoring)**: Time series → Line chart (not list)
5. **Scenario E (Alerts)**: Critical error → Toast notification (not log entry)
6. **Automatic Modality Detection**: System chooses appropriate output format
7. **React Code Generation**: Generate JSX from agent responses
8. **Startup Opportunity**: Building the Generative UI Engine SDK

Manual usage:

```python
from polymorphic_output import (
    PolymorphicOutputEngine,
    InputContext,
    create_ghost_text_response,
    create_dashboard_widget_response,
    create_chart_response,
    create_table_response
)
from generative_ui_engine import GenerativeUIEngine

# Initialize engines
output_engine = PolymorphicOutputEngine()
ui_engine = GenerativeUIEngine()

# Scenario 1: Telemetry stream → Dashboard widget
telemetry_data = {
    "metric_name": "API Latency",
    "metric_value": "2000ms",
    "trend": "up",
    "alert_level": "critical"
}

poly_response = output_engine.generate_response(
    data=telemetry_data,
    input_context=InputContext.MONITORING,
    input_signal_type="log_stream",
    urgency=0.9
)

# Generate UI component
ui_component = ui_engine.render(poly_response)
print(f"Modality: {poly_response.modality}")  # → dashboard_widget
print(f"Component: {ui_component.component_type}")  # → DashboardWidget

# Scenario 2: IDE context → Ghost text
code_suggestion = "def calculate_total(items: List[float]) -> float:\n    return sum(items)"

ghost_response = create_ghost_text_response(
    suggestion=code_suggestion,
    cursor_position={"line": 42, "column": 16}
)

ui_component = ui_engine.render(ghost_response)
# Deploy to IDE: ide.show_ghost_text(ui_component)

# Scenario 3: SQL results → Interactive table
sql_results = [
    {"id": 1, "name": "Alice", "email": "alice@example.com"},
    {"id": 2, "name": "Bob", "email": "bob@example.com"}
]

table_response = create_table_response(
    rows=sql_results,
    title="Users",
    sortable=True,
    filterable=True
)

ui_component = ui_engine.render(table_response)
# Deploy to app: app.display_table(ui_component)

# Scenario 4: Time series → Chart
data_points = [
    {"timestamp": "00:00", "value": 100},
    {"timestamp": "01:00", "value": 120},
    {"timestamp": "02:00", "value": 150}
]

chart_response = create_chart_response(
    chart_type="line",
    data_points=data_points,
    title="Request Rate",
    x_axis_label="Time",
    y_axis_label="Requests/min"
)

ui_component = ui_engine.render(chart_response)
# Deploy to dashboard: dashboard.add_chart(ui_component)
```

Integration with existing agent:

```python
from agent import DoerAgent
from polymorphic_output import PolymorphicOutputEngine, InputContext
from generative_ui_engine import GenerativeUIEngine

# Wrap existing agent
class PolymorphicDoerAgent(DoerAgent):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.poly_engine = PolymorphicOutputEngine()
        self.ui_engine = GenerativeUIEngine()
    
    def run_polymorphic(self, query, input_context, **kwargs):
        # Run standard agent
        result = self.run(query, **kwargs)
        
        # Generate polymorphic response
        poly_response = self.poly_engine.generate_response(
            data=result['response'],
            input_context=input_context
        )
        
        # Generate UI component
        ui_component = self.ui_engine.render(poly_response)
        
        return {
            **result,
            'polymorphic_response': poly_response,
            'ui_component': ui_component
        }

# Use the agent
agent = PolymorphicDoerAgent()

# IDE context → Ghost text
result = agent.run_polymorphic(
    query="Complete: def calculate_",
    input_context=InputContext.IDE
)
print(result['polymorphic_response'].modality)  # → ghost_text

# Monitoring context → Dashboard widget
result = agent.run_polymorphic(
    query="Show current latency",
    input_context=InputContext.MONITORING
)
print(result['polymorphic_response'].modality)  # → dashboard_widget
```

**The Key Insight**: "If input can be anything, output must be anything. The Agent generates the Data, but the Interface Layer generates the View. This is Just-in-Time UI."

### Universal Signal Bus (Omni-Channel Ingestion)

Run the Universal Signal Bus demonstration:
```bash
python example_universal_signal_bus.py
```

This demonstrates:
1. **Text Input**: Traditional text queries (backward compatibility)
2. **File Change Events**: Passive input from VS Code file watchers
3. **Log Streams**: System input from server logs (500 errors, warnings)
4. **Audio Streams**: Voice input from meetings and conversations
5. **Auto-Detection**: Automatic signal type detection
6. **Mixed Signals**: Multiple signal types in sequence
7. **Agent Integration**: Input-agnostic agent processing
8. **Startup Opportunity**: Building the Universal Signal Bus as a service

Manual usage:

```python
from universal_signal_bus import (
    UniversalSignalBus,
    create_signal_from_text,
    create_signal_from_file_change,
    create_signal_from_log,
    create_signal_from_audio
)

# Initialize the bus
bus = UniversalSignalBus()

# Ingest different signal types
text_context = bus.ingest(create_signal_from_text("What is 10 + 20?"))

file_context = bus.ingest(create_signal_from_file_change(
    file_path="/workspace/auth/security.py",
    change_type="modified",
    content_before="password = 'admin'",
    content_after="hashed = bcrypt.hashpw(...)",
    language="python"
))

log_context = bus.ingest(create_signal_from_log(
    level="ERROR",
    message="Database connection pool exhausted",
    error_code="500",
    service="user-api"
))

audio_context = bus.ingest(create_signal_from_audio(
    transcript="We're seeing critical performance issues",
    speaker_id="john_doe"
))

# All normalized to standard ContextObject
print(f"Intent: {log_context.intent}")      # → "server_error_500"
print(f"Priority: {log_context.priority}")  # → "critical"
print(f"Urgency: {log_context.urgency_score}") # → 0.9
```

Integration with DoerAgent:

```python
from agent import DoerAgent
from universal_signal_bus import UniversalSignalBus

bus = UniversalSignalBus()
agent = DoerAgent()

# Process any signal type
def process_signal(raw_signal):
    context = bus.ingest(raw_signal)
    result = agent.run(query=context.query, user_id=context.user_id)
    return result

# Works with any input source
process_signal({"text": "Calculate 10 + 20"})
process_signal({"file_path": "/app.py", "change_type": "modified"})
process_signal({"level": "ERROR", "message": "Failed"})
process_signal({"transcript": "Help me debug this"})
```

**The Key Insight**: "The entry point is NOT a UI component; it is a Signal Normalizer. The agent is INPUT AGNOSTIC."

### Agent Brokerage Layer (The API Economy)

Run the agent brokerage demonstration:
```bash
python example_agent_brokerage.py
```

This demonstrates:
1. **Agent Discovery**: Finding agents by capability, price, and performance
2. **Agent Bidding**: Multiple agents compete for each task
3. **Task Execution**: Automatic selection and execution of best agent
4. **Cost Optimization**: Different strategies (cheapest, fastest, best value)
5. **User Constraints**: Budget and latency limits
6. **Usage Tracking**: Real-time cost and performance monitoring
7. **Economic Comparison**: Subscription vs. utility pricing analysis

Manual usage:

```python
from agent_brokerage import (
    AgentMarketplace,
    AgentBroker,
    AgentListing,
    AgentPricing,
    PricingModel,
    create_sample_agents
)

# 1. Create marketplace and register agents
marketplace = AgentMarketplace()
for agent in create_sample_agents():
    marketplace.register_agent(agent)

# 2. Create broker
broker = AgentBroker(marketplace)

# 3. Execute task with automatic agent selection
result = broker.execute_task(
    task="Extract text from invoice.pdf",
    selection_strategy="best_value",  # or "cheapest", "fastest", "most_reliable"
    user_constraints={
        "max_budget": 0.05,        # Max $0.05 per execution
        "max_latency_ms": 2000     # Max 2000ms latency
    },
    verbose=True
)

print(f"Agent Selected: {result['agent_name']}")
print(f"Actual Cost: ${result['actual_cost']:.4f}")
print(f"Actual Latency: {result['actual_latency_ms']:.0f}ms")
print(f"Response: {result['response']}")

# 4. Track usage and costs
report = broker.get_usage_report()
print(f"Total Spent: ${report['total_spent']:.4f}")
print(f"Total Executions: {report['total_executions']}")
```

Register your own agent in the marketplace:

```python
# Define pricing
pricing = AgentPricing(
    model=PricingModel.PER_EXECUTION,
    base_price=0.01  # $0.01 per execution
)

# Create agent listing
agent = AgentListing(
    agent_id="my_pdf_agent",
    name="My PDF OCR Agent",
    description="Fast and accurate PDF text extraction",
    capabilities=["pdf_ocr", "text_extraction"],
    pricing=pricing,
    executor=my_ocr_function,  # Your implementation
    avg_latency_ms=1500.0,
    success_rate=0.95
)

# Register in marketplace
marketplace.register_agent(agent)
```

Integration with DoerAgent:

```python
from agent import DoerAgent

# Wrap DoerAgent as a marketplace agent
def doer_executor(task: str, metadata: dict) -> str:
    doer = DoerAgent(enable_telemetry=False)
    result = doer.run(task, verbose=False)
    return result["response"]

doer_listing = AgentListing(
    agent_id="doer_agent",
    name="Self-Evolving Doer Agent",
    capabilities=["calculations", "time_queries", "general_tasks"],
    pricing=AgentPricing(
        model=PricingModel.PER_EXECUTION,
        base_price=0.03
    ),
    executor=doer_executor,
    avg_latency_ms=1200.0,
    success_rate=0.92
)

marketplace.register_agent(doer_listing)
```

**The Key Insight**: "The Old World: Subscribe for $20/month. The New World: Pay $0.01 for 10 seconds. The future is an API Economy where specialized agents sell UTILITY, not subscriptions."

### OpenAgent Definition (OAD) - Standard Agent Protocol

Run the OpenAgent Definition demonstration:
```bash
python example_agent_metadata.py
```

This demonstrates:
1. **Capabilities**: Defining what the agent can do
2. **Constraints**: Defining what the agent won't/can't do
3. **IO Contract**: Standard input/output specification
4. **Trust Score**: Real performance metrics that update dynamically
5. **Agent Discovery**: Finding agents in a marketplace
6. **Agent Composition**: Validating compatibility and building pipelines

Manual usage:

```python
from agent_metadata import AgentMetadata, AgentMetadataManager

# Create metadata manifest
metadata = AgentMetadata(
    agent_id="github-coder",
    name="GitHub Coder Agent",
    version="2.3.1",
    description="Specialized agent for GitHub code operations"
)

# Define capabilities (The "Can-Do")
metadata.add_capability(
    name="python_code_generation",
    description="Can generate Python 3.9+ code",
    tags=["python", "code-generation"]
)

# Define constraints (The "Won't-Do")
metadata.add_constraint(
    type="access",
    description="No internet access outside GitHub API",
    severity="high"
)

# Set IO contract
metadata.set_io_contract(
    input_schema={"type": "object", "properties": {...}},
    output_schema={"type": "object", "properties": {...}}
)

# Set trust score
metadata.set_trust_score(
    success_rate=0.93,
    avg_latency_ms=2400.0,
    total_executions=1547
)

# Save manifest
manager = AgentMetadataManager("agent_manifest.json")
manager.save_manifest(metadata)

# Publish to marketplace
result = manager.publish_manifest()
```

Integration with DoerAgent:

```python
from agent import DoerAgent

# Agent automatically publishes and maintains OAD manifest
doer = DoerAgent(enable_metadata=True)

# Get agent's metadata manifest
manifest = doer.get_metadata_manifest()
print(f"Agent: {manifest['name']}")
print(f"Trust Score: {manifest['trust_score']['success_rate']:.1%}")

# Run tasks - trust score updates automatically
result = doer.run("What is 10 + 20?")

# Publish to marketplace
doer.publish_manifest()
```

**The Key Insight**: "This is the USB Port moment for AI. The startup that defines the Standard Agent Protocol wins the platform war."

### Orchestration Layer (Deterministic Workflows)

Run the orchestration demonstration:
```bash
# Basic demo with mock workers
python example_orchestration.py

# Advanced demo with AI agents (requires API key)
python example_orchestration_ai.py
```

This demonstrates:
1. **Deterministic State Machine**: Orchestrator manages workflow (not AI)
2. **Hub & Spoke Pattern**: Workers communicate through hub only
3. **Transformer Middleware**: Data transformation between steps
4. **Build Website Pipeline**: Product Manager → Coder → Reviewer
5. **Failure Handling**: Predefined fallback paths

Manual usage:

```python
from orchestrator import (
    Orchestrator,
    WorkerDefinition,
    WorkerType,
    create_build_website_workflow
)

# Create orchestrator (The Hub)
orchestrator = Orchestrator()

# Register workers (Probabilistic AI)
orchestrator.register_worker(
    WorkerDefinition(
        worker_type=WorkerType.CODER,
        name="AI Coder",
        description="Implements code based on specs",
        executor=coder_function,
        input_transformer=transform_input
    )
)

# Register workflow (Deterministic State Machine)
workflow = create_build_website_workflow()
orchestrator.register_workflow(workflow)

# Execute workflow
result = orchestrator.execute_workflow(
    workflow_name="build_website",
    goal="Build a portfolio website",
    verbose=True
)

print(f"Final State: {result.state}")
print(f"Steps Executed: {len(result.history)}")
```

Integration with DoerAgent:

```python
from agent import DoerAgent
from orchestrator import Orchestrator, WorkerDefinition, WorkerType

# Use DoerAgent as a worker in the orchestration layer
def ai_worker(input_data, context):
    doer = DoerAgent()
    result = doer.run(input_data)
    return result["response"]

orchestrator.register_worker(
    WorkerDefinition(
        worker_type=WorkerType.CODER,
        name="AI Coder",
        description="AI-powered coding agent",
        executor=ai_worker
    )
)
```

**The Key Insight**: "The Brain (AI workers) is probabilistic, but the Skeleton (orchestrator) is deterministic."

### Constraint Engineering (The Logic Firewall)

Run the constraint engineering demonstration:
```bash
python example_constraint_engineering.py
```

This demonstrates:
1. **Firewall Blocking Dangerous SQL**: DROP TABLE, DELETE WHERE 1=1
2. **Firewall Blocking Dangerous File Operations**: rm -rf /, protected paths
3. **Cost Limit Enforcement**: Actions exceeding $0.05 threshold
4. **Email Domain Restrictions**: Only approved domains allowed
5. **Safe Operations Approved**: Legitimate actions pass through
6. **Creative AI with Safety**: High temperature models with deterministic firewall

Manual usage:

```python
from constraint_engine import create_default_engine

# Create firewall with sensible defaults
engine = create_default_engine(
    max_cost=0.05,
    allowed_domains=["example.com", "company.com"]
)

# AI generates a plan (could be dangerous)
ai_plan = {
    "action_type": "sql_query",
    "action_data": {
        "query": "DROP TABLE users"  # Dangerous!
    }
}

# Firewall intercepts and validates
result = engine.validate_plan(ai_plan, verbose=True)

if result.approved:
    execute_action(ai_plan)
else:
    print("🚫 Blocked by firewall!")
    for violation in result.violations:
        print(f"  - {violation.message}")
```

Integration with DoerAgent:

```python
from agent import DoerAgent

# Enable constraint engine in agent
doer = DoerAgent(
    enable_constraint_engine=True,
    constraint_engine_config={
        "max_cost": 0.05,
        "allowed_domains": ["example.com", "company.com"]
    }
)

# Validate actions before execution
plan = {
    "action_type": "sql_query",
    "action_data": {"query": "SELECT * FROM users WHERE id = ?"}
}

approved, reason = doer.validate_action_plan(plan, verbose=True)
if approved:
    # Safe to execute
    result = execute(plan)
else:
    print(f"Blocked: {reason}")
```

**The Key Insight**: "If correct but rude, score 5/10. If incorrect but polite, score 0/10."

Quality is multi-dimensional. The "Source Code" of the future is the Evaluation Suite that constrains the AI.

### Evaluation Engineering (The New TDD)

Run the evaluation engineering demonstration:
```bash
python example_evaluation_engineering.py
```

This demonstrates:
1. **Golden Datasets**: 25 tricky date parsing test cases (instead of writing parseDate())
2. **Scoring Rubrics**: Multi-dimensional scoring (70% correctness + 30% clarity)
3. **Eval-DD**: Write the exam first, let AI iterate until it passes (>90%)

Manual usage:

```python
from evaluation_engineering import (
    EvaluationDataset, 
    ScoringRubric, 
    EvaluationRunner
)

# 1. Write the Golden Dataset (this is your "code")
dataset = EvaluationDataset(
    name="Date Parsing",
    description="50 tricky date strings"
)

dataset.add_case(
    id="parse_001",
    input="Parse: Jan 15, 2024",
    expected_output="2024-01-15",
    tags=["readable"]
)

# 2. Write the Scoring Rubric
rubric = ScoringRubric("Date Parser", "Correctness + Clarity")

rubric.add_criteria(
    dimension="correctness",
    weight=0.7,  # 70% of score
    description="Is the date correct?",
    evaluator=correctness_evaluator
)

rubric.add_criteria(
    dimension="tone",
    weight=0.3,  # 30% of score
    description="Is response clear?",
    evaluator=tone_evaluator
)

rubric.set_pass_threshold(0.9)  # 90% to pass

# 3. Run Evaluation
def my_ai_function(input_text: str) -> str:
    # Your AI implementation
    return ai_response

runner = EvaluationRunner(dataset, rubric, my_ai_function)
results = runner.run(verbose=True)

if results['overall_passed']:
    print("🎉 AI meets requirements!")
else:
    print("❌ Needs improvement")
    for case in runner.get_failed_cases():
        print(f"Failed: {case.case_id}")
```

**The Key Insight**: "If the answer is correct but rude, score 5/10. If incorrect but polite, score 0/10."

Quality is multi-dimensional. The "Source Code" of the future is the Evaluation Suite that constrains the AI.

### Decoupled Architecture (Recommended)

Run the decoupled example:
```bash
python example_decoupled.py
```

This demonstrates:
1. DoerAgent executing tasks (fast, synchronous)
2. ObserverAgent learning offline (asynchronous)

Manual usage:

```python
from agent import DoerAgent
from observer import ObserverAgent

# Phase 1: Execute tasks (fast, no learning)
doer = DoerAgent()
result = doer.run("What is 10 + 20?")

# Phase 2: Learn offline (separate process)
observer = ObserverAgent()
observer.process_events()  # Batch process telemetry
```

### Intent Detection

Run the intent detection demo:
```bash
python example_intent_detection.py
```

This demonstrates intent-based evaluation:
1. **Troubleshooting**: Quick resolution (≤3 turns) = SUCCESS
2. **Troubleshooting**: User trapped (>3 turns) = FAILURE
3. **Brainstorming**: Deep exploration (≥5 turns) = SUCCESS
4. **Brainstorming**: Too shallow (<5 turns) = FAILURE

Manual usage:

```python
from agent import DoerAgent
import uuid

doer = DoerAgent()
conversation_id = str(uuid.uuid4())

# Multi-turn conversation with intent detection
doer.run(
    query="How do I reset my password?",
    conversation_id=conversation_id,
    turn_number=1  # Intent detected on first turn
)

doer.run(
    query="Thanks, that worked!",
    conversation_id=conversation_id,
    turn_number=2
)

# Observer evaluates using intent-specific metrics
from observer import ObserverAgent
observer = ObserverAgent()
observer.process_events()  # Applies intent-based evaluation
```

### Silent Signals

Run the silent signals demo:
```bash
python example_silent_signals.py
```

This demonstrates the three types of implicit feedback signals:
1. **Undo Signal**: User reverses agent action (critical failure)
2. **Abandonment Signal**: User stops responding mid-workflow (loss)
3. **Acceptance Signal**: User moves to next task without follow-up (success)

Manual usage:

```python
from agent import DoerAgent

doer = DoerAgent()

# Emit an undo signal when user reverses action
doer.emit_undo_signal(
    query="Write code to delete files",
    agent_response="rm -rf /*",
    undo_action="Ctrl+Z in editor",
    user_id="user123"
)

# Emit an abandonment signal when user stops responding
doer.emit_abandonment_signal(
    query="Help me debug",
    agent_response="Check your code",
    interaction_count=3,
    user_id="user456"
)

# Emit an acceptance signal when user moves on
doer.emit_acceptance_signal(
    query="Calculate 10 + 20",
    agent_response="Result is 30",
    next_task="Calculate 20 + 30",
    user_id="user789"
)
```

### Ghost Mode (Passive Observation)

Run the Ghost Mode demonstration:
```bash
python example_ghost_mode.py
```

This demonstrates:
1. **Background Daemon**: Observer runs silently without blocking
2. **Dry Run Analysis**: Analyzes signals without taking action
3. **Confidence-Based Surfacing**: Only interrupts when highly confident
4. **Context Shadow**: Learns user behavior patterns locally
5. **Pattern Recognition**: Proactively suggests next steps based on learned workflows

Manual usage:

```python
from ghost_mode import (
    GhostModeObserver,
    ContextShadow,
    BehaviorPattern,
    ObservationResult
)

# Define callback for when observations should surface
def on_high_confidence(observation: ObservationResult):
    """Called when Ghost Mode has something important to share."""
    print(f"🔔 {observation.observation}")
    if observation.recommendation:
        print(f"💡 {observation.recommendation}")

# Create observer with confidence threshold
observer = GhostModeObserver(
    confidence_threshold=0.7,  # Only surface if confidence >= 0.7
    surfacing_callback=on_high_confidence
)

# Start the daemon (runs in background thread)
observer.start_observing(poll_interval=1.0)

# Application generates signals (non-blocking)
observer.observe_signal({
    "type": "file_change",
    "data": {
        "file_path": "/config/secrets.yaml",
        "change_type": "modified"
    }
})

# Daemon processes silently and surfaces only when confident
# → High confidence: "Security-sensitive file modified"

# Stop when done
observer.stop_observing()

# Get statistics
stats = observer.get_stats()
print(f"Processed: {stats['signals_processed']}")
print(f"Surfaced: {stats['signals_surfaced']}")
```

Context Shadow - Learning User Workflows:

```python
# Create context shadow for secure pattern storage
shadow = ContextShadow(user_id="user123")

# Learn a workflow pattern
expense_pattern = BehaviorPattern(
    pattern_id="expense_filing",
    name="Weekly Expense Filing",
    description="User files expenses every Friday",
    trigger="open_expense_form",
    steps=[
        "Open expense report form",
        "Attach receipt image",
        "Fill in amount and category",
        "Submit for approval"
    ],
    frequency=1,
    last_seen="2024-01-01T16:00:00",
    confidence=0.7
)
shadow.learn_pattern(expense_pattern)

# Query learned patterns
patterns = shadow.query_patterns(
    trigger="open_expense_form",
    min_confidence=0.5
)

for pattern in patterns:
    print(f"Pattern: {pattern.name}")
    print(f"Confidence: {pattern.confidence:.2f}")
    print(f"Next steps: {pattern.steps}")
```

Integrated workflow with Ghost Mode + Context Shadow:

```python
# Create observer with context shadow
shadow = ContextShadow(user_id="user456")
observer = GhostModeObserver(
    context_shadow=shadow,
    confidence_threshold=0.6,
    surfacing_callback=on_high_confidence
)

observer.start_observing()

# As user performs workflow, Ghost Mode learns
observer.observe_signal({
    "type": "user_action",
    "data": {
        "action": "code_review",
        "sequence": ["open_pr", "review_files", "add_comments", "approve"]
    }
})

# When user starts the workflow again, Ghost Mode recognizes it
# and proactively suggests next steps
observer.observe_signal({
    "type": "user_action",
    "data": {
        "action": "code_review",  # Recognizes the trigger
        "sequence": ["open_pr"]
    }
})
# → Surfaces: "Suggest next step: review_files"
```

**The Key Insight**: "The future interface isn't a Destination (a website). It is a Daemon (a background process). It is invisible until it is indispensable."

**Startup Opportunity**: Build the "Context Shadow" - a lightweight daemon that securely shadows employees, learning their workflows and building a local Behavior Model that can be queried by other Agents. The "Cookies" of the real world—a secure way to store user context.

### Wisdom Curator

Run the wisdom curator demo:
```bash
python example_wisdom_curator.py
```

This demonstrates:
1. Design Check: Architecture alignment verification
2. Strategic Sample: Random sampling for quality checks
3. Policy Review: Human approval for wisdom updates

Manual usage:

```python
from wisdom_curator import WisdomCurator, DesignProposal, ReviewType

# Initialize curator
curator = WisdomCurator(
    sample_rate=0.005  # 0.5% sampling rate (50 out of 10,000)
)

# 1. Design Check: Register and verify architectural proposals
proposal = DesignProposal(
    proposal_id="auth_v1",
    title="User Authentication System",
    description="Implement JWT-based auth",
    key_requirements=["Use JWT tokens", "Add rate limiting"]
)
curator.register_design_proposal(proposal)

review = curator.verify_design_alignment(
    proposal_id="auth_v1",
    implementation_description="Implemented JWT with bcrypt..."
)

# 2. Strategic Sample: Automatically sample interactions
if curator.should_sample_interaction():
    curator.create_strategic_sample(
        query="User query",
        agent_response="Agent response"
    )

# 3. Policy Review: Check wisdom updates for policy violations
if curator.requires_policy_review(proposed_wisdom, critique):
    # BLOCKED - requires human approval
    policy_review = curator.create_policy_review(
        proposed_wisdom=proposed_wisdom,
        current_wisdom=current_wisdom,
        critique=critique
    )

# Review Management
pending = curator.get_pending_reviews(ReviewType.POLICY_REVIEW)
curator.approve_review(review_id, "Safe to apply")
curator.reject_review(review_id, "Harmful pattern")

# Integration with Observer (automatic)
from observer import ObserverAgent
observer = ObserverAgent(enable_wisdom_curator=True)
observer.process_events()  # Policy review happens automatically
```

### Legacy Synchronous Mode

Run the basic example:
```bash
python example.py
```

Run the full demo:
```bash
python agent.py
```

Custom usage:

```python
from agent import SelfEvolvingAgent

# Initialize agent
agent = SelfEvolvingAgent(
    memory_file="system_instructions.json",
    score_threshold=0.8,
    max_retries=3
)

# Run a query
results = agent.run("What is 10 + 20?", verbose=True)

print(f"Success: {results['success']}")
print(f"Final Score: {results['final_score']}")
print(f"Response: {results['final_response']}")
```

## Architecture

### Decoupled Mode Components

1. **DoerAgent**: Synchronous execution agent
   - Executes tasks using wisdom database (read-only)
   - Emits telemetry events to event stream
   - No reflection or learning during execution
   - Low latency operation

2. **ObserverAgent**: Asynchronous learning agent
   - Consumes telemetry events offline
   - Analyzes execution traces
   - Performs reflection and evaluation
   - Evolves wisdom database
   - Can use more powerful models

3. **EventStream**: Telemetry system
   - Append-only event log (JSONL format)
   - Stores execution traces
   - Supports batch processing
   - Checkpoint-based progress tracking

4. **MemorySystem/Wisdom Database**: Persistent knowledge
   - Stores system instructions in JSON
   - Version tracking
   - Improvement history

5. **AgentTools**: Simple tools the agent can use
   - `calculate()`: Mathematical expressions
   - `get_current_time()`: Current date/time
   - `string_length()`: String length calculation

### Legacy Mode Components

1. **SelfEvolvingAgent**: Main agent with evolution loop
   - `act()`: Execute query with current instructions
   - `reflect()`: Evaluate response quality
   - `evolve()`: Improve instructions based on critique
   - `run()`: Main loop orchestrating all steps

## Key Benefits of Decoupled Architecture

1. **Low Runtime Latency**: Doer doesn't wait for learning
2. **Persistent Learning**: Observer builds wisdom over time
3. **Scalability**: Observer can process events in batch
4. **Model Flexibility**: Use different/more powerful models for learning
5. **Async Processing**: Learning happens offline, separate from execution
6. **Resource Efficiency**: Learning process can be scheduled independently
7. **Context Prioritization**: Critical information (safety, user prefs) is highly visible

## Prioritization Framework

The system now includes a three-layer prioritization framework that sits between the database and agent:

1. **Safety Layer (Highest Priority)**: "Have we failed at this exact task recently?"
   - Injects corrections with high urgency
   - Prevents repeating past mistakes
   - Time-windowed (7 days default)

2. **Personalization Layer (Medium Priority)**: "Does this specific user have preferred constraints?"
   - User-specific preferences (e.g., "Always use JSON output")
   - Learned from feedback
   - Priority-ranked

3. **Global Wisdom Layer (Low Priority)**: "What is the generic best practice?"
   - Base system instructions
   - Generic best practices

**Try it:**
```bash
# Run prioritization demo
python example_prioritization.py

# Test prioritization framework
python test_prioritization.py
```

See [PRIORITIZATION_FRAMEWORK.md](docs/PRIORITIZATION_FRAMEWORK.md) for detailed documentation.

## Upgrade Purge Strategy

The system includes active lifecycle management for the wisdom database. When you upgrade your base model (e.g., GPT-3.5 → GPT-4), many lessons become redundant as the new model can handle them natively.

**The Process:**
1. **Audit**: Test old failure scenarios against the new model
2. **Identify**: Mark lessons the new model solves natively
3. **Purge**: Automatically remove redundant lessons
4. **Result**: Leaner, more specialized wisdom database

**Try it:**
```bash
# Run upgrade purge demo
python example_upgrade_purge.py

# Test upgrade functionality
python test_model_upgrade.py
```

**Usage:**
```python
from model_upgrade import ModelUpgradeManager

manager = ModelUpgradeManager()
report = manager.perform_upgrade(
    new_model="gpt-4o",
    baseline_instructions="Your baseline system prompt...",
    score_threshold=0.8,
    auto_purge=True
)
```

See [UPGRADE_PURGE.md](docs/UPGRADE_PURGE.md) for detailed documentation.

## Automated Circuit Breaker

The system includes an automated circuit breaker for managing agent rollouts with deterministic metrics. When you deploy a new agent version, the circuit breaker automatically manages the rollout and can roll back if metrics degrade.

**The Process:**
1. **Probe**: Start with 1% of traffic to validate new version
2. **Watchdog**: Monitor Task Completion Rate and Latency in real-time
3. **Auto-Scale**: Advance to 5% → 20% → 100% when metrics hold
4. **Auto-Rollback**: Immediately revert if metrics degrade below thresholds

**Try it:**
```bash
# Run circuit breaker demo
python example_circuit_breaker.py

# Test circuit breaker functionality
python test_circuit_breaker.py
```

**Usage:**
```python
from agent import DoerAgent

# Enable circuit breaker in agent
doer = DoerAgent(
    enable_circuit_breaker=True,
    circuit_breaker_config_file="cb_config.json"
)

# Agent automatically handles version selection and metrics
result = doer.run(query="What is 10 + 20?", user_id="user123")

# Check which version was used
print(f"Version: {result['version_used']}")
print(f"Latency: {result['latency_ms']:.0f}ms")
```

**Configuration:**
```python
from circuit_breaker import CircuitBreakerConfig

config = CircuitBreakerConfig(
    min_task_completion_rate=0.85,  # Must stay above 85%
    max_latency_ms=2000.0,           # Must stay below 2000ms
    min_samples_per_phase=10,        # Min samples before advancing
    monitoring_window_minutes=5      # Time window for metrics
)
```

See [CIRCUIT_BREAKER.md](docs/CIRCUIT_BREAKER.md) for detailed documentation.

## Testing

Run all tests from the project root:

```bash
# Test core agent functionality (no API key required)
python tests/test_agent.py

# Test telemetry system
python tests/test_telemetry.py

# Test polymorphic output (adaptive rendering)
python tests/test_polymorphic_output.py

# Test universal signal bus (omni-channel ingestion)
python tests/test_universal_signal_bus.py

# Test agent brokerage layer (API economy)
python tests/test_agent_brokerage.py

# Test OpenAgent Definition (OAD) metadata system
python tests/test_agent_metadata.py

# Test orchestration layer (deterministic workflows)
python tests/test_orchestration.py

# Test constraint engineering (logic firewall)
python tests/test_constraint_engineering.py

# Test evaluation engineering framework
python tests/test_evaluation_engineering.py

# Test decoupled architecture
python tests/test_decoupled.py

# Test wisdom curator
python tests/test_wisdom_curator.py

# Test prioritization framework
python tests/test_prioritization.py

# Test upgrade purge strategy
python tests/test_model_upgrade.py

# Test silent signals feature
python tests/test_silent_signals.py

# Test intent detection feature
python tests/test_intent_detection.py

# Test circuit breaker system
python tests/test_circuit_breaker.py

# Test Ghost Mode (passive observation)
python tests/test_ghost_mode.py
```

All tests are designed to work without an API key except for examples that actually call the LLM.

### Configuration

Environment variables (in `.env`):
- `OPENAI_API_KEY`: Your OpenAI API key (required)
- `AGENT_MODEL`: Model for agent (default: gpt-4o-mini)
- `REFLECTION_MODEL`: Model for reflection (default: gpt-4o-mini)
- `EVOLUTION_MODEL`: Model for evolution (default: gpt-4o-mini)
- `SCORE_THRESHOLD`: Minimum acceptable score (default: 0.8)
- `MAX_RETRIES`: Maximum retry attempts (default: 3)

## Example Output

```
ATTEMPT 1/3
Current Instructions Version: 1
[ACTING] Processing query...
Agent Response: To calculate 15 * 24 + 100...
[REFLECTING] Evaluating response...
Score: 0.6
Critique: The agent did not clearly identify the calculator tool...
[EVOLVING] Score 0.6 below threshold 0.8
Rewriting system instructions...

ATTEMPT 2/3
[ACTING] Processing query...
Agent Response: I will use the calculate() tool...
[REFLECTING] Evaluating response...
Score: 0.9
[SUCCESS] Score 0.9 meets threshold 0.8
```

## System Instructions

The `system_instructions.json` file evolves over time:

```json
{
  "version": 2,
  "instructions": "You are a helpful AI assistant...",
  "improvements": [
    {
      "version": 2,
      "timestamp": "2024-01-01T12:00:00",
      "critique": "Agent should explicitly mention tool usage..."
    }
  ]
}
```

## Architecture Overview

The framework consists of several key components:

### Core Execution
- **DoerAgent**: Fast, synchronous task execution with telemetry emission
- **ObserverAgent**: Asynchronous offline learning from telemetry streams

### Input Processing
- **Universal Signal Bus**: Normalizes input from any source (text, files, logs, audio)
- **Intent Detection**: Understands conversation type and applies appropriate metrics

### Output Processing
- **Polymorphic Output**: Adapts output format to context (chat, ghost text, dashboard, etc.)
- **Generative UI Engine**: Dynamically generates UI component specifications

### Safety & Quality
- **Constraint Engine**: Deterministic firewall for validating AI-generated plans
- **Evaluation Engineering**: Test-driven development for AI with golden datasets
- **Wisdom Curator**: Human-in-the-loop review for strategic verification

### Production Features
- **Circuit Breaker**: Automated rollout management with real-time metrics
- **Agent Brokerage**: Marketplace for specialized agents with utility-based pricing
- **Ghost Mode**: Passive observation with confidence-based surfacing
- **Prioritization Framework**: Three-layer context ranking (safety, personalization, global)

For detailed architecture information, see:
- [Architecture Overview](docs/ARCHITECTURE.md)
- [Decoupled Architecture](docs/ARCHITECTURE_DECOUPLED.md)
- [Getting Started Guide](docs/GETTING_STARTED.md)

## Documentation

All documentation is available in the `docs/` directory:

- **Getting Started**: [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md)
- **Architecture**: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- **Feature Guides**: See docs/ for detailed guides on each feature

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

MIT
