# Orchestration Layer - Deterministic Workflows

## The Problem

In traditional multi-agent systems, the "Manager" is often another AI trying to figure out who should do what. This creates:
- **Unpredictability**: AI managers make inconsistent decisions
- **Complexity**: Debugging agent-to-agent communication is hard
- **Brittleness**: One confused agent breaks the whole system

## The Solution: Deterministic Orchestration

The orchestration layer implements a **deterministic state machine** that manages the flow of data between **probabilistic AI workers**.

### Key Principles

1. **The Brain (AI) is Probabilistic** - Workers are creative AI agents
2. **The Skeleton (Orchestrator) is Deterministic** - Workflow is rigid code
3. **Hub & Spoke Pattern** - Workers never talk to each other directly
4. **Transformer Middleware** - Manages data flow between states

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ORCHESTRATOR (Hub)                        │
│                  Deterministic State Machine                 │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   Worker 1   │    │   Worker 2   │    │   Worker 3   │  │
│  │ (Product Mgr)│    │   (Coder)    │    │  (Reviewer)  │  │
│  │ Probabilistic│    │ Probabilistic│    │ Probabilistic│  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│         ▲                   ▲                    ▲           │
│         │                   │                    │           │
│         └───────────────────┴────────────────────┘           │
│                             │                                │
│                   Hub & Spoke: No Direct                     │
│                   Worker-to-Worker Talk                      │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. Orchestrator (The Hub)

The central state machine that:
- Routes work to appropriate workers
- Transforms data between workers (Transformer Middleware)
- Tracks workflow state
- Enforces deterministic flow

```python
from orchestrator import Orchestrator

orchestrator = Orchestrator()
```

### 2. Workers (Probabilistic AI)

AI agents that perform specific tasks. Each worker:
- Has a defined type (Product Manager, Coder, Reviewer, etc.)
- Executes its task probabilistically (AI-powered)
- Never communicates directly with other workers

```python
from orchestrator import WorkerDefinition, WorkerType

worker = WorkerDefinition(
    worker_type=WorkerType.CODER,
    name="Coder",
    description="Implements code based on specifications",
    executor=coder_function,
    input_transformer=transform_input,
    output_transformer=transform_output
)

orchestrator.register_worker(worker)
```

### 3. Workflow (Deterministic State Machine)

Rigid definition of steps and transitions:
- Each step specifies which worker to use
- Success/failure paths are predefined
- No AI decision-making in the flow

```python
from orchestrator import WorkflowDefinition, WorkflowStep

workflow = WorkflowDefinition(
    name="build_website",
    description="Build a website from requirements",
    goal="Create a functional website"
)

workflow.add_step(
    WorkflowStep(
        step_id="create_specs",
        worker_type=WorkerType.PRODUCT_MANAGER,
        description="Product Manager creates technical specifications",
        on_success="implement_code",
        on_failure="failed"
    ),
    is_initial=True
)
```

### 4. Transformer Middleware

Functions that transform data between steps:
- **Input Transformer**: Prepares input for a worker
- **Output Transformer**: Processes worker output

```python
def coder_input_transformer(context: WorkflowContext) -> Dict[str, Any]:
    """Transform specs for Coder."""
    return context.get_last_output(WorkerType.PRODUCT_MANAGER.value)
```

## Usage

### Basic Example

```python
from orchestrator import (
    Orchestrator,
    WorkerDefinition,
    WorkerType,
    create_build_website_workflow
)

# 1. Create orchestrator
orchestrator = Orchestrator()

# 2. Register workers
orchestrator.register_worker(
    WorkerDefinition(
        worker_type=WorkerType.PRODUCT_MANAGER,
        name="Product Manager",
        description="Creates specifications",
        executor=product_manager_function
    )
)

orchestrator.register_worker(
    WorkerDefinition(
        worker_type=WorkerType.CODER,
        name="Coder",
        description="Implements code",
        executor=coder_function
    )
)

# 3. Register workflow
workflow = create_build_website_workflow()
orchestrator.register_workflow(workflow)

# 4. Execute workflow
result = orchestrator.execute_workflow(
    workflow_name="build_website",
    goal="Build a portfolio website",
    verbose=True
)

print(f"Final State: {result.state}")
print(f"History: {result.history}")
```

### Pre-built Workflows

#### Build Website Pipeline

Product Manager → Coder → Reviewer

```python
from orchestrator import create_build_website_workflow

workflow = create_build_website_workflow()
```

#### Generic Pipeline

Create a custom linear pipeline:

```python
from orchestrator import create_generic_pipeline, WorkerType

workflow = create_generic_pipeline([
    ("analyze", WorkerType.PRODUCT_MANAGER, "Analyze requirements"),
    ("design", WorkerType.CODER, "Design solution"),
    ("implement", WorkerType.CODER, "Implement code"),
    ("test", WorkerType.TESTER, "Test implementation"),
    ("deploy", WorkerType.DEPLOYER, "Deploy to production")
])
```

## Key Features

### 1. Deterministic State Machine

The workflow is rigid, deterministic code. No AI makes routing decisions.

```python
# The orchestrator follows this exact path - no AI decisions
Step 1: Product Manager creates specs
  ↓ (on_success)
Step 2: Coder implements code
  ↓ (on_success)
Step 3: Reviewer checks code
  ↓ (on_success)
Step 4: Complete
```

### 2. Hub & Spoke Pattern

Workers report to the hub, never to each other:

```python
# ✓ CORRECT: Worker → Hub → Worker
Product Manager → [Hub] → Coder

# ✗ WRONG: Worker → Worker
Product Manager → Coder  # Never happens!
```

### 3. Transformer Middleware

Data transformation happens in the middleware:

```python
# Input transformer prepares data for worker
def coder_input_transformer(context: WorkflowContext) -> Dict[str, Any]:
    specs = context.get_last_output("product_manager")
    return {
        "specifications": specs,
        "tech_stack": context.data.get("tech_stack", []),
        "constraints": context.data.get("constraints", {})
    }

# Output transformer processes worker output
def coder_output_transformer(output: Any, context: WorkflowContext) -> Dict[str, Any]:
    return {
        "code": output,
        "timestamp": datetime.now().isoformat(),
        "version": context.workflow_id
    }
```

### 4. Failure Handling

Define explicit failure paths:

```python
WorkflowStep(
    step_id="implement_code",
    worker_type=WorkerType.CODER,
    description="Implement code",
    on_success="review_code",
    on_failure="create_specs",  # Loop back on failure
    max_retries=2  # Retry up to 2 times
)
```

### 5. Workflow Context

Shared context flows through the workflow:

```python
class WorkflowContext:
    workflow_id: str        # Unique workflow instance ID
    goal: str              # High-level goal
    state: WorkflowState   # Current state
    current_step: str      # Current step ID
    data: Dict[str, Any]   # Shared data bus
    history: List[...]     # Execution history
    
# Access in workers
def worker_function(input_data: Any, context: WorkflowContext) -> Any:
    # Access goal
    print(f"Goal: {context.goal}")
    
    # Access previous outputs
    prev_output = context.get_last_output()
    
    # Access specific worker output
    specs = context.get_last_output("product_manager")
    
    # Store data for later steps
    context.data["important_info"] = "value"
```

## Testing

Run the test suite:

```bash
python test_orchestration.py
```

Run the demo:

```bash
python example_orchestration.py
```

## The Startup Opportunity

**Orchestration-as-a-Service**: There's a massive gap in the market.

Instead of:
```python
# Developer manually builds state machine
orchestrator = Orchestrator()
orchestrator.register_worker(...)
orchestrator.register_worker(...)
workflow = WorkflowDefinition(...)
```

Imagine:
```python
# Service automatically creates pipeline
pipeline = OrchestrationService.create(
    goal="Build a Website",
    # Service figures out: Product Manager → Coder → Reviewer
)
```

The service would:
1. Parse the high-level goal
2. Automatically select appropriate workers
3. Spin up the correct pipeline
4. Manage execution and monitoring

## Benefits

### 1. Predictability

Deterministic orchestration means:
- Same input → Same flow
- Easy to debug
- Easy to test

### 2. Maintainability

Workflows are:
- Readable code (not AI decisions)
- Version controlled
- Easy to modify

### 3. Observability

Every step is tracked:
```python
result = orchestrator.execute_workflow(...)

# Full audit trail
for entry in result.history:
    print(f"{entry['worker_type']}: {entry['timestamp']}")
```

### 4. Reliability

Workers can fail, but the orchestrator:
- Handles failures gracefully
- Follows predefined fallback paths
- Can retry operations

## Comparison to Traditional Approaches

| Aspect | AI Manager | Deterministic Orchestrator |
|--------|-----------|---------------------------|
| **Flow Control** | AI decides | Rigid state machine |
| **Predictability** | Low | High |
| **Debuggability** | Hard | Easy |
| **Reliability** | Brittle | Robust |
| **Worker Communication** | Direct (chaos) | Hub & Spoke (clean) |

## Best Practices

### 1. Keep Workflows Simple

```python
# ✓ GOOD: Linear pipeline
Step 1 → Step 2 → Step 3 → Done

# ✗ BAD: Complex graph with many branches
Step 1 → Step 2a, 2b, 2c → Step 3...
```

### 2. Use Transformer Middleware

```python
# ✓ GOOD: Transform data explicitly
def input_transformer(context):
    return prepare_data_for_worker(context)

# ✗ BAD: Workers access raw context
def worker(input_data, context):
    data = context.history[2]["output"]["nested"]["field"]  # Brittle!
```

### 3. Define Clear Failure Paths

```python
# ✓ GOOD: Explicit failure handling
WorkflowStep(
    step_id="risky_step",
    on_success="next_step",
    on_failure="fallback_step",
    max_retries=2
)

# ✗ BAD: No failure handling
WorkflowStep(
    step_id="risky_step",
    on_success="next_step"
    # What happens on failure? 🤷
)
```

### 4. Make Workers Idempotent

Workers should be safe to retry:
```python
def coder_worker(input_data, context):
    # ✓ GOOD: Same input → Same output
    return generate_code(input_data)
    
    # ✗ BAD: Side effects
    with open("file.txt", "w") as f:  # File gets overwritten!
        f.write(generate_code(input_data))
```

## Extension Points

### Custom Workers

Implement your own worker types:

```python
class WorkerType(Enum):
    # Built-in types
    PRODUCT_MANAGER = "product_manager"
    CODER = "coder"
    REVIEWER = "reviewer"
    
    # Custom types
    DATA_SCIENTIST = "data_scientist"
    SECURITY_AUDITOR = "security_auditor"
    PERFORMANCE_OPTIMIZER = "performance_optimizer"
```

### Custom Workflows

Build domain-specific workflows:

```python
def create_ml_pipeline() -> WorkflowDefinition:
    """Machine Learning Pipeline."""
    workflow = WorkflowDefinition(
        name="ml_pipeline",
        description="Train and deploy ML model",
        goal="Build ML model"
    )
    
    workflow.add_step(...)  # Data collection
    workflow.add_step(...)  # Feature engineering
    workflow.add_step(...)  # Model training
    workflow.add_step(...)  # Validation
    workflow.add_step(...)  # Deployment
    
    return workflow
```

## Integration with Existing Agent System

The orchestration layer integrates seamlessly:

```python
from agent import DoerAgent
from orchestrator import Orchestrator, WorkerDefinition, WorkerType

# Use DoerAgent as a worker
def doer_worker(input_data, context):
    doer = DoerAgent()
    result = doer.run(input_data)
    return result["response"]

orchestrator.register_worker(
    WorkerDefinition(
        worker_type=WorkerType.CODER,
        name="AI Coder",
        description="AI-powered coding agent",
        executor=doer_worker
    )
)
```

## License

MIT
