# Polymorphic Output (Adaptive Rendering)

## The Revolution

**The Old World:** "The AI always replies with text."

**The New World:** If the input can be anything, the output must be anything.

## The Architecture

The system determines the **Modality of Response** based on:
1. **Modality of Input** (telemetry → widget, IDE → ghost text)
2. **Nature of Data** (tabular → table, time series → chart)
3. **User Context** (debugging → inline, monitoring → dashboard)

### Scenario A (Data): Backend Telemetry → Dashboard Widget
**Input:** Backend telemetry stream detects latency spike  
**Agent Action:** Identifies spike from 500ms to 2000ms  
**Polymorphic Output:** A Dashboard Widget with red alert  
**Not:** A chat message saying "Latency is high"

**The Insight:** Don't chat with me. Draw a red line on a graph.

### Scenario B (Code): IDE Context → Ghost Text
**Input:** User typing in an IDE  
**Agent Action:** Predicts the next function  
**Polymorphic Output:** Ghost Text (inline autocomplete)  
**Not:** A popup window or chat response

**The Insight:** Don't pop up a window. Just autocomplete the code.

### Scenario C (Analysis): SQL Results → Interactive Table
**Input:** User runs database query  
**Agent Action:** Returns structured tabular data  
**Polymorphic Output:** Sortable, filterable table component  
**Not:** Text dump of rows

**The Insight:** Don't print rows. Render a table.

## Core Components

### 1. Output Modality Types

The system supports multiple output modalities:

- **TEXT**: Traditional text response
- **GHOST_TEXT**: IDE autocomplete/inline suggestion
- **DASHBOARD_WIDGET**: Real-time monitoring widget
- **CHART**: Data visualization (line, bar, pie)
- **TABLE**: Structured tabular data
- **FORM**: Interactive form with fields
- **NOTIFICATION**: Alert/toast notification
- **CODE_SNIPPET**: Formatted code block
- **CARD**: Information card/panel
- **LIST**: Ordered/unordered list
- **MODAL**: Modal dialog
- **INLINE_ERROR**: Inline error message/squiggle

### 2. Output Modality Detector

Automatically determines the appropriate output modality based on:
- **Input Context** (IDE, Monitoring, Chat, Debugging, etc.)
- **Data Type** (text, code, tabular, time_series, structured)
- **Signal Type** (file_change, log_stream, audio_stream)
- **Urgency** (0-1 scale)

**Detection Rules:**
```python
IDE context → Ghost Text or Inline Error
Monitoring context → Dashboard Widget or Chart
High urgency (≥0.8) → Notification
Tabular data → Table
Time series → Chart
Code → Code Snippet
Default → Text
```

### 3. Polymorphic Response

A structured response with modality and rendering data:

```python
@dataclass
class PolymorphicResponse:
    modality: OutputModality           # What type of output
    timestamp: str                      # When generated
    data: Union[str, Dict, List]       # The actual content
    rendering_hints: Dict[str, Any]    # How to render it
    metadata: Dict[str, Any]           # Additional context
    text_fallback: Optional[str]       # Plain text version
```

### 4. Polymorphic Output Engine

Generates polymorphic responses from agent output:

```python
engine = PolymorphicOutputEngine()

response = engine.generate_response(
    data={"metric": "latency", "value": "2000ms"},
    input_context=InputContext.MONITORING,
    input_signal_type="log_stream",
    urgency=0.9
)

# Result: Dashboard Widget, not text
```

## The Interface Layer: Generative UI Engine

**The Agent generates the Data, but the Interface Layer generates the View.**

This is "Just-in-Time UI."

### UI Component Generator

Converts polymorphic responses into UI component specifications:

```python
generator = UIComponentGenerator()
component = generator.generate_component(poly_response)

# Returns: UIComponentSpec with component_type, props, children, style
```

### Component Types

The engine generates specifications for:
- **Table**: Sortable, filterable data grids
- **Chart**: Line, bar, pie, scatter plots
- **Card**: Information panels
- **MetricCard**: Single metric displays
- **Notification**: Toast/alert components
- **CodeBlock**: Syntax-highlighted code
- **GhostText**: IDE inline suggestions
- **InlineError**: IDE error squiggles
- **DashboardWidget**: Real-time monitoring displays

### Generative UI Engine

Main SDK for dynamically rendering UI components:

```python
engine = GenerativeUIEngine()

# Render to component spec
ui_component = engine.render(poly_response)

# Render to JSON (for wire protocol)
json_spec = engine.render_to_json(poly_response)

# Render to React JSX (pseudo-code)
react_jsx = engine.render_to_react(poly_response)

# Batch render multiple responses
components = engine.batch_render([response1, response2])
```

## Usage Examples

### Example 1: Telemetry Stream → Dashboard Widget

```python
from polymorphic_output import create_dashboard_widget_response
from generative_ui_engine import GenerativeUIEngine

# Agent detects latency spike
response = create_dashboard_widget_response(
    metric_name="API Latency",
    metric_value="2000ms",
    trend="up",
    alert_level="critical"
)

# Generate UI component
engine = GenerativeUIEngine()
widget = engine.render(response)

# Deploy to dashboard
dashboard.add_widget(widget)
```

### Example 2: IDE Typing → Ghost Text

```python
from polymorphic_output import create_ghost_text_response

# User types "def calculate_"
response = create_ghost_text_response(
    suggestion="total(items: List[float]) -> float:\n    return sum(items)",
    cursor_position={"line": 42, "column": 16}
)

# Render in IDE
ide.show_ghost_text(response)
```

### Example 3: SQL Query → Table

```python
from polymorphic_output import create_table_response

# Query returns results
sql_results = [
    {"id": 1, "name": "Alice", "email": "alice@example.com"},
    {"id": 2, "name": "Bob", "email": "bob@example.com"}
]

response = create_table_response(
    rows=sql_results,
    title="Users",
    sortable=True,
    filterable=True
)

# Render as interactive table
ui_engine = GenerativeUIEngine()
table = ui_engine.render(response)
```

### Example 4: Time Series → Chart

```python
from polymorphic_output import create_chart_response

# Performance data over time
data_points = [
    {"timestamp": "00:00", "value": 100},
    {"timestamp": "01:00", "value": 120},
    {"timestamp": "02:00", "value": 150}
]

response = create_chart_response(
    chart_type="line",
    data_points=data_points,
    title="Request Rate",
    x_axis_label="Time",
    y_axis_label="Requests/min"
)

# Render as chart
chart = ui_engine.render(response)
```

### Example 5: Critical Alert → Notification

```python
from polymorphic_output import create_notification_response

# System error detected
response = create_notification_response(
    message="Database connection lost. Attempting reconnection...",
    level="error",
    action={"label": "View Details", "handler": "openErrorLog"}
)

# Show notification
notification_system.show(response)
```

## Integration with Existing Agent

### Wrapping Text Responses

```python
from generative_ui_engine import wrap_agent_response_with_ui

# Traditional agent returns text
agent_text = "The latency is 2000ms, which is high"

# Wrap with UI capabilities
result = wrap_agent_response_with_ui(
    agent_response=agent_text,
    input_context="monitoring"
)

# Result includes:
# - text: Original text response
# - polymorphic_response: Structured response with modality
# - ui_component: UI component specification
```

### Adding to DoerAgent

```python
from agent import DoerAgent
from polymorphic_output import PolymorphicOutputEngine, InputContext

class PolymorphicDoerAgent(DoerAgent):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.poly_engine = PolymorphicOutputEngine()
    
    def run_polymorphic(self, query, input_context, **kwargs):
        # Run standard agent
        result = self.run(query, **kwargs)
        
        # Generate polymorphic response
        poly_response = self.poly_engine.generate_response(
            data=result['response'],
            input_context=input_context
        )
        
        return {
            **result,
            'polymorphic_response': poly_response
        }
```

## Text Fallback

Every polymorphic response includes a plain text fallback:

- **Tables** → ASCII table format
- **Charts** → Text list of data points
- **Widgets** → Key-value pairs
- **Ghost Text** → Plain suggestion text
- **Notifications** → Alert message with level

This ensures **backward compatibility** with text-only systems.

## 🚀 The Startup Opportunity: Generative UI Engine SDK

### The Problem
- Developers hard-code every screen, form, and chart
- AI agents only return text
- Developers manually parse and render UI

### The Solution
An SDK that developers drop into their apps. The AI sends raw JSON data, and the Engine dynamically renders the perfect React/Flutter component (Table, Chart, Form, Notification) to match the data type.

### The Integration (3 lines)

```python
from generative_ui_sdk import GenerativeUIEngine

engine = GenerativeUIEngine()
ui_component = engine.render(agent_response)
app.display(ui_component)
```

### The Result
✅ Tables render themselves from SQL results  
✅ Charts appear from time series data  
✅ Notifications pop for critical alerts  
✅ Ghost text for IDE completions  
✅ All automatic. No manual UI code.

### The Market
- Every AI app needs UI rendering
- Every dashboard needs adaptive components
- Every IDE needs intelligent suggestions

### The Revenue Model
- $99/month per developer
- Enterprise: $10k/year unlimited
- Open source core + premium components

**Stop hard-coding screens. Build the engine that dreams them up.**

## Running the Examples

```bash
# Run the demonstration
python example_polymorphic_output.py

# Run the tests
python test_polymorphic_output.py
```

## Key Benefits

1. **Context-Aware**: Output adapts to input context automatically
2. **Type-Aware**: Data type determines rendering format
3. **Urgency-Aware**: Critical alerts get prominence
4. **Backward Compatible**: Always includes text fallback
5. **Framework Agnostic**: Generates specs for React, Flutter, etc.
6. **Developer Friendly**: Simple API, 3-line integration
7. **Extensible**: Easy to add new modalities and components

## The Philosophy

**"Don't chat when you can draw. Don't pop up when you can suggest. Don't print when you can render."**

The future of AI isn't just smarter responses—it's smarter interfaces that adapt to context, data, and user needs.

This is the next evolution of human-AI interaction.
