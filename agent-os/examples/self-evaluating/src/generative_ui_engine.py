# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Generative UI Engine - Just-in-Time UI

This is the "Interface Layer" that takes structured data from the agent
and dynamically generates UI components to match the data type.

The Agent generates the Data, but the Interface Layer generates the View.
This is "Just-in-Time UI."

The Startup Opportunity: An SDK that developers drop into their apps.
The AI sends raw JSON data, and the Engine dynamically renders the perfect
React/Flutter component (Table, Chart, Form, Notification) to match the data type.

Stop hard-coding screens. Build the engine that dreams them up.
"""

from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field
from .polymorphic_output import (
    PolymorphicResponse,
    OutputModality
)
import json


class ComponentType:
    """Types of UI components that can be generated."""
    # Data Display
    TABLE = "Table"
    CHART = "Chart"
    CARD = "Card"
    LIST = "List"
    METRIC_CARD = "MetricCard"
    
    # Interactive
    FORM = "Form"
    BUTTON = "Button"
    INPUT = "Input"
    
    # Feedback
    NOTIFICATION = "Notification"
    ALERT = "Alert"
    TOAST = "Toast"
    
    # Code
    CODE_BLOCK = "CodeBlock"
    GHOST_TEXT = "GhostText"
    INLINE_ERROR = "InlineError"
    
    # Layout
    DASHBOARD_WIDGET = "DashboardWidget"
    MODAL = "Modal"
    PANEL = "Panel"


@dataclass
class UIComponentSpec:
    """
    Specification for a UI component.
    
    This is the "blueprint" that the Interface Layer generates.
    The UI framework (React/Flutter) reads this spec and renders the actual component.
    """
    # Core fields
    component_type: str
    props: Dict[str, Any] = field(default_factory=dict)
    
    # Children components (for nested structures)
    children: List['UIComponentSpec'] = field(default_factory=list)
    
    # Styling hints
    style: Dict[str, Any] = field(default_factory=dict)
    
    # Event handlers (as strings/references)
    events: Dict[str, str] = field(default_factory=dict)
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "component_type": self.component_type,
            "props": self.props,
            "children": [child.to_dict() for child in self.children],
            "style": self.style,
            "events": self.events,
            "metadata": self.metadata
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    def to_react_jsx(self) -> str:
        """
        Generate React JSX code (pseudo-code representation).
        
        Note: This is a simplified representation for demonstration.
        In production, you'd use a proper JSX generator or template engine.
        """
        props_str = " ".join(f'{k}={{{json.dumps(v)}}}' for k, v in self.props.items())
        
        if not self.children:
            return f"<{self.component_type} {props_str} />"
        
        children_jsx = "\n  ".join(child.to_react_jsx() for child in self.children)
        return f"<{self.component_type} {props_str}>\n  {children_jsx}\n</{self.component_type}>"


class UIComponentGenerator:
    """
    Generates UI component specifications from polymorphic responses.
    
    This is the "compiler" that converts agent data into UI blueprints.
    """
    
    def generate_component(self, response: PolymorphicResponse) -> UIComponentSpec:
        """
        Generate a UI component spec from a polymorphic response.
        
        Args:
            response: The polymorphic response from the agent
            
        Returns:
            UIComponentSpec: The generated component specification
        """
        # Map modality to component generator
        generators = {
            OutputModality.TEXT: self._generate_text_component,
            OutputModality.GHOST_TEXT: self._generate_ghost_text_component,
            OutputModality.DASHBOARD_WIDGET: self._generate_dashboard_widget,
            OutputModality.CHART: self._generate_chart_component,
            OutputModality.TABLE: self._generate_table_component,
            OutputModality.NOTIFICATION: self._generate_notification_component,
            OutputModality.CODE_SNIPPET: self._generate_code_block_component,
            OutputModality.CARD: self._generate_card_component,
            OutputModality.LIST: self._generate_list_component,
            OutputModality.INLINE_ERROR: self._generate_inline_error_component,
        }
        
        generator = generators.get(response.modality, self._generate_text_component)
        return generator(response)
    
    def _generate_text_component(self, response: PolymorphicResponse) -> UIComponentSpec:
        """Generate a simple text/paragraph component."""
        return UIComponentSpec(
            component_type="Text",
            props={
                "content": response.data if isinstance(response.data, str) else str(response.data)
            },
            style={"whiteSpace": "pre-wrap"}
        )
    
    def _generate_ghost_text_component(self, response: PolymorphicResponse) -> UIComponentSpec:
        """Generate a ghost text (autocomplete) component for IDE."""
        return UIComponentSpec(
            component_type=ComponentType.GHOST_TEXT,
            props={
                "suggestion": response.data,
                "cursorPosition": response.rendering_hints.get("cursor_position", {}),
                "inline": True
            },
            style={
                "color": "#888",
                "fontStyle": "italic",
                "display": "inline"
            }
        )
    
    def _generate_dashboard_widget(self, response: PolymorphicResponse) -> UIComponentSpec:
        """Generate a dashboard widget for real-time monitoring."""
        data = response.data if isinstance(response.data, dict) else {"value": response.data}
        
        metric_name = data.get("metric_name", "Metric")
        metric_value = data.get("metric_value", "")
        trend = data.get("trend", "stable")
        alert_level = data.get("alert_level", "normal")
        
        # Choose color based on alert level
        color_map = {
            "critical": "#FF0000",
            "high": "#FF6600",
            "warning": "#FFAA00",
            "normal": "#00AA00"
        }
        
        return UIComponentSpec(
            component_type=ComponentType.DASHBOARD_WIDGET,
            props={
                "title": metric_name,
                "value": metric_value,
                "trend": trend,
                "alertLevel": alert_level
            },
            style={
                "borderLeft": f"4px solid {color_map.get(alert_level, '#00AA00')}",
                "padding": "16px",
                "backgroundColor": "#F5F5F5",
                "borderRadius": "8px"
            },
            children=[
                UIComponentSpec(
                    component_type="MetricDisplay",
                    props={
                        "value": metric_value,
                        "fontSize": "32px",
                        "fontWeight": "bold"
                    }
                ),
                UIComponentSpec(
                    component_type="TrendIndicator",
                    props={
                        "trend": trend,
                        "icon": "↑" if trend == "up" else "↓" if trend == "down" else "→"
                    }
                )
            ]
        )
    
    def _generate_chart_component(self, response: PolymorphicResponse) -> UIComponentSpec:
        """Generate a chart component for data visualization."""
        data = response.data if isinstance(response.data, dict) else {"data_points": response.data}
        
        chart_type = data.get("chart_type", "line")
        data_points = data.get("data_points", [])
        title = data.get("title", "Chart")
        
        return UIComponentSpec(
            component_type=ComponentType.CHART,
            props={
                "type": chart_type,
                "data": data_points,
                "title": title,
                "xAxisLabel": data.get("x_axis_label", ""),
                "yAxisLabel": data.get("y_axis_label", ""),
                "interactive": response.rendering_hints.get("interactive", True)
            },
            style={
                "width": "100%",
                "height": "400px",
                "padding": "16px"
            }
        )
    
    def _generate_table_component(self, response: PolymorphicResponse) -> UIComponentSpec:
        """Generate a table component for tabular data."""
        rows = response.data if isinstance(response.data, list) else []
        
        # Extract columns from first row
        columns = []
        if rows and isinstance(rows[0], dict):
            columns = [{"field": k, "headerName": k.replace("_", " ").title()} 
                      for k in rows[0].keys()]
        
        return UIComponentSpec(
            component_type=ComponentType.TABLE,
            props={
                "columns": columns,
                "rows": rows,
                "sortable": response.rendering_hints.get("sortable", True),
                "filterable": response.rendering_hints.get("filterable", True),
                "pagination": len(rows) > 10
            },
            style={
                "width": "100%",
                "border": "1px solid #DDD"
            }
        )
    
    def _generate_notification_component(self, response: PolymorphicResponse) -> UIComponentSpec:
        """Generate a notification/toast component."""
        data = response.data if isinstance(response.data, dict) else {"message": str(response.data)}
        
        level = data.get("level", "info")
        message = data.get("message", "")
        
        # Color map for notification levels
        color_map = {
            "error": "#F44336",
            "warning": "#FF9800",
            "success": "#4CAF50",
            "info": "#2196F3"
        }
        
        return UIComponentSpec(
            component_type=ComponentType.NOTIFICATION,
            props={
                "message": message,
                "level": level,
                "duration": response.rendering_hints.get("duration", 5000),
                "dismissible": response.rendering_hints.get("dismissible", True)
            },
            style={
                "backgroundColor": color_map.get(level, "#2196F3"),
                "color": "#FFFFFF",
                "padding": "12px 16px",
                "borderRadius": "4px",
                "boxShadow": "0 2px 8px rgba(0,0,0,0.15)"
            }
        )
    
    def _generate_code_block_component(self, response: PolymorphicResponse) -> UIComponentSpec:
        """Generate a code block component with syntax highlighting."""
        code = response.data if isinstance(response.data, str) else str(response.data)
        
        return UIComponentSpec(
            component_type=ComponentType.CODE_BLOCK,
            props={
                "code": code,
                "language": response.rendering_hints.get("language", "python"),
                "showLineNumbers": response.rendering_hints.get("show_line_numbers", True),
                "theme": "vs-dark"
            },
            style={
                "fontFamily": "monospace",
                "fontSize": "14px",
                "backgroundColor": "#1E1E1E",
                "padding": "16px",
                "borderRadius": "4px",
                "overflow": "auto"
            }
        )
    
    def _generate_card_component(self, response: PolymorphicResponse) -> UIComponentSpec:
        """Generate a card component for structured data."""
        data = response.data if isinstance(response.data, dict) else {}
        
        # Create children for each key-value pair
        children = []
        for key, value in data.items():
            children.append(
                UIComponentSpec(
                    component_type="KeyValue",
                    props={
                        "label": key.replace("_", " ").title(),
                        "value": str(value)
                    }
                )
            )
        
        return UIComponentSpec(
            component_type=ComponentType.CARD,
            props={
                "title": response.rendering_hints.get("title", "Information")
            },
            style={
                "border": "1px solid #DDD",
                "borderRadius": "8px",
                "padding": "16px",
                "backgroundColor": "#FFFFFF",
                "boxShadow": "0 2px 4px rgba(0,0,0,0.1)"
            },
            children=children
        )
    
    def _generate_list_component(self, response: PolymorphicResponse) -> UIComponentSpec:
        """Generate a list component."""
        items = response.data if isinstance(response.data, list) else [response.data]
        
        children = [
            UIComponentSpec(
                component_type="ListItem",
                props={"content": str(item)}
            )
            for item in items
        ]
        
        return UIComponentSpec(
            component_type=ComponentType.LIST,
            props={
                "ordered": response.rendering_hints.get("ordered", False)
            },
            children=children
        )
    
    def _generate_inline_error_component(self, response: PolymorphicResponse) -> UIComponentSpec:
        """Generate an inline error component (like IDE squiggles)."""
        data = response.data if isinstance(response.data, dict) else {"message": str(response.data)}
        
        return UIComponentSpec(
            component_type=ComponentType.INLINE_ERROR,
            props={
                "message": data.get("message", "Error"),
                "line": data.get("line", 1),
                "column": data.get("column", 1),
                "severity": data.get("severity", "error")
            },
            style={
                "textDecoration": "wavy underline",
                "textDecorationColor": "#FF0000",
                "cursor": "pointer"
            }
        )


class GenerativeUIEngine:
    """
    Main Generative UI Engine.
    
    This is the SDK that developers integrate into their apps.
    It takes agent responses and dynamically generates UI components.
    """
    
    def __init__(self):
        self.generator = UIComponentGenerator()
    
    def render(self, response: PolymorphicResponse) -> UIComponentSpec:
        """
        Render a polymorphic response as a UI component.
        
        Args:
            response: The polymorphic response from the agent
            
        Returns:
            UIComponentSpec: The component specification to render
        """
        return self.generator.generate_component(response)
    
    def render_to_json(self, response: PolymorphicResponse) -> str:
        """
        Render a polymorphic response as JSON component spec.
        
        Args:
            response: The polymorphic response from the agent
            
        Returns:
            str: JSON representation of the component
        """
        component = self.render(response)
        return component.to_json()
    
    def render_to_react(self, response: PolymorphicResponse) -> str:
        """
        Render a polymorphic response as React JSX (pseudo-code).
        
        Args:
            response: The polymorphic response from the agent
            
        Returns:
            str: React JSX representation (simplified)
        """
        component = self.render(response)
        return component.to_react_jsx()
    
    def batch_render(self, responses: List[PolymorphicResponse]) -> List[UIComponentSpec]:
        """
        Render multiple responses at once.
        
        Args:
            responses: List of polymorphic responses
            
        Returns:
            List[UIComponentSpec]: List of component specifications
        """
        return [self.render(response) for response in responses]


# Helper function for integrating with existing agent systems

def wrap_agent_response_with_ui(
    agent_response: str,
    input_context: str,
    data_type: Optional[str] = None
) -> Dict[str, Any]:
    """
    Wrap a traditional text agent response with UI rendering capabilities.
    
    This is a bridge function for integrating the Generative UI Engine
    with existing agents that only return text.
    
    Args:
        agent_response: The text response from the agent
        input_context: Context string (e.g., "ide", "monitoring", "chat")
        data_type: Optional data type hint
        
    Returns:
        Dict with both text response and UI component spec
    """
    from polymorphic_output import PolymorphicOutputEngine, InputContext
    
    # Map string context to enum
    context_map = {
        "ide": InputContext.IDE,
        "monitoring": InputContext.MONITORING,
        "chat": InputContext.CHAT,
        "debugging": InputContext.DEBUGGING,
        "cli": InputContext.CLI
    }
    
    context = context_map.get(input_context.lower(), InputContext.CHAT)
    
    # Generate polymorphic response
    output_engine = PolymorphicOutputEngine()
    poly_response = output_engine.generate_response(
        data=agent_response,
        input_context=context
    )
    
    # Generate UI component
    ui_engine = GenerativeUIEngine()
    ui_component = ui_engine.render(poly_response)
    
    return {
        "text": agent_response,
        "polymorphic_response": poly_response.to_dict(),
        "ui_component": ui_component.to_dict()
    }
