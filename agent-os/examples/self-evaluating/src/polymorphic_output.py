# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Polymorphic Output (Adaptive Rendering)

This module implements an adaptive output system where the agent determines
the response modality based on the input modality and context.

The Old World: "The AI always replies with text."
The New World: If input can be anything, output must be anything.

The system determines the Modality of Response based on:
1. Modality of Input (telemetry → widget, IDE → ghost text)
2. Nature of Data (tabular → table, time series → chart)
3. User Context (debugging → inline, monitoring → dashboard)

Scenario A (Data): Backend Telemetry → Dashboard Widget (not chat)
Scenario B (Code): IDE typing → Ghost Text (not popup)
Scenario C (Analysis): SQL results → Interactive Table (not text dump)
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Union
from datetime import datetime
from enum import Enum
import json


class OutputModality(Enum):
    """Types of output modalities the agent can generate."""
    TEXT = "text"                    # Traditional text response
    GHOST_TEXT = "ghost_text"        # IDE autocomplete/inline suggestion
    DASHBOARD_WIDGET = "dashboard_widget"  # Real-time monitoring widget
    CHART = "chart"                  # Data visualization (line, bar, pie)
    TABLE = "table"                  # Structured tabular data
    FORM = "form"                    # Interactive form with fields
    NOTIFICATION = "notification"    # Alert/toast notification
    CODE_SNIPPET = "code_snippet"    # Formatted code block
    CARD = "card"                    # Information card/panel
    LIST = "list"                    # Ordered/unordered list
    MODAL = "modal"                  # Modal dialog
    INLINE_ERROR = "inline_error"    # Inline error message/squiggle


class InputContext(Enum):
    """Context in which the input was received."""
    CHAT = "chat"                    # Traditional chat interface
    IDE = "ide"                      # Code editor/IDE
    MONITORING = "monitoring"        # System monitoring/observability
    DEBUGGING = "debugging"          # Active debugging session
    API = "api"                      # API call/integration
    CLI = "cli"                      # Command line interface
    FORM_SUBMISSION = "form_submission"  # Form data submission


@dataclass
class PolymorphicResponse:
    """
    Structured response with modality and rendering data.
    
    This is the output of the agent that can be rendered in any format.
    The Interface Layer uses this to generate the actual UI component.
    """
    # Core fields
    modality: OutputModality
    timestamp: str
    
    # Content (what to display)
    data: Union[str, Dict[str, Any], List[Any]]  # The actual content
    
    # Rendering hints
    rendering_hints: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Alternative representations (fallbacks)
    text_fallback: Optional[str] = None  # Plain text version
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "modality": self.modality.value,
            "timestamp": self.timestamp,
            "data": self.data,
            "rendering_hints": self.rendering_hints,
            "metadata": self.metadata,
            "text_fallback": self.text_fallback
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class OutputModalityDetector:
    """
    Determines the appropriate output modality based on input context and data type.
    
    This is the "brain" that decides: "Should I render text? A chart? Ghost text?"
    """
    
    def detect_modality(
        self,
        input_context: InputContext,
        data_type: Optional[str] = None,
        input_signal_type: Optional[str] = None,
        urgency: Optional[float] = None
    ) -> OutputModality:
        """
        Detect the appropriate output modality.
        
        Args:
            input_context: Context in which input was received
            data_type: Type of data in the response (e.g., "time_series", "tabular")
            input_signal_type: Type of input signal (e.g., "log_stream", "file_change")
            urgency: Urgency score (0-1)
            
        Returns:
            OutputModality: The detected modality
        """
        # Rule 1: IDE context → Ghost Text or Inline Error
        if input_context == InputContext.IDE:
            if data_type == "error":
                return OutputModality.INLINE_ERROR
            return OutputModality.GHOST_TEXT
        
        # Rule 2: Monitoring context → Dashboard Widget or Chart
        if input_context == InputContext.MONITORING:
            if data_type == "time_series":
                return OutputModality.CHART
            if input_signal_type == "log_stream":
                return OutputModality.DASHBOARD_WIDGET
            return OutputModality.DASHBOARD_WIDGET
        
        # Rule 3: High urgency → Notification
        if urgency and urgency >= 0.8:
            return OutputModality.NOTIFICATION
        
        # Rule 4: Tabular data → Table
        if data_type == "tabular":
            return OutputModality.TABLE
        
        # Rule 5: Time series data → Chart
        if data_type == "time_series":
            return OutputModality.CHART
        
        # Rule 6: Code data → Code Snippet
        if data_type == "code":
            return OutputModality.CODE_SNIPPET
        
        # Rule 7: Structured data → Card
        if data_type == "structured":
            return OutputModality.CARD
        
        # Rule 8: List data → List
        if data_type == "list":
            return OutputModality.LIST
        
        # Default: Text
        return OutputModality.TEXT
    
    def detect_data_type(self, data: Any) -> str:
        """
        Analyze data and determine its type.
        
        Args:
            data: The response data
            
        Returns:
            str: Data type (e.g., "time_series", "tabular", "text")
        """
        if isinstance(data, str):
            # Check if it's code
            if any(keyword in data for keyword in ["def ", "class ", "function ", "import ", "const ", "let "]):
                return "code"
            return "text"
        
        if isinstance(data, list):
            if len(data) > 0:
                # Check if it's time series (list of dicts with timestamp)
                if isinstance(data[0], dict) and any(k in data[0] for k in ["timestamp", "time", "date"]):
                    return "time_series"
                # Check if it's tabular (list of dicts with same keys)
                if isinstance(data[0], dict):
                    return "tabular"
            return "list"
        
        if isinstance(data, dict):
            # Check for specific patterns
            if "error" in data or "error_code" in data:
                return "error"
            if "labels" in data and "values" in data:
                return "chart_data"
            return "structured"
        
        return "unknown"


class PolymorphicOutputEngine:
    """
    Main engine for generating polymorphic outputs.
    
    This takes agent responses and converts them into structured
    PolymorphicResponse objects with appropriate modality.
    """
    
    def __init__(self):
        self.detector = OutputModalityDetector()
    
    def generate_response(
        self,
        data: Any,
        input_context: InputContext,
        input_signal_type: Optional[str] = None,
        urgency: Optional[float] = None,
        rendering_hints: Optional[Dict[str, Any]] = None
    ) -> PolymorphicResponse:
        """
        Generate a polymorphic response from agent output.
        
        Args:
            data: The response data from the agent
            input_context: Context in which input was received
            input_signal_type: Type of input signal
            urgency: Urgency score (0-1)
            rendering_hints: Optional hints for rendering
            
        Returns:
            PolymorphicResponse: Structured response with modality
        """
        # Detect data type
        data_type = self.detector.detect_data_type(data)
        
        # Detect appropriate modality
        modality = self.detector.detect_modality(
            input_context=input_context,
            data_type=data_type,
            input_signal_type=input_signal_type,
            urgency=urgency
        )
        
        # Generate text fallback
        text_fallback = self._generate_text_fallback(data, modality)
        
        # Create response
        response = PolymorphicResponse(
            modality=modality,
            timestamp=datetime.now().isoformat(),
            data=data,
            rendering_hints=rendering_hints or {},
            metadata={
                "data_type": data_type,
                "input_context": input_context.value
            },
            text_fallback=text_fallback
        )
        
        return response
    
    def _generate_text_fallback(self, data: Any, modality: OutputModality) -> str:
        """
        Generate a plain text fallback for any response.
        
        Args:
            data: The response data
            modality: The detected modality
            
        Returns:
            str: Plain text representation
        """
        if isinstance(data, str):
            return data
        
        if isinstance(data, dict):
            if modality == OutputModality.DASHBOARD_WIDGET:
                # Format as key-value pairs
                lines = []
                for key, value in data.items():
                    lines.append(f"{key}: {value}")
                return "\n".join(lines)
            return json.dumps(data, indent=2)
        
        if isinstance(data, list):
            if modality == OutputModality.TABLE:
                # Format as ASCII table
                return self._format_as_ascii_table(data)
            if modality == OutputModality.CHART:
                # Format as text representation
                return self._format_chart_as_text(data)
            return "\n".join(str(item) for item in data)
        
        return str(data)
    
    def _format_as_ascii_table(self, data: List[Dict]) -> str:
        """Format list of dicts as ASCII table."""
        if not data:
            return ""
        
        # Get headers
        headers = list(data[0].keys())
        
        # Calculate column widths
        col_widths = {h: len(h) for h in headers}
        for row in data:
            for h in headers:
                col_widths[h] = max(col_widths[h], len(str(row.get(h, ""))))
        
        # Build table
        lines = []
        
        # Header
        header_line = " | ".join(h.ljust(col_widths[h]) for h in headers)
        lines.append(header_line)
        lines.append("-" * len(header_line))
        
        # Rows
        for row in data:
            row_line = " | ".join(str(row.get(h, "")).ljust(col_widths[h]) for h in headers)
            lines.append(row_line)
        
        return "\n".join(lines)
    
    def _format_chart_as_text(self, data: List[Dict]) -> str:
        """Format chart data as text representation."""
        lines = []
        for item in data[:10]:  # Limit to first 10 items
            if isinstance(item, dict):
                timestamp = item.get("timestamp", item.get("label", ""))
                value = item.get("value", item.get("count", ""))
                lines.append(f"{timestamp}: {value}")
        
        if len(data) > 10:
            lines.append(f"... and {len(data) - 10} more items")
        
        return "\n".join(lines)


# Helper functions for creating specific response types

def create_ghost_text_response(
    suggestion: str,
    cursor_position: Optional[Dict[str, int]] = None
) -> PolymorphicResponse:
    """Create a ghost text response for IDE autocomplete."""
    return PolymorphicResponse(
        modality=OutputModality.GHOST_TEXT,
        timestamp=datetime.now().isoformat(),
        data=suggestion,
        rendering_hints={
            "cursor_position": cursor_position or {"line": 0, "column": 0},
            "style": "ghost"
        },
        text_fallback=suggestion
    )


def create_dashboard_widget_response(
    metric_name: str,
    metric_value: Any,
    trend: Optional[str] = None,
    alert_level: Optional[str] = None
) -> PolymorphicResponse:
    """Create a dashboard widget response for monitoring."""
    data = {
        "metric_name": metric_name,
        "metric_value": metric_value,
        "trend": trend,
        "alert_level": alert_level,
        "timestamp": datetime.now().isoformat()
    }
    
    return PolymorphicResponse(
        modality=OutputModality.DASHBOARD_WIDGET,
        timestamp=datetime.now().isoformat(),
        data=data,
        rendering_hints={
            "widget_type": "metric",
            "alert_level": alert_level or "normal"
        },
        text_fallback=f"{metric_name}: {metric_value} ({trend or 'stable'})"
    )


def create_chart_response(
    chart_type: str,
    data_points: List[Dict[str, Any]],
    title: Optional[str] = None,
    x_axis_label: Optional[str] = None,
    y_axis_label: Optional[str] = None
) -> PolymorphicResponse:
    """Create a chart response for data visualization."""
    data = {
        "chart_type": chart_type,
        "data_points": data_points,
        "title": title,
        "x_axis_label": x_axis_label,
        "y_axis_label": y_axis_label
    }
    
    return PolymorphicResponse(
        modality=OutputModality.CHART,
        timestamp=datetime.now().isoformat(),
        data=data,
        rendering_hints={
            "chart_type": chart_type,
            "interactive": True
        },
        text_fallback=f"{title or 'Chart'} with {len(data_points)} data points"
    )


def create_table_response(
    rows: List[Dict[str, Any]],
    title: Optional[str] = None,
    sortable: bool = True,
    filterable: bool = True
) -> PolymorphicResponse:
    """Create a table response for structured data."""
    return PolymorphicResponse(
        modality=OutputModality.TABLE,
        timestamp=datetime.now().isoformat(),
        data=rows,
        rendering_hints={
            "title": title,
            "sortable": sortable,
            "filterable": filterable
        },
        text_fallback=f"{title or 'Table'} with {len(rows)} rows"
    )


def create_notification_response(
    message: str,
    level: str = "info",
    action: Optional[Dict[str, str]] = None
) -> PolymorphicResponse:
    """Create a notification response for alerts."""
    data = {
        "message": message,
        "level": level,
        "action": action
    }
    
    return PolymorphicResponse(
        modality=OutputModality.NOTIFICATION,
        timestamp=datetime.now().isoformat(),
        data=data,
        rendering_hints={
            "level": level,
            "duration": 5000 if level == "info" else 10000,
            "dismissible": True
        },
        text_fallback=f"[{level.upper()}] {message}"
    )
