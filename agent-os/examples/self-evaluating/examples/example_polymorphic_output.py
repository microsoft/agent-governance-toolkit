# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example: Polymorphic Output (Adaptive Rendering)

This demonstrates the "Just-in-Time UI" architecture where the agent
determines the response modality based on the input context.

Scenario A (Data): Backend Telemetry Stream → Dashboard Widget
Scenario B (Code): User typing in IDE → Ghost Text
Scenario C (Analysis): SQL results → Interactive Table
"""

import sys
import os

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.polymorphic_output import (
    PolymorphicOutputEngine,
    OutputModalityDetector,
    InputContext,
    OutputModality,
    create_ghost_text_response,
    create_dashboard_widget_response,
    create_chart_response,
    create_table_response,
    create_notification_response
)
from src.generative_ui_engine import GenerativeUIEngine
from datetime import datetime, timedelta
import random


def print_section(title: str):
    """Print a section header."""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)


def print_response(poly_response, ui_component):
    """Print polymorphic response and UI component."""
    print(f"\n📊 Modality: {poly_response.modality.value}")
    print(f"⏰ Timestamp: {poly_response.timestamp}")
    print(f"\n💾 Data:")
    if isinstance(poly_response.data, str):
        print(f"  {poly_response.data[:200]}...")
    else:
        import json
        print(json.dumps(poly_response.data, indent=2)[:500] + "...")
    
    print(f"\n🎨 UI Component: {ui_component.component_type}")
    print(f"   Props: {list(ui_component.props.keys())}")
    
    print(f"\n📝 Text Fallback:")
    print(f"  {poly_response.text_fallback[:200]}...")


def scenario_a_telemetry_to_widget():
    """
    Scenario A: Backend Telemetry Stream → Dashboard Widget
    
    Input: System monitoring detects latency spike
    Expected: Dashboard widget with red alert (not a chat message)
    """
    print_section("Scenario A: Backend Telemetry → Dashboard Widget")
    
    print("\n🔍 Context:")
    print("  - Input: Backend telemetry stream")
    print("  - Event: Latency spike detected (500ms → 2000ms)")
    print("  - Expected: Dashboard widget with visual alert")
    print("  - NOT: Text chat message saying 'Latency is high'")
    
    # Simulate telemetry data
    telemetry_data = {
        "metric_name": "API Latency",
        "metric_value": "2000ms",
        "trend": "up",
        "alert_level": "critical",
        "baseline": "500ms",
        "spike_percentage": "300%"
    }
    
    # Generate polymorphic response
    engine = PolymorphicOutputEngine()
    response = engine.generate_response(
        data=telemetry_data,
        input_context=InputContext.MONITORING,
        input_signal_type="log_stream",
        urgency=0.9
    )
    
    # Generate UI component
    ui_engine = GenerativeUIEngine()
    ui_component = ui_engine.render(response)
    
    print_response(response, ui_component)
    
    print("\n✅ Result: Agent generated a DASHBOARD WIDGET, not text")
    print("   The red line on the graph draws itself. No chat needed.")


def scenario_b_ide_to_ghost_text():
    """
    Scenario B: User typing in IDE → Ghost Text
    
    Input: User types "def calculate_" in Python file
    Expected: Ghost text completion (not a popup)
    """
    print_section("Scenario B: IDE Context → Ghost Text")
    
    print("\n🔍 Context:")
    print("  - Input: User typing in VS Code")
    print("  - File: analytics.py")
    print("  - Cursor: After 'def calculate_'")
    print("  - Expected: Inline ghost text suggestion")
    print("  - NOT: Popup window or chat response")
    
    # Simulate IDE context
    code_suggestion = "total(items: List[float]) -> float:\n    return sum(items)"
    
    # Create ghost text response
    response = create_ghost_text_response(
        suggestion=code_suggestion,
        cursor_position={"line": 42, "column": 16}
    )
    
    # Generate UI component
    ui_engine = GenerativeUIEngine()
    ui_component = ui_engine.render(response)
    
    print_response(response, ui_component)
    
    print("\n✅ Result: Agent generated GHOST TEXT, not a popup")
    print("   The suggestion appears inline. No interruption.")


def scenario_c_sql_results_to_table():
    """
    Scenario C: SQL Query Results → Interactive Table
    
    Input: User runs SQL query
    Expected: Sortable, filterable table (not text dump)
    """
    print_section("Scenario C: SQL Results → Interactive Table")
    
    print("\n🔍 Context:")
    print("  - Input: SQL query results")
    print("  - Query: SELECT * FROM users ORDER BY created_at DESC LIMIT 10")
    print("  - Expected: Interactive table component")
    print("  - NOT: Text dump of rows")
    
    # Simulate SQL results
    sql_results = [
        {"id": 1001, "username": "alice", "email": "alice@example.com", "created_at": "2024-01-15"},
        {"id": 1002, "username": "bob", "email": "bob@example.com", "created_at": "2024-01-14"},
        {"id": 1003, "username": "charlie", "email": "charlie@example.com", "created_at": "2024-01-13"},
        {"id": 1004, "username": "diana", "email": "diana@example.com", "created_at": "2024-01-12"},
        {"id": 1005, "username": "eve", "email": "eve@example.com", "created_at": "2024-01-11"},
    ]
    
    # Create table response
    response = create_table_response(
        rows=sql_results,
        title="Users Table",
        sortable=True,
        filterable=True
    )
    
    # Generate UI component
    ui_engine = GenerativeUIEngine()
    ui_component = ui_engine.render(response)
    
    print_response(response, ui_component)
    
    print("\n✅ Result: Agent generated an INTERACTIVE TABLE, not text")
    print("   Users can sort, filter, and explore. No manual parsing.")


def scenario_d_time_series_to_chart():
    """
    Scenario D: Time Series Data → Chart
    
    Input: Performance metrics over time
    Expected: Line chart visualization
    """
    print_section("Scenario D: Time Series Data → Line Chart")
    
    print("\n🔍 Context:")
    print("  - Input: Performance metrics (last 24 hours)")
    print("  - Data Type: Time series")
    print("  - Expected: Line chart with trend visualization")
    print("  - NOT: List of numbers")
    
    # Generate time series data
    base_time = datetime.now()
    data_points = []
    
    for i in range(24):
        timestamp = (base_time - timedelta(hours=23-i)).strftime("%H:%M")
        value = 100 + random.randint(-30, 30) + (i * 2)  # Upward trend with noise
        data_points.append({
            "timestamp": timestamp,
            "value": value
        })
    
    # Create chart response
    response = create_chart_response(
        chart_type="line",
        data_points=data_points,
        title="Request Rate (Last 24 Hours)",
        x_axis_label="Time",
        y_axis_label="Requests/min"
    )
    
    # Generate UI component
    ui_engine = GenerativeUIEngine()
    ui_component = ui_engine.render(response)
    
    print_response(response, ui_component)
    
    print("\n✅ Result: Agent generated a LINE CHART, not a list")
    print("   The trend is immediately visible. No manual plotting.")


def scenario_e_critical_alert_to_notification():
    """
    Scenario E: Critical Error → Notification
    
    Input: System error with high urgency
    Expected: Toast notification (not buried in logs)
    """
    print_section("Scenario E: Critical Error → Toast Notification")
    
    print("\n🔍 Context:")
    print("  - Input: Database connection failure")
    print("  - Urgency: Critical (0.95)")
    print("  - Expected: Prominent toast notification")
    print("  - NOT: Log entry or chat message")
    
    # Create notification response
    response = create_notification_response(
        message="Database connection lost. Attempting reconnection...",
        level="error",
        action={"label": "View Details", "handler": "openErrorLog"}
    )
    
    # Generate UI component
    ui_engine = GenerativeUIEngine()
    ui_component = ui_engine.render(response)
    
    print_response(response, ui_component)
    
    print("\n✅ Result: Agent generated a NOTIFICATION, not a log entry")
    print("   User sees the alert immediately. Actionable.")


def scenario_f_automatic_modality_detection():
    """
    Scenario F: Automatic Modality Detection
    
    Shows how the engine automatically chooses the right modality
    based on context and data type.
    """
    print_section("Scenario F: Automatic Modality Detection")
    
    print("\n🔍 Testing Automatic Modality Detection:")
    
    engine = PolymorphicOutputEngine()
    detector = OutputModalityDetector()
    
    test_cases = [
        {
            "context": InputContext.IDE,
            "data": "function calculateTotal() { ... }",
            "expected": OutputModality.GHOST_TEXT
        },
        {
            "context": InputContext.MONITORING,
            "data": {"metric": "cpu_usage", "value": "85%"},
            "signal_type": "log_stream",
            "expected": OutputModality.DASHBOARD_WIDGET
        },
        {
            "context": InputContext.CHAT,
            "data": [
                {"name": "Alice", "age": 30},
                {"name": "Bob", "age": 25}
            ],
            "expected": OutputModality.TABLE
        },
        {
            "context": InputContext.MONITORING,
            "data": "Error message",
            "urgency": 0.9,
            "expected": OutputModality.NOTIFICATION
        }
    ]
    
    for i, test in enumerate(test_cases, 1):
        print(f"\n  Test {i}:")
        print(f"    Context: {test['context'].value}")
        print(f"    Data Type: {detector.detect_data_type(test['data'])}")
        
        response = engine.generate_response(
            data=test['data'],
            input_context=test['context'],
            input_signal_type=test.get('signal_type'),
            urgency=test.get('urgency')
        )
        
        print(f"    Detected Modality: {response.modality.value}")
        print(f"    Expected: {test['expected'].value}")
        print(f"    ✅ Match!" if response.modality == test['expected'] else "    ❌ Mismatch")


def scenario_g_react_code_generation():
    """
    Scenario G: React Component Code Generation
    
    Shows how the engine can generate actual React JSX code.
    """
    print_section("Scenario G: React Component Code Generation")
    
    print("\n🔍 Generating React JSX from Agent Response:")
    
    # Create a chart response
    response = create_chart_response(
        chart_type="bar",
        data_points=[
            {"label": "Jan", "value": 65},
            {"label": "Feb", "value": 78},
            {"label": "Mar", "value": 90}
        ],
        title="Monthly Sales"
    )
    
    # Generate React JSX
    ui_engine = GenerativeUIEngine()
    react_jsx = ui_engine.render_to_react(response)
    
    print("\n📝 Generated React JSX:")
    print(react_jsx)
    
    print("\n✅ Result: Drop this JSX into your React app")
    print("   No manual component creation needed.")


def startup_opportunity_demo():
    """
    Demo: The Startup Opportunity
    
    Show how this becomes a product/SDK.
    """
    print_section("🚀 Startup Opportunity: Generative UI Engine SDK")
    
    print("""
    The Problem:
      Developers hard-code every screen, form, and chart.
      AI agents only return text. Devs manually parse and render.
    
    The Solution:
      An SDK that takes AI output (JSON) and renders the perfect component.
      
    The Integration (3 lines of code):
      
      ```python
      from generative_ui_sdk import GenerativeUIEngine
      
      engine = GenerativeUIEngine()
      ui_component = engine.render(agent_response)
      app.display(ui_component)
      ```
    
    The Result:
      ✅ Tables render themselves from SQL results
      ✅ Charts appear from time series data
      ✅ Notifications pop for critical alerts
      ✅ Ghost text for IDE completions
      ✅ All automatic. No manual UI code.
    
    The Market:
      - Every AI app needs UI rendering
      - Every dashboard needs adaptive components
      - Every IDE needs intelligent suggestions
      
    The Revenue Model:
      - $99/month per developer
      - Enterprise: $10k/year unlimited
      - Open source core + premium components
    
    Stop hard-coding screens. Build the engine that dreams them up.
    """)


def main():
    """Run all scenarios."""
    print("\n")
    print("╔" + "="*68 + "╗")
    print("║" + " "*10 + "POLYMORPHIC OUTPUT - ADAPTIVE RENDERING" + " "*18 + "║")
    print("╚" + "="*68 + "╝")
    
    print("""
    The Old World: "The AI always replies with text."
    The New World: If input can be anything, output must be anything.
    
    The system determines response modality based on input context.
    The Agent generates the Data. The Interface Layer generates the View.
    This is "Just-in-Time UI."
    """)
    
    # Run scenarios
    scenario_a_telemetry_to_widget()
    scenario_b_ide_to_ghost_text()
    scenario_c_sql_results_to_table()
    scenario_d_time_series_to_chart()
    scenario_e_critical_alert_to_notification()
    scenario_f_automatic_modality_detection()
    scenario_g_react_code_generation()
    
    # Show startup opportunity
    startup_opportunity_demo()
    
    print("\n" + "="*70)
    print("  ✨ All scenarios completed successfully!")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()
