# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for Polymorphic Output (Adaptive Rendering)
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
    PolymorphicResponse,
    create_ghost_text_response,
    create_dashboard_widget_response,
    create_chart_response,
    create_table_response,
    create_notification_response
)
from src.generative_ui_engine import (
    GenerativeUIEngine,
    UIComponentGenerator,
    UIComponentSpec,
    ComponentType
)


def test_output_modality_detector():
    """Test output modality detection based on context."""
    print("\n" + "="*60)
    print("TEST: Output Modality Detector")
    print("="*60)
    
    detector = OutputModalityDetector()
    
    # Test IDE context → Ghost Text
    modality = detector.detect_modality(
        input_context=InputContext.IDE,
        data_type="code"
    )
    assert modality == OutputModality.GHOST_TEXT, "IDE context should produce ghost text"
    print("✓ IDE context → Ghost Text")
    
    # Test IDE error → Inline Error
    modality = detector.detect_modality(
        input_context=InputContext.IDE,
        data_type="error"
    )
    assert modality == OutputModality.INLINE_ERROR, "IDE error should produce inline error"
    print("✓ IDE error → Inline Error")
    
    # Test Monitoring context → Dashboard Widget
    modality = detector.detect_modality(
        input_context=InputContext.MONITORING,
        input_signal_type="log_stream"
    )
    assert modality == OutputModality.DASHBOARD_WIDGET, "Monitoring should produce dashboard widget"
    print("✓ Monitoring context → Dashboard Widget")
    
    # Test high urgency → Notification
    modality = detector.detect_modality(
        input_context=InputContext.CHAT,
        urgency=0.9
    )
    assert modality == OutputModality.NOTIFICATION, "High urgency should produce notification"
    print("✓ High urgency → Notification")
    
    # Test tabular data → Table
    modality = detector.detect_modality(
        input_context=InputContext.CHAT,
        data_type="tabular"
    )
    assert modality == OutputModality.TABLE, "Tabular data should produce table"
    print("✓ Tabular data → Table")
    
    # Test time series → Chart
    modality = detector.detect_modality(
        input_context=InputContext.CHAT,
        data_type="time_series"
    )
    assert modality == OutputModality.CHART, "Time series should produce chart"
    print("✓ Time series → Chart")
    
    print("\n✅ All modality detection tests passed")


def test_data_type_detection():
    """Test automatic data type detection."""
    print("\n" + "="*60)
    print("TEST: Data Type Detection")
    print("="*60)
    
    detector = OutputModalityDetector()
    
    # Test text
    data_type = detector.detect_data_type("Hello world")
    assert data_type == "text", "Plain string should be detected as text"
    print("✓ Text detection")
    
    # Test code
    data_type = detector.detect_data_type("def function(): pass")
    assert data_type == "code", "Code string should be detected as code"
    print("✓ Code detection")
    
    # Test tabular data (list of dicts)
    data_type = detector.detect_data_type([
        {"name": "Alice", "age": 30},
        {"name": "Bob", "age": 25}
    ])
    assert data_type == "tabular", "List of dicts should be detected as tabular"
    print("✓ Tabular data detection")
    
    # Test time series (list with timestamps)
    data_type = detector.detect_data_type([
        {"timestamp": "2024-01-01", "value": 100},
        {"timestamp": "2024-01-02", "value": 120}
    ])
    assert data_type == "time_series", "Data with timestamps should be detected as time series"
    print("✓ Time series detection")
    
    # Test structured data (dict)
    data_type = detector.detect_data_type({"metric": "cpu", "value": "80%"})
    assert data_type == "structured", "Dict should be detected as structured"
    print("✓ Structured data detection")
    
    # Test error data
    data_type = detector.detect_data_type({"error": "Connection failed"})
    assert data_type == "error", "Dict with error should be detected as error"
    print("✓ Error data detection")
    
    print("\n✅ All data type detection tests passed")


def test_polymorphic_output_engine():
    """Test polymorphic output generation."""
    print("\n" + "="*60)
    print("TEST: Polymorphic Output Engine")
    print("="*60)
    
    engine = PolymorphicOutputEngine()
    
    # Test 1: Text response in chat context
    response = engine.generate_response(
        data="Hello, how can I help?",
        input_context=InputContext.CHAT
    )
    assert response.modality == OutputModality.TEXT
    assert response.data == "Hello, how can I help?"
    assert response.text_fallback is not None
    print("✓ Text response generation")
    
    # Test 2: Ghost text in IDE context
    response = engine.generate_response(
        data="def calculate(): pass",
        input_context=InputContext.IDE
    )
    assert response.modality == OutputModality.GHOST_TEXT
    print("✓ Ghost text response generation")
    
    # Test 3: Dashboard widget in monitoring context
    response = engine.generate_response(
        data={"metric": "latency", "value": "2000ms"},
        input_context=InputContext.MONITORING,
        input_signal_type="log_stream"
    )
    assert response.modality == OutputModality.DASHBOARD_WIDGET
    print("✓ Dashboard widget response generation")
    
    # Test 4: Table for tabular data
    response = engine.generate_response(
        data=[
            {"id": 1, "name": "Alice"},
            {"id": 2, "name": "Bob"}
        ],
        input_context=InputContext.CHAT
    )
    assert response.modality == OutputModality.TABLE
    assert len(response.data) == 2
    print("✓ Table response generation")
    
    # Test 5: Notification for urgent message
    response = engine.generate_response(
        data="Critical error detected",
        input_context=InputContext.CHAT,
        urgency=0.95
    )
    assert response.modality == OutputModality.NOTIFICATION
    print("✓ Notification response generation")
    
    print("\n✅ All output engine tests passed")


def test_helper_functions():
    """Test helper functions for creating specific responses."""
    print("\n" + "="*60)
    print("TEST: Helper Functions")
    print("="*60)
    
    # Test ghost text helper
    response = create_ghost_text_response(
        suggestion="def function():",
        cursor_position={"line": 10, "column": 5}
    )
    assert response.modality == OutputModality.GHOST_TEXT
    assert response.data == "def function():"
    assert response.rendering_hints["cursor_position"]["line"] == 10
    print("✓ create_ghost_text_response")
    
    # Test dashboard widget helper
    response = create_dashboard_widget_response(
        metric_name="CPU Usage",
        metric_value="85%",
        trend="up",
        alert_level="warning"
    )
    assert response.modality == OutputModality.DASHBOARD_WIDGET
    assert response.data["metric_name"] == "CPU Usage"
    assert response.data["alert_level"] == "warning"
    print("✓ create_dashboard_widget_response")
    
    # Test chart helper
    response = create_chart_response(
        chart_type="line",
        data_points=[{"x": 1, "y": 10}, {"x": 2, "y": 20}],
        title="Test Chart"
    )
    assert response.modality == OutputModality.CHART
    assert response.data["chart_type"] == "line"
    assert len(response.data["data_points"]) == 2
    print("✓ create_chart_response")
    
    # Test table helper
    response = create_table_response(
        rows=[{"id": 1, "name": "Test"}],
        title="Test Table"
    )
    assert response.modality == OutputModality.TABLE
    assert len(response.data) == 1
    print("✓ create_table_response")
    
    # Test notification helper
    response = create_notification_response(
        message="Test notification",
        level="info"
    )
    assert response.modality == OutputModality.NOTIFICATION
    assert response.data["level"] == "info"
    print("✓ create_notification_response")
    
    print("\n✅ All helper function tests passed")


def test_ui_component_generator():
    """Test UI component generation."""
    print("\n" + "="*60)
    print("TEST: UI Component Generator")
    print("="*60)
    
    generator = UIComponentGenerator()
    
    # Test 1: Text component
    response = PolymorphicResponse(
        modality=OutputModality.TEXT,
        timestamp="2024-01-01T00:00:00",
        data="Hello world"
    )
    component = generator.generate_component(response)
    assert component.component_type == "Text"
    assert component.props["content"] == "Hello world"
    print("✓ Text component generation")
    
    # Test 2: Ghost text component
    response = create_ghost_text_response("code suggestion")
    component = generator.generate_component(response)
    assert component.component_type == ComponentType.GHOST_TEXT
    assert component.props["suggestion"] == "code suggestion"
    print("✓ Ghost text component generation")
    
    # Test 3: Dashboard widget component
    response = create_dashboard_widget_response(
        metric_name="Latency",
        metric_value="100ms",
        alert_level="normal"
    )
    component = generator.generate_component(response)
    assert component.component_type == ComponentType.DASHBOARD_WIDGET
    assert component.props["title"] == "Latency"
    assert len(component.children) > 0  # Should have child components
    print("✓ Dashboard widget component generation")
    
    # Test 4: Chart component
    response = create_chart_response(
        chart_type="bar",
        data_points=[{"x": 1, "y": 10}]
    )
    component = generator.generate_component(response)
    assert component.component_type == ComponentType.CHART
    assert component.props["type"] == "bar"
    print("✓ Chart component generation")
    
    # Test 5: Table component
    response = create_table_response(
        rows=[{"id": 1, "name": "Test"}]
    )
    component = generator.generate_component(response)
    assert component.component_type == ComponentType.TABLE
    assert len(component.props["columns"]) > 0
    print("✓ Table component generation")
    
    # Test 6: Notification component
    response = create_notification_response("Alert!", "warning")
    component = generator.generate_component(response)
    assert component.component_type == ComponentType.NOTIFICATION
    assert component.props["level"] == "warning"
    print("✓ Notification component generation")
    
    print("\n✅ All component generator tests passed")


def test_generative_ui_engine():
    """Test the main generative UI engine."""
    print("\n" + "="*60)
    print("TEST: Generative UI Engine")
    print("="*60)
    
    engine = GenerativeUIEngine()
    
    # Test 1: Render to component
    response = create_ghost_text_response("test code")
    component = engine.render(response)
    assert isinstance(component, UIComponentSpec)
    assert component.component_type == ComponentType.GHOST_TEXT
    print("✓ Render to component")
    
    # Test 2: Render to JSON
    json_str = engine.render_to_json(response)
    assert isinstance(json_str, str)
    assert "component_type" in json_str
    assert "GhostText" in json_str
    print("✓ Render to JSON")
    
    # Test 3: Render to React
    react_jsx = engine.render_to_react(response)
    assert isinstance(react_jsx, str)
    assert "<GhostText" in react_jsx or "GhostText" in react_jsx
    print("✓ Render to React")
    
    # Test 4: Batch render
    responses = [
        create_ghost_text_response("code1"),
        create_notification_response("message", "info")
    ]
    components = engine.batch_render(responses)
    assert len(components) == 2
    assert components[0].component_type == ComponentType.GHOST_TEXT
    assert components[1].component_type == ComponentType.NOTIFICATION
    print("✓ Batch render")
    
    print("\n✅ All generative UI engine tests passed")


def test_component_serialization():
    """Test component serialization (to_dict, to_json)."""
    print("\n" + "="*60)
    print("TEST: Component Serialization")
    print("="*60)
    
    # Create a component with nested children
    component = UIComponentSpec(
        component_type="Card",
        props={"title": "Test Card"},
        children=[
            UIComponentSpec(
                component_type="Text",
                props={"content": "Hello"}
            )
        ]
    )
    
    # Test to_dict
    component_dict = component.to_dict()
    assert component_dict["component_type"] == "Card"
    assert len(component_dict["children"]) == 1
    assert component_dict["children"][0]["component_type"] == "Text"
    print("✓ Component to_dict")
    
    # Test to_json
    json_str = component.to_json()
    assert isinstance(json_str, str)
    assert "Card" in json_str
    assert "Text" in json_str
    print("✓ Component to_json")
    
    print("\n✅ All serialization tests passed")


def test_text_fallback_generation():
    """Test text fallback generation for all modalities."""
    print("\n" + "="*60)
    print("TEST: Text Fallback Generation")
    print("="*60)
    
    engine = PolymorphicOutputEngine()
    
    # Test table fallback (should be ASCII table)
    response = engine.generate_response(
        data=[
            {"name": "Alice", "age": 30},
            {"name": "Bob", "age": 25}
        ],
        input_context=InputContext.CHAT
    )
    assert response.text_fallback is not None
    assert "Alice" in response.text_fallback
    assert "|" in response.text_fallback  # ASCII table separator
    print("✓ Table text fallback (ASCII table)")
    
    # Test chart fallback
    response = engine.generate_response(
        data=[
            {"timestamp": "2024-01-01", "value": 100},
            {"timestamp": "2024-01-02", "value": 120}
        ],
        input_context=InputContext.MONITORING
    )
    assert response.text_fallback is not None
    assert "2024-01-01" in response.text_fallback
    print("✓ Chart text fallback")
    
    # Test dashboard widget fallback
    response = engine.generate_response(
        data={"metric": "CPU", "value": "80%"},
        input_context=InputContext.MONITORING,
        input_signal_type="log_stream"
    )
    assert response.text_fallback is not None
    assert "metric" in response.text_fallback or "CPU" in response.text_fallback
    print("✓ Dashboard widget text fallback")
    
    print("\n✅ All text fallback tests passed")


def test_end_to_end_scenarios():
    """Test end-to-end scenarios from input to UI component."""
    print("\n" + "="*60)
    print("TEST: End-to-End Scenarios")
    print("="*60)
    
    output_engine = PolymorphicOutputEngine()
    ui_engine = GenerativeUIEngine()
    
    # Scenario 1: Telemetry → Dashboard Widget
    poly_response = output_engine.generate_response(
        data={"metric": "latency", "value": "2000ms", "alert_level": "critical"},
        input_context=InputContext.MONITORING,
        input_signal_type="log_stream",
        urgency=0.9
    )
    ui_component = ui_engine.render(poly_response)
    
    assert poly_response.modality == OutputModality.DASHBOARD_WIDGET
    assert ui_component.component_type == ComponentType.DASHBOARD_WIDGET
    print("✓ Scenario 1: Telemetry → Dashboard Widget")
    
    # Scenario 2: IDE typing → Ghost Text
    poly_response = output_engine.generate_response(
        data="def calculate_total():",
        input_context=InputContext.IDE
    )
    ui_component = ui_engine.render(poly_response)
    
    assert poly_response.modality == OutputModality.GHOST_TEXT
    assert ui_component.component_type == ComponentType.GHOST_TEXT
    print("✓ Scenario 2: IDE typing → Ghost Text")
    
    # Scenario 3: SQL results → Table
    poly_response = output_engine.generate_response(
        data=[
            {"id": 1, "name": "Alice"},
            {"id": 2, "name": "Bob"}
        ],
        input_context=InputContext.CHAT
    )
    ui_component = ui_engine.render(poly_response)
    
    assert poly_response.modality == OutputModality.TABLE
    assert ui_component.component_type == ComponentType.TABLE
    print("✓ Scenario 3: SQL results → Table")
    
    print("\n✅ All end-to-end scenarios passed")


def main():
    """Run all tests."""
    print("\n╔" + "="*58 + "╗")
    print("║  POLYMORPHIC OUTPUT TESTS - Adaptive Rendering          ║")
    print("╚" + "="*58 + "╝")
    
    try:
        test_output_modality_detector()
        test_data_type_detection()
        test_polymorphic_output_engine()
        test_helper_functions()
        test_ui_component_generator()
        test_generative_ui_engine()
        test_component_serialization()
        test_text_fallback_generation()
        test_end_to_end_scenarios()
        
        print("\n" + "="*60)
        print("  🎉 ALL TESTS PASSED!")
        print("="*60 + "\n")
        
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}\n")
        raise
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}\n")
        raise


if __name__ == "__main__":
    main()
