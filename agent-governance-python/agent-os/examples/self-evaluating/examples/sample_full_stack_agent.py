#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Full Stack Agent Sample

This sample demonstrates a comprehensive agent that integrates multiple modules:
- DoerAgent for task execution
- Universal Signal Bus for omni-channel input
- Polymorphic Output for adaptive rendering
- Generative UI Engine for dynamic UI generation
- Telemetry for event tracking
- Prioritization Framework for context management

This represents a production-ready pattern for building AI agents that can:
1. Accept input from any source (text, files, logs, audio)
2. Execute tasks with learned wisdom
3. Render output in the most appropriate format
4. Track telemetry for continuous learning
"""

import sys
import os
import uuid
from datetime import datetime

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent import DoerAgent
from src.universal_signal_bus import (
    UniversalSignalBus,
    create_signal_from_text,
    create_signal_from_file_change,
    create_signal_from_log
)
from src.polymorphic_output import (
    PolymorphicOutputEngine,
    InputContext
)
from src.generative_ui_engine import GenerativeUIEngine
from src.telemetry import EventStream, TelemetryEvent


class FullStackAgent:
    """
    A comprehensive agent that demonstrates integration of multiple modules.
    
    This agent can:
    - Accept input from any channel (text, files, logs, etc.)
    - Execute tasks using learned wisdom
    - Render output in the most appropriate format
    - Track telemetry for offline learning
    """
    
    def __init__(
        self,
        enable_telemetry: bool = True,
        enable_polymorphic_output: bool = True,
        telemetry_file: str = "fullstack_telemetry.jsonl"
    ):
        """Initialize the full stack agent."""
        # Core execution engine
        self.doer = DoerAgent(enable_telemetry=enable_telemetry)
        
        # Input processing
        self.signal_bus = UniversalSignalBus()
        
        # Output processing
        self.enable_polymorphic_output = enable_polymorphic_output
        if enable_polymorphic_output:
            self.poly_engine = PolymorphicOutputEngine()
            self.ui_engine = GenerativeUIEngine()
        
        # Telemetry
        self.enable_telemetry = enable_telemetry
        if enable_telemetry:
            self.event_stream = EventStream(telemetry_file)
    
    def process_raw_signal(self, raw_signal: dict, verbose: bool = False) -> dict:
        """
        Process a raw signal from any source.
        
        Args:
            raw_signal: Raw input signal (can be text, file change, log, etc.)
            verbose: Whether to print debug information
        
        Returns:
            Dictionary with processed result including polymorphic output
        """
        if verbose:
            print(f"\n{'='*60}")
            print("FULL STACK AGENT - Processing Signal")
            print(f"{'='*60}")
        
        # Step 1: Normalize the input signal
        if verbose:
            print("\n[1] Normalizing input signal...")
        
        context = self.signal_bus.ingest(raw_signal)
        
        if verbose:
            print(f"   Signal Type: {context.signal_type}")
            print(f"   Intent: {context.intent}")
            print(f"   Priority: {context.priority}")
            print(f"   Query: {context.query}")
        
        # Step 2: Execute the task
        if verbose:
            print("\n[2] Executing task with DoerAgent...")
        
        execution_result = self.doer.run(
            query=context.query,
            user_id=context.user_id,
            verbose=False
        )
        
        if verbose:
            print(f"   Success: {execution_result['success']}")
            print(f"   Response: {execution_result['response'][:100]}...")
        
        # Step 3: Generate polymorphic output (if enabled)
        polymorphic_response = None
        ui_component = None
        
        if self.enable_polymorphic_output:
            if verbose:
                print("\n[3] Generating polymorphic output...")
            
            # Determine the input context from the signal
            input_context_map = {
                "text": InputContext.CHAT,
                "file_change": InputContext.IDE,
                "log_stream": InputContext.MONITORING,
                "audio_stream": InputContext.VOICE
            }
            
            input_context = input_context_map.get(
                context.signal_type,
                InputContext.CHAT
            )
            
            # Generate polymorphic response
            polymorphic_response = self.poly_engine.generate_response(
                data=execution_result['response'],
                input_context=input_context,
                input_signal_type=context.signal_type,
                urgency=context.urgency_score
            )
            
            if verbose:
                print(f"   Output Modality: {polymorphic_response.modality}")
                print(f"   Confidence: {polymorphic_response.confidence_score:.2f}")
            
            # Generate UI component spec
            try:
                ui_component = self.ui_engine.render(polymorphic_response)
                if verbose:
                    print(f"   UI Component: {ui_component.component_type}")
            except Exception as e:
                if verbose:
                    print(f"   UI Component generation failed: {e}")
        
        # Step 4: Emit telemetry event (if enabled)
        if self.enable_telemetry:
            event = TelemetryEvent(
                event_type="fullstack_execution",
                timestamp=datetime.now().isoformat(),
                query=context.query,
                agent_response=execution_result['response'],
                success=execution_result['success'],
                metadata={
                    "signal_type": context.signal_type,
                    "input_context": input_context.value if self.enable_polymorphic_output else None,
                    "output_modality": polymorphic_response.modality.value if polymorphic_response else None,
                    "priority": context.priority
                }
            )
            self.event_stream.emit(event)
        
        # Step 5: Return comprehensive result
        return {
            "success": execution_result['success'],
            "raw_response": execution_result['response'],
            "context": {
                "signal_type": context.signal_type,
                "intent": context.intent,
                "priority": context.priority,
                "urgency": context.urgency_score
            },
            "polymorphic_response": polymorphic_response,
            "ui_component": ui_component,
            "execution_metadata": execution_result.get('metadata', {})
        }


def demonstrate_text_input():
    """Demonstrate processing a text input (traditional chat)."""
    print("\n" + "="*60)
    print("DEMO 1: Text Input (Chat)")
    print("="*60)
    
    agent = FullStackAgent()
    
    signal = create_signal_from_text("What is 15 * 24 + 100?")
    result = agent.process_raw_signal(signal, verbose=True)
    
    print("\n[RESULT]")
    print(f"Success: {result['success']}")
    print(f"Response: {result['raw_response']}")
    if result['polymorphic_response']:
        print(f"Output Modality: {result['polymorphic_response'].modality.value}")


def demonstrate_file_change_input():
    """Demonstrate processing a file change event (IDE integration)."""
    print("\n" + "="*60)
    print("DEMO 2: File Change Input (IDE)")
    print("="*60)
    
    agent = FullStackAgent()
    
    signal = create_signal_from_file_change(
        file_path="/workspace/auth/password.py",
        change_type="modified",
        content_before="password = 'admin123'",
        content_after="password = input('Enter password: ')",
        language="python"
    )
    result = agent.process_raw_signal(signal, verbose=True)
    
    print("\n[RESULT]")
    print(f"Signal Detected: {result['context']['signal_type']}")
    print(f"Intent: {result['context']['intent']}")
    print(f"Priority: {result['context']['priority']}")


def demonstrate_log_stream_input():
    """Demonstrate processing a log stream event (monitoring)."""
    print("\n" + "="*60)
    print("DEMO 3: Log Stream Input (Monitoring)")
    print("="*60)
    
    agent = FullStackAgent()
    
    signal = create_signal_from_log(
        level="ERROR",
        message="Database connection pool exhausted. Max connections: 100",
        error_code="500",
        service="user-api",
        stack_trace="ConnectionPoolError at line 145..."
    )
    result = agent.process_raw_signal(signal, verbose=True)
    
    print("\n[RESULT]")
    print(f"Priority: {result['context']['priority']}")
    print(f"Urgency: {result['context']['urgency']:.2f}")
    if result['polymorphic_response']:
        print(f"Suggested Output: {result['polymorphic_response'].modality.value}")


def demonstrate_batch_processing():
    """Demonstrate processing multiple signals in sequence."""
    print("\n" + "="*60)
    print("DEMO 4: Batch Processing Multiple Signals")
    print("="*60)
    
    agent = FullStackAgent()
    
    signals = [
        create_signal_from_text("Calculate the square root of 144"),
        create_signal_from_file_change(
            file_path="/config/database.yaml",
            change_type="modified",
            content_before="max_connections: 50",
            content_after="max_connections: 200"
        ),
        create_signal_from_log(
            level="WARNING",
            message="High memory usage detected: 85%",
            service="worker-node-3"
        )
    ]
    
    results = []
    for i, signal in enumerate(signals, 1):
        print(f"\n--- Processing Signal {i}/3 ---")
        result = agent.process_raw_signal(signal, verbose=False)
        results.append(result)
        print(f"✓ Processed: {result['context']['signal_type']}")
        print(f"  Priority: {result['context']['priority']}")
        print(f"  Success: {result['success']}")
    
    print(f"\n[SUMMARY]")
    print(f"Total Signals Processed: {len(results)}")
    print(f"Successful: {sum(1 for r in results if r['success'])}")
    
    # Show telemetry summary
    if agent.enable_telemetry:
        events = agent.event_stream.read_all()
        print(f"Events Logged: {len(events)}")


def main():
    """Run all demonstrations."""
    print("\n" + "="*60)
    print("FULL STACK AGENT - Comprehensive Integration Sample")
    print("="*60)
    print("\nThis sample demonstrates:")
    print("- Universal Signal Bus (omni-channel input)")
    print("- DoerAgent (task execution)")
    print("- Polymorphic Output (adaptive rendering)")
    print("- Generative UI Engine (dynamic UI)")
    print("- Telemetry (event tracking)")
    
    try:
        demonstrate_text_input()
        demonstrate_file_change_input()
        demonstrate_log_stream_input()
        demonstrate_batch_processing()
        
        print("\n" + "="*60)
        print("All demonstrations completed successfully!")
        print("="*60)
        print("\nKey Takeaways:")
        print("1. The agent accepts input from ANY source")
        print("2. Output adapts to the context automatically")
        print("3. All interactions are logged for learning")
        print("4. The system is modular and extensible")
        print("\nThis is a production-ready pattern for building")
        print("intelligent, adaptive AI agents.")
        
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
