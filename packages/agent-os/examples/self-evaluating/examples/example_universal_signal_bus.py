# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example: Universal Signal Bus (Omni-Channel Ingestion)

Demonstrates the "Input Agnostic" architecture where the agent
can accept signals from ANY source - not just text queries.

The Interface Layer sits above the Agent and normalizes wild, unstructured
signals into a standard Context Object.
"""

import sys
import os

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.universal_signal_bus import (
    UniversalSignalBus,
    SignalType,
    create_signal_from_text,
    create_signal_from_file_change,
    create_signal_from_log,
    create_signal_from_audio
)


def print_context_object(context, title: str):
    """Helper to print a context object in a readable format."""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")
    print(f"Signal Type:    {context.signal_type.value}")
    print(f"Timestamp:      {context.timestamp}")
    print(f"Intent:         {context.intent}")
    print(f"Query:          {context.query}")
    print(f"Priority:       {context.priority.upper()}")
    print(f"Urgency Score:  {context.urgency_score:.2f}")
    print(f"User ID:        {context.user_id or 'N/A'}")
    print(f"Source:         {context.source_id or 'N/A'}")
    
    if context.context:
        print("\nContext Data:")
        for key, value in context.context.items():
            if isinstance(value, str) and len(value) > 100:
                value = value[:100] + "..."
            print(f"  {key}: {value}")
    print(f"{'='*70}")


def demo_text_input():
    """Demo 1: Traditional text input (backward compatibility)."""
    print("\n" + "🔷"*35)
    print("DEMO 1: Traditional Text Input")
    print("🔷"*35)
    print("\nThe Old World: 'Go to the website, find the text box, and explain your problem.'")
    print("This still works, but now it's just ONE of many input channels.")
    
    bus = UniversalSignalBus()
    
    # Simple text query
    signal = create_signal_from_text(
        text="What is 10 + 20?",
        user_id="user123"
    )
    
    context = bus.ingest(signal)
    print_context_object(context, "Text Input Signal → Normalized Context")


def demo_file_change_input():
    """Demo 2: File change events from VS Code."""
    print("\n" + "🔷"*35)
    print("DEMO 2: Passive File Change Input")
    print("🔷"*35)
    print("\nThe 'Passive' Input: The user is coding in VS Code.")
    print("The signal is the File Change Event.")
    print("NO text box. NO explicit query. Just WATCH the code.")
    
    bus = UniversalSignalBus()
    
    # File modification
    signal = create_signal_from_file_change(
        file_path="/workspace/auth/security.py",
        change_type="modified",
        content_before="password = input('Enter password:')\nif password == 'admin123':",
        content_after="password = input('Enter password:')\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())\nif bcrypt.checkpw(password.encode(), hashed):",
        language="python",
        project="auth-service",
        user_id="developer123"
    )
    
    context = bus.ingest(signal)
    print_context_object(context, "File Change Event → Normalized Context")
    
    print("\n💡 Agent can now:")
    print("  - Analyze the security improvement")
    print("  - Suggest additional hardening")
    print("  - Update documentation automatically")
    print("  - Generate tests for the new code")


def demo_log_stream_input():
    """Demo 3: System log streams."""
    print("\n" + "🔷"*35)
    print("DEMO 3: System Log Stream Input")
    print("🔷"*35)
    print("\nThe 'System' Input: The server is throwing 500 errors.")
    print("The signal is the Log Stream.")
    print("NO human intervention. The SYSTEM speaks directly to the agent.")
    
    bus = UniversalSignalBus()
    
    # Critical server error
    signal = create_signal_from_log(
        level="ERROR",
        message="Internal Server Error: Database connection pool exhausted after 30s timeout",
        error_code="500",
        stack_trace="at DatabasePool.acquire() line 45\nat UserService.fetchUser() line 123",
        service="user-api",
        host="prod-server-03"
    )
    
    context = bus.ingest(signal)
    print_context_object(context, "Log Stream Event → Normalized Context")
    
    print("\n💡 Agent can now:")
    print("  - Diagnose the connection pool issue")
    print("  - Suggest scaling the pool size")
    print("  - Create incident report")
    print("  - Alert on-call engineer")


def demo_audio_stream_input():
    """Demo 4: Audio/voice streams."""
    print("\n" + "🔷"*35)
    print("DEMO 4: Audio Stream Input")
    print("🔷"*35)
    print("\nThe 'Audio' Input: The user is in a meeting.")
    print("The signal is the Voice Stream.")
    print("NO typing. NO text box. Just TALKING.")
    
    bus = UniversalSignalBus()
    
    # Voice input from meeting
    signal = create_signal_from_audio(
        transcript="Hey team, we're seeing critical performance issues in production. "
                  "The dashboard shows response times spiking to 5 seconds. "
                  "Can someone help me investigate this urgently?",
        speaker_id="john_doe",
        duration_seconds=15.2,
        language="en",
        confidence=0.95
    )
    
    context = bus.ingest(signal)
    print_context_object(context, "Audio Stream Event → Normalized Context")
    
    print("\n💡 Agent can now:")
    print("  - Analyze production metrics")
    print("  - Identify performance bottlenecks")
    print("  - Create Slack alert for team")
    print("  - Generate investigation runbook")


def demo_mixed_signals():
    """Demo 5: Multiple signal types in sequence."""
    print("\n" + "🔷"*35)
    print("DEMO 5: Mixed Signal Types (Omni-Channel)")
    print("🔷"*35)
    print("\nThe FUTURE: Signals come from EVERYWHERE.")
    print("The agent doesn't care HOW it gets the input.")
    print("Text, Files, Logs, Audio - all normalized to the same Context Object.")
    
    bus = UniversalSignalBus()
    
    # Ingest multiple different signal types
    signals = [
        create_signal_from_text("How do I reset my password?", user_id="user1"),
        create_signal_from_file_change("/src/auth.js", "modified", "", "// TODO: Fix login bug"),
        create_signal_from_log("WARNING", "High memory usage: 85%", service="backend"),
        create_signal_from_audio("Can you summarize the meeting notes?", speaker_id="user2")
    ]
    
    contexts = bus.batch_ingest(signals)
    
    print(f"\n✅ Ingested {len(contexts)} signals from {len(set(c.signal_type for c in contexts))} different types:")
    for i, context in enumerate(contexts, 1):
        print(f"\n  Signal {i}:")
        print(f"    Type:     {context.signal_type.value}")
        print(f"    Intent:   {context.intent}")
        print(f"    Query:    {context.query[:60]}...")
        print(f"    Priority: {context.priority}")


def demo_auto_detection():
    """Demo 6: Automatic signal type detection."""
    print("\n" + "🔷"*35)
    print("DEMO 6: Automatic Signal Type Detection")
    print("🔷"*35)
    print("\nThe bus is SMART. It auto-detects signal types.")
    print("You don't have to tell it 'this is a log' or 'this is audio'.")
    
    bus = UniversalSignalBus()
    
    # Send raw signals without specifying type - let the bus figure it out
    raw_signals = [
        {"text": "Hello agent"},  # Auto-detects as TEXT
        {"file_path": "/app.py", "change_type": "created"},  # Auto-detects as FILE_CHANGE
        {"level": "ERROR", "message": "Disk full"},  # Auto-detects as LOG_STREAM
        {"transcript": "Start recording"}  # Auto-detects as AUDIO_STREAM
    ]
    
    print("\n📥 Ingesting raw signals (no type specified)...")
    
    for i, raw_signal in enumerate(raw_signals, 1):
        context = bus.ingest(raw_signal)  # Type auto-detected!
        print(f"\n  Signal {i}: {list(raw_signal.keys())[0]} → {context.signal_type.value} ✓")


def demo_agent_integration():
    """Demo 7: Integration with DoerAgent."""
    print("\n" + "🔷"*35)
    print("DEMO 7: Agent Integration (Input Agnostic)")
    print("🔷"*35)
    print("\nThe agent is now INPUT AGNOSTIC.")
    print("It accepts a Context Object, not a string.")
    print("The source doesn't matter - text, file, log, audio - all the same.")
    
    bus = UniversalSignalBus()
    
    # Different signal sources
    text_signal = create_signal_from_text("Calculate 10 + 20")
    log_signal = create_signal_from_log("ERROR", "Failed calculation: division by zero")
    
    # Normalize both
    text_context = bus.ingest(text_signal)
    log_context = bus.ingest(log_signal)
    
    print("\n📤 Both signals normalized to ContextObject:")
    print(f"\n  Text Query → ContextObject:")
    print(f"    query: '{text_context.query}'")
    print(f"    intent: '{text_context.intent}'")
    
    print(f"\n  Log Entry → ContextObject:")
    print(f"    query: '{log_context.query}'")
    print(f"    intent: '{log_context.intent}'")
    
    print("\n✨ The agent receives the SAME interface (ContextObject) regardless of source.")
    print("   This is the 'USB Port' moment for AI input.")


def demo_startup_opportunity():
    """Demo 8: The startup opportunity."""
    print("\n" + "🔷"*35)
    print("DEMO 8: 🚀 Startup Opportunity")
    print("🔷"*35)
    print("\n💡 THE OPPORTUNITY:")
    print("   Build a managed service (API) that accepts ANY stream:")
    print("   - Audio streams")
    print("   - Log streams")
    print("   - Clickstream")
    print("   - DOM events")
    print("   - File changes")
    print("   - System metrics")
    print("")
    print("   Real-time transcribe/normalize them into JSON 'Intent Objects'")
    print("   for AI agents.")
    print("")
    print("   Don't build the Agent; build the EARS that let the Agent listen")
    print("   to the world.")
    print("")
    print("   This is 'Twilio for AI Input' - the infrastructure layer that")
    print("   connects the messy real world to the clean AI interface.")
    
    bus = UniversalSignalBus()
    
    print("\n📊 Example API Endpoint:")
    print("   POST /api/v1/ingest")
    print("   {")
    print('     "stream_type": "audio|logs|files|metrics",')
    print('     "data": { ... }')
    print("   }")
    print("")
    print("   Response:")
    print("   {")
    print('     "context_object": {')
    print('       "intent": "server_error_500",')
    print('       "query": "[ERROR] Error 500: Internal Server Error",')
    print('       "priority": "critical",')
    print('       "urgency_score": 0.9')
    print("     }")
    print("   }")
    
    # Demonstrate what the API would do
    sample_log = create_signal_from_log(
        level="CRITICAL",
        message="Payment service down - unable to process transactions",
        error_code="500",
        service="payment-api"
    )
    
    context = bus.ingest(sample_log)
    
    print("\n✅ Sample Normalized Output:")
    print(context.to_json())


def main():
    """Run all demonstrations."""
    print("\n" + "="*70)
    print("  UNIVERSAL SIGNAL BUS - OMNI-CHANNEL INGESTION")
    print("  The 'Input Agnostic' Architecture for AI Agents")
    print("="*70)
    print("\nThe Old World: 'Go to the website, find the text box, explain your problem.'")
    print("The New World: The agent LISTENS to everything - files, logs, voice, systems.")
    print("")
    print("The entry point is NOT a UI component; it is a SIGNAL NORMALIZER.")
    
    # Run demonstrations
    demo_text_input()
    demo_file_change_input()
    demo_log_stream_input()
    demo_audio_stream_input()
    demo_mixed_signals()
    demo_auto_detection()
    demo_agent_integration()
    demo_startup_opportunity()
    
    # Final summary
    print("\n" + "="*70)
    print("  KEY INSIGHTS")
    print("="*70)
    print("\n1. The entry point is a SIGNAL NORMALIZER, not a UI component.")
    print("2. The agent is INPUT AGNOSTIC - it accepts ContextObjects.")
    print("3. ANY stream (audio, logs, files, metrics) can be normalized.")
    print("4. The Interface Layer sits ABOVE the agent, handling ingestion.")
    print("5. This enables 'Passive' (files), 'System' (logs), and 'Audio' inputs.")
    print("\n🚀 STARTUP OPPORTUNITY:")
    print("   Build the 'Universal Signal Bus' as a managed API service.")
    print("   Don't build the Agent; build the EARS.")
    print("   This is the infrastructure layer that connects the messy world")
    print("   to the clean AI interface.")
    print("\n" + "="*70)


if __name__ == "__main__":
    main()
