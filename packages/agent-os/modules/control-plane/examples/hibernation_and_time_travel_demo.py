# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example: Agent Hibernation and Time-Travel Debugging

This demonstrates the two new features:
1. Agent Hibernation - "Serverless Agents" that save state to disk when idle
2. Time-Travel Debugging - Replay agent history for debugging and analysis
"""

from agent_control_plane import (
    AgentControlPlane,
    create_standard_agent,
    HibernationConfig,
    HibernationFormat,
    TimeTravelConfig,
)
from agent_control_plane.agent_kernel import ActionType
from agent_control_plane.flight_recorder import FlightRecorder
import time
from datetime import datetime


def example_agent_hibernation():
    """
    Demonstrate Agent Hibernation feature.
    
    Problem: Agents sitting idle in memory cost money or RAM.
    Solution: Serialize agent state to disk and wake only when needed.
    Result: "Serverless Agents" - Scale by Subtraction.
    """
    print("=" * 60)
    print("EXAMPLE 1: Agent Hibernation (Serverless Agents)")
    print("=" * 60)
    print()
    
    # Create control plane with hibernation enabled
    hibernation_config = HibernationConfig(
        enabled=True,
        idle_timeout_seconds=5,  # Short timeout for demo
        storage_path="/tmp/agent_hibernation_demo",
        format=HibernationFormat.JSON  # Use JSON for human-readable state files
    )
    
    control_plane = AgentControlPlane(
        enable_hibernation=True,
        hibernation_config=hibernation_config
    )
    
    # Create an agent
    agent_context = create_standard_agent(control_plane, "demo-agent-001")
    print(f"✓ Created agent: {agent_context.agent_id}")
    print(f"  Session ID: {agent_context.session_id}")
    print()
    
    # Execute some actions
    print("Executing actions...")
    result1 = control_plane.execute_action(
        agent_context,
        ActionType.FILE_READ,
        {"path": "/data/sample.txt"}
    )
    print(f"  • File read: {result1['success']}")
    
    result2 = control_plane.execute_action(
        agent_context,
        ActionType.API_CALL,
        {"url": "https://api.example.com/data", "method": "GET"}
    )
    print(f"  • API call: {result2['success']}")
    print()
    
    # Record activity
    control_plane.record_agent_activity(agent_context.agent_id)
    
    # Wait for agent to become idle
    print(f"Waiting {hibernation_config.idle_timeout_seconds} seconds for agent to become idle...")
    time.sleep(hibernation_config.idle_timeout_seconds + 1)
    print()
    
    # Hibernate the agent
    print("Hibernating idle agent...")
    metadata = control_plane.hibernate_agent(
        agent_context.agent_id,
        agent_context,
        caas_pointer="context://agent-001/session-123",  # Example caas pointer
        additional_state={"custom_data": "example"}
    )
    
    print(f"✓ Agent hibernated successfully")
    print(f"  • State file: {metadata.state_file_path}")
    print(f"  • Size: {metadata.state_size_bytes} bytes")
    print(f"  • Format: {metadata.format.value}")
    print(f"  • Context pointer (caas): {metadata.context_pointer}")
    print()
    
    # Check hibernation status
    is_hibernated = control_plane.is_agent_hibernated(agent_context.agent_id)
    print(f"✓ Agent hibernation status: {is_hibernated}")
    print()
    
    # Get hibernation statistics
    stats = control_plane.get_hibernation_statistics()
    print("Hibernation Statistics:")
    print(f"  • Total hibernated agents: {stats['total_hibernated_agents']}")
    print(f"  • Total state size: {stats['total_state_size_mb']:.2f} MB")
    print(f"  • Storage path: {stats['storage_path']}")
    print()
    
    # Simulate receiving a message for the hibernated agent
    print("Simulating incoming message for hibernated agent...")
    print("Waking agent from hibernation...")
    
    restored_state = control_plane.wake_agent(agent_context.agent_id)
    print(f"✓ Agent woken successfully")
    print(f"  • Session ID: {restored_state['session_id']}")
    print(f"  • Created at: {restored_state['created_at']}")
    print(f"  • Context pointer (caas): {restored_state['caas_pointer']}")
    print(f"  • Custom data: {restored_state['additional_state']}")
    print()
    
    # Check hibernation status again
    is_hibernated = control_plane.is_agent_hibernated(agent_context.agent_id)
    print(f"✓ Agent hibernation status after wake: {is_hibernated}")
    print()
    
    print("✅ Agent Hibernation demo complete!")
    print("   Agents can now be 'serverless' - no idle cost!")
    print()


def example_time_travel_debugging():
    """
    Demonstrate Time-Travel Debugging feature.
    
    Problem: Need to understand and debug agent behavior after the fact.
    Solution: Replay agent history from audit logs (amb + emk).
    Result: Complete observability - "Re-run the last 5 minutes exactly as it happened."
    """
    print("=" * 60)
    print("EXAMPLE 2: Time-Travel Debugging")
    print("=" * 60)
    print()
    
    # Create control plane with time-travel enabled
    flight_recorder = FlightRecorder(db_path="/tmp/time_travel_demo.db")
    
    time_travel_config = TimeTravelConfig(
        enabled=True,
        enable_state_snapshots=True,
        snapshot_interval_seconds=10
    )
    
    control_plane = AgentControlPlane(
        enable_time_travel=True,
        time_travel_config=time_travel_config
    )
    
    # Attach FlightRecorder to kernel for audit logging
    control_plane.kernel.audit_logger = flight_recorder
    control_plane.time_travel_debugger.flight_recorder = flight_recorder
    
    # Create an agent
    agent_context = create_standard_agent(control_plane, "debug-agent-001")
    print(f"✓ Created agent: {agent_context.agent_id}")
    print()
    
    # Execute a series of actions (simulating agent behavior)
    print("Executing actions to build history...")
    
    actions = [
        ("File read", ActionType.FILE_READ, {"path": "/data/config.json"}),
        ("API call", ActionType.API_CALL, {"url": "https://api.example.com/users", "method": "GET"}),
        ("Database query", ActionType.DATABASE_QUERY, {"query": "SELECT * FROM users"}),
        ("File write", ActionType.FILE_WRITE, {"path": "/data/output.txt", "content": "Result data"}),
    ]
    
    for idx, (name, action_type, params) in enumerate(actions, 1):
        result = control_plane.execute_action(agent_context, action_type, params)
        print(f"  {idx}. {name}: {result['success']}")
        
        # Capture state snapshot after each action
        control_plane.capture_agent_state_snapshot(
            agent_context.agent_id,
            agent_context,
            metadata={"action": name, "step": idx}
        )
        
        time.sleep(0.5)  # Small delay between actions
    
    print()
    
    # Now demonstrate time-travel debugging
    print("Time-Travel Debugging: Replaying last 1 minute of agent history...")
    print()
    
    # Create a replay session
    replay_session = control_plane.replay_agent_history(
        agent_context.agent_id,
        minutes=1
    )
    
    print(f"✓ Created replay session: {replay_session.session_id}")
    print(f"  • Agent: {replay_session.agent_id}")
    print(f"  • Time range: {replay_session.start_time} to {replay_session.end_time}")
    print(f"  • Total events: {len(replay_session.events)}")
    print(f"  • Mode: {replay_session.mode.value}")
    print()
    
    # Get replay summary
    summary = control_plane.get_replay_summary(replay_session.session_id)
    print("Replay Summary:")
    print(f"  • Duration: {summary['time_range']['duration_seconds']:.1f} seconds")
    print(f"  • Total events: {summary['total_events']}")
    print(f"  • Event breakdown:")
    for event_type, count in summary['event_type_breakdown'].items():
        print(f"    - {event_type}: {count}")
    print()
    
    # Replay events with a callback
    print("Replaying events:")
    
    def replay_callback(event):
        """Callback function called for each replayed event"""
        print(f"  [{event.timestamp.strftime('%H:%M:%S')}] {event.event_type.value}")
        print(f"    Tool: {event.data.get('tool_name')}")
        print(f"    Verdict: {event.data.get('policy_verdict')}")
        if event.data.get('result'):
            print(f"    Result: {event.data.get('result')[:50]}...")
        print()
    
    # Replay the history
    from agent_control_plane.time_travel_debugger import ReplayMode
    
    # Create a step-by-step replay session
    step_session = control_plane.time_travel_debugger.create_replay_session(
        agent_context.agent_id,
        replay_session.start_time,
        replay_session.end_time,
        mode=ReplayMode.STEP_BY_STEP
    )
    
    print(f"Step-by-step replay (press Enter to advance):")
    print()
    
    # Replay first 3 events step by step
    for i in range(min(3, len(step_session.events))):
        event = control_plane.time_travel_debugger.next_step(step_session.session_id)
        if event:
            print(f"Step {i+1}:")
            replay_callback(event)
            # In a real scenario, you'd wait for user input here
            # input("Press Enter for next step...")
    
    # Get progress
    progress = control_plane.time_travel_debugger.get_session_progress(step_session.session_id)
    print(f"Replay Progress: {progress['progress_percent']:.1f}% complete")
    print(f"  ({progress['current_index']} of {progress['total_events']} events)")
    print()
    
    # Get time-travel statistics
    tt_stats = control_plane.get_time_travel_statistics()
    print("Time-Travel Statistics:")
    print(f"  • Active replay sessions: {tt_stats['active_replay_sessions']}")
    print(f"  • Total state snapshots: {tt_stats['total_state_snapshots']}")
    print(f"  • Agents with snapshots: {tt_stats['agents_with_snapshots']}")
    print()
    
    # Export replay session for analysis
    print("Exporting replay session for analysis...")
    export_data = control_plane.time_travel_debugger.export_replay_session(
        replay_session.session_id
    )
    print(f"✓ Export complete ({len(export_data)} bytes)")
    print(f"  Sample: {export_data[:100]}...")
    print()
    
    print("✅ Time-Travel Debugging demo complete!")
    print("   You can now replay and debug agent behavior!")
    print()


def example_combined_features():
    """
    Demonstrate using both hibernation and time-travel together.
    
    This shows how the two features complement each other:
    - Hibernation reduces idle cost
    - Time-travel lets you debug what happened before hibernation
    """
    print("=" * 60)
    print("EXAMPLE 3: Combined Features")
    print("=" * 60)
    print()
    
    # Setup
    flight_recorder = FlightRecorder(db_path="/tmp/combined_demo.db")
    
    control_plane = AgentControlPlane(
        enable_hibernation=True,
        enable_time_travel=True,
        hibernation_config=HibernationConfig(
            idle_timeout_seconds=3,
            storage_path="/tmp/combined_demo_hibernation"
        ),
        time_travel_config=TimeTravelConfig(
            enabled=True,
            enable_state_snapshots=True
        )
    )
    
    control_plane.kernel.audit_logger = flight_recorder
    control_plane.time_travel_debugger.flight_recorder = flight_recorder
    
    agent_context = create_standard_agent(control_plane, "combined-agent-001")
    print(f"✓ Agent created: {agent_context.agent_id}")
    print()
    
    # Do some work
    print("Agent performing work...")
    for i in range(3):
        result = control_plane.execute_action(
            agent_context,
            ActionType.FILE_READ,
            {"path": f"/data/file{i}.txt"}
        )
        control_plane.capture_agent_state_snapshot(
            agent_context.agent_id,
            agent_context,
            metadata={"iteration": i}
        )
        time.sleep(0.5)
    print("✓ Work completed")
    print()
    
    # Hibernate due to inactivity
    print("Agent becomes idle...")
    time.sleep(4)
    
    hibernated = control_plane.hibernate_idle_agents()
    if hibernated:
        print(f"✓ Hibernated {len(hibernated)} idle agent(s): {hibernated}")
    else:
        # Manually hibernate for demo
        print("✓ Manually hibernating agent for demo...")
        control_plane.hibernate_agent(agent_context.agent_id, agent_context)
        hibernated = [agent_context.agent_id]
    print()
    
    # Later, debug what the agent did before hibernation
    print("Debugging agent behavior before hibernation...")
    replay_session = control_plane.replay_agent_history(
        agent_context.agent_id,
        minutes=1
    )
    
    summary = control_plane.get_replay_summary(replay_session.session_id)
    print(f"✓ Found {summary['total_events']} events before hibernation")
    print()
    
    # Wake agent for new work
    if hibernated:
        print("New message arrives, waking agent...")
        restored = control_plane.wake_agent(agent_context.agent_id)
        print(f"✓ Agent restored and ready for new work")
        print()
    
    print("✅ Combined features demo complete!")
    print("   Serverless agents + complete debugging = Perfect!")
    print()


if __name__ == "__main__":
    print("\n")
    print("╔════════════════════════════════════════════════════════════╗")
    print("║  Agent Control Plane - Advanced Features Demo             ║")
    print("║                                                            ║")
    print("║  1. Agent Hibernation (Serverless Agents)                 ║")
    print("║  2. Time-Travel Debugging                                 ║")
    print("║  3. Combined Features                                     ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print("\n")
    
    try:
        # Run all examples
        example_agent_hibernation()
        print("\n" + "─" * 60 + "\n")
        
        example_time_travel_debugging()
        print("\n" + "─" * 60 + "\n")
        
        example_combined_features()
        
        print("\n")
        print("╔════════════════════════════════════════════════════════════╗")
        print("║  All demos completed successfully! 🎉                     ║")
        print("║                                                            ║")
        print("║  Key Takeaways:                                           ║")
        print("║  • Hibernation = No idle cost (Serverless Agents)         ║")
        print("║  • Time-Travel = Complete debugging & observability       ║")
        print("║  • Together = Production-ready agent infrastructure       ║")
        print("╚════════════════════════════════════════════════════════════╝")
        print("\n")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
