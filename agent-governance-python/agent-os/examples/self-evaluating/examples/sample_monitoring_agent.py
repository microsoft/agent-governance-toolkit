#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Monitoring Agent Sample

This sample demonstrates a real-world monitoring agent that:
- Ingests log streams and system signals
- Processes them in Ghost Mode (passive observation)
- Surfaces critical issues with high confidence
- Renders output as dashboard widgets
- Tracks patterns over time

Perfect for DevOps, SRE, and production monitoring scenarios.
"""

import sys
import os
import time
import random
from datetime import datetime

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.universal_signal_bus import (
    UniversalSignalBus,
    create_signal_from_log
)
from src.polymorphic_output import (
    PolymorphicOutputEngine,
    InputContext,
    create_dashboard_widget_response
)
from src.ghost_mode import (
    GhostModeObserver,
    ContextShadow,
    BehaviorPattern,
    ObservationResult
)
from src.telemetry import EventStream, TelemetryEvent


class MonitoringAgent:
    """
    An intelligent monitoring agent that:
    1. Passively observes log streams (Ghost Mode)
    2. Detects patterns and anomalies
    3. Surfaces critical issues automatically
    4. Renders as dashboard widgets
    """
    
    def __init__(self, user_id: str = "ops_team"):
        """Initialize the monitoring agent."""
        self.user_id = user_id
        
        # Input processing
        self.signal_bus = UniversalSignalBus()
        
        # Output rendering
        self.poly_engine = PolymorphicOutputEngine()
        
        # Ghost mode observer
        self.context_shadow = ContextShadow(user_id=user_id)
        self.ghost_observer = GhostModeObserver(
            confidence_threshold=0.7,
            surfacing_callback=self._handle_high_confidence_observation,
            context_shadow=self.context_shadow
        )
        
        # Telemetry
        self.event_stream = EventStream("monitoring_telemetry.jsonl")
        
        # Statistics
        self.stats = {
            "signals_processed": 0,
            "critical_alerts": 0,
            "warnings_detected": 0,
            "patterns_learned": 0
        }
    
    def _handle_high_confidence_observation(self, observation: ObservationResult):
        """
        Callback for when Ghost Mode has a high-confidence observation.
        This is where we surface critical issues to the ops team.
        """
        print(f"\n🚨 HIGH CONFIDENCE ALERT (confidence: {observation.confidence:.2f})")
        print(f"   {observation.observation}")
        
        if observation.recommendation:
            print(f"   💡 Recommendation: {observation.recommendation}")
        
        # Render as dashboard widget
        widget_response = create_dashboard_widget_response(
            widget_type="alert",
            data={
                "severity": "critical" if observation.confidence > 0.85 else "warning",
                "message": observation.observation,
                "recommendation": observation.recommendation,
                "timestamp": datetime.now().isoformat(),
                "confidence": observation.confidence
            },
            title="System Alert"
        )
        
        print(f"   📊 Rendered as: {widget_response.modality.value}")
        
        self.stats["critical_alerts"] += 1
        
        # Log the alert
        event = TelemetryEvent(
            event_type="critical_alert",
            timestamp=datetime.now().isoformat(),
            query=observation.observation,
            agent_response=observation.recommendation or "No recommendation",
            metadata={
                "confidence": observation.confidence,
                "context": observation.context
            }
        )
        self.event_stream.emit(event)
    
    def start_monitoring(self):
        """Start the monitoring agent in Ghost Mode."""
        print("\n" + "="*60)
        print("MONITORING AGENT - Starting Ghost Mode")
        print("="*60)
        print("Monitoring system logs...")
        print("Agent will surface issues when confidence is high enough")
        print("")
        
        # Start Ghost Mode observer
        self.ghost_observer.start_observing(poll_interval=0.5)
    
    def ingest_log(self, log_level: str, message: str, service: str = "unknown", **kwargs):
        """
        Ingest a log message for processing.
        
        Args:
            log_level: Log level (INFO, WARNING, ERROR, CRITICAL)
            message: Log message
            service: Service name
            **kwargs: Additional log context
        """
        # Create signal from log
        signal = create_signal_from_log(
            level=log_level,
            message=message,
            service=service,
            **kwargs
        )
        
        # Normalize through signal bus
        context = self.signal_bus.ingest(signal)
        
        # Feed to Ghost Mode observer
        self.ghost_observer.observe_signal({
            "type": "log_stream",
            "data": {
                "level": log_level,
                "message": message,
                "service": service,
                "priority": context.priority,
                "urgency": context.urgency_score
            }
        })
        
        self.stats["signals_processed"] += 1
        
        if log_level in ["WARNING", "ERROR", "CRITICAL"]:
            self.stats["warnings_detected"] += 1
    
    def stop_monitoring(self):
        """Stop the monitoring agent."""
        self.ghost_observer.stop_observing()
        
        print("\n" + "="*60)
        print("MONITORING AGENT - Statistics")
        print("="*60)
        print(f"Signals Processed: {self.stats['signals_processed']}")
        print(f"Warnings Detected: {self.stats['warnings_detected']}")
        print(f"Critical Alerts: {self.stats['critical_alerts']}")
        
        ghost_stats = self.ghost_observer.get_stats()
        print(f"Observations Made: {ghost_stats['signals_processed']}")
        print(f"High Confidence Alerts: {ghost_stats['signals_surfaced']}")


def simulate_production_logs(agent: MonitoringAgent, duration_seconds: int = 10):
    """Simulate production log stream."""
    print(f"Simulating {duration_seconds} seconds of production logs...")
    
    # Various log scenarios
    log_scenarios = [
        # Normal operations
        {"level": "INFO", "message": "Request processed successfully", "service": "api-gateway"},
        {"level": "INFO", "message": "User logged in", "service": "auth-service"},
        {"level": "INFO", "message": "Cache hit", "service": "redis-cache"},
        
        # Warnings
        {"level": "WARNING", "message": "High memory usage: 75%", "service": "worker-node-1"},
        {"level": "WARNING", "message": "Slow query detected: 2.5s", "service": "database"},
        {"level": "WARNING", "message": "Rate limit approaching: 90% of quota", "service": "api-gateway"},
        
        # Errors (these should trigger alerts)
        {"level": "ERROR", "message": "Database connection timeout", "service": "user-api", "error_code": "500"},
        {"level": "ERROR", "message": "Failed to process payment", "service": "payment-service", "error_code": "503"},
        {"level": "CRITICAL", "message": "Service unavailable - no healthy instances", "service": "user-api"},
        {"level": "CRITICAL", "message": "Disk space critical: 95% full", "service": "storage-node-1"},
    ]
    
    start_time = time.time()
    
    while time.time() - start_time < duration_seconds:
        # Pick a random log scenario
        log = random.choice(log_scenarios)
        
        # Weight towards normal operations (80% INFO, 15% WARNING, 5% ERROR/CRITICAL)
        rand = random.random()
        if rand < 0.80:
            # Normal operation
            log = random.choice([s for s in log_scenarios if s["level"] == "INFO"])
        elif rand < 0.95:
            # Warning
            log = random.choice([s for s in log_scenarios if s["level"] == "WARNING"])
        else:
            # Error or critical
            log = random.choice([s for s in log_scenarios if s["level"] in ["ERROR", "CRITICAL"]])
        
        # Ingest the log
        agent.ingest_log(**log)
        
        # Small delay to simulate real-time stream
        time.sleep(0.1)
    
    # Add a critical issue at the end to ensure we see an alert
    print("\n--- Injecting Critical Issue ---")
    agent.ingest_log(
        level="CRITICAL",
        message="ALERT: Service down - user-api is not responding to health checks",
        service="user-api",
        error_code="503"
    )
    
    # Wait a moment for Ghost Mode to process
    time.sleep(1)


def main():
    """Run the monitoring agent demonstration."""
    print("\n" + "="*60)
    print("MONITORING AGENT - Intelligent System Monitoring")
    print("="*60)
    print("\nThis sample demonstrates:")
    print("- Ghost Mode passive observation")
    print("- Log stream ingestion")
    print("- Pattern detection")
    print("- Confidence-based alerting")
    print("- Dashboard widget rendering")
    
    try:
        # Create monitoring agent
        agent = MonitoringAgent(user_id="sre_team")
        
        # Start monitoring
        agent.start_monitoring()
        
        # Simulate production logs
        simulate_production_logs(agent, duration_seconds=10)
        
        # Stop monitoring
        agent.stop_monitoring()
        
        print("\n" + "="*60)
        print("Monitoring demonstration completed!")
        print("="*60)
        print("\nKey Insights:")
        print("1. Agent runs in background (Ghost Mode)")
        print("2. Only surfaces critical issues")
        print("3. No false alarms from low-confidence observations")
        print("4. Output automatically rendered as dashboard widgets")
        print("5. Perfect for production monitoring scenarios")
        
    except KeyboardInterrupt:
        print("\n\nMonitoring stopped by user.")
        agent.stop_monitoring()
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
