#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Control Plane v0.2.0 - Lifecycle Management Demo

This example demonstrates the new lifecycle management features introduced in v0.2.0:

1. Health Checks (ACP-001): Liveness/readiness probes for agents
2. Auto-Recovery (ACP-002): Automatic restart of crashed agents
3. Circuit Breaker (ACP-003): Prevent cascading failures
4. Agent Scaling (ACP-004): Horizontal scaling
5. Distributed Coordination (ACP-005): Leader election
6. Dependency Graph (ACP-006): Enforced start order
7. Graceful Shutdown (ACP-007): Preserve in-flight operations
8. Resource Quotas (ACP-008): Memory/CPU limits
9. Agent Observability (ACP-009): Metrics and logging
10. Hot Reload (ACP-010): Code changes without restart

Usage:
    python lifecycle_demo.py
"""

import asyncio
import random
from datetime import datetime
from typing import Dict, Any, Optional

# Import the new lifecycle management components
from agent_control_plane import (
    # Enhanced Control Plane
    EnhancedAgentControlPlane,
    create_control_plane,
    
    # Health Monitoring
    HealthCheckConfig,
    HealthStatus,
    
    # Circuit Breaker
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerOpenError,
    
    # Resource Management
    AgentResourceQuota,
    
    # Scaling
    ScalingConfig,
)


# ============================================================================
# Example Agent Classes
# ============================================================================

class ClaimsVerificationAgent:
    """
    Example agent for claims verification.
    
    Implements health check protocols for liveness and readiness monitoring.
    """
    
    def __init__(self, agent_id: str = "claims-agent"):
        self.agent_id = agent_id
        self._running = False
        self._healthy = True
        self._ready = True
        self._processed_claims = 0
        self._state: Dict[str, Any] = {}
        print(f"[{self.agent_id}] Initialized")
    
    async def start(self):
        """Start the agent"""
        self._running = True
        self._ready = True
        print(f"[{self.agent_id}] Started")
    
    async def stop(self):
        """Stop the agent gracefully"""
        self._running = False
        self._ready = False
        print(f"[{self.agent_id}] Stopped (processed {self._processed_claims} claims)")
    
    # Health check methods (ACP-001)
    async def liveness_check(self) -> bool:
        """Check if agent is alive"""
        return self._running and self._healthy
    
    async def readiness_check(self) -> bool:
        """Check if agent is ready to process requests"""
        return self._running and self._ready
    
    # State management for hot reload (ACP-010)
    def get_state(self) -> Dict[str, Any]:
        """Get agent state for preservation during reload"""
        return {
            "processed_claims": self._processed_claims,
            "custom_state": self._state.copy()
        }
    
    def set_state(self, state: Dict[str, Any]):
        """Restore agent state after reload"""
        self._processed_claims = state.get("processed_claims", 0)
        self._state = state.get("custom_state", {})
        print(f"[{self.agent_id}] State restored: {self._processed_claims} claims processed")
    
    # Business logic
    async def verify_claim(self, claim_id: str, claim_data: Dict[str, Any]) -> Dict[str, Any]:
        """Verify a claim"""
        if not self._running:
            raise RuntimeError("Agent not running")
        
        # Simulate processing time
        await asyncio.sleep(random.uniform(0.1, 0.5))
        
        self._processed_claims += 1
        
        # Simulate occasional failures for testing circuit breaker
        if random.random() < 0.1:  # 10% failure rate
            raise Exception("Verification service temporarily unavailable")
        
        return {
            "claim_id": claim_id,
            "status": "verified",
            "timestamp": datetime.now().isoformat(),
            "agent": self.agent_id
        }
    
    def simulate_unhealthy(self):
        """Simulate agent becoming unhealthy (for testing)"""
        self._healthy = False
        print(f"[{self.agent_id}] Now UNHEALTHY")
    
    def simulate_healthy(self):
        """Simulate agent recovering health"""
        self._healthy = True
        print(f"[{self.agent_id}] Now HEALTHY")


class MessageBusAgent:
    """Example message bus agent that other agents depend on"""
    
    def __init__(self):
        self.agent_id = "message-bus"
        self._running = False
        self._messages_processed = 0
    
    async def start(self):
        self._running = True
        print(f"[{self.agent_id}] Message bus started")
    
    async def stop(self):
        self._running = False
        print(f"[{self.agent_id}] Message bus stopped")
    
    async def liveness_check(self) -> bool:
        return self._running
    
    async def readiness_check(self) -> bool:
        return self._running


class DatabaseAgent:
    """Example database agent"""
    
    def __init__(self):
        self.agent_id = "database"
        self._running = False
    
    async def start(self):
        self._running = True
        print(f"[{self.agent_id}] Database connection established")
    
    async def stop(self):
        self._running = False
        print(f"[{self.agent_id}] Database connection closed")
    
    async def liveness_check(self) -> bool:
        return self._running
    
    async def readiness_check(self) -> bool:
        return self._running


# ============================================================================
# Demo Functions
# ============================================================================

async def demo_basic_lifecycle():
    """
    Demo 1: Basic Lifecycle Management
    
    Shows the new API for registering and managing agents.
    """
    print("\n" + "="*70)
    print("DEMO 1: Basic Lifecycle Management")
    print("="*70)
    
    # Create the enhanced control plane (NEW in v0.2.0)
    control_plane = create_control_plane(
        health_check_interval=5.0,      # Check health every 5 seconds
        auto_recovery=True,             # Auto-restart crashed agents
    )
    
    # Register agents with the new API (NEW in v0.2.0)
    control_plane.register(
        ClaimsVerificationAgent,
        agent_id="claims-verifier",
        replicas=2,                     # Run 2 instances
        dependencies=["message-bus"],   # Start after message-bus
        resources=AgentResourceQuota(   # Resource limits
            memory_mb=512,
            cpu_percent=25,
            max_concurrent_operations=10
        )
    )
    
    control_plane.register(
        MessageBusAgent,
        agent_id="message-bus",
        replicas=1,
        dependencies=[],                # No dependencies
    )
    
    # Start all agents in dependency order (NEW in v0.2.0)
    print("\nStarting all agents...")
    result = await control_plane.start_all()
    print(f"Startup result: {result['status']}")
    
    # Check status
    status = control_plane.get_status()
    print(f"\nControl Plane Status:")
    print(f"  Running: {status['running']}")
    print(f"  Registered agents: {status['registered_agents']}")
    print(f"  Health status: {status['health_status']}")
    
    # Graceful shutdown (NEW in v0.2.0)
    print("\nStopping all agents...")
    await control_plane.stop_all()
    print("All agents stopped.")


async def demo_circuit_breaker():
    """
    Demo 2: Circuit Breaker Pattern
    
    Shows how circuit breakers prevent cascading failures.
    """
    print("\n" + "="*70)
    print("DEMO 2: Circuit Breaker Pattern")
    print("="*70)
    
    # Create a circuit breaker (NEW in v0.2.0)
    breaker = CircuitBreaker(
        name="claims-service",
        config=CircuitBreakerConfig(
            failure_threshold=3,        # Open after 3 failures
            success_threshold=2,        # Close after 2 successes
            recovery_timeout_seconds=5.0  # Try again after 5 seconds
        )
    )
    
    agent = ClaimsVerificationAgent("demo-agent")
    await agent.start()
    
    # Simulate requests with failures
    print("\nSimulating requests through circuit breaker...")
    
    for i in range(10):
        try:
            # Use circuit breaker as context manager
            async with breaker:
                if i < 5:
                    # Simulate failures
                    raise Exception(f"Service error {i}")
                else:
                    print(f"  Request {i}: Success")
        except CircuitBreakerOpenError as e:
            print(f"  Request {i}: Circuit OPEN - {e}")
        except Exception as e:
            print(f"  Request {i}: Failed - {e}")
        
        print(f"    Circuit state: {breaker.state.value}")
        await asyncio.sleep(0.5)
    
    # Show metrics
    metrics = breaker.get_metrics()
    print(f"\nCircuit Breaker Metrics:")
    print(f"  Total calls: {metrics.total_calls}")
    print(f"  Total failures: {metrics.total_failures}")
    print(f"  Current state: {metrics.state.value}")
    
    await agent.stop()


async def demo_health_monitoring():
    """
    Demo 3: Health Monitoring
    
    Shows liveness and readiness probes.
    """
    print("\n" + "="*70)
    print("DEMO 3: Health Monitoring")
    print("="*70)
    
    control_plane = create_control_plane(
        health_check_interval=2.0,
        auto_recovery=True,
    )
    
    # Register callback for health events
    async def on_health_failed(agent_id: str):
        print(f"  🚨 Health check failed for {agent_id}!")
    
    control_plane.health_monitor.on_event("liveness_failed", on_health_failed)
    
    control_plane.register(ClaimsVerificationAgent, replicas=1)
    await control_plane.start_all()
    
    print("\nMonitoring agent health...")
    
    # Let health checks run
    await asyncio.sleep(3)
    
    # Get health status
    health = control_plane.get_all_health_status()
    print(f"\nHealth Status: {health}")
    
    # Simulate agent becoming unhealthy
    agent = control_plane.get_agent("ClaimsVerificationAgent")
    if agent:
        print("\nSimulating agent becoming unhealthy...")
        agent.simulate_unhealthy()
        
        # Wait for health check to detect
        await asyncio.sleep(5)
        
        health = control_plane.get_all_health_status()
        print(f"Health Status after failure: {health}")
    
    await control_plane.stop_all()


async def demo_scaling():
    """
    Demo 4: Horizontal Scaling
    
    Shows dynamic scaling of agent replicas.
    """
    print("\n" + "="*70)
    print("DEMO 4: Horizontal Scaling")
    print("="*70)
    
    control_plane = create_control_plane()
    
    control_plane.register(
        ClaimsVerificationAgent,
        replicas=1,
        resources=AgentResourceQuota(
            memory_mb=256,
            cpu_percent=20
        )
    )
    
    await control_plane.start_all()
    
    print(f"\nInitial replicas: {control_plane.scaler.get_replica_count('ClaimsVerificationAgent')}")
    
    # Scale up
    print("\nScaling up to 3 replicas...")
    await control_plane.scaler.scale_to("ClaimsVerificationAgent", 3)
    print(f"Current replicas: {control_plane.scaler.get_replica_count('ClaimsVerificationAgent')}")
    
    # Get available replica (load balanced)
    print("\nGetting replicas (round-robin):")
    for i in range(6):
        replica = await control_plane.scaler.get_replica("ClaimsVerificationAgent")
        print(f"  Request {i}: {id(replica)}")
    
    # Scale down
    print("\nScaling down to 1 replica...")
    await control_plane.scaler.scale_to("ClaimsVerificationAgent", 1)
    print(f"Current replicas: {control_plane.scaler.get_replica_count('ClaimsVerificationAgent')}")
    
    await control_plane.stop_all()


async def demo_dependency_graph():
    """
    Demo 5: Dependency Graph
    
    Shows enforced startup order based on dependencies.
    """
    print("\n" + "="*70)
    print("DEMO 5: Dependency Graph")
    print("="*70)
    
    control_plane = create_control_plane()
    
    # Register agents with dependencies
    control_plane.register(DatabaseAgent, agent_id="database")
    control_plane.register(MessageBusAgent, agent_id="message-bus", dependencies=["database"])
    control_plane.register(
        ClaimsVerificationAgent,
        agent_id="claims-agent",
        dependencies=["database", "message-bus"]
    )
    
    # Get startup order
    startup_order = control_plane.dependency_graph.get_startup_order()
    print(f"\nStartup order: {startup_order}")
    
    # Get parallel groups
    parallel_groups = control_plane.dependency_graph.get_parallel_startup_groups()
    print(f"\nParallel startup groups:")
    for i, group in enumerate(parallel_groups):
        print(f"  Group {i}: {group}")
    
    # Validate graph
    errors = control_plane.dependency_graph.validate()
    print(f"\nValidation errors: {errors if errors else 'None'}")
    
    # Start in correct order
    print("\nStarting agents in dependency order...")
    await control_plane.start_all()
    
    # Shutdown order is reverse
    shutdown_order = control_plane.dependency_graph.get_shutdown_order()
    print(f"\nShutdown order: {shutdown_order}")
    
    await control_plane.stop_all()


async def demo_graceful_shutdown():
    """
    Demo 6: Graceful Shutdown
    
    Shows preservation of in-flight operations during shutdown.
    """
    print("\n" + "="*70)
    print("DEMO 6: Graceful Shutdown")
    print("="*70)
    
    control_plane = create_control_plane()
    control_plane.register(ClaimsVerificationAgent, replicas=1)
    
    await control_plane.start_all()
    
    # Simulate in-flight operations
    print("\nRegistering in-flight operations...")
    op1 = control_plane.shutdown_manager.register_operation(
        agent_id="claims-agent",
        operation_type="verification",
        data={"claim_id": "CLM-001"}
    )
    op2 = control_plane.shutdown_manager.register_operation(
        agent_id="claims-agent",
        operation_type="verification",
        data={"claim_id": "CLM-002"}
    )
    
    print(f"In-flight operations: {control_plane.shutdown_manager.get_in_flight_count()}")
    
    # Complete one operation
    print("\nCompleting operation 1...")
    control_plane.shutdown_manager.complete_operation(op1)
    print(f"In-flight operations: {control_plane.shutdown_manager.get_in_flight_count()}")
    
    # Initiate graceful shutdown
    print("\nInitiating graceful shutdown (with in-flight operation)...")
    result = await control_plane.stop_all()
    
    print(f"\nShutdown result:")
    print(f"  Status: {result['status']}")
    if 'shutdown_result' in result:
        sr = result['shutdown_result']
        print(f"  In-flight at start: {sr.get('in_flight_at_start', 'N/A')}")
        print(f"  Checkpointed: {sr.get('checkpointed', [])}")


async def demo_observability():
    """
    Demo 7: Agent Observability
    
    Shows metrics collection and Prometheus export.
    """
    print("\n" + "="*70)
    print("DEMO 7: Agent Observability")
    print("="*70)
    
    control_plane = create_control_plane()
    control_plane.register(ClaimsVerificationAgent, replicas=1)
    
    await control_plane.start_all()
    
    # Record some metrics
    print("\nRecording metrics...")
    control_plane.observability.increment_counter(
        "claims-agent", "requests_total",
        labels={"status": "success"}
    )
    control_plane.observability.increment_counter(
        "claims-agent", "requests_total",
        labels={"status": "success"}
    )
    control_plane.observability.increment_counter(
        "claims-agent", "requests_total",
        labels={"status": "failure"}
    )
    
    control_plane.observability.set_gauge(
        "claims-agent", "active_connections", 5.0
    )
    
    control_plane.observability.observe_histogram(
        "claims-agent", "request_latency_ms", 150.0
    )
    control_plane.observability.observe_histogram(
        "claims-agent", "request_latency_ms", 200.0
    )
    
    # Log some messages
    control_plane.observability.log(
        "claims-agent", "info", "Processing claim CLM-001"
    )
    control_plane.observability.log(
        "claims-agent", "warning", "High latency detected",
        context={"latency_ms": 500}
    )
    
    # Get agent summary
    summary = control_plane.observability.get_agent_summary("claims-agent")
    print(f"\nAgent Summary:")
    print(f"  Total metrics: {summary['total_metrics']}")
    print(f"  Total logs: {summary['total_logs']}")
    print(f"  Log level counts: {summary['log_level_counts']}")
    
    # Export Prometheus metrics
    print("\nPrometheus Metrics Export:")
    print("-" * 40)
    prometheus_text = control_plane.get_metrics()
    print(prometheus_text[:500] + "..." if len(prometheus_text) > 500 else prometheus_text)
    
    await control_plane.stop_all()


async def demo_resource_quotas():
    """
    Demo 8: Resource Quotas
    
    Shows resource limiting per agent.
    """
    print("\n" + "="*70)
    print("DEMO 8: Resource Quotas")
    print("="*70)
    
    control_plane = create_control_plane()
    
    control_plane.register(
        ClaimsVerificationAgent,
        resources=AgentResourceQuota(
            memory_mb=512,
            cpu_percent=25,
            max_concurrent_operations=3,
            max_operations_per_minute=10
        )
    )
    
    await control_plane.start_all()
    
    # Check quota
    quota = control_plane.quota_manager.get_quota("ClaimsVerificationAgent")
    print(f"\nResource Quota for ClaimsVerificationAgent:")
    print(f"  Memory limit: {quota.memory_mb} MB")
    print(f"  CPU limit: {quota.cpu_percent}%")
    print(f"  Max concurrent ops: {quota.max_concurrent_operations}")
    print(f"  Max ops/minute: {quota.max_operations_per_minute}")
    
    # Simulate operations
    print("\nSimulating operations...")
    for i in range(5):
        can_execute = control_plane.quota_manager.can_execute("ClaimsVerificationAgent")
        print(f"  Operation {i}: {'Allowed' if can_execute else 'DENIED'}")
        if can_execute:
            control_plane.quota_manager.record_operation_start("ClaimsVerificationAgent")
    
    # Show usage
    usage = control_plane.quota_manager.get_usage("ClaimsVerificationAgent")
    print(f"\nCurrent Usage:")
    print(f"  Concurrent operations: {usage.concurrent_operations}")
    
    # Simulate resource usage
    control_plane.quota_manager.update_resource_usage(
        "ClaimsVerificationAgent",
        memory_mb=600,  # Over limit!
        cpu_percent=30   # Over limit!
    )
    
    # Check violations
    violations = control_plane.quota_manager.check_quota_violations()
    print(f"\nQuota Violations: {violations}")
    
    await control_plane.stop_all()


async def demo_full_integration():
    """
    Demo 9: Full Integration
    
    Shows all features working together.
    """
    print("\n" + "="*70)
    print("DEMO 9: Full Integration")
    print("="*70)
    
    # Create control plane with all features
    control_plane = create_control_plane(
        health_check_interval=5.0,
        auto_recovery=True,
        circuit_breaker=CircuitBreaker(
            name="default",
            failure_threshold=5,
            recovery_timeout=30.0
        )
    )
    
    # Register infrastructure
    control_plane.register(DatabaseAgent, agent_id="database")
    control_plane.register(
        MessageBusAgent,
        agent_id="message-bus",
        dependencies=["database"]
    )
    
    # Register workers with full configuration
    control_plane.register(
        ClaimsVerificationAgent,
        agent_id="claims-verifier",
        replicas=3,
        dependencies=["message-bus"],
        resources=AgentResourceQuota(
            memory_mb=512,
            cpu_percent=25,
            max_concurrent_operations=10
        )
    )
    
    print("\n📋 Registered Agents:")
    for agent_id in control_plane._registrations:
        reg = control_plane._registrations[agent_id]
        print(f"  - {agent_id}: {reg.replicas} replica(s), deps={reg.dependencies}")
    
    # Start everything
    print("\n🚀 Starting all agents...")
    result = await control_plane.start_all()
    print(f"   Status: {result['status']}")
    
    # Show comprehensive status
    status = control_plane.get_status()
    print(f"\n📊 Control Plane Status:")
    print(f"   Running: {status['running']}")
    print(f"   Node ID: {status['node_id']}")
    print(f"   Is Leader: {status['is_leader']}")
    print(f"   Health: {status['health_status']}")
    
    # Simulate some work
    print("\n⚙️ Simulating workload...")
    for i in range(5):
        agent = await control_plane.get_available_agent("claims-verifier")
        if agent:
            control_plane.observability.increment_counter(
                "claims-verifier", "requests_total"
            )
            print(f"   Request {i}: Processed by {id(agent)}")
        await asyncio.sleep(0.2)
    
    # Show metrics
    print("\n📈 Metrics Summary:")
    summary = control_plane.observability.get_agent_summary("claims-verifier")
    print(f"   Total metrics recorded: {summary['total_metrics']}")
    
    # Graceful shutdown
    print("\n🛑 Initiating graceful shutdown...")
    result = await control_plane.stop_all()
    print(f"   Status: {result['status']}")
    
    print("\n✅ Integration demo complete!")


# ============================================================================
# Main Entry Point
# ============================================================================

async def main():
    """Run all demos"""
    print("="*70)
    print("Agent Control Plane v0.2.0 - Lifecycle Management Demo")
    print("="*70)
    
    demos = [
        ("Basic Lifecycle", demo_basic_lifecycle),
        ("Circuit Breaker", demo_circuit_breaker),
        ("Health Monitoring", demo_health_monitoring),
        ("Horizontal Scaling", demo_scaling),
        ("Dependency Graph", demo_dependency_graph),
        ("Graceful Shutdown", demo_graceful_shutdown),
        ("Observability", demo_observability),
        ("Resource Quotas", demo_resource_quotas),
        ("Full Integration", demo_full_integration),
    ]
    
    for name, demo_func in demos:
        try:
            await demo_func()
        except Exception as e:
            print(f"\n❌ Error in {name}: {e}")
        
        await asyncio.sleep(0.5)
    
    print("\n" + "="*70)
    print("All demos completed!")
    print("="*70)


if __name__ == "__main__":
    asyncio.run(main())
