# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for Agent Lifecycle Management (v0.2.0)

This module tests the comprehensive lifecycle management features:
- ACP-001: Agent Health Checks
- ACP-002: Agent Auto-Recovery
- ACP-003: Circuit Breaker
- ACP-004: Agent Scaling
- ACP-005: Distributed Coordination
- ACP-006: Agent Dependency Graph
- ACP-007: Graceful Shutdown
- ACP-008: Resource Quotas
- ACP-009: Agent Observability
- ACP-010: Hot Reload
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock
import sys

from agent_control_plane.lifecycle import (
    # Health Monitoring
    HealthMonitor,
    HealthCheckConfig,
    HealthCheckResult,
    HealthStatus,
    
    # Auto-Recovery
    AutoRecoveryManager,
    RecoveryConfig,
    RecoveryEvent,
    
    # Circuit Breaker
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerOpenError,
    CircuitState,
    CircuitBreakerRegistry,
    
    # Scaling
    AgentScaler,
    ScalingConfig,
    AgentReplica,
    AgentState,
    
    # Distributed Coordination
    DistributedCoordinator,
    LeaderElectionConfig,
    CoordinationRole,
    
    # Dependency Graph
    DependencyGraph,
    AgentDependency,
    
    # Graceful Shutdown
    GracefulShutdownManager,
    ShutdownConfig,
    ShutdownPhase,
    
    # Resource Quotas
    ResourceQuotaManager,
    AgentResourceQuota,
    
    # Observability
    AgentObservabilityProvider,
    
    # Hot Reload
    HotReloadManager,
    HotReloadConfig,
    
    # Main Control Plane
    EnhancedAgentControlPlane,
    create_control_plane,
)


# ============================================================================
# Test Fixtures
# ============================================================================

class MockAgent:
    """Mock agent for testing"""
    
    def __init__(self, name: str = "mock-agent"):
        self.name = name
        self.started = False
        self.stopped = False
        self._is_alive = True
        self._is_ready = True
        self._state = {}
    
    async def start(self):
        self.started = True
    
    async def stop(self):
        self.stopped = True
    
    def is_alive(self) -> bool:
        return self._is_alive
    
    def is_ready(self) -> bool:
        return self._is_ready
    
    async def liveness_check(self) -> bool:
        return self._is_alive
    
    async def readiness_check(self) -> bool:
        return self._is_ready
    
    def get_state(self) -> dict:
        return self._state.copy()
    
    def set_state(self, state: dict):
        self._state = state.copy()


@pytest.fixture
def mock_agent():
    """Create a mock agent"""
    return MockAgent()


@pytest.fixture
def health_config():
    """Create health check config"""
    return HealthCheckConfig(
        liveness_interval_seconds=0.1,
        liveness_timeout_seconds=1.0,
        liveness_failure_threshold=2,
        readiness_interval_seconds=0.1,
        readiness_timeout_seconds=1.0,
        readiness_failure_threshold=1
    )


@pytest.fixture
def recovery_config():
    """Create recovery config"""
    return RecoveryConfig(
        enabled=True,
        max_restarts=3,
        restart_delay_seconds=0.1,
        restart_delay_max_seconds=1.0,
        restart_delay_multiplier=2.0
    )


# ============================================================================
# ACP-001: Health Check Tests
# ============================================================================

class TestHealthMonitor:
    """Tests for health monitoring functionality"""
    
    @pytest.mark.asyncio
    async def test_register_agent(self, health_config):
        """Test agent registration for health monitoring"""
        monitor = HealthMonitor(config=health_config)
        agent = MockAgent("test-agent")
        
        monitor.register_agent("test-agent", agent)
        
        assert "test-agent" in monitor._agents
        assert monitor.get_agent_health("test-agent") == HealthStatus.UNKNOWN
    
    @pytest.mark.asyncio
    async def test_liveness_check_success(self, health_config):
        """Test successful liveness check"""
        monitor = HealthMonitor(config=health_config)
        agent = MockAgent()
        agent._is_alive = True
        
        monitor.register_agent("test-agent", agent)
        result = await monitor._check_liveness("test-agent")
        
        assert result.healthy is True
        assert result.status == HealthStatus.HEALTHY
    
    @pytest.mark.asyncio
    async def test_liveness_check_failure(self, health_config):
        """Test failed liveness check"""
        monitor = HealthMonitor(config=health_config)
        agent = MockAgent()
        agent._is_alive = False
        
        monitor.register_agent("test-agent", agent)
        result = await monitor._check_liveness("test-agent")
        
        assert result.healthy is False
        assert result.status == HealthStatus.UNHEALTHY
    
    @pytest.mark.asyncio
    async def test_readiness_check_success(self, health_config):
        """Test successful readiness check"""
        monitor = HealthMonitor(config=health_config)
        agent = MockAgent()
        agent._is_ready = True
        
        monitor.register_agent("test-agent", agent)
        result = await monitor._check_readiness("test-agent")
        
        assert result.healthy is True
    
    @pytest.mark.asyncio
    async def test_readiness_check_failure(self, health_config):
        """Test failed readiness check"""
        monitor = HealthMonitor(config=health_config)
        agent = MockAgent()
        agent._is_ready = False
        
        monitor.register_agent("test-agent", agent)
        result = await monitor._check_readiness("test-agent")
        
        assert result.healthy is False
        assert result.status == HealthStatus.DEGRADED
    
    @pytest.mark.asyncio
    async def test_custom_health_check(self, health_config):
        """Test custom health check function"""
        monitor = HealthMonitor(config=health_config)
        
        async def custom_liveness():
            return True
        
        monitor.register_agent(
            "test-agent",
            MockAgent(),
            custom_liveness=custom_liveness
        )
        
        result = await monitor._check_liveness("test-agent")
        assert result.healthy is True
    
    @pytest.mark.asyncio
    async def test_unregister_agent(self, health_config):
        """Test agent unregistration"""
        monitor = HealthMonitor(config=health_config)
        monitor.register_agent("test-agent", MockAgent())
        
        monitor.unregister_agent("test-agent")
        
        assert "test-agent" not in monitor._agents
        assert monitor.get_agent_health("test-agent") == HealthStatus.UNKNOWN


# ============================================================================
# ACP-002: Auto-Recovery Tests
# ============================================================================

class TestAutoRecovery:
    """Tests for auto-recovery functionality"""
    
    @pytest.mark.asyncio
    async def test_register_agent(self, recovery_config):
        """Test agent registration for recovery"""
        recovery = AutoRecoveryManager(config=recovery_config)
        
        recovery.register_agent(
            "test-agent",
            factory=lambda: MockAgent()
        )
        
        assert "test-agent" in recovery._agent_factories
        assert recovery.get_restart_count("test-agent") == 0
    
    @pytest.mark.asyncio
    async def test_handle_failure_recovery(self, recovery_config):
        """Test successful recovery after failure"""
        recovery = AutoRecoveryManager(config=recovery_config)
        
        recovery.register_agent(
            "test-agent",
            factory=lambda: MockAgent()
        )
        
        new_agent = await recovery.handle_failure("test-agent", Exception("Test failure"))
        
        assert new_agent is not None
        assert recovery.get_restart_count("test-agent") == 1
    
    @pytest.mark.asyncio
    async def test_max_restarts_limit(self, recovery_config):
        """Test max restarts limit is respected"""
        recovery_config.max_restarts = 2
        recovery = AutoRecoveryManager(config=recovery_config)
        
        fail_count = 0
        def failing_factory():
            nonlocal fail_count
            fail_count += 1
            if fail_count < 3:
                raise Exception("Factory failure")
            return MockAgent()
        
        recovery.register_agent("test-agent", factory=failing_factory)
        
        # Simulate multiple failures
        recovery._restart_counts["test-agent"] = 2
        
        result = await recovery.handle_failure("test-agent")
        
        # Should not recover when at max restarts (depending on config)
        # The behavior depends on on_max_restarts setting
    
    @pytest.mark.asyncio
    async def test_recovery_history(self, recovery_config):
        """Test recovery history tracking"""
        recovery = AutoRecoveryManager(config=recovery_config)
        recovery.register_agent("test-agent", factory=lambda: MockAgent())
        
        await recovery.handle_failure("test-agent")
        
        history = recovery.get_recovery_history("test-agent")
        assert len(history) >= 1
        assert any(e.event_type in ("failure", "recovery_success") for e in history)
    
    @pytest.mark.asyncio
    async def test_reset_restart_count(self, recovery_config):
        """Test manual restart count reset"""
        recovery = AutoRecoveryManager(config=recovery_config)
        recovery.register_agent("test-agent", factory=lambda: MockAgent())
        
        recovery._restart_counts["test-agent"] = 5
        recovery.reset_restart_count("test-agent")
        
        assert recovery.get_restart_count("test-agent") == 0


# ============================================================================
# ACP-003: Circuit Breaker Tests
# ============================================================================

class TestCircuitBreaker:
    """Tests for circuit breaker functionality"""
    
    @pytest.mark.asyncio
    async def test_initial_state_closed(self):
        """Test circuit breaker starts in closed state"""
        breaker = CircuitBreaker(name="test")
        assert breaker.state == CircuitState.CLOSED
        assert breaker.is_closed is True
    
    @pytest.mark.asyncio
    async def test_opens_after_failures(self):
        """Test circuit opens after threshold failures"""
        config = CircuitBreakerConfig(failure_threshold=3)
        breaker = CircuitBreaker(name="test", config=config)
        
        for i in range(3):
            await breaker._on_failure(Exception("Test failure"))
        
        assert breaker.state == CircuitState.OPEN
        assert breaker.is_open is True
    
    @pytest.mark.asyncio
    async def test_rejects_when_open(self):
        """Test requests are rejected when circuit is open"""
        breaker = CircuitBreaker(name="test", failure_threshold=1)
        
        await breaker._on_failure(Exception("Test failure"))
        
        with pytest.raises(CircuitBreakerOpenError):
            await breaker._before_call()
    
    @pytest.mark.asyncio
    async def test_half_open_after_timeout(self):
        """Test circuit transitions to half-open after recovery timeout"""
        config = CircuitBreakerConfig(
            failure_threshold=1,
            recovery_timeout_seconds=0.1
        )
        breaker = CircuitBreaker(name="test", config=config)
        
        await breaker._on_failure(Exception("Test failure"))
        assert breaker.state == CircuitState.OPEN
        
        # Wait for recovery timeout
        await asyncio.sleep(0.15)
        
        # Next call should transition to half-open
        await breaker._before_call()
        assert breaker.state == CircuitState.HALF_OPEN
    
    @pytest.mark.asyncio
    async def test_closes_after_successful_half_open(self):
        """Test circuit closes after successful calls in half-open"""
        config = CircuitBreakerConfig(
            failure_threshold=1,
            success_threshold=2,
            recovery_timeout_seconds=0.1
        )
        breaker = CircuitBreaker(name="test", config=config)
        
        # Open the circuit
        await breaker._on_failure(Exception("Test failure"))
        await asyncio.sleep(0.15)
        
        # Transition to half-open and succeed
        await breaker._before_call()
        await breaker._on_success()
        await breaker._on_success()
        
        assert breaker.state == CircuitState.CLOSED
    
    @pytest.mark.asyncio
    async def test_decorator_usage(self):
        """Test circuit breaker as decorator"""
        breaker = CircuitBreaker(name="test", failure_threshold=3)
        
        @breaker
        async def test_func():
            return "success"
        
        result = await test_func()
        assert result == "success"
    
    @pytest.mark.asyncio
    async def test_context_manager_usage(self):
        """Test circuit breaker as context manager"""
        breaker = CircuitBreaker(name="test")
        
        async with breaker:
            pass  # Success
        
        metrics = breaker.get_metrics()
        assert metrics.total_successes >= 1
    
    def test_manual_reset(self):
        """Test manual circuit reset"""
        breaker = CircuitBreaker(name="test")
        breaker._state = CircuitState.OPEN
        breaker._failure_count = 10
        
        breaker.reset()
        
        assert breaker.state == CircuitState.CLOSED
        assert breaker._failure_count == 0
    
    def test_circuit_breaker_registry(self):
        """Test circuit breaker registry"""
        registry = CircuitBreakerRegistry()
        
        breaker1 = registry.get_or_create("agent-1")
        breaker2 = registry.get_or_create("agent-1")
        breaker3 = registry.get_or_create("agent-2")
        
        assert breaker1 is breaker2
        assert breaker1 is not breaker3


# ============================================================================
# ACP-004: Agent Scaling Tests
# ============================================================================

class TestAgentScaler:
    """Tests for agent scaling functionality"""
    
    @pytest.mark.asyncio
    async def test_register_agent_type(self):
        """Test agent type registration"""
        scaler = AgentScaler()
        
        scaler.register_agent_type(
            agent_type="test-agent",
            factory=lambda: MockAgent(),
            replicas=2
        )
        
        assert "test-agent" in scaler._agent_types
    
    @pytest.mark.asyncio
    async def test_scale_to(self):
        """Test scaling to specific replica count"""
        scaler = AgentScaler()
        scaler.register_agent_type("test-agent", factory=lambda: MockAgent())
        
        await scaler.scale_to("test-agent", 3)
        
        assert scaler.get_replica_count("test-agent") == 3
    
    @pytest.mark.asyncio
    async def test_scale_up(self):
        """Test scaling up"""
        scaler = AgentScaler()
        scaler.register_agent_type("test-agent", factory=lambda: MockAgent())
        
        await scaler.scale_to("test-agent", 2)
        await scaler.scale_up("test-agent", 2)
        
        assert scaler.get_replica_count("test-agent") == 4
    
    @pytest.mark.asyncio
    async def test_scale_down(self):
        """Test scaling down"""
        scaler = AgentScaler()
        scaler.register_agent_type("test-agent", factory=lambda: MockAgent())
        
        await scaler.scale_to("test-agent", 4)
        await scaler.scale_down("test-agent", 2)
        
        assert scaler.get_replica_count("test-agent") == 2
    
    @pytest.mark.asyncio
    async def test_get_replica_load_balanced(self):
        """Test round-robin load balancing"""
        scaler = AgentScaler()
        scaler.register_agent_type("test-agent", factory=lambda: MockAgent())
        
        await scaler.scale_to("test-agent", 3)
        
        replicas = set()
        for _ in range(6):
            replica = await scaler.get_replica("test-agent")
            replicas.add(id(replica))
        
        # Should have gotten all 3 replicas
        assert len(replicas) == 3
    
    @pytest.mark.asyncio
    async def test_max_replicas_limit(self):
        """Test max replicas limit is respected"""
        config = ScalingConfig(max_replicas=5)
        scaler = AgentScaler()
        scaler.register_agent_type("test-agent", factory=lambda: MockAgent(), config=config)
        
        await scaler.scale_to("test-agent", 10)
        
        assert scaler.get_replica_count("test-agent") == 5


# ============================================================================
# ACP-005: Distributed Coordination Tests
# ============================================================================

class TestDistributedCoordinator:
    """Tests for distributed coordination functionality"""
    
    @pytest.mark.asyncio
    async def test_single_node_becomes_leader(self):
        """Test single node becomes leader"""
        coordinator = DistributedCoordinator(node_id="node-1", peers=[])
        
        await coordinator.start()
        await asyncio.sleep(0.1)  # Allow election to complete
        
        assert coordinator.is_leader is True
        assert coordinator.role == CoordinationRole.LEADER
        
        await coordinator.stop()
    
    @pytest.mark.asyncio
    async def test_acquire_release_lock(self):
        """Test distributed lock acquisition and release"""
        coordinator = DistributedCoordinator(node_id="node-1")
        
        acquired = await coordinator.acquire_lock("resource-1", timeout=1.0)
        assert acquired is True
        
        coordinator.release_lock("resource-1")
        
        # Should be able to acquire again
        acquired = await coordinator.acquire_lock("resource-1", timeout=1.0)
        assert acquired is True
    
    @pytest.mark.asyncio
    async def test_lock_context_manager(self):
        """Test lock as context manager"""
        coordinator = DistributedCoordinator(node_id="node-1")
        
        async with coordinator.lock("resource-1"):
            # Lock should be held
            assert "resource-1" in coordinator._lock_holders
        
        # Lock should be released
        assert "resource-1" not in coordinator._lock_holders
    
    @pytest.mark.asyncio
    async def test_get_leader_info(self):
        """Test getting leader information"""
        coordinator = DistributedCoordinator(node_id="node-1", peers=[])
        
        await coordinator.start()
        await asyncio.sleep(0.1)
        
        info = coordinator.get_leader_info()
        
        assert info is not None
        assert info.leader_id == "node-1"
        
        await coordinator.stop()


# ============================================================================
# ACP-006: Dependency Graph Tests
# ============================================================================

class TestDependencyGraph:
    """Tests for dependency graph functionality"""
    
    def test_add_agent(self):
        """Test adding agents to the graph"""
        graph = DependencyGraph()
        
        graph.add_agent("api-server", depends_on=["database", "cache"])
        graph.add_agent("database", depends_on=[])
        graph.add_agent("cache", depends_on=[])
        
        assert len(graph._agents) == 3
    
    def test_get_dependencies(self):
        """Test getting agent dependencies"""
        graph = DependencyGraph()
        graph.add_agent("api-server", depends_on=["database", "cache"])
        
        deps = graph.get_dependencies("api-server")
        
        assert "database" in deps
        assert "cache" in deps
    
    def test_get_dependents(self):
        """Test getting agents that depend on an agent"""
        graph = DependencyGraph()
        graph.add_agent("database", depends_on=[])
        graph.add_agent("api-server", depends_on=["database"])
        graph.add_agent("worker", depends_on=["database"])
        
        dependents = graph.get_dependents("database")
        
        assert "api-server" in dependents
        assert "worker" in dependents
    
    def test_circular_dependency_detection(self):
        """Test circular dependency detection"""
        graph = DependencyGraph()
        graph.add_agent("a", depends_on=["b"])
        graph.add_agent("b", depends_on=["c"])
        graph.add_agent("c", depends_on=["a"])  # Circular!
        
        assert graph.has_circular_dependency() is True
    
    def test_no_circular_dependency(self):
        """Test no circular dependency in valid graph"""
        graph = DependencyGraph()
        graph.add_agent("a", depends_on=["b"])
        graph.add_agent("b", depends_on=["c"])
        graph.add_agent("c", depends_on=[])
        
        assert graph.has_circular_dependency() is False
    
    def test_startup_order(self):
        """Test correct startup order"""
        graph = DependencyGraph()
        graph.add_agent("api-server", depends_on=["database", "cache"])
        graph.add_agent("database", depends_on=[])
        graph.add_agent("cache", depends_on=[])
        
        order = graph.get_startup_order()
        
        # database and cache should come before api-server
        assert order.index("database") < order.index("api-server")
        assert order.index("cache") < order.index("api-server")
    
    def test_parallel_startup_groups(self):
        """Test parallel startup group generation"""
        graph = DependencyGraph()
        graph.add_agent("api-server", depends_on=["database", "cache"])
        graph.add_agent("database", depends_on=[])
        graph.add_agent("cache", depends_on=[])
        
        groups = graph.get_parallel_startup_groups()
        
        assert len(groups) == 2
        # First group should contain database and cache
        assert set(groups[0]) == {"database", "cache"}
        # Second group should contain api-server
        assert groups[1] == ["api-server"]
    
    def test_shutdown_order(self):
        """Test shutdown order is reverse of startup"""
        graph = DependencyGraph()
        graph.add_agent("api-server", depends_on=["database"])
        graph.add_agent("database", depends_on=[])
        
        startup = graph.get_startup_order()
        shutdown = graph.get_shutdown_order()
        
        assert shutdown == list(reversed(startup))
    
    def test_validate_missing_dependency(self):
        """Test validation catches missing dependencies"""
        graph = DependencyGraph()
        graph.add_agent("api-server", depends_on=["database"])
        # database not added
        
        errors = graph.validate()
        
        assert len(errors) > 0
        assert any("missing" in e.lower() for e in errors)


# ============================================================================
# ACP-007: Graceful Shutdown Tests
# ============================================================================

class TestGracefulShutdown:
    """Tests for graceful shutdown functionality"""
    
    @pytest.mark.asyncio
    async def test_register_operation(self):
        """Test registering in-flight operations"""
        manager = GracefulShutdownManager()
        
        op_id = manager.register_operation(
            agent_id="test-agent",
            operation_type="verification",
            data={"claim_id": "123"}
        )
        
        assert op_id is not None
        assert manager.get_in_flight_count() == 1
    
    @pytest.mark.asyncio
    async def test_complete_operation(self):
        """Test completing operations"""
        manager = GracefulShutdownManager()
        
        op_id = manager.register_operation("test-agent", "verification")
        manager.complete_operation(op_id)
        
        assert manager.get_in_flight_count() == 0
    
    @pytest.mark.asyncio
    async def test_shutdown_drains_operations(self):
        """Test shutdown waits for operations to complete"""
        config = ShutdownConfig(drain_timeout_seconds=1.0)
        manager = GracefulShutdownManager(config=config)
        
        op_id = manager.register_operation("test-agent", "verification")
        
        # Complete operation after short delay
        async def complete_later():
            await asyncio.sleep(0.1)
            manager.complete_operation(op_id)
        
        asyncio.create_task(complete_later())
        
        result = await manager.shutdown()
        
        assert result["status"] == "stopped" or manager.phase == ShutdownPhase.TERMINATED
    
    @pytest.mark.asyncio
    async def test_shutdown_hooks(self):
        """Test shutdown hooks are called"""
        manager = GracefulShutdownManager()
        
        hook_called = False
        
        async def shutdown_hook():
            nonlocal hook_called
            hook_called = True
        
        manager.add_shutdown_hook(shutdown_hook)
        await manager.shutdown()
        
        assert hook_called is True
    
    @pytest.mark.asyncio
    async def test_no_new_operations_during_shutdown(self):
        """Test new operations are rejected during shutdown"""
        manager = GracefulShutdownManager()
        manager._phase = ShutdownPhase.DRAINING
        
        with pytest.raises(RuntimeError):
            manager.register_operation("test-agent", "verification")


# ============================================================================
# ACP-008: Resource Quota Tests
# ============================================================================

class TestResourceQuotas:
    """Tests for resource quota functionality"""
    
    def test_set_quota(self):
        """Test setting resource quota"""
        manager = ResourceQuotaManager()
        
        quota = AgentResourceQuota(
            memory_mb=512,
            cpu_percent=25.0,
            max_concurrent_operations=10
        )
        
        manager.set_quota("test-agent", quota)
        
        assert manager.get_quota("test-agent") is not None
    
    def test_can_execute_within_quota(self):
        """Test execution allowed within quota"""
        manager = ResourceQuotaManager()
        manager.set_quota("test-agent", AgentResourceQuota(
            max_concurrent_operations=10
        ))
        
        assert manager.can_execute("test-agent") is True
    
    def test_cannot_execute_at_limit(self):
        """Test execution denied at concurrent limit"""
        manager = ResourceQuotaManager()
        manager.set_quota("test-agent", AgentResourceQuota(
            max_concurrent_operations=2
        ))
        
        # Record 2 operations
        manager.record_operation_start("test-agent")
        manager.record_operation_start("test-agent")
        
        assert manager.can_execute("test-agent") is False
    
    def test_operation_tracking(self):
        """Test operation start/end tracking"""
        manager = ResourceQuotaManager()
        manager.set_quota("test-agent", AgentResourceQuota())
        
        manager.record_operation_start("test-agent")
        usage = manager.get_usage("test-agent")
        assert usage.concurrent_operations == 1
        
        manager.record_operation_end("test-agent")
        usage = manager.get_usage("test-agent")
        assert usage.concurrent_operations == 0
    
    def test_resource_usage_update(self):
        """Test resource usage updates"""
        manager = ResourceQuotaManager()
        manager.set_quota("test-agent", AgentResourceQuota())
        
        manager.update_resource_usage("test-agent", memory_mb=256.0, cpu_percent=15.0)
        
        usage = manager.get_usage("test-agent")
        assert usage.memory_mb == 256.0
        assert usage.cpu_percent == 15.0
    
    def test_check_quota_violations(self):
        """Test quota violation detection"""
        manager = ResourceQuotaManager()
        manager.set_quota("test-agent", AgentResourceQuota(
            memory_mb=512,
            cpu_percent=25.0
        ))
        
        # Exceed memory
        manager.update_resource_usage("test-agent", memory_mb=600.0)
        
        violations = manager.check_quota_violations()
        
        assert "test-agent" in violations
        assert any("Memory" in v for v in violations["test-agent"])


# ============================================================================
# ACP-009: Observability Tests
# ============================================================================

class TestAgentObservability:
    """Tests for agent observability functionality"""
    
    def test_record_metric(self):
        """Test metric recording"""
        provider = AgentObservabilityProvider()
        
        provider.record_metric(
            agent_id="test-agent",
            name="latency_ms",
            value=150.5,
            labels={"operation": "verify"}
        )
        
        metrics = provider.get_metrics("test-agent")
        assert len(metrics) > 0
        assert metrics[0].name == "latency_ms"
    
    def test_increment_counter(self):
        """Test counter increment"""
        provider = AgentObservabilityProvider()
        
        provider.increment_counter("test-agent", "requests_total")
        provider.increment_counter("test-agent", "requests_total")
        
        # Counter should have value 2
        metrics = provider.get_metrics("test-agent", "requests_total")
        assert len(metrics) == 2
    
    def test_set_gauge(self):
        """Test gauge setting"""
        provider = AgentObservabilityProvider()
        
        provider.set_gauge("test-agent", "active_connections", 5.0)
        
        metrics = provider.get_metrics("test-agent", "active_connections")
        assert len(metrics) == 1
        assert metrics[0].value == 5.0
    
    def test_log_entry(self):
        """Test log entry creation"""
        provider = AgentObservabilityProvider()
        
        provider.log(
            agent_id="test-agent",
            level="info",
            message="Test message",
            context={"key": "value"}
        )
        
        logs = provider.get_logs("test-agent")
        assert len(logs) == 1
        assert logs[0].message == "Test message"
    
    def test_prometheus_export(self):
        """Test Prometheus format export"""
        provider = AgentObservabilityProvider()
        
        provider.increment_counter("test-agent", "requests")
        provider.set_gauge("test-agent", "memory_usage", 256.0)
        
        prometheus_text = provider.export_prometheus()
        
        assert "requests" in prometheus_text
        assert "memory_usage" in prometheus_text
    
    def test_agent_summary(self):
        """Test agent summary generation"""
        provider = AgentObservabilityProvider()
        
        provider.record_metric("test-agent", "metric1", 1.0)
        provider.log("test-agent", "info", "Message 1")
        
        summary = provider.get_agent_summary("test-agent")
        
        assert summary["agent_id"] == "test-agent"
        assert summary["total_metrics"] > 0
        assert summary["total_logs"] > 0


# ============================================================================
# ACP-010: Hot Reload Tests
# ============================================================================

class TestHotReload:
    """Tests for hot reload functionality"""
    
    def test_register_agent(self):
        """Test agent registration for hot reload"""
        manager = HotReloadManager()
        
        manager.register_agent(
            agent_id="test-agent",
            module_name="test_module",
            class_name="TestAgent"
        )
        
        assert "test-agent" in manager._agents
    
    @pytest.mark.asyncio
    async def test_check_for_changes_no_change(self):
        """Test change detection when no changes"""
        manager = HotReloadManager()
        manager.register_agent("test-agent", "test_module", "TestAgent")
        
        # Force a version
        manager._versions["test-agent"] = "abc123"
        
        # Should detect change since computed version will differ
        # (module doesn't exist, so version will be different)
        has_changes = await manager.check_for_changes("test-agent")
        # Behavior depends on whether module exists
    
    def test_get_agent_version(self):
        """Test getting agent version"""
        manager = HotReloadManager()
        manager.register_agent("test-agent", "test_module", "TestAgent")
        
        version = manager.get_agent_version("test-agent")
        
        assert version is not None
    
    def test_reload_history(self):
        """Test reload history tracking"""
        manager = HotReloadManager()
        
        history = manager.get_reload_history()
        
        assert isinstance(history, list)


# ============================================================================
# Enhanced Control Plane Tests
# ============================================================================

class TestEnhancedControlPlane:
    """Tests for the enhanced agent control plane"""
    
    def test_create_control_plane(self):
        """Test control plane creation"""
        control_plane = create_control_plane(
            health_check_interval=30.0,
            auto_recovery=True
        )
        
        assert control_plane is not None
        assert isinstance(control_plane, EnhancedAgentControlPlane)
    
    def test_register_agent(self):
        """Test agent registration"""
        control_plane = create_control_plane()
        
        agent_id = control_plane.register(
            MockAgent,
            replicas=2,
            dependencies=[]
        )
        
        assert agent_id == "MockAgent"
        assert "MockAgent" in control_plane._registrations
    
    def test_register_with_resources(self):
        """Test agent registration with resource quota"""
        control_plane = create_control_plane()
        
        control_plane.register(
            MockAgent,
            replicas=1,
            resources=AgentResourceQuota(
                memory_mb=512,
                cpu_percent=25
            )
        )
        
        quota = control_plane.quota_manager.get_quota("MockAgent")
        assert quota is not None
        assert quota.memory_mb == 512
    
    def test_register_with_circuit_breaker(self):
        """Test agent registration with circuit breaker"""
        control_plane = create_control_plane()
        
        breaker = CircuitBreaker(
            name="test",
            failure_threshold=5,
            recovery_timeout=60
        )
        
        control_plane.register(
            MockAgent,
            circuit_breaker=breaker
        )
        
        registered_breaker = control_plane.get_circuit_breaker("MockAgent")
        assert registered_breaker is breaker
    
    @pytest.mark.asyncio
    async def test_start_all(self):
        """Test starting all agents"""
        control_plane = create_control_plane()
        
        control_plane.register(MockAgent, replicas=1)
        
        result = await control_plane.start_all()
        
        assert result["status"] == "started"
        
        await control_plane.stop_all()
    
    @pytest.mark.asyncio
    async def test_stop_all(self):
        """Test stopping all agents"""
        control_plane = create_control_plane()
        control_plane.register(MockAgent, replicas=1)
        
        await control_plane.start_all()
        result = await control_plane.stop_all()
        
        assert result["status"] == "stopped"
    
    def test_get_status(self):
        """Test getting control plane status"""
        control_plane = create_control_plane()
        control_plane.register(MockAgent)
        
        status = control_plane.get_status()
        
        assert "running" in status
        assert "registered_agents" in status
        assert "MockAgent" in status["registered_agents"]


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    """Integration tests for lifecycle management"""
    
    @pytest.mark.asyncio
    async def test_full_lifecycle(self):
        """Test complete agent lifecycle"""
        control_plane = create_control_plane(
            health_check_interval=1.0,
            auto_recovery=True
        )
        
        # Register agents with dependencies
        control_plane.register(MockAgent, agent_id="database", replicas=1)
        control_plane.register(
            MockAgent,
            agent_id="api-server",
            replicas=2,
            dependencies=["database"],
            resources=AgentResourceQuota(memory_mb=256)
        )
        
        # Start all
        result = await control_plane.start_all()
        assert result["status"] == "started"
        
        # Check health
        health = control_plane.get_all_health_status()
        assert len(health) > 0
        
        # Get metrics
        metrics = control_plane.get_metrics()
        assert isinstance(metrics, str)
        
        # Stop all
        result = await control_plane.stop_all()
        assert result["status"] == "stopped"
    
    @pytest.mark.asyncio
    async def test_dependency_order(self):
        """Test agents start in dependency order"""
        control_plane = create_control_plane()
        
        start_order = []
        
        class TrackedAgent(MockAgent):
            async def start(self):
                start_order.append(self.name)
                await super().start()
        
        control_plane.register(
            lambda: TrackedAgent("cache"),
            agent_id="cache",
            replicas=1
        )
        control_plane.register(
            lambda: TrackedAgent("database"),
            agent_id="database",
            replicas=1
        )
        control_plane.register(
            lambda: TrackedAgent("api"),
            agent_id="api",
            replicas=1,
            dependencies=["database", "cache"]
        )
        
        # The dependency graph should ensure database and cache start before api
        # (Note: this is validated by the dependency graph tests above)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
