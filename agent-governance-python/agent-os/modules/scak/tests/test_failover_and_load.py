# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for failover, health monitoring, and load testing.
"""

import pytest
import asyncio
from src.kernel.failover import (
    CircuitBreaker,
    CircuitState,
    HealthMonitor,
    HealthStatus,
    FailoverManager
)
from src.kernel.load_testing import (
    LoadTester,
    LoadProfile
)


class TestCircuitBreaker:
    """Test circuit breaker pattern."""
    
    @pytest.fixture
    def breaker(self):
        """Create circuit breaker."""
        return CircuitBreaker(
            "test_service",
            failure_threshold=3,
            timeout_seconds=2
        )
    
    @pytest.mark.asyncio
    async def test_circuit_closed_success(self, breaker):
        """Test circuit stays closed on success."""
        async def successful_call():
            return "success"
        
        result = await breaker.call(successful_call)
        
        assert result == "success"
        assert breaker.state == CircuitState.CLOSED
        assert breaker.failure_count == 0
    
    @pytest.mark.asyncio
    async def test_circuit_opens_on_failures(self, breaker):
        """Test circuit opens after threshold failures."""
        call_count = 0
        
        async def failing_call():
            nonlocal call_count
            call_count += 1
            raise RuntimeError("Service down")
        
        # Make calls until circuit opens
        for i in range(breaker.failure_threshold):
            try:
                await breaker.call(failing_call)
            except RuntimeError:
                pass
        
        assert breaker.state == CircuitState.OPEN
        assert breaker.failure_count >= breaker.failure_threshold
    
    @pytest.mark.asyncio
    async def test_circuit_uses_fallback_when_open(self, breaker):
        """Test fallback is used when circuit open."""
        from datetime import datetime
        
        # Force circuit open
        breaker.state = CircuitState.OPEN
        breaker.last_failure_time = datetime.now()
        
        async def main_call():
            raise RuntimeError("Not available")
        
        async def fallback_call():
            return "fallback_result"
        
        result = await breaker.call(main_call, fallback=fallback_call)
        
        assert result == "fallback_result"
    
    @pytest.mark.asyncio
    async def test_circuit_rejects_without_fallback(self, breaker):
        """Test circuit rejects calls when open and no fallback."""
        from datetime import datetime
        
        # Force circuit open
        breaker.state = CircuitState.OPEN
        breaker.last_failure_time = datetime.now()
        
        async def main_call():
            return "success"
        
        with pytest.raises(RuntimeError, match="OPEN"):
            await breaker.call(main_call)
    
    def test_get_stats(self, breaker):
        """Test getting circuit breaker stats."""
        breaker.failure_count = 5
        breaker.success_count = 10
        
        stats = breaker.get_stats()
        
        assert stats["name"] == "test_service"
        assert stats["state"] == CircuitState.CLOSED.value
        assert stats["failure_count"] == 5
        assert stats["success_count"] == 10


class TestHealthMonitor:
    """Test health monitoring."""
    
    @pytest.fixture
    def monitor(self):
        """Create health monitor."""
        return HealthMonitor(
            check_interval_seconds=1,
            unhealthy_threshold=2
        )
    
    @pytest.mark.asyncio
    async def test_register_component(self, monitor):
        """Test registering component for monitoring."""
        async def health_check():
            return True
        
        monitor.register_component(
            "component-1",
            "agent",
            health_check
        )
        
        assert "component-1" in monitor.components
        assert "component-1" in monitor.health_checks
    
    @pytest.mark.asyncio
    async def test_check_healthy_component(self, monitor):
        """Test checking healthy component."""
        async def health_check():
            return True
        
        monitor.register_component("comp-1", "agent", health_check)
        
        status = await monitor.check_component("comp-1")
        
        assert status == HealthStatus.HEALTHY
        assert monitor.components["comp-1"].consecutive_failures == 0
    
    @pytest.mark.asyncio
    async def test_check_unhealthy_component(self, monitor):
        """Test component becomes unhealthy after threshold."""
        call_count = 0
        
        async def health_check():
            nonlocal call_count
            call_count += 1
            return False  # Always fails
        
        monitor.register_component("comp-1", "agent", health_check)
        
        # Check multiple times
        for _ in range(monitor.unhealthy_threshold):
            await monitor.check_component("comp-1")
        
        status = await monitor.check_component("comp-1")
        
        assert status == HealthStatus.UNHEALTHY
        assert monitor.components["comp-1"].consecutive_failures >= monitor.unhealthy_threshold
    
    @pytest.mark.asyncio
    async def test_system_health_aggregation(self, monitor):
        """Test aggregated system health."""
        async def healthy_check():
            return True
        
        async def unhealthy_check():
            return False
        
        monitor.register_component("comp-1", "agent", healthy_check)
        monitor.register_component("comp-2", "agent", unhealthy_check)
        
        # Check both
        await monitor.check_component("comp-1")
        
        for _ in range(monitor.unhealthy_threshold + 1):
            await monitor.check_component("comp-2")
        
        health = monitor.get_system_health()
        
        assert health["overall"] == HealthStatus.UNHEALTHY.value
        assert "comp-1" in health["components"]
        assert "comp-2" in health["components"]
    
    @pytest.mark.asyncio
    async def test_continuous_monitoring(self, monitor):
        """Test starting and stopping monitoring."""
        async def health_check():
            return True
        
        monitor.register_component("comp-1", "agent", health_check)
        
        # Start monitoring
        await monitor.start_monitoring()
        assert monitor.monitoring is True
        
        # Let it run briefly
        await asyncio.sleep(0.5)
        
        # Stop monitoring
        await monitor.stop_monitoring()
        assert monitor.monitoring is False


class TestFailoverManager:
    """Test failover management."""
    
    @pytest.fixture
    def manager(self):
        """Create failover manager."""
        monitor = HealthMonitor()
        
        # Track health states
        health_states = {
            "primary": True,
            "backup": True
        }
        
        # Register components with mocked checks
        async def primary_check():
            return health_states["primary"]
        
        async def backup_check():
            return health_states["backup"]
        
        monitor.register_component("primary", "agent", primary_check)
        monitor.register_component("backup", "agent", backup_check)
        
        manager = FailoverManager(monitor)
        manager._health_states = health_states  # Store for test manipulation
        
        return manager
    
    def test_register_backup(self, manager):
        """Test registering backup component."""
        manager.register_backup("primary", "backup")
        
        assert "primary" in manager.backups
        assert "backup" in manager.backups["primary"]
        assert manager.active["primary"] == "primary"
    
    @pytest.mark.asyncio
    async def test_failover_on_primary_failure(self, manager):
        """Test automatic failover when primary fails."""
        manager.register_backup("primary", "backup")
        
        # Make primary return unhealthy
        manager._health_states["primary"] = False
        
        # Need to fail multiple times to reach unhealthy threshold
        for _ in range(3):
            await manager.health_monitor.check_component("primary")
        
        active = await manager.get_active_component("primary")
        
        # Should failover to backup
        assert active == "backup"
        assert manager.active["primary"] == "backup"
    
    @pytest.mark.asyncio
    async def test_failback_when_primary_recovers(self, manager):
        """Test failback to primary when it recovers AND backup fails."""
        manager.register_backup("primary", "backup")
        
        # Initially make primary fail, causing failover to backup
        manager._health_states["primary"] = False
        
        # Fail primary multiple times to reach unhealthy
        for _ in range(3):
            await manager.health_monitor.check_component("primary")
        
        await manager.get_active_component("primary")
        assert manager.active["primary"] == "backup"
        
        # Now make primary healthy again AND backup fail
        manager._health_states["primary"] = True
        manager._health_states["backup"] = False
        
        # Fail backup to trigger failback
        for _ in range(3):
            await manager.health_monitor.check_component("backup")
        
        active = await manager.get_active_component("primary")
        
        # Should failback to primary (since backup is now unhealthy)
        assert active == "primary"
        assert manager.active["primary"] == "primary"
    
    def test_get_failover_stats(self, manager):
        """Test getting failover statistics."""
        manager.register_backup("comp-1", "backup-1")
        manager.register_backup("comp-2", "backup-2")
        
        # Simulate failover
        manager.active["comp-1"] = "backup-1"
        
        stats = manager.get_failover_stats()
        
        assert stats["primary_components"] == 2
        assert stats["total_backups"] == 2
        assert "comp-1" in stats["failovers"]
        assert stats["failovers"]["comp-1"] == "backup-1"


class TestLoadTester:
    """Test load testing framework."""
    
    @pytest.fixture
    def tester(self):
        """Create load tester."""
        return LoadTester()
    
    @pytest.mark.asyncio
    async def test_ramp_up_load_test(self, tester):
        """Test ramp-up load profile."""
        call_count = 0
        
        async def target_function():
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.01)  # Simulate work
        
        result = await tester.run_load_test(
            target_function,
            profile=LoadProfile.RAMP_UP,
            total_requests=50,
            concurrent_requests=10,
            ramp_up_seconds=1
        )
        
        assert result.status.value == "completed"
        assert result.total_requests == 50
        assert result.successful_requests > 0
        assert result.requests_per_second > 0
        assert result.latency_mean > 0
    
    @pytest.mark.asyncio
    async def test_spike_load_test(self, tester):
        """Test spike load profile."""
        async def target_function():
            await asyncio.sleep(0.01)
        
        result = await tester.run_load_test(
            target_function,
            profile=LoadProfile.SPIKE,
            total_requests=30,
            concurrent_requests=15
        )
        
        assert result.status.value == "completed"
        assert result.total_requests == 30
    
    @pytest.mark.asyncio
    async def test_endurance_load_test(self, tester):
        """Test endurance load profile."""
        async def target_function():
            await asyncio.sleep(0.01)
        
        result = await tester.run_load_test(
            target_function,
            profile=LoadProfile.ENDURANCE,
            duration_seconds=1,
            concurrent_requests=5
        )
        
        assert result.status.value == "completed"
        assert result.duration_seconds >= 0.5  # At least half the duration
    
    @pytest.mark.asyncio
    async def test_error_rate_tracking(self, tester):
        """Test tracking error rate."""
        call_count = 0
        
        async def target_function():
            nonlocal call_count
            call_count += 1
            
            # Fail 20% of the time
            if call_count % 5 == 0:
                raise RuntimeError("Simulated failure")
            
            await asyncio.sleep(0.01)
        
        result = await tester.run_load_test(
            target_function,
            profile=LoadProfile.RAMP_UP,
            total_requests=50,
            concurrent_requests=10
        )
        
        assert result.failed_requests > 0
        assert result.error_rate > 0
        assert result.error_rate < 1.0  # Not all failed
    
    @pytest.mark.asyncio
    async def test_latency_percentiles(self, tester):
        """Test latency percentile calculation."""
        async def target_function():
            await asyncio.sleep(0.02)  # Consistent 20ms
        
        result = await tester.run_load_test(
            target_function,
            profile=LoadProfile.SPIKE,
            total_requests=20,
            concurrent_requests=5
        )
        
        # Check latency metrics are calculated
        assert result.latency_min > 0
        assert result.latency_max > 0
        assert result.latency_mean > 0
        assert result.latency_median > 0
        assert result.latency_p95 > 0
        assert result.latency_p99 > 0
        
        # p99 should be >= p95 >= median
        assert result.latency_p99 >= result.latency_p95
        assert result.latency_p95 >= result.latency_median
    
    def test_list_tests(self, tester):
        """Test listing completed tests."""
        # Initially empty
        tests = tester.list_tests()
        assert len(tests) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
