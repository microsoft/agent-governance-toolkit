# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Lifecycle Management - v0.2.0

This module provides comprehensive lifecycle management for autonomous AI agents,
including health monitoring, auto-recovery, circuit breakers, scaling, distributed
coordination, dependency management, graceful shutdown, resource quotas, observability,
and hot reload capabilities.

Features:
    - ACP-001: Agent Health Checks (liveness/readiness probes)
    - ACP-002: Agent Auto-Recovery (automatic restart of crashed agents)
    - ACP-003: Circuit Breaker (prevent cascading failures)
    - ACP-004: Agent Scaling (horizontal scaling for high-throughput)
    - ACP-005: Distributed Coordination (leader election, consensus)
    - ACP-006: Agent Dependency Graph (enforced start order)
    - ACP-007: Graceful Shutdown (preserve in-flight verifications)
    - ACP-008: Resource Quotas (memory/CPU limits per agent)
    - ACP-009: Agent Observability (metrics/logging integration)
    - ACP-010: Hot Reload (code changes without full restart)

Research Foundations:
    - Circuit Breaker pattern (Michael Nygard, "Release It!")
    - Kubernetes probe patterns (liveness, readiness, startup)
    - Raft consensus algorithm (Ongaro & Ousterhout, 2014)
    - Actor model supervision (Erlang/OTP, Akka)
"""

from typing import (
    Dict, List, Optional, Any, Union, Callable, Type, Set, Awaitable,
    TypeVar, Generic, Protocol, runtime_checkable
)
from dataclasses import dataclass, field
from enum import Enum, auto
from datetime import datetime, timedelta
from collections import defaultdict, deque
from abc import ABC, abstractmethod
import asyncio
import time
import uuid
import logging
import threading
import weakref
import traceback
import hashlib
import importlib
import sys


# Configure module logger
logger = logging.getLogger(__name__)


# ============================================================================
# Enums and Constants
# ============================================================================

class HealthStatus(Enum):
    """Health status of an agent"""
    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    DEGRADED = "degraded"
    STARTING = "starting"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


class AgentState(Enum):
    """State of an agent in the lifecycle"""
    REGISTERED = "registered"
    PENDING = "pending"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"
    RECOVERING = "recovering"


class CircuitState(Enum):
    """State of a circuit breaker"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing recovery


class CoordinationRole(Enum):
    """Role in distributed coordination"""
    LEADER = "leader"
    FOLLOWER = "follower"
    CANDIDATE = "candidate"


class ShutdownPhase(Enum):
    """Phases of graceful shutdown"""
    RUNNING = "running"
    DRAINING = "draining"
    STOPPING = "stopping"
    TERMINATED = "terminated"


# ============================================================================
# ACP-001: Agent Health Checks
# ============================================================================

@dataclass
class HealthCheckResult:
    """Result of a health check probe"""
    healthy: bool
    status: HealthStatus
    message: str = ""
    latency_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HealthCheckConfig:
    """Configuration for health check probes"""
    # Liveness probe settings
    liveness_interval_seconds: float = 10.0
    liveness_timeout_seconds: float = 5.0
    liveness_failure_threshold: int = 3
    
    # Readiness probe settings
    readiness_interval_seconds: float = 5.0
    readiness_timeout_seconds: float = 3.0
    readiness_failure_threshold: int = 1
    
    # Startup probe settings (for slow-starting agents)
    startup_probe_enabled: bool = True
    startup_timeout_seconds: float = 60.0
    startup_period_seconds: float = 5.0
    
    # Custom health check function
    custom_health_check: Optional[Callable[[], Awaitable[bool]]] = None


@runtime_checkable
class HealthCheckable(Protocol):
    """Protocol for agents that support health checks"""
    
    async def liveness_check(self) -> bool:
        """Check if the agent is alive (not deadlocked/crashed)"""
        ...
    
    async def readiness_check(self) -> bool:
        """Check if the agent is ready to accept requests"""
        ...


class HealthMonitor:
    """
    Monitors agent health via liveness and readiness probes.
    
    Implements Kubernetes-style health checking patterns:
    - Liveness: Is the agent alive? If not, restart it.
    - Readiness: Is the agent ready to accept requests?
    - Startup: Has the agent finished starting up?
    
    Usage:
        monitor = HealthMonitor(config=HealthCheckConfig())
        
        # Register an agent
        monitor.register_agent(agent_id, agent_instance)
        
        # Start monitoring
        await monitor.start()
        
        # Check status
        status = monitor.get_agent_health(agent_id)
    """
    
    def __init__(self, config: Optional[HealthCheckConfig] = None):
        self.config = config or HealthCheckConfig()
        self._agents: Dict[str, Any] = {}
        self._health_status: Dict[str, HealthStatus] = {}
        self._liveness_failures: Dict[str, int] = defaultdict(int)
        self._readiness_failures: Dict[str, int] = defaultdict(int)
        self._last_check: Dict[str, datetime] = {}
        self._check_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self._running = False
        self._tasks: List[asyncio.Task] = []
        self._callbacks: Dict[str, List[Callable]] = defaultdict(list)
        self._lock = asyncio.Lock()
    
    def register_agent(
        self,
        agent_id: str,
        agent: Any,
        custom_liveness: Optional[Callable[[], Awaitable[bool]]] = None,
        custom_readiness: Optional[Callable[[], Awaitable[bool]]] = None
    ) -> None:
        """Register an agent for health monitoring"""
        self._agents[agent_id] = {
            "agent": agent,
            "custom_liveness": custom_liveness,
            "custom_readiness": custom_readiness,
            "registered_at": datetime.now()
        }
        self._health_status[agent_id] = HealthStatus.UNKNOWN
        logger.info(f"Registered agent {agent_id} for health monitoring")
    
    def unregister_agent(self, agent_id: str) -> None:
        """Unregister an agent from health monitoring"""
        if agent_id in self._agents:
            del self._agents[agent_id]
            self._health_status.pop(agent_id, None)
            self._liveness_failures.pop(agent_id, None)
            self._readiness_failures.pop(agent_id, None)
            logger.info(f"Unregistered agent {agent_id} from health monitoring")
    
    async def start(self) -> None:
        """Start the health monitoring loop"""
        if self._running:
            return
        
        self._running = True
        self._tasks.append(asyncio.create_task(self._liveness_loop()))
        self._tasks.append(asyncio.create_task(self._readiness_loop()))
        logger.info("Health monitor started")
    
    async def stop(self) -> None:
        """Stop the health monitoring loop"""
        self._running = False
        for task in self._tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._tasks.clear()
        logger.info("Health monitor stopped")
    
    async def _liveness_loop(self) -> None:
        """Main loop for liveness checks"""
        while self._running:
            for agent_id in list(self._agents.keys()):
                try:
                    result = await self._check_liveness(agent_id)
                    self._check_history[agent_id].append(result)
                    
                    if not result.healthy:
                        self._liveness_failures[agent_id] += 1
                        if self._liveness_failures[agent_id] >= self.config.liveness_failure_threshold:
                            self._health_status[agent_id] = HealthStatus.FAILED
                            await self._trigger_callbacks("liveness_failed", agent_id)
                    else:
                        self._liveness_failures[agent_id] = 0
                        if self._health_status[agent_id] == HealthStatus.FAILED:
                            self._health_status[agent_id] = HealthStatus.HEALTHY
                            await self._trigger_callbacks("liveness_restored", agent_id)
                            
                except Exception as e:
                    logger.error(f"Liveness check failed for {agent_id}: {e}")
                    self._liveness_failures[agent_id] += 1
            
            await asyncio.sleep(self.config.liveness_interval_seconds)
    
    async def _readiness_loop(self) -> None:
        """Main loop for readiness checks"""
        while self._running:
            for agent_id in list(self._agents.keys()):
                try:
                    result = await self._check_readiness(agent_id)
                    
                    if not result.healthy:
                        self._readiness_failures[agent_id] += 1
                        if self._readiness_failures[agent_id] >= self.config.readiness_failure_threshold:
                            if self._health_status[agent_id] == HealthStatus.HEALTHY:
                                self._health_status[agent_id] = HealthStatus.DEGRADED
                                await self._trigger_callbacks("readiness_failed", agent_id)
                    else:
                        self._readiness_failures[agent_id] = 0
                        if self._health_status[agent_id] == HealthStatus.DEGRADED:
                            self._health_status[agent_id] = HealthStatus.HEALTHY
                            await self._trigger_callbacks("readiness_restored", agent_id)
                            
                except Exception as e:
                    logger.error(f"Readiness check failed for {agent_id}: {e}")
                    self._readiness_failures[agent_id] += 1
            
            await asyncio.sleep(self.config.readiness_interval_seconds)
    
    async def _check_liveness(self, agent_id: str) -> HealthCheckResult:
        """Perform liveness check for an agent"""
        start_time = time.time()
        agent_info = self._agents.get(agent_id)
        
        if not agent_info:
            return HealthCheckResult(
                healthy=False,
                status=HealthStatus.UNKNOWN,
                message="Agent not found"
            )
        
        agent = agent_info["agent"]
        custom_check = agent_info.get("custom_liveness")
        
        try:
            # Try custom liveness check first
            if custom_check:
                healthy = await asyncio.wait_for(
                    custom_check(),
                    timeout=self.config.liveness_timeout_seconds
                )
            # Try protocol method
            elif isinstance(agent, HealthCheckable):
                healthy = await asyncio.wait_for(
                    agent.liveness_check(),
                    timeout=self.config.liveness_timeout_seconds
                )
            # Fallback: check if agent has is_alive method
            elif hasattr(agent, 'is_alive'):
                if asyncio.iscoroutinefunction(agent.is_alive):
                    healthy = await asyncio.wait_for(
                        agent.is_alive(),
                        timeout=self.config.liveness_timeout_seconds
                    )
                else:
                    healthy = agent.is_alive()
            else:
                # Default: assume healthy if agent exists
                healthy = True
            
            latency_ms = (time.time() - start_time) * 1000
            self._last_check[agent_id] = datetime.now()
            
            return HealthCheckResult(
                healthy=healthy,
                status=HealthStatus.HEALTHY if healthy else HealthStatus.UNHEALTHY,
                latency_ms=latency_ms
            )
            
        except asyncio.TimeoutError:
            return HealthCheckResult(
                healthy=False,
                status=HealthStatus.UNHEALTHY,
                message="Liveness check timed out",
                latency_ms=self.config.liveness_timeout_seconds * 1000
            )
        except Exception as e:
            return HealthCheckResult(
                healthy=False,
                status=HealthStatus.FAILED,
                message=str(e),
                latency_ms=(time.time() - start_time) * 1000
            )
    
    async def _check_readiness(self, agent_id: str) -> HealthCheckResult:
        """Perform readiness check for an agent"""
        start_time = time.time()
        agent_info = self._agents.get(agent_id)
        
        if not agent_info:
            return HealthCheckResult(
                healthy=False,
                status=HealthStatus.UNKNOWN,
                message="Agent not found"
            )
        
        agent = agent_info["agent"]
        custom_check = agent_info.get("custom_readiness")
        
        try:
            if custom_check:
                ready = await asyncio.wait_for(
                    custom_check(),
                    timeout=self.config.readiness_timeout_seconds
                )
            elif isinstance(agent, HealthCheckable):
                ready = await asyncio.wait_for(
                    agent.readiness_check(),
                    timeout=self.config.readiness_timeout_seconds
                )
            elif hasattr(agent, 'is_ready'):
                if asyncio.iscoroutinefunction(agent.is_ready):
                    ready = await asyncio.wait_for(
                        agent.is_ready(),
                        timeout=self.config.readiness_timeout_seconds
                    )
                else:
                    ready = agent.is_ready()
            else:
                ready = True
            
            latency_ms = (time.time() - start_time) * 1000
            
            return HealthCheckResult(
                healthy=ready,
                status=HealthStatus.HEALTHY if ready else HealthStatus.DEGRADED,
                latency_ms=latency_ms
            )
            
        except asyncio.TimeoutError:
            return HealthCheckResult(
                healthy=False,
                status=HealthStatus.DEGRADED,
                message="Readiness check timed out",
                latency_ms=self.config.readiness_timeout_seconds * 1000
            )
        except Exception as e:
            return HealthCheckResult(
                healthy=False,
                status=HealthStatus.DEGRADED,
                message=str(e),
                latency_ms=(time.time() - start_time) * 1000
            )
    
    def on_event(self, event: str, callback: Callable[[str], Awaitable[None]]) -> None:
        """Register a callback for health events"""
        self._callbacks[event].append(callback)
    
    async def _trigger_callbacks(self, event: str, agent_id: str) -> None:
        """Trigger all callbacks for an event"""
        for callback in self._callbacks.get(event, []):
            try:
                await callback(agent_id)
            except Exception as e:
                logger.error(f"Callback error for {event}: {e}")
    
    def get_agent_health(self, agent_id: str) -> HealthStatus:
        """Get the current health status of an agent"""
        return self._health_status.get(agent_id, HealthStatus.UNKNOWN)
    
    def get_all_health_status(self) -> Dict[str, HealthStatus]:
        """Get health status for all agents"""
        return dict(self._health_status)
    
    def get_health_history(self, agent_id: str) -> List[HealthCheckResult]:
        """Get health check history for an agent"""
        return list(self._check_history.get(agent_id, []))


# ============================================================================
# ACP-002: Agent Auto-Recovery
# ============================================================================

@dataclass
class RecoveryConfig:
    """Configuration for auto-recovery behavior"""
    enabled: bool = True
    max_restarts: int = 5
    restart_delay_seconds: float = 1.0
    restart_delay_max_seconds: float = 60.0
    restart_delay_multiplier: float = 2.0
    reset_restart_count_after_seconds: float = 300.0
    on_max_restarts: str = "stop"  # "stop", "alert", "continue"


@dataclass
class RecoveryEvent:
    """Record of a recovery event"""
    agent_id: str
    event_type: str  # "restart", "failure", "recovery_success", "max_restarts"
    timestamp: datetime = field(default_factory=datetime.now)
    attempt: int = 0
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


class AutoRecoveryManager:
    """
    Manages automatic recovery of failed agents.
    
    Implements exponential backoff for restart attempts and tracks
    recovery history for analysis.
    
    Features:
    - Automatic restart with exponential backoff
    - Maximum restart limit with configurable behavior
    - Recovery event logging
    - Callbacks for recovery events
    
    Usage:
        recovery = AutoRecoveryManager(config=RecoveryConfig())
        recovery.register_agent(agent_id, agent_factory)
        
        # When agent fails
        await recovery.handle_failure(agent_id, error)
    """
    
    def __init__(self, config: Optional[RecoveryConfig] = None):
        self.config = config or RecoveryConfig()
        self._agent_factories: Dict[str, Callable[[], Any]] = {}
        self._restart_counts: Dict[str, int] = defaultdict(int)
        self._last_restart: Dict[str, datetime] = {}
        self._current_delay: Dict[str, float] = {}
        self._recovery_history: deque = deque(maxlen=1000)
        self._callbacks: Dict[str, List[Callable]] = defaultdict(list)
        self._agents: Dict[str, Any] = {}
        self._lock = asyncio.Lock()
    
    def register_agent(
        self,
        agent_id: str,
        factory: Callable[[], Any],
        initial_instance: Optional[Any] = None
    ) -> None:
        """Register an agent with its factory function for recovery"""
        self._agent_factories[agent_id] = factory
        if initial_instance:
            self._agents[agent_id] = initial_instance
        self._restart_counts[agent_id] = 0
        self._current_delay[agent_id] = self.config.restart_delay_seconds
        logger.info(f"Registered agent {agent_id} for auto-recovery")
    
    def unregister_agent(self, agent_id: str) -> None:
        """Unregister an agent from auto-recovery"""
        self._agent_factories.pop(agent_id, None)
        self._agents.pop(agent_id, None)
        self._restart_counts.pop(agent_id, None)
        self._last_restart.pop(agent_id, None)
        self._current_delay.pop(agent_id, None)
    
    async def handle_failure(
        self,
        agent_id: str,
        error: Optional[Exception] = None
    ) -> Optional[Any]:
        """
        Handle an agent failure and attempt recovery.
        
        Returns the new agent instance if recovery succeeds, None otherwise.
        """
        if not self.config.enabled:
            logger.info(f"Auto-recovery disabled, not recovering {agent_id}")
            return None
        
        async with self._lock:
            # Check if we should reset restart count
            if agent_id in self._last_restart:
                time_since_last = (datetime.now() - self._last_restart[agent_id]).total_seconds()
                if time_since_last > self.config.reset_restart_count_after_seconds:
                    self._restart_counts[agent_id] = 0
                    self._current_delay[agent_id] = self.config.restart_delay_seconds
            
            # Check if max restarts reached
            if self._restart_counts[agent_id] >= self.config.max_restarts:
                event = RecoveryEvent(
                    agent_id=agent_id,
                    event_type="max_restarts",
                    attempt=self._restart_counts[agent_id],
                    error=str(error) if error else None
                )
                self._recovery_history.append(event)
                await self._trigger_callbacks("max_restarts", agent_id, event)
                
                if self.config.on_max_restarts == "stop":
                    logger.error(f"Max restarts reached for {agent_id}, stopping")
                    return None
                elif self.config.on_max_restarts == "alert":
                    logger.warning(f"Max restarts reached for {agent_id}, alerting")
                    await self._trigger_callbacks("alert", agent_id, event)
                # "continue" falls through to attempt restart anyway
            
            # Calculate delay with exponential backoff
            delay = self._current_delay.get(agent_id, self.config.restart_delay_seconds)
            
            # Log failure event
            failure_event = RecoveryEvent(
                agent_id=agent_id,
                event_type="failure",
                attempt=self._restart_counts[agent_id],
                error=str(error) if error else None
            )
            self._recovery_history.append(failure_event)
            await self._trigger_callbacks("failure", agent_id, failure_event)
            
            logger.info(f"Attempting recovery for {agent_id} after {delay:.1f}s delay")
            await asyncio.sleep(delay)
            
            # Attempt restart
            try:
                factory = self._agent_factories.get(agent_id)
                if not factory:
                    logger.error(f"No factory registered for {agent_id}")
                    return None
                
                new_agent = factory()
                if asyncio.iscoroutine(new_agent):
                    new_agent = await new_agent
                
                # Start the agent if it has a start method
                if hasattr(new_agent, 'start'):
                    if asyncio.iscoroutinefunction(new_agent.start):
                        await new_agent.start()
                    else:
                        new_agent.start()
                
                self._agents[agent_id] = new_agent
                self._restart_counts[agent_id] += 1
                self._last_restart[agent_id] = datetime.now()
                
                # Increase delay for next potential failure (exponential backoff)
                self._current_delay[agent_id] = min(
                    delay * self.config.restart_delay_multiplier,
                    self.config.restart_delay_max_seconds
                )
                
                success_event = RecoveryEvent(
                    agent_id=agent_id,
                    event_type="recovery_success",
                    attempt=self._restart_counts[agent_id]
                )
                self._recovery_history.append(success_event)
                await self._trigger_callbacks("recovery_success", agent_id, success_event)
                
                logger.info(f"Successfully recovered agent {agent_id}")
                return new_agent
                
            except Exception as e:
                logger.error(f"Failed to recover agent {agent_id}: {e}")
                self._restart_counts[agent_id] += 1
                return await self.handle_failure(agent_id, e)
    
    def on_event(
        self,
        event: str,
        callback: Callable[[str, RecoveryEvent], Awaitable[None]]
    ) -> None:
        """Register a callback for recovery events"""
        self._callbacks[event].append(callback)
    
    async def _trigger_callbacks(
        self,
        event: str,
        agent_id: str,
        recovery_event: RecoveryEvent
    ) -> None:
        """Trigger all callbacks for an event"""
        for callback in self._callbacks.get(event, []):
            try:
                await callback(agent_id, recovery_event)
            except Exception as e:
                logger.error(f"Callback error for {event}: {e}")
    
    def get_agent(self, agent_id: str) -> Optional[Any]:
        """Get the current agent instance"""
        return self._agents.get(agent_id)
    
    def get_restart_count(self, agent_id: str) -> int:
        """Get the restart count for an agent"""
        return self._restart_counts.get(agent_id, 0)
    
    def get_recovery_history(
        self,
        agent_id: Optional[str] = None
    ) -> List[RecoveryEvent]:
        """Get recovery history, optionally filtered by agent"""
        if agent_id:
            return [e for e in self._recovery_history if e.agent_id == agent_id]
        return list(self._recovery_history)
    
    def reset_restart_count(self, agent_id: str) -> None:
        """Manually reset the restart count for an agent"""
        self._restart_counts[agent_id] = 0
        self._current_delay[agent_id] = self.config.restart_delay_seconds


# ============================================================================
# ACP-003: Circuit Breaker
# ============================================================================

@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker behavior"""
    failure_threshold: int = 5
    success_threshold: int = 3
    recovery_timeout_seconds: float = 60.0
    half_open_max_calls: int = 3
    exclude_exceptions: List[Type[Exception]] = field(default_factory=list)
    include_exceptions: Optional[List[Type[Exception]]] = None
    

@dataclass
class CircuitBreakerMetrics:
    """Metrics for a circuit breaker"""
    state: CircuitState
    failure_count: int
    success_count: int
    total_calls: int
    total_failures: int
    total_successes: int
    last_failure_time: Optional[datetime]
    last_success_time: Optional[datetime]
    state_changed_at: datetime


class CircuitBreaker:
    """
    Circuit breaker for preventing cascading failures.
    
    Implements the circuit breaker pattern to protect against cascading
    failures when an agent or service becomes unavailable.
    
    States:
    - CLOSED: Normal operation, requests pass through
    - OPEN: Failing, requests are rejected immediately
    - HALF_OPEN: Testing recovery, limited requests allowed
    
    Features:
    - Configurable failure/success thresholds
    - Automatic recovery timeout
    - Exception filtering
    - Metrics collection
    
    Usage:
        breaker = CircuitBreaker(
            config=CircuitBreakerConfig(
                failure_threshold=5,
                recovery_timeout=60
            )
        )
        
        # Use as decorator
        @breaker
        async def call_agent():
            ...
        
        # Or use context manager
        async with breaker:
            await call_agent()
    """
    
    def __init__(
        self,
        name: str = "default",
        config: Optional[CircuitBreakerConfig] = None,
        failure_threshold: Optional[int] = None,
        recovery_timeout: Optional[float] = None
    ):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        
        # Allow direct parameter override for convenience API
        if failure_threshold is not None:
            self.config.failure_threshold = failure_threshold
        if recovery_timeout is not None:
            self.config.recovery_timeout_seconds = recovery_timeout
        
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._half_open_calls = 0
        self._last_failure_time: Optional[datetime] = None
        self._last_success_time: Optional[datetime] = None
        self._state_changed_at = datetime.now()
        self._total_calls = 0
        self._total_failures = 0
        self._total_successes = 0
        self._lock = asyncio.Lock()
        self._callbacks: Dict[str, List[Callable]] = defaultdict(list)
    
    @property
    def state(self) -> CircuitState:
        """Get the current circuit state"""
        return self._state
    
    @property
    def is_closed(self) -> bool:
        """Check if circuit is closed (normal operation)"""
        return self._state == CircuitState.CLOSED
    
    @property
    def is_open(self) -> bool:
        """Check if circuit is open (rejecting requests)"""
        return self._state == CircuitState.OPEN
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self._before_call()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if exc_type is None:
            await self._on_success()
        else:
            if self._should_count_exception(exc_type):
                await self._on_failure(exc_val)
        return False
    
    def __call__(self, func: Callable) -> Callable:
        """Decorator for wrapping functions with circuit breaker"""
        async def wrapper(*args, **kwargs):
            await self._before_call()
            try:
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)
                await self._on_success()
                return result
            except Exception as e:
                if self._should_count_exception(type(e)):
                    await self._on_failure(e)
                raise
        return wrapper
    
    async def _before_call(self) -> None:
        """Check circuit state before a call"""
        async with self._lock:
            self._total_calls += 1
            
            if self._state == CircuitState.OPEN:
                # Check if recovery timeout has elapsed
                if self._last_failure_time:
                    elapsed = (datetime.now() - self._last_failure_time).total_seconds()
                    if elapsed >= self.config.recovery_timeout_seconds:
                        self._transition_to(CircuitState.HALF_OPEN)
                        self._half_open_calls = 0
                    else:
                        raise CircuitBreakerOpenError(
                            f"Circuit {self.name} is open, retry after "
                            f"{self.config.recovery_timeout_seconds - elapsed:.1f}s"
                        )
                else:
                    raise CircuitBreakerOpenError(f"Circuit {self.name} is open")
            
            elif self._state == CircuitState.HALF_OPEN:
                if self._half_open_calls >= self.config.half_open_max_calls:
                    raise CircuitBreakerOpenError(
                        f"Circuit {self.name} is half-open, max test calls reached"
                    )
                self._half_open_calls += 1
    
    async def _on_success(self) -> None:
        """Handle a successful call"""
        async with self._lock:
            self._total_successes += 1
            self._last_success_time = datetime.now()
            
            if self._state == CircuitState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.config.success_threshold:
                    self._transition_to(CircuitState.CLOSED)
            elif self._state == CircuitState.CLOSED:
                self._failure_count = 0
    
    async def _on_failure(self, error: Exception) -> None:
        """Handle a failed call"""
        async with self._lock:
            self._total_failures += 1
            self._last_failure_time = datetime.now()
            self._failure_count += 1
            
            if self._state == CircuitState.HALF_OPEN:
                # Any failure in half-open state opens the circuit
                self._transition_to(CircuitState.OPEN)
            elif self._state == CircuitState.CLOSED:
                if self._failure_count >= self.config.failure_threshold:
                    self._transition_to(CircuitState.OPEN)
    
    def _transition_to(self, new_state: CircuitState) -> None:
        """Transition to a new circuit state"""
        old_state = self._state
        self._state = new_state
        self._state_changed_at = datetime.now()
        
        if new_state == CircuitState.CLOSED:
            self._failure_count = 0
            self._success_count = 0
        elif new_state == CircuitState.HALF_OPEN:
            self._success_count = 0
            self._half_open_calls = 0
        
        logger.info(f"Circuit {self.name} transitioned from {old_state.value} to {new_state.value}")
        
        # Trigger callbacks asynchronously
        asyncio.create_task(self._trigger_state_change(old_state, new_state))
    
    async def _trigger_state_change(
        self,
        old_state: CircuitState,
        new_state: CircuitState
    ) -> None:
        """Trigger callbacks for state change"""
        for callback in self._callbacks.get("state_change", []):
            try:
                await callback(self.name, old_state, new_state)
            except Exception as e:
                logger.error(f"Circuit breaker callback error: {e}")
    
    def _should_count_exception(self, exc_type: Type[Exception]) -> bool:
        """Determine if an exception should be counted as a failure"""
        # Check exclude list
        for excluded in self.config.exclude_exceptions:
            if issubclass(exc_type, excluded):
                return False
        
        # Check include list if specified
        if self.config.include_exceptions is not None:
            for included in self.config.include_exceptions:
                if issubclass(exc_type, included):
                    return True
            return False
        
        return True
    
    def on_state_change(
        self,
        callback: Callable[[str, CircuitState, CircuitState], Awaitable[None]]
    ) -> None:
        """Register a callback for state changes"""
        self._callbacks["state_change"].append(callback)
    
    def get_metrics(self) -> CircuitBreakerMetrics:
        """Get current circuit breaker metrics"""
        return CircuitBreakerMetrics(
            state=self._state,
            failure_count=self._failure_count,
            success_count=self._success_count,
            total_calls=self._total_calls,
            total_failures=self._total_failures,
            total_successes=self._total_successes,
            last_failure_time=self._last_failure_time,
            last_success_time=self._last_success_time,
            state_changed_at=self._state_changed_at
        )
    
    def reset(self) -> None:
        """Manually reset the circuit breaker to closed state"""
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._success_count = 0
        self._half_open_calls = 0
        self._state_changed_at = datetime.now()
        logger.info(f"Circuit {self.name} manually reset to CLOSED")


class CircuitBreakerOpenError(Exception):
    """Raised when a circuit breaker is open"""
    pass


class CircuitBreakerRegistry:
    """Registry for managing multiple circuit breakers"""
    
    def __init__(self):
        self._breakers: Dict[str, CircuitBreaker] = {}
    
    def get_or_create(
        self,
        name: str,
        config: Optional[CircuitBreakerConfig] = None
    ) -> CircuitBreaker:
        """Get or create a circuit breaker by name"""
        if name not in self._breakers:
            self._breakers[name] = CircuitBreaker(name=name, config=config)
        return self._breakers[name]
    
    def get(self, name: str) -> Optional[CircuitBreaker]:
        """Get a circuit breaker by name"""
        return self._breakers.get(name)
    
    def get_all_metrics(self) -> Dict[str, CircuitBreakerMetrics]:
        """Get metrics for all circuit breakers"""
        return {name: cb.get_metrics() for name, cb in self._breakers.items()}


# ============================================================================
# ACP-004: Agent Scaling
# ============================================================================

@dataclass
class ScalingConfig:
    """Configuration for agent scaling"""
    min_replicas: int = 1
    max_replicas: int = 10
    target_cpu_utilization: float = 0.7
    target_memory_utilization: float = 0.8
    scale_up_threshold: float = 0.8
    scale_down_threshold: float = 0.3
    scale_up_cooldown_seconds: float = 60.0
    scale_down_cooldown_seconds: float = 300.0
    scale_up_increment: int = 1
    scale_down_increment: int = 1


@dataclass
class AgentReplica:
    """Represents a replica of an agent"""
    replica_id: str
    agent_id: str
    instance: Any
    created_at: datetime = field(default_factory=datetime.now)
    status: AgentState = AgentState.PENDING
    metrics: Dict[str, float] = field(default_factory=dict)


class AgentScaler:
    """
    Horizontal scaling manager for agents.
    
    Provides automatic scaling based on load metrics, supporting both
    scale-up and scale-down with configurable thresholds and cooldowns.
    
    Features:
    - Automatic scale-up/scale-down based on utilization
    - Configurable min/max replicas
    - Load balancing across replicas
    - Cooldown periods to prevent thrashing
    
    Usage:
        scaler = AgentScaler()
        
        # Register agent type with factory
        scaler.register_agent_type(
            agent_type="claims_agent",
            factory=create_claims_agent,
            config=ScalingConfig(min_replicas=2, max_replicas=10)
        )
        
        # Get available replica
        agent = await scaler.get_replica("claims_agent")
        
        # Manual scaling
        await scaler.scale_to("claims_agent", replicas=5)
    """
    
    def __init__(self):
        self._agent_types: Dict[str, Dict[str, Any]] = {}
        self._replicas: Dict[str, Dict[str, AgentReplica]] = defaultdict(dict)
        self._last_scale_up: Dict[str, datetime] = {}
        self._last_scale_down: Dict[str, datetime] = {}
        self._load_balancer_index: Dict[str, int] = defaultdict(int)
        self._lock = asyncio.Lock()
        self._running = False
        self._scaling_task: Optional[asyncio.Task] = None
    
    def register_agent_type(
        self,
        agent_type: str,
        factory: Callable[[], Any],
        config: Optional[ScalingConfig] = None,
        replicas: int = 1
    ) -> None:
        """Register an agent type for scaling"""
        config = config or ScalingConfig()
        self._agent_types[agent_type] = {
            "factory": factory,
            "config": config,
            "target_replicas": max(config.min_replicas, replicas)
        }
        logger.info(f"Registered agent type {agent_type} for scaling")
    
    async def start(self) -> None:
        """Start the scaling manager"""
        if self._running:
            return
        
        self._running = True
        
        # Initialize replicas for all registered types
        for agent_type, info in self._agent_types.items():
            await self.scale_to(agent_type, info["target_replicas"])
        
        # Start autoscaling loop
        self._scaling_task = asyncio.create_task(self._autoscaling_loop())
        logger.info("Agent scaler started")
    
    async def stop(self) -> None:
        """Stop the scaling manager"""
        self._running = False
        if self._scaling_task:
            self._scaling_task.cancel()
            try:
                await self._scaling_task
            except asyncio.CancelledError:
                pass
        
        # Stop all replicas
        for agent_type in list(self._replicas.keys()):
            await self.scale_to(agent_type, 0)
        
        logger.info("Agent scaler stopped")
    
    async def scale_to(self, agent_type: str, replicas: int) -> None:
        """Scale an agent type to a specific number of replicas"""
        if agent_type not in self._agent_types:
            raise ValueError(f"Unknown agent type: {agent_type}")
        
        async with self._lock:
            config = self._agent_types[agent_type]["config"]
            replicas = max(0, min(replicas, config.max_replicas))
            
            current_count = len(self._replicas[agent_type])
            
            if replicas > current_count:
                # Scale up
                for _ in range(replicas - current_count):
                    await self._create_replica(agent_type)
            elif replicas < current_count:
                # Scale down
                to_remove = current_count - replicas
                replica_ids = list(self._replicas[agent_type].keys())[:to_remove]
                for replica_id in replica_ids:
                    await self._remove_replica(agent_type, replica_id)
            
            self._agent_types[agent_type]["target_replicas"] = replicas
            logger.info(f"Scaled {agent_type} to {replicas} replicas")
    
    async def scale_up(self, agent_type: str, count: int = 1) -> None:
        """Scale up an agent type by adding replicas"""
        current = len(self._replicas.get(agent_type, {}))
        await self.scale_to(agent_type, current + count)
    
    async def scale_down(self, agent_type: str, count: int = 1) -> None:
        """Scale down an agent type by removing replicas"""
        current = len(self._replicas.get(agent_type, {}))
        await self.scale_to(agent_type, max(0, current - count))
    
    async def _create_replica(self, agent_type: str) -> AgentReplica:
        """Create a new replica for an agent type"""
        factory = self._agent_types[agent_type]["factory"]
        replica_id = f"{agent_type}-{uuid.uuid4().hex[:8]}"
        
        instance = factory()
        if asyncio.iscoroutine(instance):
            instance = await instance
        
        # Start the agent if it has a start method
        if hasattr(instance, 'start'):
            if asyncio.iscoroutinefunction(instance.start):
                await instance.start()
            else:
                instance.start()
        
        replica = AgentReplica(
            replica_id=replica_id,
            agent_id=agent_type,
            instance=instance,
            status=AgentState.RUNNING
        )
        
        self._replicas[agent_type][replica_id] = replica
        logger.info(f"Created replica {replica_id} for {agent_type}")
        return replica
    
    async def _remove_replica(self, agent_type: str, replica_id: str) -> None:
        """Remove a replica"""
        replica = self._replicas[agent_type].pop(replica_id, None)
        if replica and replica.instance:
            # Stop the agent if it has a stop method
            if hasattr(replica.instance, 'stop'):
                if asyncio.iscoroutinefunction(replica.instance.stop):
                    await replica.instance.stop()
                else:
                    replica.instance.stop()
        logger.info(f"Removed replica {replica_id} from {agent_type}")
    
    async def get_replica(self, agent_type: str) -> Optional[Any]:
        """Get an available replica using round-robin load balancing"""
        replicas = self._replicas.get(agent_type, {})
        if not replicas:
            return None
        
        # Round-robin selection
        replica_list = list(replicas.values())
        running_replicas = [r for r in replica_list if r.status == AgentState.RUNNING]
        
        if not running_replicas:
            return None
        
        index = self._load_balancer_index[agent_type] % len(running_replicas)
        self._load_balancer_index[agent_type] += 1
        
        return running_replicas[index].instance
    
    async def _autoscaling_loop(self) -> None:
        """Background loop for automatic scaling"""
        while self._running:
            try:
                for agent_type, info in self._agent_types.items():
                    config = info["config"]
                    replicas = self._replicas.get(agent_type, {})
                    
                    if not replicas:
                        continue
                    
                    # Calculate average utilization
                    total_cpu = sum(r.metrics.get("cpu", 0) for r in replicas.values())
                    avg_cpu = total_cpu / len(replicas) if replicas else 0
                    
                    now = datetime.now()
                    
                    # Check scale up
                    if avg_cpu > config.scale_up_threshold:
                        last_scale = self._last_scale_up.get(agent_type, datetime.min)
                        if (now - last_scale).total_seconds() > config.scale_up_cooldown_seconds:
                            if len(replicas) < config.max_replicas:
                                await self.scale_up(agent_type, config.scale_up_increment)
                                self._last_scale_up[agent_type] = now
                    
                    # Check scale down
                    elif avg_cpu < config.scale_down_threshold:
                        last_scale = self._last_scale_down.get(agent_type, datetime.min)
                        if (now - last_scale).total_seconds() > config.scale_down_cooldown_seconds:
                            if len(replicas) > config.min_replicas:
                                await self.scale_down(agent_type, config.scale_down_increment)
                                self._last_scale_down[agent_type] = now
                
            except Exception as e:
                logger.error(f"Autoscaling loop error: {e}")
            
            await asyncio.sleep(10)  # Check every 10 seconds
    
    def update_replica_metrics(
        self,
        agent_type: str,
        replica_id: str,
        metrics: Dict[str, float]
    ) -> None:
        """Update metrics for a replica"""
        if agent_type in self._replicas and replica_id in self._replicas[agent_type]:
            self._replicas[agent_type][replica_id].metrics.update(metrics)
    
    def get_replica_count(self, agent_type: str) -> int:
        """Get the current replica count for an agent type"""
        return len(self._replicas.get(agent_type, {}))
    
    def get_all_replicas(self, agent_type: str) -> List[AgentReplica]:
        """Get all replicas for an agent type"""
        return list(self._replicas.get(agent_type, {}).values())


# ============================================================================
# ACP-005: Distributed Coordination
# ============================================================================

@dataclass
class LeaderElectionConfig:
    """Configuration for leader election"""
    heartbeat_interval_seconds: float = 1.0
    election_timeout_min_seconds: float = 3.0
    election_timeout_max_seconds: float = 5.0
    lease_duration_seconds: float = 15.0


@dataclass
class LeaderInfo:
    """Information about the current leader"""
    leader_id: str
    elected_at: datetime
    lease_expires_at: datetime
    term: int


class DistributedCoordinator:
    """
    Distributed coordination for stateful operations.
    
    Implements leader election and basic consensus for coordinating
    multiple agent instances.
    
    Features:
    - Leader election using Raft-like protocol
    - Distributed locks
    - Heartbeat-based failure detection
    - Automatic leader failover
    
    Usage:
        coordinator = DistributedCoordinator(node_id="node-1")
        
        # Start coordination
        await coordinator.start()
        
        # Check if leader
        if coordinator.is_leader:
            # Perform leader-only operations
            ...
        
        # Acquire distributed lock
        async with coordinator.lock("resource-1"):
            # Critical section
            ...
    """
    
    def __init__(
        self,
        node_id: str,
        config: Optional[LeaderElectionConfig] = None,
        peers: Optional[List[str]] = None
    ):
        self.node_id = node_id
        self.config = config or LeaderElectionConfig()
        self.peers = peers or []
        
        self._role = CoordinationRole.FOLLOWER
        self._current_term = 0
        self._voted_for: Optional[str] = None
        self._leader_id: Optional[str] = None
        self._leader_lease_expires: Optional[datetime] = None
        
        self._last_heartbeat = datetime.now()
        self._election_timeout = self._random_election_timeout()
        
        self._locks: Dict[str, asyncio.Lock] = {}
        self._lock_holders: Dict[str, str] = {}
        
        self._running = False
        self._tasks: List[asyncio.Task] = []
        self._callbacks: Dict[str, List[Callable]] = defaultdict(list)
        self._lock = asyncio.Lock()
    
    def _random_election_timeout(self) -> float:
        """Generate a random election timeout"""
        import random
        return random.uniform(
            self.config.election_timeout_min_seconds,
            self.config.election_timeout_max_seconds
        )
    
    @property
    def is_leader(self) -> bool:
        """Check if this node is the leader"""
        return self._role == CoordinationRole.LEADER
    
    @property
    def role(self) -> CoordinationRole:
        """Get current role"""
        return self._role
    
    @property
    def leader_id(self) -> Optional[str]:
        """Get the current leader ID"""
        return self._leader_id
    
    async def start(self) -> None:
        """Start the coordinator"""
        if self._running:
            return
        
        self._running = True
        self._tasks.append(asyncio.create_task(self._election_loop()))
        
        # If no peers, become leader immediately
        if not self.peers:
            await self._become_leader()
        
        logger.info(f"Distributed coordinator started for node {self.node_id}")
    
    async def stop(self) -> None:
        """Stop the coordinator"""
        self._running = False
        for task in self._tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._tasks.clear()
        logger.info(f"Distributed coordinator stopped for node {self.node_id}")
    
    async def _election_loop(self) -> None:
        """Main election and heartbeat loop"""
        while self._running:
            try:
                if self._role == CoordinationRole.LEADER:
                    # Send heartbeats as leader
                    await self._send_heartbeats()
                    await asyncio.sleep(self.config.heartbeat_interval_seconds)
                else:
                    # Check for election timeout
                    elapsed = (datetime.now() - self._last_heartbeat).total_seconds()
                    if elapsed > self._election_timeout:
                        await self._start_election()
                    await asyncio.sleep(0.1)
                    
            except Exception as e:
                logger.error(f"Election loop error: {e}")
                await asyncio.sleep(1)
    
    async def _start_election(self) -> None:
        """Start a leader election"""
        async with self._lock:
            self._role = CoordinationRole.CANDIDATE
            self._current_term += 1
            self._voted_for = self.node_id
            self._election_timeout = self._random_election_timeout()
            
            logger.info(f"Node {self.node_id} starting election for term {self._current_term}")
            
            # In a real implementation, request votes from peers
            # For single-node or simple cases, just become leader
            if not self.peers:
                await self._become_leader()
            else:
                # Simplified: if we're a candidate and no peers respond, become leader
                votes_received = 1  # Vote for self
                votes_needed = (len(self.peers) + 1) // 2 + 1
                
                # In real implementation: send RequestVote RPCs to peers
                # For now, simulate winning the election
                if votes_received >= votes_needed or not self.peers:
                    await self._become_leader()
    
    async def _become_leader(self) -> None:
        """Transition to leader role"""
        self._role = CoordinationRole.LEADER
        self._leader_id = self.node_id
        self._leader_lease_expires = datetime.now() + timedelta(
            seconds=self.config.lease_duration_seconds
        )
        
        logger.info(f"Node {self.node_id} became leader for term {self._current_term}")
        await self._trigger_callbacks("leader_elected", self.node_id)
    
    async def _send_heartbeats(self) -> None:
        """Send heartbeats to followers"""
        self._leader_lease_expires = datetime.now() + timedelta(
            seconds=self.config.lease_duration_seconds
        )
        # In real implementation: send AppendEntries RPCs to peers
    
    def receive_heartbeat(self, leader_id: str, term: int) -> None:
        """Receive a heartbeat from the leader"""
        if term >= self._current_term:
            self._current_term = term
            self._role = CoordinationRole.FOLLOWER
            self._leader_id = leader_id
            self._last_heartbeat = datetime.now()
            self._voted_for = None
    
    async def acquire_lock(self, resource_id: str, timeout: float = 30.0) -> bool:
        """Acquire a distributed lock"""
        if resource_id not in self._locks:
            self._locks[resource_id] = asyncio.Lock()
        
        try:
            acquired = await asyncio.wait_for(
                self._locks[resource_id].acquire(),
                timeout=timeout
            )
            if acquired:
                self._lock_holders[resource_id] = self.node_id
                logger.debug(f"Node {self.node_id} acquired lock on {resource_id}")
            return acquired
        except asyncio.TimeoutError:
            return False
    
    def release_lock(self, resource_id: str) -> None:
        """Release a distributed lock"""
        if resource_id in self._locks and self._locks[resource_id].locked():
            self._locks[resource_id].release()
            self._lock_holders.pop(resource_id, None)
            logger.debug(f"Node {self.node_id} released lock on {resource_id}")
    
    def lock(self, resource_id: str, timeout: float = 30.0):
        """Context manager for distributed lock"""
        return DistributedLockContext(self, resource_id, timeout)
    
    def on_event(
        self,
        event: str,
        callback: Callable[[str], Awaitable[None]]
    ) -> None:
        """Register a callback for coordination events"""
        self._callbacks[event].append(callback)
    
    async def _trigger_callbacks(self, event: str, *args) -> None:
        """Trigger callbacks for an event"""
        for callback in self._callbacks.get(event, []):
            try:
                await callback(*args)
            except Exception as e:
                logger.error(f"Coordination callback error: {e}")
    
    def get_leader_info(self) -> Optional[LeaderInfo]:
        """Get information about the current leader"""
        if self._leader_id:
            return LeaderInfo(
                leader_id=self._leader_id,
                elected_at=datetime.now(),  # Would be tracked in real implementation
                lease_expires_at=self._leader_lease_expires or datetime.now(),
                term=self._current_term
            )
        return None


class DistributedLockContext:
    """Context manager for distributed locks"""
    
    def __init__(
        self,
        coordinator: DistributedCoordinator,
        resource_id: str,
        timeout: float
    ):
        self._coordinator = coordinator
        self._resource_id = resource_id
        self._timeout = timeout
    
    async def __aenter__(self):
        acquired = await self._coordinator.acquire_lock(self._resource_id, self._timeout)
        if not acquired:
            raise TimeoutError(f"Failed to acquire lock on {self._resource_id}")
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self._coordinator.release_lock(self._resource_id)
        return False


# ============================================================================
# ACP-006: Agent Dependency Graph
# ============================================================================

@dataclass
class AgentDependency:
    """Represents a dependency between agents"""
    agent_id: str
    depends_on: List[str]
    optional_depends_on: List[str] = field(default_factory=list)
    startup_timeout_seconds: float = 60.0


class DependencyGraph:
    """
    Manages agent startup order based on dependencies.
    
    Ensures agents start in the correct order, respecting dependencies
    and detecting circular dependencies.
    
    Features:
    - Topological sorting for startup order
    - Circular dependency detection
    - Optional vs required dependencies
    - Parallel startup where possible
    
    Usage:
        graph = DependencyGraph()
        
        graph.add_agent("api-server", depends_on=["database", "cache"])
        graph.add_agent("database", depends_on=[])
        graph.add_agent("cache", depends_on=[])
        
        # Get startup order
        order = graph.get_startup_order()
        # Returns: ["database", "cache", "api-server"]
    """
    
    def __init__(self):
        self._agents: Dict[str, AgentDependency] = {}
        self._graph: Dict[str, Set[str]] = defaultdict(set)  # agent -> depends_on
        self._reverse_graph: Dict[str, Set[str]] = defaultdict(set)  # agent -> depended_by
    
    def add_agent(
        self,
        agent_id: str,
        depends_on: Optional[List[str]] = None,
        optional_depends_on: Optional[List[str]] = None,
        startup_timeout: float = 60.0
    ) -> None:
        """Add an agent with its dependencies"""
        depends_on = depends_on or []
        optional_depends_on = optional_depends_on or []
        
        self._agents[agent_id] = AgentDependency(
            agent_id=agent_id,
            depends_on=depends_on,
            optional_depends_on=optional_depends_on,
            startup_timeout_seconds=startup_timeout
        )
        
        # Update graphs
        for dep in depends_on:
            self._graph[agent_id].add(dep)
            self._reverse_graph[dep].add(agent_id)
        
        logger.debug(f"Added agent {agent_id} with dependencies: {depends_on}")
    
    def remove_agent(self, agent_id: str) -> None:
        """Remove an agent from the dependency graph"""
        if agent_id in self._agents:
            # Remove from graphs
            for dep in self._graph[agent_id]:
                self._reverse_graph[dep].discard(agent_id)
            del self._graph[agent_id]
            del self._agents[agent_id]
    
    def get_dependencies(self, agent_id: str) -> List[str]:
        """Get all dependencies for an agent"""
        agent = self._agents.get(agent_id)
        if agent:
            return agent.depends_on + agent.optional_depends_on
        return []
    
    def get_dependents(self, agent_id: str) -> List[str]:
        """Get all agents that depend on this agent"""
        return list(self._reverse_graph.get(agent_id, set()))
    
    def has_circular_dependency(self) -> bool:
        """Check if there are any circular dependencies"""
        visited = set()
        rec_stack = set()
        
        def dfs(node: str) -> bool:
            visited.add(node)
            rec_stack.add(node)
            
            for neighbor in self._graph.get(node, set()):
                if neighbor not in visited:
                    if dfs(neighbor):
                        return True
                elif neighbor in rec_stack:
                    return True
            
            rec_stack.remove(node)
            return False
        
        for agent_id in self._agents:
            if agent_id not in visited:
                if dfs(agent_id):
                    return True
        
        return False
    
    def get_startup_order(self) -> List[str]:
        """
        Get the startup order using topological sort.
        
        Returns agents in order such that dependencies are started first.
        Raises ValueError if there are circular dependencies.
        """
        if self.has_circular_dependency():
            raise ValueError("Circular dependency detected in agent graph")
        
        # Kahn's algorithm for topological sort
        in_degree = {agent_id: 0 for agent_id in self._agents}
        for agent_id in self._agents:
            for dep in self._graph.get(agent_id, set()):
                if dep in in_degree:
                    in_degree[agent_id] += 1
        
        # Start with agents that have no dependencies
        queue = deque([a for a, d in in_degree.items() if d == 0])
        result = []
        
        while queue:
            agent_id = queue.popleft()
            result.append(agent_id)
            
            for dependent in self._reverse_graph.get(agent_id, set()):
                if dependent in in_degree:
                    in_degree[dependent] -= 1
                    if in_degree[dependent] == 0:
                        queue.append(dependent)
        
        return result
    
    def get_parallel_startup_groups(self) -> List[List[str]]:
        """
        Get groups of agents that can be started in parallel.
        
        Returns a list of groups, where agents within a group can start
        simultaneously, but groups must be started in order.
        """
        if self.has_circular_dependency():
            raise ValueError("Circular dependency detected")
        
        result = []
        remaining = set(self._agents.keys())
        started = set()
        
        while remaining:
            # Find agents whose dependencies are all started
            group = []
            for agent_id in remaining:
                deps = self._graph.get(agent_id, set())
                if all(dep in started or dep not in self._agents for dep in deps):
                    group.append(agent_id)
            
            if not group:
                raise ValueError("Unable to resolve dependencies")
            
            result.append(group)
            for agent_id in group:
                remaining.remove(agent_id)
                started.add(agent_id)
        
        return result
    
    def get_shutdown_order(self) -> List[str]:
        """Get the shutdown order (reverse of startup order)"""
        return list(reversed(self.get_startup_order()))
    
    def validate(self) -> List[str]:
        """
        Validate the dependency graph.
        
        Returns a list of validation errors, or empty list if valid.
        """
        errors = []
        
        # Check for circular dependencies
        if self.has_circular_dependency():
            errors.append("Circular dependency detected")
        
        # Check for missing dependencies
        for agent_id, agent in self._agents.items():
            for dep in agent.depends_on:
                if dep not in self._agents:
                    errors.append(f"Agent {agent_id} depends on missing agent {dep}")
        
        return errors


# ============================================================================
# ACP-007: Graceful Shutdown
# ============================================================================

@dataclass
class ShutdownConfig:
    """Configuration for graceful shutdown"""
    drain_timeout_seconds: float = 30.0
    force_timeout_seconds: float = 60.0
    checkpoint_enabled: bool = True
    save_in_flight: bool = True


@dataclass
class InFlightOperation:
    """Represents an in-flight operation during shutdown"""
    operation_id: str
    agent_id: str
    operation_type: str
    started_at: datetime
    data: Dict[str, Any] = field(default_factory=dict)


class GracefulShutdownManager:
    """
    Manages graceful shutdown to preserve in-flight verifications.
    
    Features:
    - Drain period for completing in-flight operations
    - Operation checkpointing
    - Configurable force timeout
    - Shutdown hooks
    
    Usage:
        shutdown_manager = GracefulShutdownManager(
            config=ShutdownConfig(drain_timeout_seconds=30)
        )
        
        # Register in-flight operation
        op_id = shutdown_manager.register_operation(
            agent_id="claims-agent",
            operation_type="verification",
            data={"claim_id": "123"}
        )
        
        # Complete operation
        shutdown_manager.complete_operation(op_id)
        
        # Initiate graceful shutdown
        await shutdown_manager.shutdown()
    """
    
    def __init__(self, config: Optional[ShutdownConfig] = None):
        self.config = config or ShutdownConfig()
        self._phase = ShutdownPhase.RUNNING
        self._in_flight: Dict[str, InFlightOperation] = {}
        self._shutdown_hooks: List[Callable[[], Awaitable[None]]] = []
        self._checkpoint_data: Dict[str, Any] = {}
        self._lock = asyncio.Lock()
        self._shutdown_event = asyncio.Event()
    
    @property
    def phase(self) -> ShutdownPhase:
        """Get the current shutdown phase"""
        return self._phase
    
    @property
    def is_shutting_down(self) -> bool:
        """Check if shutdown is in progress"""
        return self._phase != ShutdownPhase.RUNNING
    
    def register_operation(
        self,
        agent_id: str,
        operation_type: str,
        data: Optional[Dict[str, Any]] = None
    ) -> str:
        """Register an in-flight operation"""
        if self._phase != ShutdownPhase.RUNNING:
            raise RuntimeError("Cannot register new operations during shutdown")
        
        operation_id = str(uuid.uuid4())
        self._in_flight[operation_id] = InFlightOperation(
            operation_id=operation_id,
            agent_id=agent_id,
            operation_type=operation_type,
            started_at=datetime.now(),
            data=data or {}
        )
        return operation_id
    
    def complete_operation(self, operation_id: str) -> None:
        """Mark an operation as complete"""
        self._in_flight.pop(operation_id, None)
        
        # Check if all operations complete during draining
        if self._phase == ShutdownPhase.DRAINING and not self._in_flight:
            self._shutdown_event.set()
    
    def get_in_flight_count(self) -> int:
        """Get the number of in-flight operations"""
        return len(self._in_flight)
    
    def get_in_flight_operations(self) -> List[InFlightOperation]:
        """Get all in-flight operations"""
        return list(self._in_flight.values())
    
    def add_shutdown_hook(
        self,
        hook: Callable[[], Awaitable[None]]
    ) -> None:
        """Add a shutdown hook to be called during shutdown"""
        self._shutdown_hooks.append(hook)
    
    async def shutdown(self) -> Dict[str, Any]:
        """
        Initiate graceful shutdown.
        
        Returns a summary of the shutdown process.
        """
        async with self._lock:
            if self._phase != ShutdownPhase.RUNNING:
                return {"status": "already_shutting_down", "phase": self._phase.value}
            
            logger.info("Initiating graceful shutdown")
            result = {
                "started_at": datetime.now().isoformat(),
                "in_flight_at_start": len(self._in_flight),
                "checkpointed": [],
                "timed_out": []
            }
            
            # Phase 1: Draining
            self._phase = ShutdownPhase.DRAINING
            logger.info(f"Draining {len(self._in_flight)} in-flight operations")
            
            if self._in_flight:
                self._shutdown_event.clear()
                try:
                    await asyncio.wait_for(
                        self._shutdown_event.wait(),
                        timeout=self.config.drain_timeout_seconds
                    )
                except asyncio.TimeoutError:
                    logger.warning("Drain timeout reached, saving remaining operations")
                    
                    # Checkpoint remaining operations
                    if self.config.save_in_flight:
                        for op_id, op in list(self._in_flight.items()):
                            self._checkpoint_data[op_id] = {
                                "agent_id": op.agent_id,
                                "operation_type": op.operation_type,
                                "data": op.data,
                                "started_at": op.started_at.isoformat()
                            }
                            result["checkpointed"].append(op_id)
                    
                    result["timed_out"] = list(self._in_flight.keys())
            
            # Phase 2: Stopping
            self._phase = ShutdownPhase.STOPPING
            logger.info("Running shutdown hooks")
            
            for hook in self._shutdown_hooks:
                try:
                    await asyncio.wait_for(
                        hook(),
                        timeout=self.config.force_timeout_seconds
                    )
                except asyncio.TimeoutError:
                    logger.warning("Shutdown hook timed out")
                except Exception as e:
                    logger.error(f"Shutdown hook error: {e}")
            
            # Phase 3: Terminated
            self._phase = ShutdownPhase.TERMINATED
            result["completed_at"] = datetime.now().isoformat()
            result["checkpoint_data"] = self._checkpoint_data
            
            logger.info("Graceful shutdown complete")
            return result
    
    def get_checkpoint_data(self) -> Dict[str, Any]:
        """Get checkpointed data from shutdown"""
        return dict(self._checkpoint_data)
    
    async def restore_from_checkpoint(
        self,
        checkpoint_data: Dict[str, Any]
    ) -> List[InFlightOperation]:
        """Restore operations from checkpoint data"""
        restored = []
        for op_id, data in checkpoint_data.items():
            op = InFlightOperation(
                operation_id=op_id,
                agent_id=data["agent_id"],
                operation_type=data["operation_type"],
                started_at=datetime.fromisoformat(data["started_at"]),
                data=data.get("data", {})
            )
            self._in_flight[op_id] = op
            restored.append(op)
        
        logger.info(f"Restored {len(restored)} operations from checkpoint")
        return restored


# ============================================================================
# ACP-008: Resource Quotas
# ============================================================================

@dataclass
class AgentResourceQuota:
    """Resource quota limits for an agent"""
    memory_mb: int = 512
    cpu_percent: float = 25.0
    max_concurrent_operations: int = 10
    max_operations_per_minute: int = 100
    network_bandwidth_mbps: Optional[float] = None
    storage_mb: Optional[int] = None


@dataclass
class ResourceUsage:
    """Current resource usage for an agent"""
    agent_id: str
    memory_mb: float = 0.0
    cpu_percent: float = 0.0
    concurrent_operations: int = 0
    operations_this_minute: int = 0
    timestamp: datetime = field(default_factory=datetime.now)


class ResourceQuotaManager:
    """
    Manages resource quotas and limits per agent.
    
    Features:
    - Memory and CPU limits
    - Concurrent operation limits
    - Rate limiting (operations per minute)
    - Usage tracking and reporting
    
    Usage:
        quota_manager = ResourceQuotaManager()
        
        quota_manager.set_quota("claims-agent", AgentResourceQuota(
            memory_mb=512,
            cpu_percent=25,
            max_concurrent_operations=10
        ))
        
        # Check before operation
        if quota_manager.can_execute("claims-agent"):
            quota_manager.record_operation("claims-agent")
            # Execute operation
    """
    
    def __init__(self):
        self._quotas: Dict[str, AgentResourceQuota] = {}
        self._usage: Dict[str, ResourceUsage] = {}
        self._operation_counts: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._lock = asyncio.Lock()
    
    def set_quota(self, agent_id: str, quota: AgentResourceQuota) -> None:
        """Set the resource quota for an agent"""
        self._quotas[agent_id] = quota
        if agent_id not in self._usage:
            self._usage[agent_id] = ResourceUsage(agent_id=agent_id)
        logger.info(f"Set quota for {agent_id}: memory={quota.memory_mb}MB, cpu={quota.cpu_percent}%")
    
    def get_quota(self, agent_id: str) -> Optional[AgentResourceQuota]:
        """Get the quota for an agent"""
        return self._quotas.get(agent_id)
    
    def can_execute(self, agent_id: str) -> bool:
        """Check if an agent can execute a new operation"""
        quota = self._quotas.get(agent_id)
        if not quota:
            return True  # No quota means no limits
        
        usage = self._usage.get(agent_id)
        if not usage:
            return True
        
        # Check concurrent operations
        if usage.concurrent_operations >= quota.max_concurrent_operations:
            logger.warning(f"Agent {agent_id} at max concurrent operations")
            return False
        
        # Check rate limit
        ops_this_minute = self._count_recent_operations(agent_id, seconds=60)
        if ops_this_minute >= quota.max_operations_per_minute:
            logger.warning(f"Agent {agent_id} at rate limit")
            return False
        
        # Check memory
        if usage.memory_mb > quota.memory_mb:
            logger.warning(f"Agent {agent_id} over memory quota")
            return False
        
        # Check CPU
        if usage.cpu_percent > quota.cpu_percent:
            logger.warning(f"Agent {agent_id} over CPU quota")
            return False
        
        return True
    
    def record_operation_start(self, agent_id: str) -> None:
        """Record the start of an operation"""
        if agent_id not in self._usage:
            self._usage[agent_id] = ResourceUsage(agent_id=agent_id)
        
        self._usage[agent_id].concurrent_operations += 1
        self._operation_counts[agent_id].append(datetime.now())
    
    def record_operation_end(self, agent_id: str) -> None:
        """Record the end of an operation"""
        if agent_id in self._usage:
            self._usage[agent_id].concurrent_operations = max(
                0, self._usage[agent_id].concurrent_operations - 1
            )
    
    def update_resource_usage(
        self,
        agent_id: str,
        memory_mb: Optional[float] = None,
        cpu_percent: Optional[float] = None
    ) -> None:
        """Update the resource usage for an agent"""
        if agent_id not in self._usage:
            self._usage[agent_id] = ResourceUsage(agent_id=agent_id)
        
        usage = self._usage[agent_id]
        if memory_mb is not None:
            usage.memory_mb = memory_mb
        if cpu_percent is not None:
            usage.cpu_percent = cpu_percent
        usage.timestamp = datetime.now()
    
    def _count_recent_operations(self, agent_id: str, seconds: int) -> int:
        """Count operations in the last N seconds"""
        cutoff = datetime.now() - timedelta(seconds=seconds)
        count = 0
        for ts in self._operation_counts.get(agent_id, []):
            if ts > cutoff:
                count += 1
        return count
    
    def get_usage(self, agent_id: str) -> Optional[ResourceUsage]:
        """Get current usage for an agent"""
        return self._usage.get(agent_id)
    
    def get_all_usage(self) -> Dict[str, ResourceUsage]:
        """Get usage for all agents"""
        return dict(self._usage)
    
    def check_quota_violations(self) -> Dict[str, List[str]]:
        """Check for quota violations across all agents"""
        violations = {}
        
        for agent_id, quota in self._quotas.items():
            usage = self._usage.get(agent_id)
            if not usage:
                continue
            
            agent_violations = []
            
            if usage.memory_mb > quota.memory_mb:
                agent_violations.append(
                    f"Memory: {usage.memory_mb:.1f}MB > {quota.memory_mb}MB"
                )
            
            if usage.cpu_percent > quota.cpu_percent:
                agent_violations.append(
                    f"CPU: {usage.cpu_percent:.1f}% > {quota.cpu_percent}%"
                )
            
            if usage.concurrent_operations > quota.max_concurrent_operations:
                agent_violations.append(
                    f"Concurrent ops: {usage.concurrent_operations} > {quota.max_concurrent_operations}"
                )
            
            if agent_violations:
                violations[agent_id] = agent_violations
        
        return violations


# ============================================================================
# ACP-009: Agent Observability
# ============================================================================

@dataclass
class AgentMetric:
    """A metric measurement for an agent"""
    name: str
    value: float
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    metric_type: str = "gauge"  # gauge, counter, histogram


@dataclass
class AgentLogEntry:
    """A log entry from an agent"""
    agent_id: str
    level: str  # debug, info, warning, error, critical
    message: str
    timestamp: datetime = field(default_factory=datetime.now)
    context: Dict[str, Any] = field(default_factory=dict)


class AgentObservabilityProvider:
    """
    Built-in observability for agents (metrics, logging, tracing).
    
    Features:
    - Structured logging with context
    - Metrics collection (counters, gauges, histograms)
    - Distributed tracing support
    - Prometheus-compatible export
    
    Usage:
        observability = AgentObservabilityProvider()
        
        # Record metric
        observability.record_metric(
            agent_id="claims-agent",
            name="verification_latency_ms",
            value=150.5,
            labels={"claim_type": "auto"}
        )
        
        # Log with context
        observability.log(
            agent_id="claims-agent",
            level="info",
            message="Verification completed",
            context={"claim_id": "123", "result": "approved"}
        )
        
        # Export metrics
        metrics = observability.export_prometheus()
    """
    
    def __init__(self, max_log_entries: int = 10000, max_metrics: int = 10000):
        self._metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_metrics))
        self._logs: deque = deque(maxlen=max_log_entries)
        self._counters: Dict[str, float] = defaultdict(float)
        self._gauges: Dict[str, float] = {}
        self._histograms: Dict[str, List[float]] = defaultdict(list)
        self._metric_metadata: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
    
    def record_metric(
        self,
        agent_id: str,
        name: str,
        value: float,
        labels: Optional[Dict[str, str]] = None,
        metric_type: str = "gauge"
    ) -> None:
        """Record a metric for an agent"""
        labels = labels or {}
        labels["agent_id"] = agent_id
        
        metric = AgentMetric(
            name=name,
            value=value,
            labels=labels,
            metric_type=metric_type
        )
        
        full_name = f"{name}:{self._make_label_key(labels)}"
        self._metrics[agent_id].append(metric)
        
        # Update aggregates
        if metric_type == "counter":
            self._counters[full_name] += value
        elif metric_type == "gauge":
            self._gauges[full_name] = value
        elif metric_type == "histogram":
            self._histograms[name].append(value)
    
    def increment_counter(
        self,
        agent_id: str,
        name: str,
        value: float = 1.0,
        labels: Optional[Dict[str, str]] = None
    ) -> None:
        """Increment a counter metric"""
        self.record_metric(agent_id, name, value, labels, metric_type="counter")
    
    def set_gauge(
        self,
        agent_id: str,
        name: str,
        value: float,
        labels: Optional[Dict[str, str]] = None
    ) -> None:
        """Set a gauge metric"""
        self.record_metric(agent_id, name, value, labels, metric_type="gauge")
    
    def observe_histogram(
        self,
        agent_id: str,
        name: str,
        value: float,
        labels: Optional[Dict[str, str]] = None
    ) -> None:
        """Observe a value for a histogram metric"""
        self.record_metric(agent_id, name, value, labels, metric_type="histogram")
    
    def log(
        self,
        agent_id: str,
        level: str,
        message: str,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log a message with structured context"""
        entry = AgentLogEntry(
            agent_id=agent_id,
            level=level,
            message=message,
            context=context or {}
        )
        self._logs.append(entry)
        
        # Also log to Python logger
        log_func = getattr(logger, level.lower(), logger.info)
        log_func(f"[{agent_id}] {message}", extra={"context": context})
    
    def get_metrics(
        self,
        agent_id: Optional[str] = None,
        name: Optional[str] = None
    ) -> List[AgentMetric]:
        """Get recorded metrics"""
        if agent_id:
            metrics = list(self._metrics.get(agent_id, []))
        else:
            metrics = []
            for agent_metrics in self._metrics.values():
                metrics.extend(agent_metrics)
        
        if name:
            metrics = [m for m in metrics if m.name == name]
        
        return metrics
    
    def get_logs(
        self,
        agent_id: Optional[str] = None,
        level: Optional[str] = None,
        limit: int = 100
    ) -> List[AgentLogEntry]:
        """Get log entries"""
        logs = list(self._logs)
        
        if agent_id:
            logs = [l for l in logs if l.agent_id == agent_id]
        if level:
            logs = [l for l in logs if l.level == level]
        
        return logs[-limit:]
    
    def export_prometheus(self) -> str:
        """Export metrics in Prometheus text format"""
        lines = []
        
        # Export counters
        for full_name, value in self._counters.items():
            name = full_name.split(":")[0]
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{full_name.replace(':', '')} {value}")
        
        # Export gauges
        for full_name, value in self._gauges.items():
            name = full_name.split(":")[0]
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{full_name.replace(':', '')} {value}")
        
        # Export histogram summaries
        for name, values in self._histograms.items():
            if values:
                lines.append(f"# TYPE {name} histogram")
                lines.append(f"{name}_count {len(values)}")
                lines.append(f"{name}_sum {sum(values)}")
                
                # Calculate percentiles
                sorted_vals = sorted(values)
                for p in [0.5, 0.9, 0.99]:
                    idx = int(len(sorted_vals) * p)
                    lines.append(f'{name}{{quantile="{p}"}} {sorted_vals[idx]}')
        
        return "\n".join(lines)
    
    def _make_label_key(self, labels: Dict[str, str]) -> str:
        """Create a unique key from labels"""
        return ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
    
    def get_agent_summary(self, agent_id: str) -> Dict[str, Any]:
        """Get an observability summary for an agent"""
        metrics = self.get_metrics(agent_id)
        logs = self.get_logs(agent_id)
        
        return {
            "agent_id": agent_id,
            "total_metrics": len(metrics),
            "total_logs": len(logs),
            "recent_metrics": metrics[-10:] if metrics else [],
            "recent_logs": logs[-10:] if logs else [],
            "log_level_counts": self._count_log_levels(logs)
        }
    
    def _count_log_levels(self, logs: List[AgentLogEntry]) -> Dict[str, int]:
        """Count logs by level"""
        counts = defaultdict(int)
        for log in logs:
            counts[log.level] += 1
        return dict(counts)


# ============================================================================
# ACP-010: Hot Reload
# ============================================================================

@dataclass
class HotReloadConfig:
    """Configuration for hot reload"""
    enabled: bool = True
    watch_paths: List[str] = field(default_factory=list)
    reload_delay_seconds: float = 1.0
    preserve_state: bool = True


@dataclass
class ReloadEvent:
    """Record of a hot reload event"""
    agent_id: str
    old_version: str
    new_version: str
    timestamp: datetime = field(default_factory=datetime.now)
    success: bool = True
    error: Optional[str] = None
    preserved_state: Dict[str, Any] = field(default_factory=dict)


class HotReloadManager:
    """
    Manages hot reload of agent code without full restart.
    
    Features:
    - Code change detection
    - Graceful reload with state preservation
    - Version tracking
    - Rollback support
    
    Usage:
        hot_reload = HotReloadManager(
            config=HotReloadConfig(
                watch_paths=["./agents"],
                preserve_state=True
            )
        )
        
        # Register agent
        hot_reload.register_agent(
            agent_id="claims-agent",
            module_name="agents.claims",
            class_name="ClaimsAgent"
        )
        
        # Trigger reload
        await hot_reload.reload_agent("claims-agent")
    """
    
    def __init__(self, config: Optional[HotReloadConfig] = None):
        self.config = config or HotReloadConfig()
        self._agents: Dict[str, Dict[str, Any]] = {}
        self._versions: Dict[str, str] = {}
        self._previous_versions: Dict[str, Any] = {}
        self._reload_history: deque = deque(maxlen=100)
        self._callbacks: Dict[str, List[Callable]] = defaultdict(list)
        self._lock = asyncio.Lock()
    
    def register_agent(
        self,
        agent_id: str,
        module_name: str,
        class_name: str,
        factory: Optional[Callable[[], Any]] = None,
        instance: Optional[Any] = None,
        state_extractor: Optional[Callable[[Any], Dict[str, Any]]] = None,
        state_injector: Optional[Callable[[Any, Dict[str, Any]], None]] = None
    ) -> None:
        """Register an agent for hot reload"""
        self._agents[agent_id] = {
            "module_name": module_name,
            "class_name": class_name,
            "factory": factory,
            "instance": instance,
            "state_extractor": state_extractor,
            "state_injector": state_injector
        }
        self._versions[agent_id] = self._compute_version(module_name)
        logger.info(f"Registered agent {agent_id} for hot reload (version: {self._versions[agent_id][:8]})")
    
    def _compute_version(self, module_name: str) -> str:
        """Compute a version hash for a module"""
        try:
            module = sys.modules.get(module_name)
            if module and hasattr(module, '__file__') and module.__file__:
                with open(module.__file__, 'rb') as f:
                    return hashlib.sha256(f.read()).hexdigest()
        except Exception as e:
            logger.warning(f"Could not compute version for {module_name}: {e}")
        
        return hashlib.sha256(module_name.encode()).hexdigest()
    
    async def check_for_changes(self, agent_id: str) -> bool:
        """Check if an agent's code has changed"""
        if agent_id not in self._agents:
            return False
        
        module_name = self._agents[agent_id]["module_name"]
        new_version = self._compute_version(module_name)
        old_version = self._versions.get(agent_id, "")
        
        return new_version != old_version
    
    async def reload_agent(
        self,
        agent_id: str,
        force: bool = False
    ) -> ReloadEvent:
        """Reload an agent with optional state preservation"""
        if agent_id not in self._agents:
            raise ValueError(f"Agent {agent_id} not registered for hot reload")
        
        async with self._lock:
            agent_info = self._agents[agent_id]
            module_name = agent_info["module_name"]
            class_name = agent_info["class_name"]
            old_version = self._versions.get(agent_id, "unknown")
            
            # Check if reload needed
            if not force and not await self.check_for_changes(agent_id):
                return ReloadEvent(
                    agent_id=agent_id,
                    old_version=old_version,
                    new_version=old_version,
                    success=True,
                    error="No changes detected"
                )
            
            try:
                # Extract state from current instance
                preserved_state = {}
                if self.config.preserve_state and agent_info.get("instance"):
                    extractor = agent_info.get("state_extractor")
                    if extractor:
                        preserved_state = extractor(agent_info["instance"])
                    elif hasattr(agent_info["instance"], 'get_state'):
                        preserved_state = agent_info["instance"].get_state()
                
                # Stop old instance
                old_instance = agent_info.get("instance")
                if old_instance and hasattr(old_instance, 'stop'):
                    if asyncio.iscoroutinefunction(old_instance.stop):
                        await old_instance.stop()
                    else:
                        old_instance.stop()
                
                # Store for potential rollback
                self._previous_versions[agent_id] = {
                    "instance": old_instance,
                    "version": old_version
                }
                
                # Reload the module
                if module_name in sys.modules:
                    module = importlib.reload(sys.modules[module_name])
                else:
                    module = importlib.import_module(module_name)
                
                # Create new instance
                agent_class = getattr(module, class_name)
                
                if agent_info.get("factory"):
                    new_instance = agent_info["factory"]()
                else:
                    new_instance = agent_class()
                
                if asyncio.iscoroutine(new_instance):
                    new_instance = await new_instance
                
                # Inject preserved state
                if preserved_state:
                    injector = agent_info.get("state_injector")
                    if injector:
                        injector(new_instance, preserved_state)
                    elif hasattr(new_instance, 'set_state'):
                        new_instance.set_state(preserved_state)
                
                # Start new instance
                if hasattr(new_instance, 'start'):
                    if asyncio.iscoroutinefunction(new_instance.start):
                        await new_instance.start()
                    else:
                        new_instance.start()
                
                # Update registry
                agent_info["instance"] = new_instance
                new_version = self._compute_version(module_name)
                self._versions[agent_id] = new_version
                
                event = ReloadEvent(
                    agent_id=agent_id,
                    old_version=old_version,
                    new_version=new_version,
                    success=True,
                    preserved_state=preserved_state
                )
                
                self._reload_history.append(event)
                await self._trigger_callbacks("reload_success", agent_id, event)
                
                logger.info(f"Hot reloaded agent {agent_id}: {old_version[:8]} -> {new_version[:8]}")
                return event
                
            except Exception as e:
                event = ReloadEvent(
                    agent_id=agent_id,
                    old_version=old_version,
                    new_version=old_version,
                    success=False,
                    error=str(e)
                )
                
                self._reload_history.append(event)
                await self._trigger_callbacks("reload_failed", agent_id, event)
                
                logger.error(f"Hot reload failed for {agent_id}: {e}")
                return event
    
    async def rollback_agent(self, agent_id: str) -> bool:
        """Rollback an agent to the previous version"""
        if agent_id not in self._previous_versions:
            logger.warning(f"No previous version available for {agent_id}")
            return False
        
        async with self._lock:
            try:
                prev = self._previous_versions[agent_id]
                agent_info = self._agents[agent_id]
                
                # Stop current instance
                current = agent_info.get("instance")
                if current and hasattr(current, 'stop'):
                    if asyncio.iscoroutinefunction(current.stop):
                        await current.stop()
                    else:
                        current.stop()
                
                # Restore previous instance
                prev_instance = prev["instance"]
                if prev_instance and hasattr(prev_instance, 'start'):
                    if asyncio.iscoroutinefunction(prev_instance.start):
                        await prev_instance.start()
                    else:
                        prev_instance.start()
                
                agent_info["instance"] = prev_instance
                self._versions[agent_id] = prev["version"]
                
                logger.info(f"Rolled back agent {agent_id} to version {prev['version'][:8]}")
                return True
                
            except Exception as e:
                logger.error(f"Rollback failed for {agent_id}: {e}")
                return False
    
    def get_agent_version(self, agent_id: str) -> Optional[str]:
        """Get the current version of an agent"""
        return self._versions.get(agent_id)
    
    def get_agent_instance(self, agent_id: str) -> Optional[Any]:
        """Get the current instance of an agent"""
        if agent_id in self._agents:
            return self._agents[agent_id].get("instance")
        return None
    
    def get_reload_history(
        self,
        agent_id: Optional[str] = None
    ) -> List[ReloadEvent]:
        """Get reload history"""
        history = list(self._reload_history)
        if agent_id:
            history = [e for e in history if e.agent_id == agent_id]
        return history
    
    def on_event(
        self,
        event: str,
        callback: Callable[[str, ReloadEvent], Awaitable[None]]
    ) -> None:
        """Register a callback for reload events"""
        self._callbacks[event].append(callback)
    
    async def _trigger_callbacks(
        self,
        event: str,
        agent_id: str,
        reload_event: ReloadEvent
    ) -> None:
        """Trigger callbacks for an event"""
        for callback in self._callbacks.get(event, []):
            try:
                await callback(agent_id, reload_event)
            except Exception as e:
                logger.error(f"Hot reload callback error: {e}")


# ============================================================================
# Main Agent Registration
# ============================================================================

@dataclass
class AgentRegistration:
    """Registration details for an agent in the control plane"""
    agent_type: Type
    replicas: int = 1
    dependencies: List[str] = field(default_factory=list)
    resources: Optional[AgentResourceQuota] = None
    health_config: Optional[HealthCheckConfig] = None
    recovery_config: Optional[RecoveryConfig] = None
    circuit_breaker: Optional[CircuitBreaker] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# Enhanced Agent Control Plane
# ============================================================================

class EnhancedAgentControlPlane:
    """
    Enhanced Agent Control Plane with full lifecycle management.
    
    This is the main interface for managing autonomous AI agents with
    comprehensive lifecycle features including health monitoring,
    auto-recovery, circuit breakers, scaling, distributed coordination,
    dependency management, graceful shutdown, resource quotas,
    observability, and hot reload.
    
    Usage:
        control_plane = EnhancedAgentControlPlane(
            health_check_interval=30,
            auto_recovery=True,
            circuit_breaker=CircuitBreaker(
                failure_threshold=5,
                recovery_timeout=60
            )
        )
        
        control_plane.register(
            ClaimsAgent,
            replicas=3,
            dependencies=["message-bus"],
            resources=AgentResourceQuota(
                memory_mb=512,
                cpu_percent=25
            )
        )
        
        await control_plane.start_all()
    """
    
    def __init__(
        self,
        health_check_interval: float = 30.0,
        auto_recovery: bool = True,
        circuit_breaker: Optional[CircuitBreaker] = None,
        node_id: Optional[str] = None,
        health_config: Optional[HealthCheckConfig] = None,
        recovery_config: Optional[RecoveryConfig] = None,
        scaling_config: Optional[ScalingConfig] = None,
        shutdown_config: Optional[ShutdownConfig] = None,
        hot_reload_config: Optional[HotReloadConfig] = None
    ):
        """
        Initialize the Enhanced Agent Control Plane.
        
        Args:
            health_check_interval: Interval between health checks (seconds)
            auto_recovery: Enable automatic recovery of failed agents
            circuit_breaker: Default circuit breaker configuration
            node_id: Node ID for distributed coordination
            health_config: Health check configuration
            recovery_config: Auto-recovery configuration
            scaling_config: Agent scaling configuration
            shutdown_config: Graceful shutdown configuration
            hot_reload_config: Hot reload configuration
        """
        self.node_id = node_id or f"node-{uuid.uuid4().hex[:8]}"
        
        # Configure health monitoring
        health_config = health_config or HealthCheckConfig()
        health_config.liveness_interval_seconds = health_check_interval
        self.health_monitor = HealthMonitor(config=health_config)
        
        # Configure auto-recovery
        recovery_config = recovery_config or RecoveryConfig()
        recovery_config.enabled = auto_recovery
        self.recovery_manager = AutoRecoveryManager(config=recovery_config)
        
        # Configure circuit breakers
        self.default_circuit_breaker = circuit_breaker
        self.circuit_breaker_registry = CircuitBreakerRegistry()
        
        # Configure scaling
        self.scaler = AgentScaler()
        self.default_scaling_config = scaling_config or ScalingConfig()
        
        # Configure distributed coordination
        self.coordinator = DistributedCoordinator(node_id=self.node_id)
        
        # Configure dependency graph
        self.dependency_graph = DependencyGraph()
        
        # Configure graceful shutdown
        self.shutdown_manager = GracefulShutdownManager(
            config=shutdown_config or ShutdownConfig()
        )
        
        # Configure resource quotas
        self.quota_manager = ResourceQuotaManager()
        
        # Configure observability
        self.observability = AgentObservabilityProvider()
        
        # Configure hot reload
        self.hot_reload = HotReloadManager(
            config=hot_reload_config or HotReloadConfig()
        )
        
        # Agent registrations
        self._registrations: Dict[str, AgentRegistration] = {}
        self._instances: Dict[str, List[Any]] = defaultdict(list)
        self._running = False
        
        # Wire up callbacks
        self._setup_callbacks()
    
    def _setup_callbacks(self) -> None:
        """Set up internal callbacks between components"""
        # Health -> Recovery: trigger recovery on health failure
        async def on_liveness_failed(agent_id: str):
            self.observability.log(agent_id, "error", "Liveness check failed")
            self.observability.increment_counter(agent_id, "health_failures_total")
            await self.recovery_manager.handle_failure(agent_id)
        
        self.health_monitor.on_event("liveness_failed", on_liveness_failed)
        
        # Recovery -> Health: register recovered agents
        async def on_recovery_success(agent_id: str, event: RecoveryEvent):
            self.observability.log(agent_id, "info", f"Agent recovered (attempt {event.attempt})")
            self.observability.increment_counter(agent_id, "recoveries_total")
            agent = self.recovery_manager.get_agent(agent_id)
            if agent:
                self.health_monitor.register_agent(agent_id, agent)
        
        self.recovery_manager.on_event("recovery_success", on_recovery_success)
    
    def register(
        self,
        agent_type: Type,
        agent_id: Optional[str] = None,
        replicas: int = 1,
        dependencies: Optional[List[str]] = None,
        resources: Optional[AgentResourceQuota] = None,
        health_config: Optional[HealthCheckConfig] = None,
        recovery_config: Optional[RecoveryConfig] = None,
        circuit_breaker: Optional[CircuitBreaker] = None,
        **metadata
    ) -> str:
        """
        Register an agent type with the control plane.
        
        Args:
            agent_type: The agent class to register
            agent_id: Optional agent ID (defaults to class name)
            replicas: Number of replicas to create
            dependencies: List of agent IDs this agent depends on
            resources: Resource quota for this agent
            health_config: Health check configuration
            recovery_config: Auto-recovery configuration
            circuit_breaker: Circuit breaker for this agent
            **metadata: Additional metadata
            
        Returns:
            The agent ID
        """
        agent_id = agent_id or agent_type.__name__
        dependencies = dependencies or []
        
        registration = AgentRegistration(
            agent_type=agent_type,
            replicas=replicas,
            dependencies=dependencies,
            resources=resources,
            health_config=health_config,
            recovery_config=recovery_config,
            circuit_breaker=circuit_breaker or self.default_circuit_breaker,
            metadata=metadata
        )
        
        self._registrations[agent_id] = registration
        
        # Register with dependency graph
        self.dependency_graph.add_agent(agent_id, depends_on=dependencies)
        
        # Register with scaler
        self.scaler.register_agent_type(
            agent_type=agent_id,
            factory=lambda at=agent_type: at(),
            config=self.default_scaling_config,
            replicas=replicas
        )
        
        # Set resource quota if provided
        if resources:
            self.quota_manager.set_quota(agent_id, resources)
        
        # Register circuit breaker
        if circuit_breaker:
            self.circuit_breaker_registry._breakers[agent_id] = circuit_breaker
        
        self.observability.log(
            agent_id, "info",
            f"Registered agent with {replicas} replicas, dependencies: {dependencies}"
        )
        
        logger.info(f"Registered agent {agent_id}: replicas={replicas}, dependencies={dependencies}")
        return agent_id
    
    async def start_all(self) -> Dict[str, Any]:
        """
        Start all registered agents in dependency order.
        
        Returns:
            Summary of startup results
        """
        if self._running:
            return {"status": "already_running"}
        
        result = {
            "started_at": datetime.now().isoformat(),
            "agents": {},
            "errors": []
        }
        
        try:
            # Validate dependency graph
            errors = self.dependency_graph.validate()
            if errors:
                result["errors"] = errors
                return result
            
            # Get startup order
            startup_groups = self.dependency_graph.get_parallel_startup_groups()
            
            # Start coordinator
            await self.coordinator.start()
            
            # Start health monitor
            await self.health_monitor.start()
            
            # Start agents in dependency order
            for group in startup_groups:
                # Start agents in this group in parallel
                tasks = []
                for agent_id in group:
                    tasks.append(self._start_agent(agent_id))
                
                group_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for agent_id, res in zip(group, group_results):
                    if isinstance(res, Exception):
                        result["agents"][agent_id] = {
                            "status": "failed",
                            "error": str(res)
                        }
                        result["errors"].append(f"{agent_id}: {res}")
                    else:
                        result["agents"][agent_id] = res
            
            # Start scaler
            await self.scaler.start()
            
            self._running = True
            result["status"] = "started"
            
        except Exception as e:
            result["status"] = "failed"
            result["errors"].append(str(e))
            logger.error(f"Failed to start control plane: {e}")
        
        return result
    
    async def _start_agent(self, agent_id: str) -> Dict[str, Any]:
        """Start a single agent"""
        registration = self._registrations.get(agent_id)
        if not registration:
            raise ValueError(f"Agent {agent_id} not registered")
        
        result = {
            "agent_id": agent_id,
            "status": "starting",
            "replicas": []
        }
        
        # Check resource quota
        if registration.resources:
            self.quota_manager.set_quota(agent_id, registration.resources)
        
        # Create factory for recovery manager
        def create_agent():
            return registration.agent_type()
        
        # Register with recovery manager
        self.recovery_manager.register_agent(agent_id, create_agent)
        
        # Create replicas
        for i in range(registration.replicas):
            replica_id = f"{agent_id}-{i}"
            try:
                instance = create_agent()
                
                # Start instance if it has start method
                if hasattr(instance, 'start'):
                    if asyncio.iscoroutinefunction(instance.start):
                        await instance.start()
                    else:
                        instance.start()
                
                self._instances[agent_id].append(instance)
                
                # Register with health monitor
                self.health_monitor.register_agent(replica_id, instance)
                
                result["replicas"].append({
                    "replica_id": replica_id,
                    "status": "running"
                })
                
                self.observability.log(agent_id, "info", f"Started replica {replica_id}")
                
            except Exception as e:
                result["replicas"].append({
                    "replica_id": replica_id,
                    "status": "failed",
                    "error": str(e)
                })
                self.observability.log(agent_id, "error", f"Failed to start replica {replica_id}: {e}")
        
        result["status"] = "running"
        return result
    
    async def stop_all(self) -> Dict[str, Any]:
        """
        Stop all agents gracefully.
        
        Returns:
            Summary of shutdown results
        """
        if not self._running:
            return {"status": "not_running"}
        
        # Initiate graceful shutdown
        shutdown_result = await self.shutdown_manager.shutdown()
        
        # Stop components in reverse order
        await self.scaler.stop()
        await self.health_monitor.stop()
        await self.coordinator.stop()
        
        # Stop agents in reverse dependency order
        shutdown_order = self.dependency_graph.get_shutdown_order()
        
        for agent_id in shutdown_order:
            for instance in self._instances.get(agent_id, []):
                try:
                    if hasattr(instance, 'stop'):
                        if asyncio.iscoroutinefunction(instance.stop):
                            await instance.stop()
                        else:
                            instance.stop()
                except Exception as e:
                    logger.error(f"Error stopping {agent_id}: {e}")
            
            self._instances[agent_id].clear()
        
        self._running = False
        
        return {
            "status": "stopped",
            "shutdown_result": shutdown_result
        }
    
    def get_agent(self, agent_id: str, replica_index: int = 0) -> Optional[Any]:
        """Get an agent instance by ID"""
        instances = self._instances.get(agent_id, [])
        if 0 <= replica_index < len(instances):
            return instances[replica_index]
        return None
    
    async def get_available_agent(self, agent_id: str) -> Optional[Any]:
        """Get an available agent instance (load balanced)"""
        # Check circuit breaker
        breaker = self.circuit_breaker_registry.get(agent_id)
        if breaker and breaker.is_open:
            return None
        
        # Check resource quota
        if not self.quota_manager.can_execute(agent_id):
            return None
        
        # Get replica from scaler
        return await self.scaler.get_replica(agent_id)
    
    def get_health_status(self, agent_id: str) -> HealthStatus:
        """Get the health status of an agent"""
        return self.health_monitor.get_agent_health(agent_id)
    
    def get_all_health_status(self) -> Dict[str, HealthStatus]:
        """Get health status for all agents"""
        return self.health_monitor.get_all_health_status()
    
    def get_circuit_breaker(self, agent_id: str) -> Optional[CircuitBreaker]:
        """Get the circuit breaker for an agent"""
        return self.circuit_breaker_registry.get(agent_id)
    
    def get_metrics(self) -> str:
        """Get Prometheus-formatted metrics"""
        return self.observability.export_prometheus()
    
    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive status of the control plane"""
        return {
            "running": self._running,
            "node_id": self.node_id,
            "is_leader": self.coordinator.is_leader,
            "registered_agents": list(self._registrations.keys()),
            "health_status": {
                k: v.value for k, v in self.health_monitor.get_all_health_status().items()
            },
            "circuit_breakers": {
                name: cb.get_metrics().__dict__
                for name, cb in self.circuit_breaker_registry._breakers.items()
            },
            "resource_violations": self.quota_manager.check_quota_violations(),
            "in_flight_operations": self.shutdown_manager.get_in_flight_count()
        }


# Convenience factory function
def create_control_plane(
    health_check_interval: float = 30.0,
    auto_recovery: bool = True,
    circuit_breaker: Optional[CircuitBreaker] = None,
    **kwargs
) -> EnhancedAgentControlPlane:
    """
    Create an enhanced agent control plane.
    
    This is the recommended way to create a control plane instance.
    
    Args:
        health_check_interval: Interval between health checks
        auto_recovery: Enable automatic recovery
        circuit_breaker: Default circuit breaker
        **kwargs: Additional configuration
        
    Returns:
        Configured EnhancedAgentControlPlane instance
    """
    return EnhancedAgentControlPlane(
        health_check_interval=health_check_interval,
        auto_recovery=auto_recovery,
        circuit_breaker=circuit_breaker,
        **kwargs
    )


# Backwards compatibility alias
AgentControlPlaneV2 = EnhancedAgentControlPlane
