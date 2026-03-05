# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the new ATR v0.2.0 features."""

import asyncio

import pytest

import atr
from atr import (
    AccessControlManager,
    AccessDeniedError,
    AccessPolicy,
    BackoffStrategy,
    CallableHealthCheck,
    DependencyContainer,
    FunctionStep,
    HealthCheckRegistry,
    HealthStatus,
    InjectionToken,
    MetricsCollector,
    Principal,
    RateLimitPolicy,
    Registry,
    RetryPolicy,
    ToolChain,
    VersionConstraintError,
    compose,
)
from atr.registry import parse_version, version_matches

# ---------------------------------------------------------------------------
# Versioning Tests (ATR-002)
# ---------------------------------------------------------------------------


class TestVersioning:
    """Tests for tool versioning functionality."""

    def test_parse_version(self):
        """Test version string parsing."""
        assert parse_version("1.0.0") == (1, 0, 0)
        assert parse_version("2.3.4") == (2, 3, 4)
        assert parse_version("0.0.1") == (0, 0, 1)
        assert parse_version("10.20.30") == (10, 20, 30)

    def test_version_matches_exact(self):
        """Test exact version matching."""
        assert version_matches("1.0.0", "1.0.0") is True
        assert version_matches("1.0.0", "1.0.1") is False
        assert version_matches("2.0.0", "1.0.0") is False

    def test_version_matches_gte(self):
        """Test >= version constraint."""
        assert version_matches("1.0.0", ">=1.0.0") is True
        assert version_matches("1.0.1", ">=1.0.0") is True
        assert version_matches("2.0.0", ">=1.0.0") is True
        assert version_matches("0.9.0", ">=1.0.0") is False

    def test_version_matches_caret(self):
        """Test ^ (caret) version constraint - same major."""
        assert version_matches("1.0.0", "^1.0.0") is True
        assert version_matches("1.5.0", "^1.0.0") is True
        assert version_matches("1.99.99", "^1.0.0") is True
        assert version_matches("2.0.0", "^1.0.0") is False
        assert version_matches("0.9.0", "^1.0.0") is False

    def test_version_matches_tilde(self):
        """Test ~ (tilde) version constraint - same major.minor."""
        assert version_matches("1.0.0", "~1.0.0") is True
        assert version_matches("1.0.5", "~1.0.0") is True
        assert version_matches("1.1.0", "~1.0.0") is False
        assert version_matches("2.0.0", "~1.0.0") is False

    def test_version_matches_wildcard(self):
        """Test * (any) version constraint."""
        assert version_matches("1.0.0", "*") is True
        assert version_matches("99.99.99", "*") is True
        assert version_matches("0.0.1", "") is True

    def test_register_multiple_versions(self):
        """Test registering multiple versions of same tool."""
        registry = Registry()

        @atr.register(name="versioned_tool", version="1.0.0", registry=registry)
        def tool_v1(x: int) -> int:
            return x * 1

        @atr.register(name="versioned_tool", version="2.0.0", registry=registry)
        def tool_v2(x: int) -> int:
            return x * 2

        # Get latest (should be 2.0.0)
        latest = registry.get_tool("versioned_tool")
        assert latest.version == "2.0.0"

        # Get specific version
        v1 = registry.get_tool("versioned_tool", version="1.0.0")
        assert v1.version == "1.0.0"

        # Get all versions
        versions = registry.get_all_versions("versioned_tool")
        assert versions == ["2.0.0", "1.0.0"]

    def test_version_constraint_no_match(self):
        """Test error when no version matches constraint."""
        registry = Registry()

        @atr.register(name="old_tool", version="1.0.0", registry=registry)
        def old_tool(x: int) -> int:
            return x

        with pytest.raises(VersionConstraintError):
            registry.get_tool("old_tool", version=">=2.0.0")

    def test_deprecate_tool(self):
        """Test tool deprecation."""
        registry = Registry()

        @atr.register(name="deprecated_tool", version="1.0.0", registry=registry)
        def deprecated_func(x: int) -> int:
            return x

        @atr.register(name="deprecated_tool", version="2.0.0", registry=registry)
        def new_func(x: int) -> int:
            return x * 2

        registry.deprecate_tool("deprecated_tool", "1.0.0", "Use v2.0.0 instead")

        # Without include_deprecated, should get v2
        tool = registry.get_tool("deprecated_tool")
        assert tool.version == "2.0.0"

        # With include_deprecated, can get v1
        tool_v1 = registry.get_tool("deprecated_tool", version="1.0.0", include_deprecated=True)
        assert tool_v1.version == "1.0.0"
        assert tool_v1.metadata.deprecated is True


# ---------------------------------------------------------------------------
# Async Support Tests (ATR-003)
# ---------------------------------------------------------------------------


class TestAsyncSupport:
    """Tests for async tool support."""

    def test_async_detection(self):
        """Test automatic async detection."""
        registry = Registry()

        @atr.register(name="sync_tool", registry=registry)
        def sync_func(x: int) -> int:
            return x

        @atr.register(name="async_tool", registry=registry)
        async def async_func(x: int) -> int:
            return x

        sync_spec = registry.get_tool("sync_tool")
        async_spec = registry.get_tool("async_tool")

        assert sync_spec.is_async is False
        assert async_spec.is_async is True

    def test_explicit_async_flag(self):
        """Test explicit async flag override."""
        registry = Registry()

        @atr.register(name="forced_async", async_=True, registry=registry)
        def sync_but_async(x: int) -> int:
            return x

        spec = registry.get_tool("forced_async")
        assert spec.is_async is True

    @pytest.mark.asyncio
    async def test_async_tool_execution(self):
        """Test executing async tool via handle."""
        registry = Registry()

        @atr.register(name="async_adder", registry=registry)
        async def async_add(a: int, b: int) -> int:
            await asyncio.sleep(0.01)
            return a + b

        handle = registry.get_tool_handle("async_adder")
        result = await handle.call_async(a=1, b=2)
        assert result == 3


# ---------------------------------------------------------------------------
# Dependency Injection Tests (ATR-004)
# ---------------------------------------------------------------------------


class TestDependencyInjection:
    """Tests for dependency injection."""

    def test_container_register_and_resolve(self):
        """Test basic container functionality."""
        container = DependencyContainer()

        class Config:
            def __init__(self, api_key: str):
                self.api_key = api_key

        config = Config(api_key="secret123")
        container.register(Config, config)

        resolved = container.resolve(Config)
        assert resolved.api_key == "secret123"

    def test_resolve_by_name(self):
        """Test resolving by string name."""
        container = DependencyContainer()
        container.register("api_key", "my-secret-key")

        assert container.resolve("api_key") == "my-secret-key"

    def test_injection_token(self):
        """Test InjectionToken usage."""
        container = DependencyContainer()

        CONFIG_TOKEN = InjectionToken[str]("config")
        container.register(CONFIG_TOKEN, "token_value")

        assert container.resolve(CONFIG_TOKEN) == "token_value"

    def test_factory_registration(self):
        """Test factory function registration."""
        container = DependencyContainer()
        call_count = [0]

        def create_connection():
            call_count[0] += 1
            return f"connection_{call_count[0]}"

        container.register("db", factory=create_connection, singleton=True)

        # Should return same instance
        conn1 = container.resolve("db")
        conn2 = container.resolve("db")
        assert conn1 == conn2
        assert call_count[0] == 1

    def test_child_container(self):
        """Test child container inheritance."""
        parent = DependencyContainer()
        parent.register("shared", "parent_value")

        child = parent.create_child()
        child.register("child_only", "child_value")

        # Child can access parent values
        assert child.resolve("shared") == "parent_value"
        assert child.resolve("child_only") == "child_value"

        # Parent doesn't have child values
        assert parent.resolve("child_only") is None


# ---------------------------------------------------------------------------
# Access Control Tests (ATR-005)
# ---------------------------------------------------------------------------


class TestAccessControl:
    """Tests for access control."""

    def test_principal_creation(self):
        """Test principal creation."""
        principal = Principal.create(
            id="agent-1",
            type="agent",
            roles=["claims-agent", "reader"],
            attributes={"department": "claims"},
        )

        assert principal.id == "agent-1"
        assert principal.has_role("claims-agent") is True
        assert principal.has_role("admin") is False
        assert principal.get_attribute("department") == "claims"

    def test_access_policy_roles_only(self):
        """Test role-based access policy."""
        policy = AccessPolicy.roles_only("admin", "claims-agent")

        admin = Principal.create("admin-1", roles=["admin"])
        claims = Principal.create("claims-1", roles=["claims-agent"])
        visitor = Principal.create("visitor-1", roles=["viewer"])

        assert policy.allows(admin, "any_tool") is True
        assert policy.allows(claims, "any_tool") is True
        assert policy.allows(visitor, "any_tool") is False

    def test_access_policy_denied_principals(self):
        """Test explicit principal denial."""
        policy = AccessPolicy(allowed_roles={"user"}, denied_principals={"bad_user"})

        good_user = Principal.create("good_user", roles=["user"])
        bad_user = Principal.create("bad_user", roles=["user"])

        assert policy.allows(good_user, "tool") is True
        assert policy.allows(bad_user, "tool") is False  # Explicitly denied

    def test_access_control_manager(self):
        """Test access control manager."""
        manager = AccessControlManager()

        manager.set_policy("sensitive_tool", AccessPolicy.roles_only("admin"))

        admin = Principal.create("admin-1", roles=["admin"])
        user = Principal.create("user-1", roles=["user"])

        assert manager.can_access(admin, "sensitive_tool") is True
        assert manager.can_access(user, "sensitive_tool") is False

        # Tool without specific policy uses default (allow all)
        assert manager.can_access(user, "public_tool") is True

    def test_access_denied_error(self):
        """Test access denied error raising."""
        manager = AccessControlManager()
        manager.set_policy("restricted", AccessPolicy.deny_all())

        user = Principal.create("user-1")

        with pytest.raises(AccessDeniedError):
            manager.require_access(user, "restricted")


# ---------------------------------------------------------------------------
# Rate Limiting Tests (ATR-006)
# ---------------------------------------------------------------------------


class TestRateLimiting:
    """Tests for rate limiting."""

    def test_rate_limit_parsing(self):
        """Test parsing rate limit strings."""
        policy = RateLimitPolicy.from_string("10/minute")
        assert policy.limit == 10
        assert policy.period == 60

        policy2 = RateLimitPolicy.from_string("5/second")
        assert policy2.limit == 5
        assert policy2.period == 1

        policy3 = RateLimitPolicy.from_string("100/hour")
        assert policy3.limit == 100
        assert policy3.period == 3600

    def test_rate_limit_acquire(self):
        """Test rate limit acquisition."""
        policy = RateLimitPolicy(limit=3, period=10)

        # Should allow first 3
        assert policy.acquire(blocking=False) is True
        assert policy.acquire(blocking=False) is True
        assert policy.acquire(blocking=False) is True

        # 4th should be blocked
        assert policy.acquire(blocking=False) is False

    def test_rate_limit_reset(self):
        """Test rate limit reset."""
        policy = RateLimitPolicy(limit=2, period=10)

        policy.acquire(blocking=False)
        policy.acquire(blocking=False)
        assert policy.acquire(blocking=False) is False

        policy.reset()
        assert policy.acquire(blocking=False) is True


# ---------------------------------------------------------------------------
# Retry Policy Tests (ATR-010)
# ---------------------------------------------------------------------------


class TestRetryPolicy:
    """Tests for retry policies."""

    def test_retry_policy_creation(self):
        """Test retry policy creation."""
        policy = RetryPolicy(max_attempts=3, backoff=BackoffStrategy.EXPONENTIAL, initial_delay=1.0)

        assert policy.max_attempts == 3
        assert policy.backoff == BackoffStrategy.EXPONENTIAL

    def test_backoff_calculation_exponential(self):
        """Test exponential backoff calculation."""
        policy = RetryPolicy(backoff=BackoffStrategy.EXPONENTIAL, initial_delay=1.0, jitter=False)

        assert policy.calculate_delay(1) == 0  # First attempt, no delay
        assert policy.calculate_delay(2) == 1.0  # 1 * 2^0
        assert policy.calculate_delay(3) == 2.0  # 1 * 2^1
        assert policy.calculate_delay(4) == 4.0  # 1 * 2^2

    def test_backoff_calculation_linear(self):
        """Test linear backoff calculation."""
        policy = RetryPolicy(backoff=BackoffStrategy.LINEAR, initial_delay=1.0, jitter=False)

        assert policy.calculate_delay(1) == 0
        assert policy.calculate_delay(2) == 1.0
        assert policy.calculate_delay(3) == 2.0
        assert policy.calculate_delay(4) == 3.0

    def test_max_delay_cap(self):
        """Test max delay cap."""
        policy = RetryPolicy(
            backoff=BackoffStrategy.EXPONENTIAL, initial_delay=1.0, max_delay=5.0, jitter=False
        )

        # At attempt 5, would be 8.0 but capped at 5.0
        assert policy.calculate_delay(5) == 5.0

    def test_should_retry_on_exception(self):
        """Test exception filtering."""
        policy = RetryPolicy(retry_on=(ValueError, TypeError))

        assert policy.should_retry(ValueError()) is True
        assert policy.should_retry(TypeError()) is True
        assert policy.should_retry(RuntimeError()) is False

    def test_should_retry_all_exceptions(self):
        """Test retry on all exceptions."""
        policy = RetryPolicy()  # retry_on=None means all

        assert policy.should_retry(ValueError()) is True
        assert policy.should_retry(RuntimeError()) is True


# ---------------------------------------------------------------------------
# Metrics Tests (ATR-009)
# ---------------------------------------------------------------------------


class TestMetrics:
    """Tests for metrics collection."""

    def test_metrics_recording(self):
        """Test basic metrics recording."""
        collector = MetricsCollector()

        collector.record_call("my_tool", latency_ms=100, success=True)
        collector.record_call("my_tool", latency_ms=200, success=True)
        collector.record_call("my_tool", latency_ms=150, success=False, error=ValueError("test"))

        metrics = collector.get_metrics("my_tool")

        assert metrics.total_calls == 3
        assert metrics.successful_calls == 2
        assert metrics.failed_calls == 1
        assert metrics.avg_latency_ms == 150.0
        assert metrics.min_latency_ms == 100
        assert metrics.max_latency_ms == 200

    def test_success_rate_calculation(self):
        """Test success rate calculation."""
        collector = MetricsCollector()

        for _ in range(8):
            collector.record_call("tool", latency_ms=10, success=True)
        for _ in range(2):
            collector.record_call("tool", latency_ms=10, success=False)

        metrics = collector.get_metrics("tool")
        assert metrics.success_rate == 80.0
        assert metrics.error_rate == 20.0

    def test_error_breakdown(self):
        """Test error type breakdown."""
        collector = MetricsCollector()

        collector.record_call("tool", latency_ms=10, success=False, error=ValueError())
        collector.record_call("tool", latency_ms=10, success=False, error=ValueError())
        collector.record_call("tool", latency_ms=10, success=False, error=TypeError())

        breakdown = collector.get_error_breakdown("tool")
        assert breakdown["ValueError"] == 2
        assert breakdown["TypeError"] == 1


# ---------------------------------------------------------------------------
# Health Check Tests (ATR-008)
# ---------------------------------------------------------------------------


class TestHealthChecks:
    """Tests for health checks."""

    def test_callable_health_check_success(self):
        """Test callable health check with success."""
        check = CallableHealthCheck(lambda: True, name="test_check")
        result = check.check()

        assert result.status == HealthStatus.HEALTHY
        assert result.is_healthy is True

    def test_callable_health_check_failure(self):
        """Test callable health check with failure."""
        check = CallableHealthCheck(lambda: False, name="test_check")
        result = check.check()

        assert result.status == HealthStatus.UNHEALTHY
        assert result.is_healthy is False

    def test_callable_health_check_exception(self):
        """Test callable health check with exception."""

        def failing_check():
            raise RuntimeError("Connection failed")

        check = CallableHealthCheck(failing_check, name="failing")
        result = check.check()

        assert result.status == HealthStatus.UNHEALTHY
        assert "exception" in result.message.lower()

    def test_health_check_registry(self):
        """Test health check registry."""
        registry = HealthCheckRegistry()

        registry.register("tool1", lambda: True)
        registry.register("tool2", lambda: False)

        results = registry.check_all(use_cache=False)

        assert results["tool1"].status == HealthStatus.HEALTHY
        assert results["tool2"].status == HealthStatus.UNHEALTHY

    def test_health_check_caching(self):
        """Test health check result caching."""
        call_count = [0]

        def counting_check():
            call_count[0] += 1
            return True

        registry = HealthCheckRegistry()
        registry.register("counted", counting_check)

        # First call
        registry.check("counted", use_cache=True)
        assert call_count[0] == 1

        # Second call should use cache
        registry.check("counted", use_cache=True)
        assert call_count[0] == 1

        # Without cache
        registry.check("counted", use_cache=False)
        assert call_count[0] == 2


# ---------------------------------------------------------------------------
# Tool Composition Tests (ATR-007)
# ---------------------------------------------------------------------------


class TestToolComposition:
    """Tests for tool composition."""

    def test_function_step(self):
        """Test basic function step."""

        def double(x: int) -> int:
            return x * 2

        step = FunctionStep(double)
        result = step.execute(5, {})

        assert result.success is True
        assert result.value == 10

    def test_pipeline_sequential(self):
        """Test sequential pipeline."""

        def add_one(x: int) -> int:
            return x + 1

        def double(x: int) -> int:
            return x * 2

        pipeline = compose(add_one, double, name="math_pipeline")
        result = pipeline.execute(5, {})

        # (5 + 1) * 2 = 12
        assert result.success is True
        assert result.value == 12

    def test_tool_chain_builder(self):
        """Test fluent tool chain builder."""
        chain = (
            ToolChain(name="processing")
            .then(lambda x: x + 1)  # noqa: ARG005
            .then(lambda x: x * 2)  # noqa: ARG005
            .build()
        )

        result = chain.execute(10, {})
        assert result.value == 22  # (10 + 1) * 2

    def test_pipeline_error_handling(self):
        """Test pipeline error handling."""

        def failing_step(x: int) -> int:  # noqa: ARG001
            raise ValueError("Intentional failure")

        def never_reached(x: int) -> int:
            return x * 100

        pipeline = compose(failing_step, never_reached, name="failing")
        result = pipeline.execute(5, {})

        assert result.success is False
        assert isinstance(result.error, ValueError)

    def test_tool_result_map(self):
        """Test ToolResult mapping."""
        from atr.composition import ToolResult

        result = ToolResult.ok(5, "test")
        mapped = result.map(lambda x: x * 2)

        assert mapped.success is True
        assert mapped.value == 10

    def test_tool_result_unwrap(self):
        """Test ToolResult unwrap."""
        from atr.composition import ToolResult

        ok_result = ToolResult.ok(42, "test")
        assert ok_result.unwrap() == 42

        err_result = ToolResult.fail(ValueError("error"), "test")
        with pytest.raises(ValueError):
            err_result.unwrap()


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------


class TestIntegration:
    """Integration tests combining multiple features."""

    def test_full_tool_registration_with_features(self):
        """Test registering tool with all features."""
        registry = Registry()

        @atr.register(
            name="full_featured_tool",
            version="1.0.0",
            cost="medium",
            tags=["integration", "test"],
            permissions=["test-agent"],
            rate_limit="100/minute",
            retry_policy=RetryPolicy(max_attempts=2),
            registry=registry,
        )
        def featured_tool(x: int, y: int = 10) -> int:
            """A fully featured tool."""
            return x + y

        # Verify registration
        spec = registry.get_tool("full_featured_tool")

        assert spec.name == "full_featured_tool"
        assert spec.version == "1.0.0"
        assert spec.metadata.permissions == ["test-agent"]
        assert spec.metadata.rate_limit == "100/minute"
        assert spec._retry_policy is not None
        assert spec._rate_limit_policy is not None
        assert spec._access_policy is not None

    def test_tool_handle_execution(self):
        """Test tool execution through handle."""
        registry = Registry()

        @atr.register(name="adder", registry=registry)
        def add(a: int, b: int) -> int:
            return a + b

        handle = registry.get_tool_handle("adder")
        result = handle.call(a=5, b=3)

        assert result == 8

    def test_anthropic_schema_generation(self):
        """Test Anthropic tool schema generation."""
        registry = Registry()

        @atr.register(name="schema_test", registry=registry)
        def test_func(query: str, limit: int = 10) -> str:  # noqa: ARG001
            """Search for items."""
            return f"Results for {query}"

        spec = registry.get_tool("schema_test")
        schema = spec.to_anthropic_tool_schema()

        assert schema["name"] == "schema_test"
        assert "input_schema" in schema
        assert schema["input_schema"]["type"] == "object"
        assert "query" in schema["input_schema"]["properties"]
