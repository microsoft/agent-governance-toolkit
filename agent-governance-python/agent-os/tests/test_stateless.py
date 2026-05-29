# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test Stateless Kernel (MCP June 2026 compliant).
"""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest


class TestStatelessKernel:
    """Test StatelessKernel class."""

    def test_import_stateless(self):
        """Test importing stateless module."""
        from agent_os.stateless import (
            ExecutionContext,
            StatelessKernel,
        )
        assert StatelessKernel is not None
        assert ExecutionContext is not None

    def test_create_kernel(self):
        """Test creating a stateless kernel."""
        from agent_os.stateless import StatelessKernel

        kernel = StatelessKernel()
        assert kernel is not None
        assert kernel.backend is not None

    def test_execution_context(self):
        """Test ExecutionContext creation."""
        from agent_os.stateless import ExecutionContext

        ctx = ExecutionContext(
            agent_id="test-agent",
            policies=["read_only"],
            history=[]
        )

        assert ctx.agent_id == "test-agent"
        assert "read_only" in ctx.policies
        assert ctx.history == []

    def test_context_to_dict(self):
        """Test ExecutionContext serialization."""
        from agent_os.stateless import ExecutionContext

        ctx = ExecutionContext(
            agent_id="test-agent",
            policies=["strict"],
            metadata={"key": "value"}
        )

        d = ctx.to_dict()
        assert d["agent_id"] == "test-agent"
        assert d["policies"] == ["strict"]
        assert d["metadata"]["key"] == "value"

    @pytest.mark.asyncio
    async def test_execute_allowed_action(self):
        """Test executing an allowed action."""
        from agent_os.stateless import ExecutionContext, StatelessKernel

        kernel = StatelessKernel()
        context = ExecutionContext(agent_id="test", policies=[])

        result = await kernel.execute(
            action="database_query",
            params={"query": "SELECT 1"},
            context=context
        )

        assert result.success is True
        assert result.error is None
        assert result.signal is None

    @pytest.mark.asyncio
    async def test_execute_blocked_by_read_only(self):
        """Test action blocked by read_only policy."""
        from agent_os.stateless import ExecutionContext, StatelessKernel

        kernel = StatelessKernel()
        context = ExecutionContext(
            agent_id="test",
            policies=["read_only"]
        )

        result = await kernel.execute(
            action="file_write",
            params={"path": "/data/file.txt"},
            context=context
        )

        assert result.success is False
        assert result.signal == "SIGKILL"
        assert "read_only" in result.error

    @pytest.mark.asyncio
    async def test_execute_blocked_by_no_pii(self):
        """Test action blocked by no_pii policy."""
        from agent_os.stateless import ExecutionContext, StatelessKernel

        kernel = StatelessKernel()
        context = ExecutionContext(
            agent_id="test",
            policies=["no_pii"]
        )

        result = await kernel.execute(
            action="database_query",
            params={"query": "SELECT ssn FROM users"},
            context=context
        )

        assert result.success is False
        assert result.signal == "SIGKILL"
        assert "ssn" in result.error.lower()

    @pytest.mark.asyncio
    async def test_execute_global_approval_blocks_empty_policy_list(self):
        """Empty/unknown ``policies`` list must NOT bypass the global
        approval gate. ``file_write`` is in DEFAULT_POLICIES['strict']
        require_approval set, so even an empty policy list denies it."""
        from agent_os.stateless import ExecutionContext, StatelessKernel

        kernel = StatelessKernel()
        for policy_set in ([], ["nonexistent_policy_name"]):
            context = ExecutionContext(agent_id="t", policies=policy_set)
            result = await kernel.execute(
                action="file_write",
                params={"path": "/data/x", "approved": True},
                context=context,
            )
            assert result.success is False, f"policies={policy_set!r}"
            assert result.signal == "SIGKILL"
            assert "requires approval" in result.error.lower()

    @pytest.mark.asyncio
    async def test_execute_global_approval_bypassed_with_trusted_intent(self):
        """The global approval gate is satisfied by a trusted IntentManager
        that returns ``allowed=True, was_planned=True``."""
        from agent_os.stateless import ExecutionContext, StatelessKernel

        class ApprovedIntentManager:
            async def check_action(self, **kwargs):
                return SimpleNamespace(
                    allowed=True, reason=None, was_planned=True,
                    trust_penalty=0.0, drift_policy_applied=None,
                )

        kernel = StatelessKernel(intent_manager=ApprovedIntentManager())
        context = ExecutionContext(
            agent_id="t", policies=[], intent_id="intent-ok",
        )
        result = await kernel.execute(
            action="file_write",
            params={"path": "/data/x"},
            context=context,
        )
        assert result.success is True

    @pytest.mark.asyncio
    async def test_execute_requires_trusted_approval_ignores_caller_flag(self):
        """Caller-controlled approved=True must not satisfy approval policy."""
        from agent_os.stateless import ExecutionContext, StatelessKernel

        kernel = StatelessKernel()
        context = ExecutionContext(agent_id="test", policies=["strict"])

        result = await kernel.execute(
            action="file_write",
            params={"path": "/data/file.txt", "approved": True},
            context=context,
        )

        assert result.success is False
        assert result.signal == "SIGKILL"
        assert "caller-supplied approval flags are ignored" in result.error.lower()

    @pytest.mark.asyncio
    async def test_execute_strips_falsy_approved_from_downstream_params(self):
        """approved=False (and any key presence) must be stripped before
        IntentManager.check_action and _execute_action see params.
        """
        from agent_os.stateless import ExecutionContext, StatelessKernel

        captured: dict[str, dict] = {}

        class SpyIntentManager:
            async def check_action(self, **kwargs):
                captured["intent_params"] = dict(kwargs.get("params") or {})
                return SimpleNamespace(
                    allowed=True,
                    reason=None,
                    was_planned=True,
                    trust_penalty=0.0,
                    drift_policy_applied=None,
                )

        kernel = StatelessKernel(intent_manager=SpyIntentManager())

        async def spy_execute(action, params, state):
            captured["exec_params"] = dict(params)
            return {"data": {"status": "executed", "action": action}}

        kernel._execute_action = spy_execute  # type: ignore[assignment]

        context = ExecutionContext(
            agent_id="test",
            policies=["strict"],
            intent_id="intent-approved",
        )

        for falsy in (False, 0, ""):
            captured.clear()
            result = await kernel.execute(
                action="file_write",
                params={"path": "/data/file.txt", "approved": falsy},
                context=context,
            )

            assert result.success is True, f"falsy={falsy!r}"
            assert "approved" not in captured["intent_params"], (
                f"approved leaked to IntentManager.check_action with falsy={falsy!r}: "
                f"{captured['intent_params']}"
            )
            assert "approved" not in captured["exec_params"], (
                f"approved leaked to _execute_action with falsy={falsy!r}: "
                f"{captured['exec_params']}"
            )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "approval_key",
        ["Approved", "APPROVED", "approv\u0435d"],  # case + Cyrillic 'е'
    )
    async def test_execute_strips_confusable_approved_keys(self, approval_key):
        """Case-variant and Unicode-confusable 'approved' keys must be stripped
        before downstream params reach IntentManager / _execute_action."""
        from agent_os.stateless import ExecutionContext, StatelessKernel

        captured: dict[str, dict] = {}

        class SpyIntentManager:
            async def check_action(self, **kwargs):
                captured["intent_params"] = dict(kwargs.get("params") or {})
                return SimpleNamespace(
                    allowed=True, reason=None, was_planned=True,
                    trust_penalty=0.0, drift_policy_applied=None,
                )

        kernel = StatelessKernel(intent_manager=SpyIntentManager())

        async def spy_execute(action, params, state):
            captured["exec_params"] = dict(params)
            return {"data": {"status": "executed", "action": action}}

        kernel._execute_action = spy_execute  # type: ignore[assignment]

        context = ExecutionContext(
            agent_id="test", policies=["strict"], intent_id="intent-x",
        )
        result = await kernel.execute(
            action="file_write",
            params={"path": "/data/x", approval_key: True},
            context=context,
        )
        assert result.success is True
        import unicodedata as _u
        for bag in (captured["intent_params"], captured["exec_params"]):
            for k in bag:
                assert _u.normalize("NFKC", str(k)).casefold() != "approved", (
                    f"confusable key {approval_key!r} leaked as {k!r}"
                )

    @pytest.mark.asyncio
    async def test_execute_strips_nested_approved_keys(self):
        """Nested approved keys (e.g. in metadata dicts/lists) are stripped recursively."""
        from agent_os.stateless import ExecutionContext, StatelessKernel

        captured: dict[str, dict] = {}

        class SpyIntentManager:
            async def check_action(self, **kwargs):
                captured["intent_params"] = dict(kwargs.get("params") or {})
                return SimpleNamespace(
                    allowed=True, reason=None, was_planned=True,
                    trust_penalty=0.0, drift_policy_applied=None,
                )

        kernel = StatelessKernel(intent_manager=SpyIntentManager())

        async def spy_execute(action, params, state):
            captured["exec_params"] = dict(params)
            return {"data": {"status": "executed", "action": action}}

        kernel._execute_action = spy_execute  # type: ignore[assignment]

        context = ExecutionContext(
            agent_id="test", policies=["strict"], intent_id="intent-nested",
        )
        result = await kernel.execute(
            action="file_write",
            params={"path": "/data/x", "meta": {"approved": True, "tag": "ok"}},
            context=context,
        )
        assert result.success is True
        assert "approved" not in captured["exec_params"].get("meta", {})
        assert captured["exec_params"]["meta"].get("tag") == "ok"

    @pytest.mark.asyncio
    async def test_execute_allows_restricted_action_with_approved_intent(self):
        """Trusted intent approval can authorize actions requiring approval."""
        from agent_os.stateless import ExecutionContext, StatelessKernel

        class ApprovedIntentManager:
            async def check_action(self, **kwargs):
                return SimpleNamespace(
                    allowed=True,
                    reason=None,
                    was_planned=True,
                    trust_penalty=0.0,
                    drift_policy_applied=None,
                )

        kernel = StatelessKernel(intent_manager=ApprovedIntentManager())
        context = ExecutionContext(
            agent_id="test",
            policies=["strict"],
            intent_id="intent-approved",
        )

        result = await kernel.execute(
            action="file_write",
            params={"path": "/data/file.txt", "approved": True},
            context=context,
        )

        assert result.success is True
        assert result.data["action"] == "file_write"

    @pytest.mark.asyncio
    async def test_execute_denies_restricted_action_when_intent_drift_allowed(self):
        """Approval-required actions must be explicitly planned, not soft-drifted."""
        from agent_os.stateless import ExecutionContext, StatelessKernel

        class DriftAllowedIntentManager:
            async def check_action(self, **kwargs):
                return SimpleNamespace(
                    allowed=True,
                    was_planned=False,
                    trust_penalty=0.1,
                    drift_policy_applied=SimpleNamespace(value="soft_block"),
                )

        kernel = StatelessKernel(intent_manager=DriftAllowedIntentManager())
        context = ExecutionContext(
            agent_id="test",
            policies=["strict"],
            intent_id="intent-drift",
        )

        result = await kernel.execute(
            action="file_write",
            params={"path": "/data/file.txt"},
            context=context,
        )

        assert result.success is False
        assert result.signal == "SIGKILL"
        assert "requires trusted approval" in result.error.lower()

    @pytest.mark.asyncio
    async def test_execute_fails_closed_on_partial_intent_manager(self):
        """A partial/misbehaving IntentManager returning an object missing
        required attributes (e.g. ``.was_planned``) must fail closed with
        SIGKILL rather than bubbling an AttributeError as a 500."""
        from agent_os.stateless import ExecutionContext, StatelessKernel

        class PartialIntentManager:
            async def check_action(self, **kwargs):
                # Returns an object missing ``.was_planned`` /
                # ``.trust_penalty`` / ``.drift_policy_applied`` — only
                # ``.allowed`` and ``.reason`` are present. Should still
                # fail closed instead of raising AttributeError.
                return SimpleNamespace(allowed=True, reason=None)

        kernel = StatelessKernel(intent_manager=PartialIntentManager())
        context = ExecutionContext(
            agent_id="test",
            policies=["strict"],
            intent_id="intent-partial",
        )

        result = await kernel.execute(
            action="file_write",
            params={"path": "/data/file.txt"},
            context=context,
        )

        assert result.success is False
        assert result.signal == "SIGKILL"
        assert result.metadata.get("intent_error") is True

    @pytest.mark.asyncio
    async def test_execute_updates_context(self):
        """Test that execution updates context."""
        from agent_os.stateless import ExecutionContext, StatelessKernel

        kernel = StatelessKernel()
        context = ExecutionContext(
            agent_id="test",
            policies=[],
            history=[]
        )

        result = await kernel.execute(
            action="api_call",
            params={"url": "https://example.com"},
            context=context
        )

        assert result.success is True
        assert result.updated_context is not None
        assert len(result.updated_context.history) == 1
        assert result.updated_context.history[0]["action"] == "api_call"

    @pytest.mark.asyncio
    async def test_stateless_execute_helper(self):
        """Test stateless_execute convenience function."""
        from agent_os.stateless import stateless_execute

        result = await stateless_execute(
            action="database_query",
            params={"query": "SELECT 1"},
            agent_id="test-agent",
            policies=[]
        )

        assert result.success is True


class TestMemoryBackend:
    """Test in-memory state backend."""

    @pytest.mark.asyncio
    async def test_memory_backend_get_set(self):
        """Test get/set operations."""
        from agent_os.stateless import MemoryBackend

        backend = MemoryBackend()

        await backend.set("key1", {"data": "value"})
        result = await backend.get("key1")

        assert result["data"] == "value"

    @pytest.mark.asyncio
    async def test_memory_backend_delete(self):
        """Test delete operation."""
        from agent_os.stateless import MemoryBackend

        backend = MemoryBackend()

        await backend.set("key1", {"data": "value"})
        await backend.delete("key1")
        result = await backend.get("key1")

        assert result is None

    @pytest.mark.asyncio
    async def test_memory_backend_missing_key(self):
        """Test getting non-existent key."""
        from agent_os.stateless import MemoryBackend

        backend = MemoryBackend()
        result = await backend.get("nonexistent")

        assert result is None


class TestRedisBackend:
    """Test Redis state backend logic."""

    def test_default_prefix(self):
        """Test that the default prefix is set correctly."""
        from agent_os.stateless import RedisBackend

        backend = RedisBackend()
        assert backend._prefix == "agent-os:"

    def test_custom_prefix(self):
        """Test that a custom prefix is set correctly."""
        from agent_os.stateless import RedisBackend

        custom_prefix = "my-custom-app:"
        backend = RedisBackend(key_prefix=custom_prefix)
        assert backend._prefix == custom_prefix

    def test_none_prefix_raises_error(self):
        """Test that None prefix raises TypeError."""
        from agent_os.stateless import RedisBackend

        with pytest.raises(TypeError):
            RedisBackend(key_prefix=None)

    @pytest.mark.asyncio
    async def test_operations_use_prefix(self):
        """Test that get/set/delete operations actually use the prefix."""
        from agent_os.stateless import RedisBackend

        # Setup backend and mock
        prefix = "test-prefix:"
        backend = RedisBackend(key_prefix=prefix)

        mock_client = AsyncMock()

        backend._client = mock_client

        test_key = "user-session-123"
        test_value = {"status": "active"}
        expected_redis_key = f"{prefix}{test_key}"

        await backend.set(test_key, test_value, ttl=60)

        mock_client.set.assert_called_with(
            expected_redis_key,
            json.dumps(test_value),
            ex=60
        )

        mock_client.get.return_value = json.dumps(test_value).encode('utf-8')

        result = await backend.get(test_key)

        mock_client.get.assert_called_with(expected_redis_key)
        assert result == test_value

        await backend.delete(test_key)

        mock_client.delete.assert_called_with(expected_redis_key)


class TestRedisConfig:
    """Test RedisConfig dataclass and its integration with RedisBackend."""

    def test_default_values(self):
        """Test RedisConfig defaults."""
        from agent_os.stateless import RedisConfig

        cfg = RedisConfig()
        assert cfg.host == "localhost"
        assert cfg.port == 6379
        assert cfg.db == 0
        assert cfg.password is None
        assert cfg.pool_size == 10
        assert cfg.connect_timeout == 5.0
        assert cfg.read_timeout == 10.0
        assert cfg.retry_on_timeout is True

    def test_custom_values(self):
        """Test RedisConfig with custom settings."""
        from agent_os.stateless import RedisConfig

        cfg = RedisConfig(
            host="redis.prod",
            port=6380,
            db=2,
            password="secret",
            pool_size=20,
            connect_timeout=2.0,
            read_timeout=3.0,
            retry_on_timeout=False,
        )
        assert cfg.host == "redis.prod"
        assert cfg.port == 6380
        assert cfg.db == 2
        assert cfg.password == "secret"
        assert cfg.pool_size == 20
        assert cfg.connect_timeout == 2.0
        assert cfg.read_timeout == 3.0
        assert cfg.retry_on_timeout is False

    def test_to_url_without_password(self):
        """Test URL generation without password."""
        from agent_os.stateless import RedisConfig

        cfg = RedisConfig(host="myhost", port=6380, db=3)
        assert cfg.to_url() == "redis://myhost:6380/3"

    def test_to_url_omits_password(self):
        """to_url() must NOT embed the password into the URL.

        The password is passed separately to the redis client via the
        keyword argument so it cannot leak into tracebacks, structured
        logs at the connection layer, or any consumer that round-trips
        the URL string.
        """
        from agent_os.stateless import RedisConfig

        cfg = RedisConfig(host="myhost", port=6380, db=1, password="s3cret")
        url = cfg.to_url()
        assert url == "redis://myhost:6380/1"
        assert "s3cret" not in url

    def test_backend_uses_config_url(self):
        """Test that RedisBackend.url is derived from RedisConfig."""
        from agent_os.stateless import RedisBackend, RedisConfig

        cfg = RedisConfig(host="redis.example.com", port=6380, db=5)
        backend = RedisBackend(config=cfg)
        assert backend.url == "redis://redis.example.com:6380/5"

    def test_backend_backward_compat_without_config(self):
        """Test that RedisBackend works without RedisConfig (backward compat)."""
        from agent_os.stateless import RedisBackend

        backend = RedisBackend(url="redis://custom:9999")
        assert backend.url == "redis://custom:9999"
        assert backend._config is None

    @pytest.mark.asyncio
    async def test_get_client_creates_pool_with_config(self):
        """Test that _get_client creates a ConnectionPool when config is provided."""
        from unittest.mock import MagicMock, patch

        from agent_os.stateless import RedisBackend, RedisConfig

        cfg = RedisConfig(
            pool_size=25,
            connect_timeout=3.0,
            read_timeout=7.0,
            retry_on_timeout=False,
        )
        backend = RedisBackend(config=cfg)

        mock_pool = MagicMock()
        mock_redis_cls = MagicMock()

        with patch("redis.asyncio.ConnectionPool") as MockPool, \
             patch("redis.asyncio.Redis") as MockRedis:
            MockPool.from_url.return_value = mock_pool
            MockRedis.return_value = mock_redis_cls

            client = await backend._get_client()

            MockPool.from_url.assert_called_once_with(
                cfg.to_url(),
                max_connections=25,
                socket_connect_timeout=3.0,
                socket_timeout=7.0,
                retry_on_timeout=False,
            )
            MockRedis.assert_called_once_with(connection_pool=mock_pool)
            assert client is mock_redis_cls

    @pytest.mark.asyncio
    async def test_get_client_without_config_uses_from_url(self):
        """Test that _get_client uses from_url when no config is given."""
        from unittest.mock import MagicMock, patch

        from agent_os.stateless import RedisBackend

        backend = RedisBackend(url="redis://localhost:6379")

        mock_client = MagicMock()
        with patch("redis.asyncio.from_url", return_value=mock_client) as mock_from_url:
            client = await backend._get_client()
            mock_from_url.assert_called_once_with("redis://localhost:6379")
            assert client is mock_client


class TestPolicyChecking:
    """Test policy enforcement logic."""

    def test_default_policies(self):
        """Test default policies are loaded."""
        from agent_os.stateless import StatelessKernel

        kernel = StatelessKernel()

        assert "read_only" in kernel.policies
        assert "no_pii" in kernel.policies
        assert "strict" in kernel.policies

    def test_custom_policies(self):
        """Test custom policies can be provided."""
        from agent_os.stateless import StatelessKernel

        custom = {
            "custom_policy": {
                "blocked_actions": ["dangerous_action"]
            }
        }

        kernel = StatelessKernel(policies=custom)

        assert "custom_policy" in kernel.policies
        assert "read_only" in kernel.policies  # Still has defaults

    @pytest.mark.asyncio
    async def test_multiple_policies(self):
        """Test multiple policies are checked."""
        from agent_os.stateless import ExecutionContext, StatelessKernel

        kernel = StatelessKernel()
        context = ExecutionContext(
            agent_id="test",
            policies=["read_only", "no_pii"]
        )

        # This should be blocked by read_only
        result = await kernel.execute(
            action="send_email",
            params={"to": "user@example.com"},
            context=context
        )

        assert result.success is False


class TestMemoryBackendTTL:
    """Test TTL expiration for MemoryBackend."""

    @pytest.mark.asyncio
    async def test_ttl_entry_expires(self):
        """Test that an entry expires after TTL elapses."""
        from unittest.mock import patch
        from agent_os.stateless import MemoryBackend

        backend = MemoryBackend()
        with patch("agent_os.stateless.time") as mock_time:
            mock_time.monotonic.return_value = 100.0
            await backend.set("k", {"v": 1}, ttl=5)

            mock_time.monotonic.return_value = 104.9
            assert (await backend.get("k")) == {"v": 1}

            mock_time.monotonic.return_value = 105.0
            assert (await backend.get("k")) is None

    @pytest.mark.asyncio
    async def test_no_ttl_never_expires(self):
        """Test that entries without TTL persist indefinitely."""
        from agent_os.stateless import MemoryBackend

        backend = MemoryBackend()
        await backend.set("k", {"v": 1})
        assert (await backend.get("k")) == {"v": 1}

    @pytest.mark.asyncio
    async def test_expired_entry_is_deleted(self):
        """Test that expired entry is removed from store on get."""
        from unittest.mock import patch
        from agent_os.stateless import MemoryBackend

        backend = MemoryBackend()
        with patch("agent_os.stateless.time") as mock_time:
            mock_time.monotonic.return_value = 0.0
            await backend.set("k", {"v": 1}, ttl=1)

            mock_time.monotonic.return_value = 2.0
            await backend.get("k")
            assert "k" not in backend._store


class TestSerializationErrorHandling:
    """Test serialization error handling in RedisBackend."""

    @pytest.mark.asyncio
    async def test_set_non_serializable_raises(self):
        """Test that non-JSON-serializable values raise SerializationError."""
        from agent_os.stateless import RedisBackend
        from agent_os.exceptions import SerializationError

        backend = RedisBackend()
        backend._client = AsyncMock()

        with pytest.raises(SerializationError) as exc_info:
            await backend.set("bad", {"fn": lambda: None})

        assert "bad" in str(exc_info.value)
        assert exc_info.value.details["key"] == "bad"
        assert exc_info.value.details["value_type"] == "dict"

    @pytest.mark.asyncio
    async def test_get_corrupt_data_raises(self):
        """Test that corrupt stored data raises SerializationError."""
        from agent_os.stateless import RedisBackend
        from agent_os.exceptions import SerializationError

        backend = RedisBackend()
        mock_client = AsyncMock()
        mock_client.get.return_value = b"not-valid-json{{"
        backend._client = mock_client

        with pytest.raises(SerializationError) as exc_info:
            await backend.get("corrupt")

        assert "corrupt" in str(exc_info.value)
        assert exc_info.value.details["key"] == "corrupt"

    @pytest.mark.asyncio
    async def test_serialization_error_has_error_code(self):
        """Test SerializationError carries proper error_code."""
        from agent_os.exceptions import SerializationError

        err = SerializationError("test", details={"key": "k"})
        assert err.error_code == "SERIALIZATION_ERROR"
        d = err.to_dict()
        assert d["error"] == "SERIALIZATION_ERROR"
        assert d["details"]["key"] == "k"


class TestRedisErrorHandling:
    """Test Redis backend error handling (#155)."""

    @pytest.mark.asyncio
    async def test_connection_error_on_get(self):
        """Test that ConnectionError on get propagates cleanly."""
        from agent_os.stateless import RedisBackend

        backend = RedisBackend()
        mock_client = AsyncMock()
        mock_client.get.side_effect = ConnectionError("Connection refused")
        backend._client = mock_client

        with pytest.raises(ConnectionError, match="Connection refused"):
            await backend.get("some-key")

    @pytest.mark.asyncio
    async def test_connection_error_on_set(self):
        """Test that ConnectionError on set propagates cleanly."""
        from agent_os.stateless import RedisBackend

        backend = RedisBackend()
        mock_client = AsyncMock()
        mock_client.set.side_effect = ConnectionError("Connection refused")
        backend._client = mock_client

        with pytest.raises(ConnectionError, match="Connection refused"):
            await backend.set("key", {"data": "value"})

    @pytest.mark.asyncio
    async def test_connection_error_on_delete(self):
        """Test that ConnectionError on delete propagates cleanly."""
        from agent_os.stateless import RedisBackend

        backend = RedisBackend()
        mock_client = AsyncMock()
        mock_client.delete.side_effect = ConnectionError("Connection refused")
        backend._client = mock_client

        with pytest.raises(ConnectionError, match="Connection refused"):
            await backend.delete("key")

    @pytest.mark.asyncio
    async def test_reconnect_after_failure(self):
        """Test that a new client is created after resetting _client."""
        from agent_os.stateless import RedisBackend

        backend = RedisBackend()
        mock_client_bad = AsyncMock()
        mock_client_bad.get.side_effect = ConnectionError("down")
        backend._client = mock_client_bad

        with pytest.raises(ConnectionError):
            await backend.get("key")

        # Simulate reconnection by resetting client
        mock_client_good = AsyncMock()
        mock_client_good.get.return_value = json.dumps({"ok": True}).encode()
        backend._client = mock_client_good

        result = await backend.get("key")
        assert result == {"ok": True}

    @pytest.mark.asyncio
    async def test_unavailable_redis_via_get_client(self):
        """Test that _get_client raises when Redis is unavailable."""
        from agent_os.stateless import RedisBackend

        backend = RedisBackend(url="redis://unreachable:6379")

        with patch("redis.asyncio.from_url", side_effect=ConnectionError("unreachable")):
            with pytest.raises(ConnectionError, match="unreachable"):
                await backend._get_client()

    @pytest.mark.asyncio
    async def test_timeout_error_on_get(self):
        """Test that TimeoutError on get propagates cleanly."""
        from agent_os.stateless import RedisBackend

        backend = RedisBackend()
        mock_client = AsyncMock()
        mock_client.get.side_effect = TimeoutError("Read timed out")
        backend._client = mock_client

        with pytest.raises(TimeoutError, match="Read timed out"):
            await backend.get("key")

    @pytest.mark.asyncio
    async def test_kernel_execute_with_failing_backend_state_ref(self):
        """Test StatelessKernel propagates backend errors when loading state."""
        from agent_os.stateless import ExecutionContext, StatelessKernel

        failing_backend = AsyncMock()
        failing_backend.get.side_effect = ConnectionError("Redis down")

        kernel = StatelessKernel(backend=failing_backend)
        context = ExecutionContext(
            agent_id="test",
            policies=[],
            state_ref="state:test",
        )

        with pytest.raises(ConnectionError, match="Redis down"):
            await kernel.execute(action="query", params={}, context=context)

    @pytest.mark.asyncio
    async def test_kernel_execute_without_state_ref_ignores_backend(self):
        """Test StatelessKernel works even with a broken backend if no state_ref."""
        from agent_os.stateless import ExecutionContext, StatelessKernel

        failing_backend = AsyncMock()
        failing_backend.get.side_effect = ConnectionError("Redis down")

        kernel = StatelessKernel(backend=failing_backend)
        context = ExecutionContext(agent_id="test", policies=[])

        result = await kernel.execute(action="query", params={}, context=context)
        assert result.success is True
