# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for adapter code quality improvements.

Covers: retry logic, timeout support, structured logging, error recovery,
health checks, and type hints across all integration adapters.

Run with: python -m pytest tests/test_adapter_quality.py -v --tb=short
"""

import asyncio
import logging
import time
from unittest.mock import MagicMock, AsyncMock, patch

import pytest

from agent_os.integrations.base import (
    BaseIntegration,
    ExecutionContext,
    GovernancePolicy,
)
from agent_os.integrations.openai_adapter import (
    OpenAIKernel,
    retry_with_backoff,
    _is_transient,
)
from agent_os.integrations.langchain_adapter import (
    LangChainKernel,
    PolicyViolationError,
)
from agent_os.integrations.autogen_adapter import AutoGenKernel
from agent_os.integrations.semantic_kernel_adapter import SemanticKernelWrapper


# =============================================================================
# Retry Logic (OpenAI adapter — #181)
# =============================================================================


class FakeRateLimitError(Exception):
    pass


FakeRateLimitError.__name__ = "RateLimitError"


class FakeAPIConnectionError(Exception):
    pass


FakeAPIConnectionError.__name__ = "APIConnectionError"


def test_retry_succeeds_on_first_try():
    fn = MagicMock(return_value="ok")
    result = retry_with_backoff(fn, max_retries=3, base_delay=0.01)
    assert result == "ok"
    assert fn.call_count == 1


def test_retry_succeeds_after_transient_failure():
    fn = MagicMock(side_effect=[FakeRateLimitError("rate limit"), "ok"])
    result = retry_with_backoff(fn, max_retries=3, base_delay=0.01, max_delay=0.05)
    assert result == "ok"
    assert fn.call_count == 2


def test_retry_exhausts_max_retries():
    fn = MagicMock(side_effect=FakeRateLimitError("rate limit"))
    with pytest.raises(FakeRateLimitError):
        retry_with_backoff(fn, max_retries=2, base_delay=0.01, max_delay=0.05)
    assert fn.call_count == 3  # 1 initial + 2 retries


def test_retry_does_not_retry_non_transient():
    fn = MagicMock(side_effect=ValueError("bad value"))
    with pytest.raises(ValueError):
        retry_with_backoff(fn, max_retries=3, base_delay=0.01)
    assert fn.call_count == 1


def test_is_transient_detects_known_errors():
    assert _is_transient(FakeRateLimitError("x"))
    assert _is_transient(FakeAPIConnectionError("x"))
    assert not _is_transient(ValueError("x"))


def test_retry_logs_attempts(caplog):
    fn = MagicMock(side_effect=[FakeRateLimitError("rate limit"), "ok"])
    with caplog.at_level(logging.WARNING, logger="agent_os.openai"):
        retry_with_backoff(fn, max_retries=3, base_delay=0.01, max_delay=0.05)
    assert "Retry 1/3" in caplog.text


def test_openai_kernel_retry_params():
    kernel = OpenAIKernel(max_retries=5, timeout_seconds=60.0)
    assert kernel.max_retries == 5
    assert kernel.timeout_seconds == 60.0


# =============================================================================
# Timeout Support (#182)
# =============================================================================


def test_langchain_kernel_has_timeout():
    kernel = LangChainKernel(timeout_seconds=120.0)
    assert kernel.timeout_seconds == 120.0


def test_langchain_kernel_default_timeout():
    kernel = LangChainKernel()
    assert kernel.timeout_seconds == 300.0


@pytest.mark.slow
async def test_langchain_ainvoke_timeout():
    """ainvoke should raise TimeoutError when the operation exceeds timeout."""
    chain = MagicMock()
    chain.name = "slow-chain"

    async def slow_ainvoke(*args, **kwargs):
        await asyncio.sleep(10)
        return "result"

    chain.ainvoke = slow_ainvoke

    kernel = LangChainKernel(timeout_seconds=0.1)
    governed = kernel.wrap(chain)

    with pytest.raises(asyncio.TimeoutError):
        await governed.ainvoke({"input": "test"})


def test_autogen_kernel_has_timeout():
    kernel = AutoGenKernel(timeout_seconds=60.0)
    assert kernel.timeout_seconds == 60.0


def test_semantic_kernel_has_timeout():
    wrapper = SemanticKernelWrapper(timeout_seconds=90.0)
    assert wrapper.timeout_seconds == 90.0


# =============================================================================
# Structured Logging (LangChain adapter — #183)
# =============================================================================


def _make_mock_chain(name="test-chain"):
    chain = MagicMock()
    chain.name = name
    chain.invoke.return_value = "invoke-result"
    chain.run.return_value = "run-result"
    chain.batch.return_value = ["batch-1", "batch-2"]
    chain.stream.return_value = iter(["chunk-1", "chunk-2"])
    return chain


def test_langchain_invoke_logs_debug_and_info(caplog):
    chain = _make_mock_chain()
    kernel = LangChainKernel()
    governed = kernel.wrap(chain)

    with caplog.at_level(logging.DEBUG, logger="agent_os.langchain"):
        governed.invoke({"input": "hello"})

    assert "invoke called" in caplog.text
    assert "Policy ALLOW" in caplog.text


def test_langchain_invoke_logs_deny(caplog):
    chain = _make_mock_chain()
    policy = GovernancePolicy(blocked_patterns=["forbidden"])
    kernel = LangChainKernel(policy=policy)
    governed = kernel.wrap(chain)

    with caplog.at_level(logging.INFO, logger="agent_os.langchain"):
        with pytest.raises(PolicyViolationError):
            governed.invoke("forbidden input")

    assert "Policy DENY" in caplog.text


def test_langchain_run_logs(caplog):
    chain = _make_mock_chain()
    kernel = LangChainKernel()
    governed = kernel.wrap(chain)

    with caplog.at_level(logging.DEBUG, logger="agent_os.langchain"):
        governed.run("hello")

    assert "run called" in caplog.text


def test_langchain_batch_logs(caplog):
    chain = _make_mock_chain()
    kernel = LangChainKernel()
    governed = kernel.wrap(chain)

    with caplog.at_level(logging.DEBUG, logger="agent_os.langchain"):
        governed.batch(["a", "b"])

    assert "batch called" in caplog.text


def test_langchain_stream_logs(caplog):
    chain = _make_mock_chain()
    kernel = LangChainKernel()
    governed = kernel.wrap(chain)

    with caplog.at_level(logging.DEBUG, logger="agent_os.langchain"):
        list(governed.stream("hello"))

    assert "stream called" in caplog.text


def test_langchain_invoke_logs_error(caplog):
    chain = _make_mock_chain()
    chain.invoke.side_effect = RuntimeError("boom")
    kernel = LangChainKernel()
    governed = kernel.wrap(chain)

    with caplog.at_level(logging.ERROR, logger="agent_os.langchain"):
        with pytest.raises(RuntimeError, match="boom"):
            governed.invoke("hello")

    assert "invoke failed" in caplog.text


# =============================================================================
# Error Recovery (AutoGen adapter — #185)
# =============================================================================


def _make_mock_autogen_agent(name="agent-1"):
    agent = MagicMock()
    agent.name = name
    return agent


def test_autogen_on_error_callback():
    errors_captured = []

    def error_handler(exc, agent_id):
        errors_captured.append((str(exc), agent_id))

    agent = _make_mock_autogen_agent()
    agent.initiate_chat.side_effect = RuntimeError("connection lost")

    kernel = AutoGenKernel(on_error=error_handler)
    kernel.govern(agent)

    result = agent.initiate_chat(MagicMock(), message="hello")
    assert result is None
    assert len(errors_captured) == 1
    assert "connection lost" in errors_captured[0][0]


def test_autogen_generate_reply_error_recovery():
    errors_captured = []

    def error_handler(exc, agent_id):
        errors_captured.append(str(exc))

    agent = _make_mock_autogen_agent()
    agent.generate_reply.side_effect = RuntimeError("model error")

    kernel = AutoGenKernel(on_error=error_handler)
    kernel.govern(agent)

    result = agent.generate_reply(messages=["hi"], sender=MagicMock())
    assert "[ERROR:" in result
    assert len(errors_captured) == 1


def test_autogen_receive_error_recovery():
    errors_captured = []

    def error_handler(exc, agent_id):
        errors_captured.append(str(exc))

    agent = _make_mock_autogen_agent()
    agent.receive.side_effect = RuntimeError("timeout")

    kernel = AutoGenKernel(on_error=error_handler)
    kernel.govern(agent)

    result = agent.receive("hello", MagicMock())
    assert result is None
    assert len(errors_captured) == 1


def test_autogen_without_on_error_raises():
    agent = _make_mock_autogen_agent()
    agent.initiate_chat.side_effect = RuntimeError("connection lost")

    kernel = AutoGenKernel()
    kernel.govern(agent)

    with pytest.raises(RuntimeError, match="connection lost"):
        agent.initiate_chat(MagicMock(), message="hello")


def test_autogen_governance_failure_with_callback():
    """When governance check itself fails, on_error is called for generate_reply."""
    errors_captured = []

    def error_handler(exc, agent_id):
        errors_captured.append(str(exc))

    agent = _make_mock_autogen_agent()
    kernel = AutoGenKernel(on_error=error_handler)

    # Patch pre_execute to raise
    original_pre = kernel.pre_execute
    kernel.pre_execute = MagicMock(side_effect=RuntimeError("governance db down"))

    kernel.govern(agent)
    result = agent.generate_reply(messages=["hi"], sender=MagicMock())
    assert "[ERROR:" in result


# =============================================================================
# Health Check (#187)
# =============================================================================


def test_openai_kernel_health_check():
    kernel = OpenAIKernel()
    health = kernel.health_check()
    assert health["status"] == "healthy"
    assert health["backend"] == "openai"
    assert health["last_error"] is None
    assert health["uptime_seconds"] >= 0


def test_openai_kernel_health_check_degraded():
    kernel = OpenAIKernel()
    kernel._last_error = "rate limit exceeded"
    health = kernel.health_check()
    assert health["status"] == "degraded"
    assert health["last_error"] == "rate limit exceeded"


def test_langchain_kernel_health_check():
    kernel = LangChainKernel()
    health = kernel.health_check()
    assert health["status"] == "healthy"
    assert health["backend"] == "langchain"
    assert health["uptime_seconds"] >= 0


def test_langchain_kernel_health_degraded():
    kernel = LangChainKernel()
    kernel._last_error = "connection error"
    health = kernel.health_check()
    assert health["status"] == "degraded"


def test_autogen_kernel_health_check():
    kernel = AutoGenKernel()
    health = kernel.health_check()
    assert health["status"] == "healthy"
    assert health["backend"] == "autogen"
    assert health["uptime_seconds"] >= 0


def test_autogen_kernel_health_degraded():
    kernel = AutoGenKernel()
    kernel._last_error = "some error"
    health = kernel.health_check()
    assert health["status"] == "degraded"


def test_semantic_kernel_health_check():
    wrapper = SemanticKernelWrapper()
    health = wrapper.health_check()
    assert health["status"] == "healthy"
    assert health["backend"] == "semantic_kernel"
    assert health["uptime_seconds"] >= 0


def test_semantic_kernel_health_unhealthy():
    wrapper = SemanticKernelWrapper()
    wrapper._killed = True
    health = wrapper.health_check()
    assert health["status"] == "unhealthy"


def test_semantic_kernel_health_degraded():
    wrapper = SemanticKernelWrapper()
    wrapper._last_error = "some error"
    health = wrapper.health_check()
    assert health["status"] == "degraded"


def test_health_check_returns_dict_keys():
    """All adapters return the same set of keys."""
    expected_keys = {"status", "backend", "backend_connected", "last_error", "uptime_seconds"}
    for adapter in (OpenAIKernel(), LangChainKernel(), AutoGenKernel(), SemanticKernelWrapper()):
        health = adapter.health_check()
        assert set(health.keys()) == expected_keys, f"{type(adapter).__name__} keys mismatch"


# =============================================================================
# Type Hints Smoke Tests (#188, #189)
# =============================================================================


def test_base_integration_type_hints():
    """Verify BaseIntegration methods have return type annotations."""
    import inspect

    for method_name in ("pre_execute", "post_execute", "create_context", "on", "emit", "signal"):
        method = getattr(BaseIntegration, method_name)
        sig = inspect.signature(method)
        assert sig.return_annotation != inspect.Parameter.empty, (
            f"BaseIntegration.{method_name} missing return annotation"
        )


def test_openai_agents_sdk_kernel_has_health_check():
    from agent_os.integrations.openai_agents_sdk import OpenAIAgentsKernel

    kernel = OpenAIAgentsKernel()
    health = kernel.health_check()
    assert health["status"] == "healthy"
    assert health["backend"] == "openai_agents_sdk"
