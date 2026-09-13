# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for environment variable configuration."""
import os
import pytest
from agent_os.integrations.config import AgentOSConfig, get_config, reset_config

@pytest.fixture(autouse=True)
def _clean_config(monkeypatch):
    """Reset singleton and clear AGENT_OS_ env vars between tests."""
    reset_config()
    for key in list(os.environ):
        if key.startswith('AGENT_OS_'):
            monkeypatch.delenv(key, raising=False)
    yield
    reset_config()

class TestAgentOSConfigDefaults:

    def test_defaults(self):
        cfg = AgentOSConfig()
        assert cfg.log_level == 'INFO'
        assert cfg.state_backend == 'memory'
        assert cfg.redis_url == 'redis://localhost:6379'
        assert cfg.audit_enabled is True
        assert cfg.audit_max_entries == 10000
        assert cfg.health_check_timeout == 5.0
        assert cfg.rate_limit_calls == 100
        assert cfg.rate_limit_window == 60
        assert cfg.webhook_timeout == 5.0
        assert cfg.webhook_retries == 3

class TestFromEnv:

    def test_int_override(self, monkeypatch):
        monkeypatch.setenv('AGENT_OS_AUDIT_MAX_ENTRIES', '2048')
        cfg = AgentOSConfig.from_env()
        assert cfg.audit_max_entries == 2048

    def test_float_override(self, monkeypatch):
        monkeypatch.setenv('AGENT_OS_HEALTH_CHECK_TIMEOUT', '10.5')
        cfg = AgentOSConfig.from_env()
        assert cfg.health_check_timeout == 10.5

    def test_bool_true_variants(self, monkeypatch):
        for val in ('true', '1', 'yes', 'True', 'YES'):
            monkeypatch.setenv('AGENT_OS_AUDIT_ENABLED', val)
            cfg = AgentOSConfig.from_env()
            assert cfg.audit_enabled is True

    def test_bool_false_variants(self, monkeypatch):
        for val in ('false', '0', 'no'):
            monkeypatch.setenv('AGENT_OS_AUDIT_ENABLED', val)
            cfg = AgentOSConfig.from_env()
            assert cfg.audit_enabled is False

    def test_string_override(self, monkeypatch):
        monkeypatch.setenv('AGENT_OS_STATE_BACKEND', 'redis')
        monkeypatch.setenv('AGENT_OS_LOG_LEVEL', 'DEBUG')
        cfg = AgentOSConfig.from_env()
        assert cfg.state_backend == 'redis'
        assert cfg.log_level == 'DEBUG'

    def test_multiple_overrides(self, monkeypatch):
        monkeypatch.setenv('AGENT_OS_RATE_LIMIT_CALLS', '500')
        monkeypatch.setenv('AGENT_OS_WEBHOOK_RETRIES', '5')
        monkeypatch.setenv('AGENT_OS_REDIS_URL', 'redis://prod:6380')
        cfg = AgentOSConfig.from_env()
        assert cfg.rate_limit_calls == 500
        assert cfg.webhook_retries == 5
        assert cfg.redis_url == 'redis://prod:6380'

    def test_unset_vars_use_defaults(self):
        cfg = AgentOSConfig.from_env()
        assert cfg.audit_max_entries == 10000
        assert cfg.log_level == 'INFO'

class TestSerialization:

    def test_to_dict(self):
        cfg = AgentOSConfig()
        d = cfg.to_dict()
        assert d['audit_max_entries'] == 10000
        assert d['state_backend'] == 'memory'
        assert isinstance(d, dict)
        assert len(d) == 10

    def test_from_dict(self):
        data = {'audit_max_entries': 999, 'log_level': 'WARNING', 'state_backend': 'dynamodb'}
        cfg = AgentOSConfig.from_dict(data)
        assert cfg.audit_max_entries == 999
        assert cfg.log_level == 'WARNING'
        assert cfg.state_backend == 'dynamodb'
        assert cfg.webhook_retries == 3

    def test_from_dict_ignores_unknown_keys(self):
        data = {'rate_limit_calls': 100, 'unknown_key': 'ignored'}
        cfg = AgentOSConfig.from_dict(data)
        assert cfg.rate_limit_calls == 100
        assert not hasattr(cfg, 'unknown_key')

    def test_roundtrip(self):
        original = AgentOSConfig(audit_max_entries=777, log_level='ERROR')
        restored = AgentOSConfig.from_dict(original.to_dict())
        assert original == restored

class TestSingleton:

    def test_get_config_returns_same_instance(self):
        c1 = get_config()
        c2 = get_config()
        assert c1 is c2

    def test_reset_config_clears_singleton(self):
        c1 = get_config()
        reset_config()
        c2 = get_config()
        assert c1 is not c2

    def test_get_config_reads_env(self, monkeypatch):
        monkeypatch.setenv('AGENT_OS_RATE_LIMIT_CALLS', '42')
        reset_config()
        cfg = get_config()
        assert cfg.rate_limit_calls == 42
