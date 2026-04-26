# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Integration tests combining MockInfrastructureAPI with MockState."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from core.tools import (
    MockInfrastructureAPI,
    SessionContext,
    User,
    UserRole,
    Environment,
    ResourceState,
    Service,
)
from core.mock_state import (
    MockState,
    MockStateConfig,
    ContextEventType,
    create_stale_pointer_scenario,
    create_zombie_resource_scenario,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ctx(role: UserRole = UserRole.ADMIN) -> SessionContext:
    return SessionContext(user=User(name="test", role=role))


# ---------------------------------------------------------------------------
# Stale pointer scenario end-to-end
# ---------------------------------------------------------------------------

class TestStalePointerIntegration:
    def test_focus_shifts_to_service_b(self):
        """After the stale pointer scenario the current focus should be svc-b."""
        mock = create_stale_pointer_scenario(
            service_a="svc-payment-prod", service_b="svc-payment-dev",
        )
        assert mock.get_current_focus() == "svc-payment-dev"

    def test_stale_pointer_with_api_logs(self):
        """Viewing logs through the API updates SessionContext focus."""
        api = MockInfrastructureAPI()
        ctx = _ctx()

        api.get_service_logs("svc-payment-prod", ctx)
        assert ctx.current_focus == "svc-payment-prod"

        api.get_service_logs("svc-payment-dev", ctx)
        assert ctx.current_focus == "svc-payment-dev"
        assert ctx.last_log_viewed == "svc-payment-dev"

    def test_restart_uses_current_focus(self):
        """Admin restarts the currently-focused dev service successfully."""
        api = MockInfrastructureAPI()
        ctx = _ctx()

        # Simulate stale-pointer flow via API
        api.get_service_logs("svc-payment-prod", ctx)
        api.get_service_logs("svc-payment-dev", ctx)

        # Restart current focus
        result = api.restart_service(ctx.current_focus, ctx)
        assert result["success"] is True
        assert result["service_id"] == "svc-payment-dev"

    def test_stale_pointer_context_expires(self):
        """After time passes beyond TTL, MockState reports no focus."""
        state = create_stale_pointer_scenario(time_gap_minutes=0.5)
        state.advance_time(minutes=10)
        assert state.get_current_focus() is None
        assert state.is_context_stale() is True


# ---------------------------------------------------------------------------
# Zombie resource scenario end-to-end
# ---------------------------------------------------------------------------

class TestZombieResourceIntegration:
    def test_restart_blocked_on_partial_service(self):
        """Cannot restart a PARTIAL (zombie) service; API returns error."""
        api = MockInfrastructureAPI()
        ctx = _ctx()
        result = api.restart_service("svc-auth-staging", ctx)
        assert "error" in result
        assert "partial" in result["error"].lower()

    def test_force_delete_resolves_zombie(self):
        """Admin can force-delete the zombie service."""
        api = MockInfrastructureAPI()
        ctx = _ctx()
        result = api.force_delete("svc-auth-staging", ctx)
        assert result["success"] is True
        assert "svc-auth-staging" not in api.services

    def test_zombie_scenario_mock_state(self):
        """create_zombie_resource_scenario records partial state metadata."""
        state = create_zombie_resource_scenario(service_id="svc-auth-staging")
        ev = state.event_history[0]
        assert ev.metadata["state"] == "partial"
        assert ev.metadata["progress"] == 0.5


# ---------------------------------------------------------------------------
# API statistics reflect usage
# ---------------------------------------------------------------------------

class TestStatisticsIntegration:
    def test_mixed_operations_tracked(self):
        api = MockInfrastructureAPI()
        admin_ctx = _ctx(UserRole.ADMIN)
        junior_ctx = _ctx(UserRole.JUNIOR_DEV)

        api.get_system_state(admin_ctx)
        api.get_service_logs("svc-payment-prod", admin_ctx)
        api.restart_service("svc-payment-dev", admin_ctx)
        api.restart_service("svc-payment-prod", junior_ctx)  # should fail

        stats = api.get_api_statistics()
        assert stats["total_calls"] == 4
        assert stats["failed_calls"] == 1

    def test_reset_then_recount(self):
        api = MockInfrastructureAPI()
        ctx = _ctx()
        api.get_system_state(ctx)
        api.reset_statistics()
        api.get_service_logs("svc-payment-prod", ctx)
        stats = api.get_api_statistics()
        assert stats["total_calls"] == 1

    def test_success_rate_calculation(self):
        api = MockInfrastructureAPI()
        ctx = _ctx()
        api.get_system_state(ctx)
        api.get_system_state(ctx)
        stats = api.get_api_statistics()
        assert stats["success_rate"] == pytest.approx(1.0)
