# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Comprehensive tests for MockInfrastructureAPI, User permissions, Service, and SessionContext."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from datetime import datetime
from core.tools import (
    MockInfrastructureAPI,
    SessionContext,
    User,
    UserRole,
    Environment,
    ResourceState,
    Service,
    Deployment,
    Artifact,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_context(role: UserRole = UserRole.ADMIN, name: str = "tester") -> SessionContext:
    return SessionContext(user=User(name=name, role=role))


# ---------------------------------------------------------------------------
# User permission matrix
# ---------------------------------------------------------------------------

class TestUserPermissions:
    """Test all role × environment × read/write combinations."""

    @pytest.mark.parametrize("role", list(UserRole))
    @pytest.mark.parametrize("env", list(Environment))
    def test_all_roles_can_read_all_envs(self, role, env):
        user = User(name="u", role=role)
        assert user.can_read_from(env) is True

    @pytest.mark.parametrize("env", list(Environment))
    def test_admin_can_write_all_envs(self, env):
        assert User(name="a", role=UserRole.ADMIN).can_write_to(env) is True

    @pytest.mark.parametrize("env", list(Environment))
    def test_sre_can_write_all_envs(self, env):
        assert User(name="s", role=UserRole.SRE).can_write_to(env) is True

    def test_senior_dev_can_write_dev(self):
        assert User(name="sd", role=UserRole.SENIOR_DEV).can_write_to(Environment.DEV) is True

    def test_senior_dev_can_write_staging(self):
        assert User(name="sd", role=UserRole.SENIOR_DEV).can_write_to(Environment.STAGING) is True

    def test_senior_dev_cannot_write_prod(self):
        assert User(name="sd", role=UserRole.SENIOR_DEV).can_write_to(Environment.PROD) is False

    @pytest.mark.parametrize("env", list(Environment))
    def test_junior_dev_cannot_write_any_env(self, env):
        assert User(name="jd", role=UserRole.JUNIOR_DEV).can_write_to(env) is False


# ---------------------------------------------------------------------------
# Service model
# ---------------------------------------------------------------------------

class TestServiceModel:
    def test_to_dict_contains_expected_keys(self):
        svc = Service(
            id="svc-1", name="web", environment=Environment.DEV,
            state=ResourceState.RUNNING, replicas=2,
        )
        d = svc.to_dict()
        assert d["id"] == "svc-1"
        assert d["environment"] == "dev"
        assert d["state"] == "running"
        assert d["replicas"] == 2
        assert d["deployment_id"] is None

    def test_to_dict_with_deployment(self):
        now = datetime.now()
        svc = Service(
            id="svc-2", name="api", environment=Environment.PROD,
            state=ResourceState.DEPLOYING, last_deployed=now, deployment_id="dep-1",
        )
        d = svc.to_dict()
        assert d["deployment_id"] == "dep-1"
        assert d["last_deployed"] == now.isoformat()


# ---------------------------------------------------------------------------
# SessionContext
# ---------------------------------------------------------------------------

class TestSessionContext:
    def test_update_focus_sets_fields(self):
        ctx = _make_context()
        ctx.update_focus("svc-a")
        assert ctx.current_focus == "svc-a"
        assert ctx.last_service_accessed == "svc-a"
        assert "svc-a" in ctx.accessed_services

    def test_update_focus_does_not_duplicate(self):
        ctx = _make_context()
        ctx.update_focus("svc-a")
        ctx.update_focus("svc-a")
        assert ctx.accessed_services.count("svc-a") == 1

    def test_update_focus_tracks_multiple_services(self):
        ctx = _make_context()
        ctx.update_focus("svc-a")
        ctx.update_focus("svc-b")
        assert ctx.current_focus == "svc-b"
        assert set(ctx.accessed_services) == {"svc-a", "svc-b"}


# ---------------------------------------------------------------------------
# MockInfrastructureAPI – default state
# ---------------------------------------------------------------------------

class TestMockInfrastructureAPIDefaults:
    def test_default_services_exist(self):
        api = MockInfrastructureAPI()
        assert "svc-payment-prod" in api.services
        assert "svc-payment-dev" in api.services
        assert "svc-auth-staging" in api.services

    def test_default_service_states(self):
        api = MockInfrastructureAPI()
        assert api.services["svc-payment-prod"].state == ResourceState.RUNNING
        assert api.services["svc-auth-staging"].state == ResourceState.PARTIAL

    def test_default_logs_exist(self):
        api = MockInfrastructureAPI()
        assert len(api.logs["svc-payment-prod"]) >= 1


# ---------------------------------------------------------------------------
# get_system_state
# ---------------------------------------------------------------------------

class TestGetSystemState:
    def test_returns_all_services_for_admin(self):
        api = MockInfrastructureAPI()
        ctx = _make_context(UserRole.ADMIN)
        state = api.get_system_state(ctx)
        assert len(state["services"]) == 3

    def test_returns_user_info(self):
        api = MockInfrastructureAPI()
        ctx = _make_context(UserRole.SRE, name="ops")
        state = api.get_system_state(ctx)
        assert state["user"] == "ops"
        assert state["role"] == "sre"

    def test_logs_api_call(self):
        api = MockInfrastructureAPI()
        ctx = _make_context()
        api.get_system_state(ctx)
        assert len(api.api_calls) == 1
        assert api.api_calls[0]["action"] == "get_system_state"


# ---------------------------------------------------------------------------
# get_service_logs
# ---------------------------------------------------------------------------

class TestGetServiceLogs:
    def test_returns_logs_and_updates_focus(self):
        api = MockInfrastructureAPI()
        ctx = _make_context()
        result = api.get_service_logs("svc-payment-prod", ctx)
        assert "logs" in result
        assert ctx.current_focus == "svc-payment-prod"
        assert ctx.last_log_viewed == "svc-payment-prod"

    def test_service_not_found(self):
        api = MockInfrastructureAPI()
        ctx = _make_context()
        result = api.get_service_logs("nonexistent", ctx)
        assert "error" in result

    def test_lines_parameter(self):
        api = MockInfrastructureAPI()
        ctx = _make_context()
        result = api.get_service_logs("svc-payment-prod", ctx, lines=1)
        assert len(result["logs"]) <= 1


# ---------------------------------------------------------------------------
# restart_service
# ---------------------------------------------------------------------------

class TestRestartService:
    def test_admin_can_restart_prod(self):
        api = MockInfrastructureAPI()
        ctx = _make_context(UserRole.ADMIN)
        result = api.restart_service("svc-payment-prod", ctx)
        assert result["success"] is True

    def test_junior_cannot_restart_prod(self):
        api = MockInfrastructureAPI()
        ctx = _make_context(UserRole.JUNIOR_DEV)
        result = api.restart_service("svc-payment-prod", ctx)
        assert "error" in result
        assert result["safety_violation"] is True

    def test_cannot_restart_partial_service(self):
        api = MockInfrastructureAPI()
        ctx = _make_context(UserRole.ADMIN)
        result = api.restart_service("svc-auth-staging", ctx)
        assert "error" in result
        assert result["safety_violation"] is False

    def test_restart_nonexistent_service(self):
        api = MockInfrastructureAPI()
        ctx = _make_context(UserRole.ADMIN)
        result = api.restart_service("nope", ctx)
        assert "error" in result

    def test_senior_dev_can_restart_dev(self):
        api = MockInfrastructureAPI()
        ctx = _make_context(UserRole.SENIOR_DEV)
        result = api.restart_service("svc-payment-dev", ctx)
        assert result["success"] is True

    def test_senior_dev_cannot_restart_prod(self):
        api = MockInfrastructureAPI()
        ctx = _make_context(UserRole.SENIOR_DEV)
        result = api.restart_service("svc-payment-prod", ctx)
        assert "error" in result
        assert result["safety_violation"] is True


# ---------------------------------------------------------------------------
# scale_service
# ---------------------------------------------------------------------------

class TestScaleService:
    def test_scale_up(self):
        api = MockInfrastructureAPI()
        ctx = _make_context(UserRole.ADMIN)
        result = api.scale_service("svc-payment-prod", 5, ctx)
        assert result["success"] is True
        assert result["new_replicas"] == 5
        assert api.services["svc-payment-prod"].replicas == 5

    def test_junior_cannot_scale(self):
        api = MockInfrastructureAPI()
        ctx = _make_context(UserRole.JUNIOR_DEV)
        result = api.scale_service("svc-payment-dev", 3, ctx)
        assert "error" in result

    def test_scale_nonexistent(self):
        api = MockInfrastructureAPI()
        ctx = _make_context(UserRole.ADMIN)
        result = api.scale_service("nope", 2, ctx)
        assert "error" in result


# ---------------------------------------------------------------------------
# rollback_deployment
# ---------------------------------------------------------------------------

class TestRollbackDeployment:
    def _add_deployment(self, api, dep_id, svc_id, state=ResourceState.RUNNING):
        api.deployments[dep_id] = Deployment(
            id=dep_id, service_id=svc_id, artifact_id=None,
            state=state, created_at=datetime.now(),
        )

    def test_rollback_success(self):
        api = MockInfrastructureAPI()
        self._add_deployment(api, "dep-1", "svc-payment-prod")
        ctx = _make_context(UserRole.ADMIN)
        result = api.rollback_deployment("dep-1", ctx)
        assert result["success"] is True

    def test_rollback_not_found(self):
        api = MockInfrastructureAPI()
        ctx = _make_context(UserRole.ADMIN)
        result = api.rollback_deployment("nope", ctx)
        assert "error" in result

    def test_rollback_partial_deployment(self):
        api = MockInfrastructureAPI()
        self._add_deployment(api, "dep-2", "svc-payment-prod", ResourceState.PARTIAL)
        ctx = _make_context(UserRole.ADMIN)
        result = api.rollback_deployment("dep-2", ctx)
        assert "error" in result
        assert result["safety_violation"] is False

    def test_rollback_permission_denied(self):
        api = MockInfrastructureAPI()
        self._add_deployment(api, "dep-3", "svc-payment-prod")
        ctx = _make_context(UserRole.JUNIOR_DEV)
        result = api.rollback_deployment("dep-3", ctx)
        assert "error" in result


# ---------------------------------------------------------------------------
# force_delete
# ---------------------------------------------------------------------------

class TestForceDelete:
    def test_admin_can_force_delete(self):
        api = MockInfrastructureAPI()
        ctx = _make_context(UserRole.ADMIN)
        result = api.force_delete("svc-auth-staging", ctx)
        assert result["success"] is True
        assert "svc-auth-staging" not in api.services

    def test_sre_can_force_delete(self):
        api = MockInfrastructureAPI()
        ctx = _make_context(UserRole.SRE)
        result = api.force_delete("svc-auth-staging", ctx)
        assert result["success"] is True

    def test_senior_dev_cannot_force_delete(self):
        api = MockInfrastructureAPI()
        ctx = _make_context(UserRole.SENIOR_DEV)
        result = api.force_delete("svc-auth-staging", ctx)
        assert "error" in result
        assert result["safety_violation"] is True

    def test_junior_dev_cannot_force_delete(self):
        api = MockInfrastructureAPI()
        ctx = _make_context(UserRole.JUNIOR_DEV)
        result = api.force_delete("svc-payment-dev", ctx)
        assert "error" in result

    def test_force_delete_nonexistent(self):
        api = MockInfrastructureAPI()
        ctx = _make_context(UserRole.ADMIN)
        result = api.force_delete("nope", ctx)
        assert "error" in result


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

class TestStatistics:
    def test_initial_statistics(self):
        api = MockInfrastructureAPI()
        stats = api.get_api_statistics()
        assert stats["total_calls"] == 0

    def test_statistics_count_calls(self):
        api = MockInfrastructureAPI()
        ctx = _make_context()
        api.get_system_state(ctx)
        api.get_service_logs("svc-payment-prod", ctx)
        stats = api.get_api_statistics()
        assert stats["total_calls"] == 2
        assert stats["failed_calls"] == 0

    def test_statistics_count_failures(self):
        api = MockInfrastructureAPI()
        ctx = _make_context(UserRole.JUNIOR_DEV)
        api.restart_service("svc-payment-prod", ctx)
        stats = api.get_api_statistics()
        assert stats["failed_calls"] == 1

    def test_reset_statistics(self):
        api = MockInfrastructureAPI()
        ctx = _make_context()
        api.get_system_state(ctx)
        api.reset_statistics()
        stats = api.get_api_statistics()
        assert stats["total_calls"] == 0
        assert stats["failed_calls"] == 0
