# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Policy operation routes: validate, test, and save (contract sections 7.4 - 7.6).

SPEC INVARIANT (contract sections 5.2, 9.5): ``POST /api/v1/policy/save`` is the ONLY
operation in this entire adapter with ``runtime_mutating: true``. ``validate`` and ``test``
use POST but are computation-only and stay ``read_only_surface: true``. Per contract section
8.1, ``save`` persists then reloads (the reload happens inside
:meth:`PolicyRegistry.save`); the standalone ``POST /api/v1/policy/reload`` route is excluded
by the spec and is deliberately not registered anywhere in this app.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import yaml
from fastapi import APIRouter, Request

from agentmesh.engine_api.capabilities import capability_flags
from agentmesh.engine_api.errors import (
    ENGINE_UNAVAILABLE,
    FIXTURE_LOAD_ERROR,
    POLICY_PARSE_ERROR,
    ApiError,
)
from agentmesh.engine_api.models import (
    FixtureResult,
    PolicyValidationError,
    SaveRequest,
    SaveResponse,
    TestRequest,
    TestResponse,
    ValidateRequest,
    ValidateResponse,
)
from agentmesh.engine_api.policy_registry import PolicyRegistry

router = APIRouter()


def _registry(request: Request) -> PolicyRegistry:
    return request.app.state.policy_registry


def _load_replay():
    """Return the ``agent_compliance.policy_test.replay`` callable.

    Imported lazily so the adapter carries no hard dependency on agent-compliance. Raises
    :class:`ImportError` when the policy-test engine is not installed; the caller maps that
    to a ``503 ENGINE_UNAVAILABLE`` envelope. Routed through this helper so tests can
    substitute a fake replay without agent-compliance present.
    """
    from agent_compliance.policy_test import replay

    return replay


def _safe_policy_dir(request: Request, override: str | None) -> str:
    """Resolve the policy directory for a test run with a path-containment guard.

    ``override`` arrives over HTTP and is therefore untrusted. Resolve it (and the
    engine's configured policy root) to real absolute paths and require the override to
    stay within that root; otherwise an HTTP client could steer the file-reading replay
    engine at arbitrary server paths. Returns the engine policy directory unchanged when
    no override is supplied. Raises a ``422 FIXTURE_LOAD_ERROR`` envelope when the
    override escapes the configured root.
    """
    base = os.path.realpath(_registry(request).policy_dir)
    if override is None:
        return base
    candidate = os.path.realpath(override)
    if candidate == base:
        return base
    # Containment guard: the resolved override must stay within the engine policy root,
    # or an HTTP client could steer the file-reading replay engine at arbitrary server
    # paths. ``Path.is_relative_to`` (Python 3.11+) is the readable check and avoids the
    # trailing-separator edge case of a bare ``startswith``.
    if not Path(candidate).is_relative_to(base):
        raise ApiError(
            422,
            FIXTURE_LOAD_ERROR,
            "policy_dir override must resolve within the engine policy directory",
            {"policy_dir": override},
        )
    # Equivalent normalized ``startswith`` barrier, kept because CodeQL's py/path-injection
    # query recognizes this form (not ``is_relative_to``) as the sanitizer for the resolved
    # value returned below. ``rstrip`` avoids a doubled separator when ``base`` is the root.
    if not candidate.startswith(base.rstrip(os.sep) + os.sep):
        raise ApiError(
            422,
            FIXTURE_LOAD_ERROR,
            "policy_dir override must resolve within the engine policy directory",
            {"policy_dir": override},
        )
    return candidate


@router.post(
    "/api/v1/policy/validate",
    operation_id="validatePolicy",
    tags=["policy"],
    response_model=ValidateResponse,
)
@capability_flags(runtime_mutating=False, user_intent_required=False, read_only_surface=True)
async def validate_policy(body: ValidateRequest) -> ValidateResponse:
    """Lint and parse a policy document. Computation only; no side effects.

    Unparseable content yields a ``422 POLICY_PARSE_ERROR`` envelope. Content that parses
    but fails lint rules yields ``200`` with ``valid: false`` and a list of errors.
    """
    try:
        if body.format == "yaml":
            yaml.safe_load(body.content)
        else:
            json.loads(body.content)
    except (yaml.YAMLError, json.JSONDecodeError, ValueError) as exc:
        raise ApiError(
            422,
            POLICY_PARSE_ERROR,
            f"Policy content failed to parse: {exc}",
            {"format": body.format},
        )

    # JSON is a subset of YAML, so the YAML-based schema linter accepts both formats.
    from agentmesh.governance.policy import validate_policy_schema

    lint_errors = validate_policy_schema(body.content)
    return ValidateResponse(
        valid=not lint_errors,
        errors=[PolicyValidationError(line=0, col=0, message=msg) for msg in lint_errors],
    )


@router.post(
    "/api/v1/policy/test",
    operation_id="testPolicy",
    tags=["policy"],
    response_model=TestResponse,
)
@capability_flags(runtime_mutating=False, user_intent_required=False, read_only_surface=True)
async def test_policy(request: Request, body: TestRequest) -> TestResponse:
    """Replay inline fixtures against loaded policies. Computation only; no side effects.

    Wraps ``agent_compliance.policy_test.replay`` by materializing the inline fixtures into a
    temporary directory for the duration of the request, then discarding it. Returns
    ``503 ENGINE_UNAVAILABLE`` when the policy-test engine is not installed, and
    ``422 FIXTURE_LOAD_ERROR`` when fixtures or policies cannot be loaded.
    """
    try:
        replay = _load_replay()
    except ImportError:
        raise ApiError(
            503,
            ENGINE_UNAVAILABLE,
            "Policy-test engine (agent-compliance) is not installed",
            {"package": "agent-compliance"},
        )

    policy_dir = _safe_policy_dir(request, body.policy_dir)
    fixtures_payload = [fixture.model_dump() for fixture in body.fixtures]

    with tempfile.TemporaryDirectory(prefix="agt-policy-test-") as tmp:
        fixtures_file = Path(tmp) / "fixtures.json"
        fixtures_file.write_text(json.dumps(fixtures_payload), encoding="utf-8")
        try:
            report = replay(policy_dir, fixtures_file)
        except (FileNotFoundError, ValueError, KeyError, yaml.YAMLError, json.JSONDecodeError) as exc:
            raise ApiError(
                422,
                FIXTURE_LOAD_ERROR,
                f"Could not load fixtures or policies: {exc}",
                {"policy_dir": policy_dir},
            )

    results = [
        FixtureResult(
            fixture_id=item.fixture_id,
            passed=item.passed,
            expected_verdict=item.expected_verdict,
            actual_verdict=item.actual_verdict,
            expected_rule=item.expected_rule,
            actual_rule=item.actual_rule,
            fixture_path=item.fixture_path or None,
            resolution_metadata=item.resolution_metadata,
        )
        for item in report.results
    ]
    return TestResponse(
        total=report.total,
        passed=report.passed,
        failed=report.failed,
        results=results,
    )


@router.post(
    "/api/v1/policy/save",
    operation_id="savePolicy",
    tags=["policy"],
    response_model=SaveResponse,
)
@capability_flags(runtime_mutating=True, user_intent_required=True, read_only_surface=False)
async def save_policy(request: Request, body: SaveRequest) -> SaveResponse:
    """Persist a policy to the engine policy directory, then reload.

    This is the single write endpoint in the Studio surface. Persisting triggers a registry
    reload (contract section 8.1), which is why no standalone reload route exists. Content is
    schema-validated before any write so a malformed document cannot overwrite a valid policy
    and then surface with ``rules_count: 0``.
    """
    # JSON is a subset of YAML, so the YAML-based schema validator accepts both formats.
    from agentmesh.governance.policy import validate_policy_schema

    schema_errors = validate_policy_schema(body.content)
    if schema_errors:
        raise ApiError(
            422,
            POLICY_PARSE_ERROR,
            "Policy content failed schema validation; nothing was saved",
            {"errors": schema_errors},
        )
    registry = _registry(request)
    version = registry.save(body.id, body.content, body.format)
    return SaveResponse(
        id=body.id,
        saved_at=datetime.now(UTC),
        version=version,
    )
