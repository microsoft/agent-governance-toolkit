# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Error envelope model, standard codes, and exception handlers for the Engine API.

Implements ``docs/studio/engine-api-contract.md`` section 10 (Error Model). Every error
response - whether raised explicitly via :class:`ApiError`, produced by FastAPI request
validation, or bubbled up as an unhandled exception - is rendered as the section 10.2
envelope: ``{status, code, message, details}``.

The full section 10.3 code set is defined here as module constants. The routes in this
adapter can actually emit five of them (``POLICY_NOT_FOUND``, ``POLICY_PARSE_ERROR``,
``FIXTURE_LOAD_ERROR``, ``VALIDATION_ERROR``, ``FORBIDDEN``) plus ``ENGINE_UNAVAILABLE`` when
the optional policy-test engine is not installed. ``FORBIDDEN`` is returned by
``POST /api/v1/policy/save`` when the write path is disabled (its default; see
``AGENTMESH_ENABLE_POLICY_SAVE``). ``UNAUTHORIZED`` is reserved for the non-loopback token
auth layer (issue #7) and is defined here but not wired by this issue.

**Handler ordering.** :func:`register_error_handlers` installs a handler for
:class:`fastapi.exceptions.RequestValidationError` that overrides FastAPI's default. Without
it, FastAPI would emit its built-in ``{"detail": [...]}`` body instead of the envelope.
"""

from __future__ import annotations

import logging
from typing import Any, Final

from fastapi import Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)

# ── Standard error codes (section 10.3) ──────────────────────────────────────
POLICY_NOT_FOUND: Final = "POLICY_NOT_FOUND"
POLICY_PARSE_ERROR: Final = "POLICY_PARSE_ERROR"
FIXTURE_LOAD_ERROR: Final = "FIXTURE_LOAD_ERROR"
VALIDATION_ERROR: Final = "VALIDATION_ERROR"
UNAUTHORIZED: Final = "UNAUTHORIZED"
FORBIDDEN: Final = "FORBIDDEN"
RATE_LIMITED: Final = "RATE_LIMITED"
ENGINE_UNAVAILABLE: Final = "ENGINE_UNAVAILABLE"
INTERNAL_ERROR: Final = "INTERNAL_ERROR"

#: The complete section 10.3 enumeration, in spec order.
STANDARD_ERROR_CODES: Final[tuple[str, ...]] = (
    POLICY_NOT_FOUND,
    POLICY_PARSE_ERROR,
    FIXTURE_LOAD_ERROR,
    VALIDATION_ERROR,
    UNAUTHORIZED,
    FORBIDDEN,
    RATE_LIMITED,
    ENGINE_UNAVAILABLE,
    INTERNAL_ERROR,
)

#: Default code for a bare HTTP status raised without an explicit code (e.g. a plain
#: ``HTTPException`` from framework internals). Routes in this adapter raise
#: :class:`ApiError` with an explicit code, so this mapping is a fallback only.
_STATUS_TO_CODE: Final[dict[int, str]] = {
    400: VALIDATION_ERROR,
    401: UNAUTHORIZED,
    403: FORBIDDEN,
    404: POLICY_NOT_FOUND,
    422: VALIDATION_ERROR,
    429: RATE_LIMITED,
    500: INTERNAL_ERROR,
    503: ENGINE_UNAVAILABLE,
}


class ErrorEnvelope(BaseModel):
    """The section 10.2 error envelope returned by every error response."""

    status: int = Field(..., description="HTTP status code (mirrors the response status)")
    code: str = Field(..., description="Machine-readable code in SCREAMING_SNAKE_CASE")
    message: str = Field(..., description="Human-readable description safe to display in the UI")
    details: dict[str, Any] = Field(
        default_factory=dict, description="Endpoint-specific diagnostic information"
    )


class ApiError(Exception):
    """Raise to emit a section 10.2 error envelope with an explicit code.

    Args:
        status: HTTP status code for the response.
        code: One of the section 10.3 codes.
        message: Human-readable, UI-safe description.
        details: Optional endpoint-specific diagnostics.
    """

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.details: dict[str, Any] = details or {}


def _envelope_response(
    status: int, code: str, message: str, details: dict[str, Any] | None = None
) -> JSONResponse:
    envelope = ErrorEnvelope(status=status, code=code, message=message, details=details or {})
    return JSONResponse(status_code=status, content=envelope.model_dump())


async def _api_error_handler(_request: Request, exc: ApiError) -> JSONResponse:
    return _envelope_response(exc.status, exc.code, exc.message, exc.details)


async def _validation_error_handler(
    _request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Remap FastAPI's request-validation failures to the envelope shape.

    Without this handler FastAPI returns its default ``{"detail": [...]}`` body. The raw
    validation errors are preserved (JSON-sanitized) under ``details.errors``.
    """
    return _envelope_response(
        422,
        VALIDATION_ERROR,
        "Request validation failed",
        {"errors": jsonable_encoder(exc.errors())},
    )


async def _http_exception_handler(
    _request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    code = _STATUS_TO_CODE.get(
        exc.status_code,
        VALIDATION_ERROR if 400 <= exc.status_code < 500 else INTERNAL_ERROR,
    )
    message = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    return _envelope_response(exc.status_code, code, message)


async def _unhandled_exception_handler(_request: Request, exc: Exception) -> JSONResponse:
    # Log the full traceback server-side; the client only receives the sanitized 500 below
    # (no exception detail), so without this the original error would be lost entirely.
    logger.exception("Unhandled exception in Engine API request")
    return _envelope_response(500, INTERNAL_ERROR, "Internal engine error")


def register_error_handlers(app: Any) -> None:
    """Install the envelope exception handlers on a FastAPI app.

    The :class:`RequestValidationError` handler is installed explicitly so it overrides
    FastAPI's default validation responder; otherwise the default ``{"detail": [...]}``
    body would win.

    Args:
        app: A ``fastapi.FastAPI`` instance.
    """
    app.add_exception_handler(ApiError, _api_error_handler)
    app.add_exception_handler(RequestValidationError, _validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, _http_exception_handler)
    app.add_exception_handler(Exception, _unhandled_exception_handler)
