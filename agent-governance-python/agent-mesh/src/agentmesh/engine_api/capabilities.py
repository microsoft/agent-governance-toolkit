# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Capability metadata model and decorator for the AGT Studio Engine API.

This module implements the capability-flag substrate defined in
``docs/studio/engine-api-contract.md`` section 5 (Capability Metadata) and
section 6 (Read-only Invariant).

Every Engine API endpoint carries three boolean capability flags:

* ``runtime_mutating`` - the operation persists a change to engine state.
* ``user_intent_required`` - the operation MUST only be invoked from an explicit
  user gesture (button click, confirm dialog), never speculatively.
* ``read_only_surface`` - the operation is safe to expose on a read-only Studio
  surface. An endpoint is read-only if and only if ``runtime_mutating`` is false.

The read-only invariant (``read_only_surface == (not runtime_mutating)``) is
enforced at :class:`CapabilityFlags` construction time, so the iff rule cannot
be forged. Any violating construction raises :class:`ValueError`.

The :func:`capability_flags` decorator validates the flags and attaches the
resulting :class:`CapabilityFlags` instance to the wrapped callable under the
attribute named by :data:`CAPABILITY_FLAGS_ATTR` (``__capability_flags__``).
The OpenAPI hook in :mod:`agentmesh.engine_api.openapi` reads that attribute.
"""

from __future__ import annotations

from typing import Callable, TypeVar

from pydantic import BaseModel, ConfigDict, model_validator

#: Name of the attribute that :func:`capability_flags` attaches to a decorated
#: callable. A dunder name is used so it does not collide with user attributes.
CAPABILITY_FLAGS_ATTR = "__capability_flags__"

F = TypeVar("F", bound=Callable[..., object])


class CapabilityFlags(BaseModel):
    """The three authoritative capability flags for an Engine API operation.

    The model is frozen: once constructed, the flags cannot be mutated. This
    keeps the validated read-only invariant intact for the lifetime of the
    instance.

    Raises:
        ValueError: if ``read_only_surface != (not runtime_mutating)``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    runtime_mutating: bool
    user_intent_required: bool
    read_only_surface: bool

    @model_validator(mode="after")
    def _enforce_read_only_invariant(self) -> "CapabilityFlags":
        expected_read_only = not self.runtime_mutating
        if self.read_only_surface != expected_read_only:
            raise ValueError(
                "read-only invariant violated: read_only_surface must equal "
                "(not runtime_mutating). Got read_only_surface="
                f"{self.read_only_surface!r} with runtime_mutating="
                f"{self.runtime_mutating!r}; expected read_only_surface="
                f"{expected_read_only!r}."
            )
        return self


def capability_flags(
    *,
    runtime_mutating: bool,
    user_intent_required: bool,
    read_only_surface: bool,
) -> Callable[[F], F]:
    """Attach validated :class:`CapabilityFlags` to a callable.

    The flags are validated through :class:`CapabilityFlags`, so the read-only
    invariant is enforced at decoration time: decorating with an inconsistent
    combination raises :class:`ValueError` immediately, before any server
    starts. The validated instance is stored on the callable under
    :data:`CAPABILITY_FLAGS_ATTR`.

    Usage::

        @capability_flags(
            runtime_mutating=False,
            user_intent_required=False,
            read_only_surface=True,
        )
        async def get_health(): ...

    Args:
        runtime_mutating: Whether the operation persists engine state changes.
        user_intent_required: Whether the operation requires an explicit user
            gesture.
        read_only_surface: Whether the operation is safe on a read-only surface.
            Must equal ``not runtime_mutating``.

    Returns:
        A decorator that attaches the flags and returns the original callable.

    Raises:
        ValueError: if the flag combination violates the read-only invariant.
    """
    flags = CapabilityFlags(
        runtime_mutating=runtime_mutating,
        user_intent_required=user_intent_required,
        read_only_surface=read_only_surface,
    )

    def decorator(fn: F) -> F:
        setattr(fn, CAPABILITY_FLAGS_ATTR, flags)
        return fn

    return decorator
