# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Circuit Breaker — backward-compatibility shim.

Attempts to import the canonical implementation from
``agent_sre.cascade.circuit_breaker``.  When ``agent_sre`` is not
installed the standalone fallback in ``agent_os._circuit_breaker_impl``
is re-exported so that ``agent_os`` (and in particular ``stateless.py``)
continues to work without requiring the optional SRE package.

.. deprecated::
    Prefer importing directly from ``agent_sre.cascade.circuit_breaker``.
"""

from __future__ import annotations

try:
    from agent_sre.cascade.circuit_breaker import (  # noqa: F401
        CascadeDetector,
        CircuitBreaker,
        CircuitBreakerConfig,
        CircuitBreakerOpen,
        CircuitOpenError,
        CircuitState,
    )
except ImportError:
    from agent_os._circuit_breaker_impl import (  # noqa: F401
        CascadeDetector,
        CircuitBreaker,
        CircuitBreakerConfig,
        CircuitBreakerOpen,
        CircuitOpenError,
        CircuitState,
    )
