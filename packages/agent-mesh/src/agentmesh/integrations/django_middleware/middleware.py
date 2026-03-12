# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AgentTrustMiddleware for Django
===============================

Validates incoming HTTP requests against AgentMesh trust headers.
Configurable via Django settings; returns 403 JSON on trust failure.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, List, Optional

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse


logger = logging.getLogger(__name__)

# Marker attribute set by @trust_exempt decorator
_TRUST_EXEMPT_ATTR = "_agentmesh_trust_exempt"
# Marker attribute set by @trust_required decorator (per-view min score)
_TRUST_REQUIRED_ATTR = "_agentmesh_min_trust_score"


def _get_setting(name: str, default: Any) -> Any:
    """Read a Django setting with a fallback default."""
    return getattr(settings, name, default)


class AgentTrustMiddleware:
    """Django middleware that enforces AgentMesh trust verification.

    Configuration via Django settings:

    - ``AGENTMESH_MIN_TRUST_SCORE`` — minimum trust score (0-1000, default 500)
    - ``AGENTMESH_DID_HEADER`` — request header carrying the agent DID
      (default ``"X-Agent-DID"``)
    - ``AGENTMESH_SIGNATURE_HEADER`` — request header carrying the agent
      signature (default ``"X-Agent-Signature"``)
    - ``AGENTMESH_EXEMPT_PATHS`` — list of URL path prefixes that skip
      trust verification (default ``[]``)

    On success the middleware sets ``request.agent_did`` and
    ``request.agent_trust_score`` for downstream views.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _min_trust_score() -> int:
        return int(_get_setting("AGENTMESH_MIN_TRUST_SCORE", 500))

    @staticmethod
    def _did_header() -> str:
        return str(_get_setting("AGENTMESH_DID_HEADER", "X-Agent-DID"))

    @staticmethod
    def _signature_header() -> str:
        return str(_get_setting("AGENTMESH_SIGNATURE_HEADER", "X-Agent-Signature"))

    @staticmethod
    def _exempt_paths() -> List[str]:
        return list(_get_setting("AGENTMESH_EXEMPT_PATHS", []))

    # ------------------------------------------------------------------
    # request processing
    # ------------------------------------------------------------------

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Check path-based exemptions first
        for prefix in self._exempt_paths():
            if request.path.startswith(prefix):
                return self.get_response(request)

        did_header = self._did_header()
        sig_header = self._signature_header()

        # Django normalises headers to META keys: HTTP_X_AGENT_DID
        agent_did: str = request.META.get(
            "HTTP_" + did_header.upper().replace("-", "_"), ""
        )
        agent_sig: str = request.META.get(
            "HTTP_" + sig_header.upper().replace("-", "_"), ""
        )

        if not agent_did:
            return JsonResponse(
                {
                    "error": "Missing agent DID",
                    "detail": f"The {did_header} header is required.",
                },
                status=403,
            )

        # Resolve per-view override via @trust_required decorator
        view_func = self._resolve_view_func(request)
        if view_func is not None and getattr(view_func, _TRUST_EXEMPT_ATTR, False):
            # @trust_exempt — skip verification entirely
            request.agent_did = agent_did  # type: ignore[attr-defined]
            request.agent_trust_score = None  # type: ignore[attr-defined]
            return self.get_response(request)

        per_view_score: Optional[int] = None
        if view_func is not None:
            per_view_score = getattr(view_func, _TRUST_REQUIRED_ATTR, None)

        min_score = per_view_score if per_view_score is not None else self._min_trust_score()

        # Derive trust score — simple heuristic:
        # agents that provide a valid DID get a baseline score; agents that
        # also provide a signature get a higher score.
        trust_score = self._evaluate_trust(agent_did, agent_sig)

        if trust_score < min_score:
            logger.warning(
                "Trust verification failed for %s: score %d < required %d",
                agent_did,
                trust_score,
                min_score,
            )
            return JsonResponse(
                {
                    "error": "Trust verification failed",
                    "detail": (
                        f"Agent trust score ({trust_score}) is below the "
                        f"required threshold ({min_score})."
                    ),
                    "agent_did": agent_did,
                    "trust_score": trust_score,
                    "required_score": min_score,
                },
                status=403,
            )

        # Attach trust info to request for downstream views
        request.agent_did = agent_did  # type: ignore[attr-defined]
        request.agent_trust_score = trust_score  # type: ignore[attr-defined]
        return self.get_response(request)

    # ------------------------------------------------------------------
    # internal
    # ------------------------------------------------------------------

    @staticmethod
    def _evaluate_trust(agent_did: str, agent_sig: str) -> int:
        """Return trust score for the given agent.

        This is a simplified evaluation: agents with a signature receive
        a score of 750 (trusted); agents without get 400 (standard).
        Production deployments should plug in ``TrustBridge.verify_peer``
        or an equivalent async lookup.
        """
        if agent_did and agent_sig:
            return 750
        return 400

    @staticmethod
    def _resolve_view_func(request: HttpRequest) -> Optional[Callable[..., Any]]:
        """Resolve the view function for the current request, if possible."""
        from django.urls import resolve, Resolver404

        try:
            match = resolve(request.path)
            return match.func  # type: ignore[return-value]
        except Resolver404:
            return None
