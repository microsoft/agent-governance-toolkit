# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic context/memory management
"""
Heuristic Router — routes all queries to the default retriever.

No pattern-based classification; every query receives the same default route.
"""

from typing import Optional, List
from caas.models import ModelTier, RoutingDecision


class HeuristicRouter:
    """
    Basic router that sends every query to the default (SMART) model tier.
    """

    def __init__(
        self,
        short_query_threshold: int = 50,
        enable_canned_responses: bool = True,
    ):
        """
        Initialize the router.

        Args:
            short_query_threshold: Kept for API compatibility (unused).
            enable_canned_responses: Kept for API compatibility (unused).
        """
        self.short_query_threshold = short_query_threshold
        self.enable_canned_responses = enable_canned_responses

    def route(self, query: str) -> RoutingDecision:
        """
        Route *query* — always returns the default SMART tier.

        Args:
            query: The user query to route.

        Returns:
            RoutingDecision for the default model tier.
        """
        return RoutingDecision(
            model_tier=ModelTier.SMART,
            reason="Default route — all queries sent to smart model",
            confidence=1.0,
            query_length=len(query),
            matched_keywords=[],
            suggested_model="gpt-4o",
            estimated_cost="high",
        )

    def get_canned_response(self, query: str) -> Optional[str]:
        """
        Always returns ``None`` — canned responses are not supported.
        """
        return None
