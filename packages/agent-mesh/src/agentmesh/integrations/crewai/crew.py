# Copyright (c) Agent-Mesh Contributors. All rights reserved.
# Licensed under the MIT License.
"""CrewAI trust-aware crew wrapper.

Provides a wrapper for CrewAI Crew that enforces trust verification
between all agents before and during crew execution.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from agentmesh.exceptions import TrustViolationError

from .agent import TrustAwareAgent

logger = logging.getLogger(__name__)


class TrustAwareCrew:
    """Wrapper for CrewAI Crew that enforces trust between all agents.

    Verifies that every agent in the crew meets the trust threshold
    before allowing crew execution.

    Args:
        agents: List of TrustAwareAgent instances.
        tasks: List of tasks for the crew.
        min_trust_score: Minimum trust score (0–1000) for all agents.
        **kwargs: Forwarded to CrewAI Crew constructor when crewai is installed.

    Example::

        from agentmesh.integrations.crewai import TrustAwareAgent, TrustAwareCrew

        researcher = TrustAwareAgent(agent_did="did:mesh:r1", role="Researcher")
        writer = TrustAwareAgent(agent_did="did:mesh:w1", role="Writer")
        crew = TrustAwareCrew(agents=[researcher, writer], tasks=[...])
        result = crew.kickoff()
    """

    def __init__(
        self,
        agents: List[TrustAwareAgent],
        tasks: Optional[List[Any]] = None,
        min_trust_score: int = 500,
        **kwargs: Any,
    ) -> None:
        self.agents = agents
        self.tasks = tasks or []
        self.min_trust_score = min_trust_score
        self._crewai_kwargs = kwargs
        self._crewai_crew: Any = None

    def verify_crew_trust(self) -> Dict[str, Any]:
        """Verify all agents in crew meet trust requirements.

        Returns:
            Dictionary with per-agent trust status and overall result.
        """
        results: Dict[str, Any] = {}
        all_trusted = True

        for agent in self.agents:
            score = agent.trust_store.get_trust_score(agent.agent_did)
            trusted = score >= self.min_trust_score
            results[agent.agent_did] = {
                "score": score,
                "threshold": self.min_trust_score,
                "trusted": trusted,
            }
            if not trusted:
                all_trusted = False

        return {"agents": results, "all_trusted": all_trusted}

    def kickoff(self, **kwargs: Any) -> Dict[str, Any]:
        """Run crew with trust enforcement.

        Verifies trust for all agents, then attempts to run the crew
        via CrewAI (if installed) or returns a trust-verified stub result.

        Args:
            **kwargs: Forwarded to CrewAI Crew.kickoff().

        Returns:
            Dictionary containing trust verification report and crew result.

        Raises:
            TrustViolationError: If any agent fails trust verification.
        """
        trust_report = self.verify_crew_trust()

        if not trust_report["all_trusted"]:
            untrusted = [
                did
                for did, info in trust_report["agents"].items()
                if not info["trusted"]
            ]
            raise TrustViolationError(
                f"Crew trust verification failed for agents: {untrusted}"
            )

        crew_result: Any = None
        try:
            from crewai import Crew as CrewAICrew

            crewai_agents = [
                a.crewai_agent for a in self.agents if a.crewai_agent is not None
            ]
            if crewai_agents:
                self._crewai_crew = CrewAICrew(
                    agents=crewai_agents,
                    tasks=self.tasks,
                    **self._crewai_kwargs,
                )
                crew_result = self._crewai_crew.kickoff(**kwargs)
        except ImportError:
            logger.debug("crewai not installed; returning trust-only result")
            crew_result = {
                "status": "trust_verified",
                "agents": [a.agent_did for a in self.agents],
            }

        return {"trust_report": trust_report, "result": crew_result}
