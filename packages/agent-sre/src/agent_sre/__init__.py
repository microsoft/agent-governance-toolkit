# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Agent SRE — Reliability Engineering for AI Agent Systems.

agent-sre brings Site Reliability Engineering practices to AI agents.
It provides the primitives needed to define, measure, and enforce
reliability for autonomous agent workloads:

Core concepts
-------------
* **SLI (Service Level Indicator)** — a quantitative measure of agent
  behavior such as task success rate, tool-call accuracy, response
  latency, cost-per-task, or hallucination rate.  Built-in SLIs live
  in ``agent_sre.slo.indicators``.

* **SLO (Service Level Objective)** — a reliability target that
  combines one or more SLIs with an error budget.  When the budget
  burns too fast the SLO status transitions through HEALTHY → WARNING
  → CRITICAL → EXHAUSTED and can trigger alerts or freeze deployments.

* **Error Budget** — the tolerable amount of unreliability
  (``1 − SLO target``).  Burn-rate alerting surfaces problems before
  the budget is fully consumed.

Quick start::

    from agent_sre import SLO, ErrorBudget
    from agent_sre.slo.indicators import TaskSuccessRate

    sli = TaskSuccessRate(target=0.95)
    slo = SLO("my-agent", indicators=[sli],
              error_budget=ErrorBudget(total=0.05))
    slo.record_event(good=True)

See https://github.com/microsoft/agent-governance-toolkit for full documentation.
"""

from agent_sre.slo.indicators import SLI, SLIRegistry, SLIValue
from agent_sre.slo.objectives import SLO, ErrorBudget

__all__ = [
    "ErrorBudget",
    "SLI",
    "SLIRegistry",
    "SLIValue",
    "SLO",
]

__version__ = "1.1.1"
