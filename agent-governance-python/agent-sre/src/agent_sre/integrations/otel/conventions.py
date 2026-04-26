# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""OpenTelemetry semantic conventions for AI agent reliability.

Defines attribute keys and metric names following OTEL naming conventions.
All agent-specific attributes are prefixed with 'agent.sre.' to avoid
collisions with standard OTEL conventions.
"""

# --- Attribute Keys ---

# Agent identity
AGENT_ID = "agent.id"
AGENT_NAME = "agent.name"

# SLO attributes
SLO_NAME = "agent.sre.slo.name"
SLO_STATUS = "agent.sre.slo.status"

# SLI attributes
SLI_NAME = "agent.sre.sli.name"
SLI_TARGET = "agent.sre.sli.target"
SLI_WINDOW = "agent.sre.sli.window"

# Error budget attributes
ERROR_BUDGET_TOTAL = "agent.sre.error_budget.total"
ERROR_BUDGET_CONSUMED = "agent.sre.error_budget.consumed"

# Cost attributes
COST_USD = "agent.sre.cost.usd"
COST_AGENT_ID = "agent.sre.cost.agent_id"
COST_TASK_ID = "agent.sre.cost.task_id"

# Incident attributes
INCIDENT_ID = "agent.sre.incident.id"
INCIDENT_SEVERITY = "agent.sre.incident.severity"
INCIDENT_STATE = "agent.sre.incident.state"
SIGNAL_TYPE = "agent.sre.signal.type"
SIGNAL_SOURCE = "agent.sre.signal.source"

# Chaos attributes
CHAOS_EXPERIMENT_ID = "agent.sre.chaos.experiment_id"
CHAOS_EXPERIMENT_NAME = "agent.sre.chaos.experiment_name"
CHAOS_FAULT_TYPE = "agent.sre.chaos.fault_type"
CHAOS_FAULT_TARGET = "agent.sre.chaos.fault_target"

# Span attributes (replay traces)
SPAN_COST_USD = "agent.sre.span.cost_usd"
SPAN_KIND_AGENT = "agent.sre.span.kind"

# --- Metric Names ---

METRIC_SLI_VALUE = "agent.sre.sli.value"
METRIC_SLI_COMPLIANCE = "agent.sre.sli.compliance"
METRIC_ERROR_BUDGET_REMAINING = "agent.sre.error_budget.remaining"
METRIC_BURN_RATE = "agent.sre.burn_rate"
METRIC_SLO_STATUS = "agent.sre.slo.status_code"
METRIC_COST_TOTAL = "agent.sre.cost.total_usd"
METRIC_COST_PER_TASK = "agent.sre.cost.per_task_usd"
METRIC_COST_BUDGET_UTILIZATION = "agent.sre.cost.budget_utilization"
METRIC_INCIDENTS_OPEN = "agent.sre.incidents.open"
METRIC_LATENCY = "agent.sre.latency_ms"
METRIC_RESILIENCE_SCORE = "agent.sre.chaos.resilience_score"

# --- Event Names ---

EVENT_SLO_STATUS_CHANGE = "agent.sre.slo.status_change"
EVENT_BURN_RATE_ALERT = "agent.sre.burn_rate.alert"
EVENT_COST_ALERT = "agent.sre.cost.alert"
EVENT_INCIDENT_DETECTED = "agent.sre.incident.detected"
EVENT_INCIDENT_RESOLVED = "agent.sre.incident.resolved"
EVENT_SIGNAL_RECEIVED = "agent.sre.signal.received"
EVENT_FAULT_INJECTED = "agent.sre.chaos.fault_injected"
EVENT_CHAOS_COMPLETED = "agent.sre.chaos.completed"

# --- Status Code Mapping ---

SLO_STATUS_CODES = {
    "healthy": 0,
    "warning": 1,
    "critical": 2,
    "exhausted": 3,
    "unknown": -1,
}
