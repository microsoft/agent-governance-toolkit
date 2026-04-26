# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Pre-built Grafana Dashboards for Agent OS.

Provides JSON dashboard definitions ready for import.
"""

import json


def get_grafana_dashboard(name: str = "agent-os-overview") -> dict:
    """
    Get a pre-built Grafana dashboard.
    
    Available dashboards:
    - agent-os-overview: Main overview for SOC teams
    - agent-os-safety: Safety metrics detail
    - agent-os-performance: Performance metrics
    - agent-os-amb: AMB health and throughput
    - agent-os-cmvk: CMVK verification metrics
    
    Usage:
        dashboard = get_grafana_dashboard("agent-os-overview")
        # Import via Grafana API or UI
    """
    dashboards = {
        "agent-os-overview": _overview_dashboard(),
        "agent-os-safety": _safety_dashboard(),
        "agent-os-performance": _performance_dashboard(),
        "agent-os-amb": _amb_dashboard(),
        "agent-os-cmvk": _cmvk_dashboard(),
    }
    return dashboards.get(name, dashboards["agent-os-overview"])


def _overview_dashboard() -> dict:
    """Main Agent OS overview dashboard."""
    return {
        "dashboard": {
            "id": None,
            "uid": "agent-os-overview",
            "title": "Agent OS - Overview",
            "tags": ["agent-os", "ai-safety"],
            "timezone": "browser",
            "schemaVersion": 38,
            "version": 1,
            "refresh": "10s",
            "panels": [
                # Row 1: Key Safety Metrics
                {
                    "id": 1,
                    "type": "stat",
                    "title": "Violation Rate",
                    "gridPos": {"h": 4, "w": 6, "x": 0, "y": 0},
                    "targets": [
                        {
                            "expr": "agent_os_violation_rate{window='all_time'}",
                            "refId": "A"
                        }
                    ],
                    "options": {
                        "colorMode": "value",
                        "graphMode": "none",
                        "orientation": "auto",
                        "textMode": "value_and_name"
                    },
                    "fieldConfig": {
                        "defaults": {
                            "unit": "percentunit",
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 0.001},
                                    {"color": "red", "value": 0.01}
                                ]
                            }
                        }
                    }
                },
                {
                    "id": 2,
                    "type": "stat",
                    "title": "SIGKILL Count (24h)",
                    "gridPos": {"h": 4, "w": 6, "x": 6, "y": 0},
                    "targets": [
                        {
                            "expr": "increase(agent_os_sigkill_total[24h])",
                            "refId": "A"
                        }
                    ],
                    "options": {"colorMode": "value"}
                },
                {
                    "id": 3,
                    "type": "stat",
                    "title": "Kernel Uptime",
                    "gridPos": {"h": 4, "w": 6, "x": 12, "y": 0},
                    "targets": [
                        {
                            "expr": "agent_os_kernel_uptime_seconds",
                            "refId": "A"
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {"unit": "s"}
                    }
                },
                {
                    "id": 4,
                    "type": "stat",
                    "title": "Active Agents",
                    "gridPos": {"h": 4, "w": 6, "x": 18, "y": 0},
                    "targets": [
                        {
                            "expr": "agent_os_active_agents",
                            "refId": "A"
                        }
                    ]
                },
                
                # Row 2: Time Series
                {
                    "id": 5,
                    "type": "timeseries",
                    "title": "Requests per Second",
                    "gridPos": {"h": 8, "w": 12, "x": 0, "y": 4},
                    "targets": [
                        {
                            "expr": "rate(agent_os_requests_total[1m])",
                            "legendFormat": "{{action}} - {{status}}",
                            "refId": "A"
                        }
                    ]
                },
                {
                    "id": 6,
                    "type": "timeseries",
                    "title": "Policy Check Latency (p99)",
                    "gridPos": {"h": 8, "w": 12, "x": 12, "y": 4},
                    "targets": [
                        {
                            "expr": "histogram_quantile(0.99, rate(agent_os_policy_check_duration_seconds_bucket[5m]))",
                            "legendFormat": "p99",
                            "refId": "A"
                        },
                        {
                            "expr": "histogram_quantile(0.50, rate(agent_os_policy_check_duration_seconds_bucket[5m]))",
                            "legendFormat": "p50",
                            "refId": "B"
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "s",
                            "thresholds": {
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 0.005},
                                    {"color": "red", "value": 0.01}
                                ]
                            }
                        }
                    }
                },
                
                # Row 3: Violations and Signals
                {
                    "id": 7,
                    "type": "timeseries",
                    "title": "Violations Over Time",
                    "gridPos": {"h": 8, "w": 12, "x": 0, "y": 12},
                    "targets": [
                        {
                            "expr": "rate(agent_os_violations_total[5m])",
                            "legendFormat": "{{policy}}",
                            "refId": "A"
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "custom": {
                                "fillOpacity": 30
                            }
                        }
                    }
                },
                {
                    "id": 8,
                    "type": "timeseries",
                    "title": "Signals Sent",
                    "gridPos": {"h": 8, "w": 12, "x": 12, "y": 12},
                    "targets": [
                        {
                            "expr": "rate(agent_os_signals_total[5m])",
                            "legendFormat": "{{signal}}",
                            "refId": "A"
                        }
                    ]
                },
                
                # Row 4: Recovery
                {
                    "id": 9,
                    "type": "histogram",
                    "title": "MTTR Distribution",
                    "gridPos": {"h": 8, "w": 12, "x": 0, "y": 20},
                    "targets": [
                        {
                            "expr": "agent_os_mttr_seconds_bucket",
                            "refId": "A"
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {"unit": "s"}
                    }
                },
                {
                    "id": 10,
                    "type": "table",
                    "title": "Recent Violations",
                    "gridPos": {"h": 8, "w": 12, "x": 12, "y": 20},
                    "targets": [
                        {
                            "expr": "topk(10, agent_os_violations_total)",
                            "format": "table",
                            "refId": "A"
                        }
                    ]
                }
            ]
        },
        "folderId": 0,
        "overwrite": True
    }


def _safety_dashboard() -> dict:
    """Detailed safety metrics dashboard."""
    return {
        "dashboard": {
            "id": None,
            "uid": "agent-os-safety",
            "title": "Agent OS - Safety Metrics",
            "tags": ["agent-os", "ai-safety", "compliance"],
            "timezone": "browser",
            "schemaVersion": 38,
            "version": 1,
            "panels": [
                {
                    "id": 1,
                    "type": "stat",
                    "title": "30-Day Violation Count",
                    "gridPos": {"h": 6, "w": 8, "x": 0, "y": 0},
                    "targets": [
                        {
                            "expr": "increase(agent_os_violations_total[30d])",
                            "refId": "A"
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "thresholds": {
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "red", "value": 1}
                                ]
                            }
                        }
                    }
                }
            ]
        }
    }


def _performance_dashboard() -> dict:
    """Performance metrics dashboard."""
    return {
        "dashboard": {
            "id": None,
            "uid": "agent-os-performance",
            "title": "Agent OS - Performance",
            "tags": ["agent-os", "performance"],
            "timezone": "browser",
            "schemaVersion": 38,
            "version": 1,
            "panels": []
        }
    }


def export_dashboard(name: str, path: str):
    """Export dashboard to JSON file."""
    dashboard = get_grafana_dashboard(name)
    with open(path, "w") as f:
        json.dump(dashboard, f, indent=2)


def _amb_dashboard() -> dict:
    """AMB (Agent Message Bus) health dashboard."""
    return {
        "dashboard": {
            "id": None,
            "uid": "agent-os-amb",
            "title": "Agent OS - AMB Health",
            "tags": ["agent-os", "amb", "messaging"],
            "timezone": "browser",
            "schemaVersion": 38,
            "version": 1,
            "refresh": "5s",
            "panels": [
                # Row 1: Key Metrics
                {
                    "id": 1,
                    "type": "stat",
                    "title": "Messages/sec",
                    "gridPos": {"h": 4, "w": 6, "x": 0, "y": 0},
                    "targets": [
                        {
                            "expr": "sum(rate(amb_messages_published_total[1m]))",
                            "refId": "A"
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "msg/s",
                            "thresholds": {
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 10000},
                                    {"color": "red", "value": 50000}
                                ]
                            }
                        }
                    }
                },
                {
                    "id": 2,
                    "type": "stat",
                    "title": "Queue Depth",
                    "gridPos": {"h": 4, "w": 6, "x": 6, "y": 0},
                    "targets": [
                        {
                            "expr": "sum(amb_queue_depth)",
                            "refId": "A"
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "thresholds": {
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 500},
                                    {"color": "red", "value": 1000}
                                ]
                            }
                        }
                    }
                },
                {
                    "id": 3,
                    "type": "stat",
                    "title": "Backpressure Events (1h)",
                    "gridPos": {"h": 4, "w": 6, "x": 12, "y": 0},
                    "targets": [
                        {
                            "expr": "increase(amb_backpressure_activated_total[1h])",
                            "refId": "A"
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "thresholds": {
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 1},
                                    {"color": "red", "value": 10}
                                ]
                            }
                        }
                    }
                },
                {
                    "id": 4,
                    "type": "stat",
                    "title": "Delivery Failures (1h)",
                    "gridPos": {"h": 4, "w": 6, "x": 18, "y": 0},
                    "targets": [
                        {
                            "expr": "increase(amb_delivery_failures_total[1h])",
                            "refId": "A"
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "thresholds": {
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 1},
                                    {"color": "red", "value": 10}
                                ]
                            }
                        }
                    }
                },
                
                # Row 2: Throughput
                {
                    "id": 5,
                    "type": "timeseries",
                    "title": "Message Throughput",
                    "gridPos": {"h": 8, "w": 12, "x": 0, "y": 4},
                    "targets": [
                        {
                            "expr": "rate(amb_messages_published_total[1m])",
                            "legendFormat": "Published - {{topic}}",
                            "refId": "A"
                        },
                        {
                            "expr": "rate(amb_messages_delivered_total[1m])",
                            "legendFormat": "Delivered - {{topic}}",
                            "refId": "B"
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {"unit": "msg/s"}
                    }
                },
                {
                    "id": 6,
                    "type": "timeseries",
                    "title": "Queue Depth by Topic",
                    "gridPos": {"h": 8, "w": 12, "x": 12, "y": 4},
                    "targets": [
                        {
                            "expr": "amb_queue_depth",
                            "legendFormat": "{{topic}}",
                            "refId": "A"
                        }
                    ]
                },
                
                # Row 3: Latency
                {
                    "id": 7,
                    "type": "timeseries",
                    "title": "Publish Latency",
                    "gridPos": {"h": 8, "w": 12, "x": 0, "y": 12},
                    "targets": [
                        {
                            "expr": "histogram_quantile(0.99, rate(amb_publish_duration_seconds_bucket[5m]))",
                            "legendFormat": "p99",
                            "refId": "A"
                        },
                        {
                            "expr": "histogram_quantile(0.95, rate(amb_publish_duration_seconds_bucket[5m]))",
                            "legendFormat": "p95",
                            "refId": "B"
                        },
                        {
                            "expr": "histogram_quantile(0.50, rate(amb_publish_duration_seconds_bucket[5m]))",
                            "legendFormat": "p50",
                            "refId": "C"
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "s",
                            "thresholds": {
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 0.01},
                                    {"color": "red", "value": 0.1}
                                ]
                            }
                        }
                    }
                },
                {
                    "id": 8,
                    "type": "timeseries",
                    "title": "Delivery Latency",
                    "gridPos": {"h": 8, "w": 12, "x": 12, "y": 12},
                    "targets": [
                        {
                            "expr": "histogram_quantile(0.99, rate(amb_delivery_duration_seconds_bucket[5m]))",
                            "legendFormat": "p99",
                            "refId": "A"
                        },
                        {
                            "expr": "histogram_quantile(0.50, rate(amb_delivery_duration_seconds_bucket[5m]))",
                            "legendFormat": "p50",
                            "refId": "B"
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {"unit": "s"}
                    }
                },
                
                # Row 4: Health
                {
                    "id": 9,
                    "type": "timeseries",
                    "title": "Priority Lane Distribution",
                    "gridPos": {"h": 8, "w": 12, "x": 0, "y": 20},
                    "targets": [
                        {
                            "expr": "rate(amb_messages_published_total[5m])",
                            "legendFormat": "{{priority}}",
                            "refId": "A"
                        }
                    ],
                    "options": {
                        "legend": {"displayMode": "table"}
                    }
                },
                {
                    "id": 10,
                    "type": "table",
                    "title": "Dead Letter Queue",
                    "gridPos": {"h": 8, "w": 12, "x": 12, "y": 20},
                    "targets": [
                        {
                            "expr": "amb_dlq_messages_total",
                            "format": "table",
                            "refId": "A"
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "thresholds": {
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "red", "value": 1}
                                ]
                            }
                        }
                    }
                },
                
                # Row 5: Broker Health
                {
                    "id": 11,
                    "type": "stat",
                    "title": "Broker Status",
                    "gridPos": {"h": 4, "w": 8, "x": 0, "y": 28},
                    "targets": [
                        {
                            "expr": "amb_broker_connected",
                            "refId": "A"
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "mappings": [
                                {"type": "value", "options": {"1": {"text": "Connected", "color": "green"}}},
                                {"type": "value", "options": {"0": {"text": "Disconnected", "color": "red"}}}
                            ]
                        }
                    }
                },
                {
                    "id": 12,
                    "type": "stat",
                    "title": "Persistence Status",
                    "gridPos": {"h": 4, "w": 8, "x": 8, "y": 28},
                    "targets": [
                        {
                            "expr": "amb_persistence_enabled",
                            "refId": "A"
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "mappings": [
                                {"type": "value", "options": {"1": {"text": "Enabled", "color": "green"}}},
                                {"type": "value", "options": {"0": {"text": "Disabled", "color": "yellow"}}}
                            ]
                        }
                    }
                },
                {
                    "id": 13,
                    "type": "stat",
                    "title": "Messages in WAL",
                    "gridPos": {"h": 4, "w": 8, "x": 16, "y": 28},
                    "targets": [
                        {
                            "expr": "amb_wal_messages_pending",
                            "refId": "A"
                        }
                    ]
                }
            ]
        },
        "folderId": 0,
        "overwrite": True
    }


def _cmvk_dashboard() -> dict:
    """CMVK (Verification Kernel) dashboard for ML Ops."""
    return {
        "dashboard": {
            "id": None,
            "uid": "agent-os-cmvk",
            "title": "Agent OS - CMVK Verification",
            "tags": ["agent-os", "cmvk", "ml-ops", "verification"],
            "timezone": "browser",
            "schemaVersion": 38,
            "version": 1,
            "refresh": "10s",
            "panels": [
                # Row 1: Key CMVK Metrics
                {
                    "id": 1,
                    "type": "stat",
                    "title": "Model Consensus Rate",
                    "description": "Current agreement ratio across verification models (target: >90%)",
                    "gridPos": {"h": 4, "w": 6, "x": 0, "y": 0},
                    "targets": [
                        {
                            "expr": "agent_os_cmvk_consensus_ratio",
                            "refId": "A"
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "percentunit",
                            "thresholds": {
                                "steps": [
                                    {"color": "red", "value": None},
                                    {"color": "yellow", "value": 0.7},
                                    {"color": "green", "value": 0.9}
                                ]
                            }
                        }
                    }
                },
                {
                    "id": 2,
                    "type": "stat",
                    "title": "Verifications (24h)",
                    "gridPos": {"h": 4, "w": 6, "x": 6, "y": 0},
                    "targets": [
                        {
                            "expr": "increase(agent_os_cmvk_verifications_total[24h])",
                            "refId": "A"
                        }
                    ]
                },
                {
                    "id": 3,
                    "type": "stat",
                    "title": "Flagged Claims (24h)",
                    "description": "Claims flagged due to model disagreement",
                    "gridPos": {"h": 4, "w": 6, "x": 12, "y": 0},
                    "targets": [
                        {
                            "expr": "increase(agent_os_cmvk_verifications_total{result='flagged'}[24h])",
                            "refId": "A"
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "thresholds": {
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 10},
                                    {"color": "red", "value": 50}
                                ]
                            }
                        }
                    }
                },
                {
                    "id": 4,
                    "type": "stat",
                    "title": "Avg Verification Time",
                    "gridPos": {"h": 4, "w": 6, "x": 18, "y": 0},
                    "targets": [
                        {
                            "expr": "histogram_quantile(0.50, rate(agent_os_cmvk_verification_duration_seconds_bucket[5m]))",
                            "refId": "A"
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "s",
                            "thresholds": {
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 3},
                                    {"color": "red", "value": 10}
                                ]
                            }
                        }
                    }
                },
                
                # Row 2: Verification Results
                {
                    "id": 5,
                    "type": "piechart",
                    "title": "Verification Results (24h)",
                    "gridPos": {"h": 8, "w": 8, "x": 0, "y": 4},
                    "targets": [
                        {
                            "expr": "increase(agent_os_cmvk_verifications_total[24h])",
                            "legendFormat": "{{result}}",
                            "refId": "A"
                        }
                    ],
                    "options": {
                        "legend": {"displayMode": "table", "placement": "right"}
                    }
                },
                {
                    "id": 6,
                    "type": "timeseries",
                    "title": "Verification Rate Over Time",
                    "gridPos": {"h": 8, "w": 16, "x": 8, "y": 4},
                    "targets": [
                        {
                            "expr": "rate(agent_os_cmvk_verifications_total[5m])",
                            "legendFormat": "{{result}}",
                            "refId": "A"
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "req/s",
                            "custom": {
                                "fillOpacity": 30
                            }
                        }
                    }
                },
                
                # Row 3: Drift and Consensus
                {
                    "id": 7,
                    "type": "timeseries",
                    "title": "Drift Score Distribution",
                    "description": "Lower is better. High drift = model disagreement.",
                    "gridPos": {"h": 8, "w": 12, "x": 0, "y": 12},
                    "targets": [
                        {
                            "expr": "histogram_quantile(0.99, rate(agent_os_cmvk_drift_score_bucket[5m]))",
                            "legendFormat": "p99",
                            "refId": "A"
                        },
                        {
                            "expr": "histogram_quantile(0.95, rate(agent_os_cmvk_drift_score_bucket[5m]))",
                            "legendFormat": "p95",
                            "refId": "B"
                        },
                        {
                            "expr": "histogram_quantile(0.50, rate(agent_os_cmvk_drift_score_bucket[5m]))",
                            "legendFormat": "p50",
                            "refId": "C"
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "thresholds": {
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 0.15},
                                    {"color": "red", "value": 0.30}
                                ]
                            }
                        }
                    }
                },
                {
                    "id": 8,
                    "type": "timeseries",
                    "title": "Model Disagreements Rate",
                    "gridPos": {"h": 8, "w": 12, "x": 12, "y": 12},
                    "targets": [
                        {
                            "expr": "rate(agent_os_cmvk_model_disagreements_total[5m])",
                            "legendFormat": "{{model_pair}}",
                            "refId": "A"
                        }
                    ]
                },
                
                # Row 4: Per-Model Performance
                {
                    "id": 9,
                    "type": "timeseries",
                    "title": "Model Response Latency",
                    "description": "Individual model response times",
                    "gridPos": {"h": 8, "w": 12, "x": 0, "y": 20},
                    "targets": [
                        {
                            "expr": "histogram_quantile(0.95, rate(agent_os_cmvk_model_latency_seconds_bucket[5m]))",
                            "legendFormat": "{{model}} p95",
                            "refId": "A"
                        }
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "unit": "s",
                            "thresholds": {
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 2},
                                    {"color": "red", "value": 5}
                                ]
                            }
                        }
                    }
                },
                {
                    "id": 10,
                    "type": "bargauge",
                    "title": "Claims by Confidence Level",
                    "gridPos": {"h": 8, "w": 12, "x": 12, "y": 20},
                    "targets": [
                        {
                            "expr": "increase(agent_os_cmvk_claims_by_confidence[24h])",
                            "legendFormat": "{{confidence_bucket}}",
                            "refId": "A"
                        }
                    ],
                    "options": {
                        "displayMode": "gradient",
                        "orientation": "horizontal"
                    },
                    "fieldConfig": {
                        "defaults": {
                            "thresholds": {
                                "steps": [
                                    {"color": "red", "value": None},
                                    {"color": "yellow", "value": 0},
                                    {"color": "green", "value": 0}
                                ]
                            }
                        },
                        "overrides": [
                            {
                                "matcher": {"id": "byName", "options": "high"},
                                "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "green"}}]
                            },
                            {
                                "matcher": {"id": "byName", "options": "medium"},
                                "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "yellow"}}]
                            },
                            {
                                "matcher": {"id": "byName", "options": "low"},
                                "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": "red"}}]
                            }
                        ]
                    }
                },
                
                # Row 5: Verification Duration
                {
                    "id": 11,
                    "type": "heatmap",
                    "title": "Verification Duration Heatmap",
                    "gridPos": {"h": 8, "w": 12, "x": 0, "y": 28},
                    "targets": [
                        {
                            "expr": "sum(rate(agent_os_cmvk_verification_duration_seconds_bucket[1m])) by (le)",
                            "format": "heatmap",
                            "refId": "A"
                        }
                    ],
                    "options": {
                        "yAxis": {"unit": "s"}
                    }
                },
                {
                    "id": 12,
                    "type": "table",
                    "title": "Recent High-Drift Claims",
                    "description": "Claims with drift >0.20 that may need review",
                    "gridPos": {"h": 8, "w": 12, "x": 12, "y": 28},
                    "targets": [
                        {
                            "expr": "topk(10, agent_os_cmvk_drift_score > 0.20)",
                            "format": "table",
                            "refId": "A"
                        }
                    ]
                }
            ]
        },
        "folderId": 0,
        "overwrite": True
    }
