#!/usr/bin/env python3
"""CLI for DecisionAssure Impact."""
import sys
import json
import logging
from pathlib import Path
from typing import List
from datetime import datetime, timedelta, timezone

import click
import yaml

from .engine import ImpactEngine
from .drift import DriftDetector
from .models.trace import TraceBatch, DecisionTrace, Action
from .models.impact import ImpactReport

logger = logging.getLogger(__name__)


@click.group()
def cli():
    """DecisionAssure Impact – governance change impact analysis."""
    pass


@cli.command()
@click.option(
    "--traces",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to traces JSONL file.",
)
@click.option(
    "--policy-current",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to current policy YAML.",
)
@click.option(
    "--policy-proposed",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to proposed policy YAML.",
)
@click.option(
    "--output-json",
    type=click.Path(dir_okay=False),
    help="Export report to JSON file.",
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Enable verbose logging.",
)
def impact(traces, policy_current, policy_proposed, output_json, verbose):
    """Run counterfactual impact analysis."""
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    click.echo(f"Loading traces from {traces}...")
    trace_list = load_traces(traces)
    click.echo(f"Loaded {len(trace_list)} traces.")

    with open(policy_current, "r") as f:
        curr_policy = yaml.safe_load(f)
    with open(policy_proposed, "r") as f:
        prop_policy = yaml.safe_load(f)

    # ========== FIX: Add valid delegation ==========
    now = datetime.now(timezone.utc)
    authority = {
        "delegations": [
            {
                "id": "delegation_123",
                "grantor": "admin",
                "grantee": "agent",
                "permissions": ["refund", "payment", "credit_decision", "aml_check"],
                "valid_from": now - timedelta(days=1),
                "valid_until": now + timedelta(days=365),
            }
        ],
        "global_tool_capabilities": {"payment-api": ["read", "write"]},
    }
    # ==============================================

    engine = ImpactEngine(trace_list)
    report = engine.analyze_impact(curr_policy, authority, prop_policy, authority)

    print_report(report)

    if output_json:
        with open(output_json, "w") as f:
            json.dump(report.model_dump(mode="json", exclude_none=True), f, indent=2, default=str)
        click.echo(f"Report saved to {output_json}")

    if report.recommendation == "BLOCK":
        click.echo("❌ BLOCK recommended – exiting with non-zero code.", err=True)
        sys.exit(1)
    else:
        sys.exit(0)


@cli.command()
@click.option(
    "--traces",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to traces JSONL file.",
)
@click.option(
    "--policy-current",
    required=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to current policy YAML.",
)
@click.option(
    "--drift-threshold",
    default=1.0,
    help="Drift threshold in hours.",
)
def detect_drift(traces, policy_current, drift_threshold):
    """Detect governance drift in production traces."""
    trace_list = load_traces(traces)
    detector = DriftDetector(drift_threshold)

    with open(policy_current, "r") as f:
        policy = yaml.safe_load(f)

    drifted_sessions = 0
    for trace in trace_list:
        for decision in trace.decisions:
            age = decision.evidence_age_hours
            if age > drift_threshold:
                drifted_sessions += 1
                break

    click.echo(f"Sessions analyzed: {len(trace_list)}")
    click.echo(f"Sessions with drift: {drifted_sessions}")
    click.echo(f"Drift rate: {drifted_sessions / len(trace_list) * 100:.2f}%")


def load_traces(filepath: str) -> List[TraceBatch]:
    """Load traces from JSONL file."""
    traces = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                decisions = []
                for d in data.get("decisions", []):
                    action_data = d.get("action", {})
                    action = Action(
                        id=action_data.get("id"),
                        name=action_data.get("name", ""),
                        parameters=action_data.get("parameters", {}),
                        tool=action_data.get("tool", ""),
                        version=action_data.get("version", ""),
                        transaction_amount=action_data.get("transaction_amount"),
                    )
                    # Extract model_version from context or decision-level field
                    model_version = d.get("context", {}).get("model_version", "") or d.get("model_version", "")
                    decision = DecisionTrace(
                        action=action,
                        agent_id=d.get("agent_id"),
                        agent_version=d.get("agent_version", ""),
                        timestamp=d.get("timestamp"),
                        policy_version=d.get("policy_version", ""),
                        authority_chain=d.get("authority_chain", []),
                        context=d.get("context", {}),
                        evidence_used=d.get("evidence_used", []),
                        evidence_age_hours=d.get("context", {}).get("evidence_age_hours", 0.0),
                        tool_permissions_at_time=d.get("tool_permissions_at_time", []),
                        model_version=model_version,
                        result=d.get("result", ""),
                    )
                    decisions.append(decision)
                trace = TraceBatch(
                    trace_id=data.get("trace_id"),
                    decisions=decisions,
                    environment=data.get("environment", {}),
                    metadata=data.get("metadata", {}),
                )
                traces.append(trace)
            except Exception as e:
                logger.warning(f"Skipping malformed trace line: {e}")
                continue
    return traces


def print_report(report: ImpactReport):
    """Pretty-print the impact report."""
    print("\n" + "=" * 80)
    print("  DECISIONASSURE IMPACT REPORT")
    print("=" * 80)
    print(f"\nChange: {report.change_description}")
    print("-" * 80)
    print("EXECUTION DATA")
    print("-" * 80)
    print(f"Traces analyzed:              {report.total_traces_analyzed:>15,}")
    print(f"Decisions evaluated:          {report.total_decisions_evaluated:>15,}")

    print("\n" + "-" * 80)
    print("COUNTERFACTUAL GOVERNANCE DIFF")
    print("-" * 80)
    print(f"ADMISSIBLE → INADMISSIBLE:    {report.transitions.admissible_to_inadmissible:>15,}")
    print(f"INADMISSIBLE → ADMISSIBLE:    {report.transitions.inadmissible_to_admissible:>15,}")
    print(f"Invalidated:                  {report.transitions.invalidated:>15,}")
    print(f"Unchanged:                    {report.transitions.unchanged:>15,}")
    print(f"Impact rate:                  {report.impact_rate:>14.2f}%")

    print("\n" + "-" * 80)
    print("BLAST RADIUS")
    print("-" * 80)
    print(f"Agents affected:              {len(report.blast_radius.agents_affected):>15}")
    print(f"Tools affected:               {len(report.blast_radius.tools_affected):>15}")
    print(f"Policy versions affected:     {len(report.blast_radius.policy_versions_affected):>15}")
    print(f"Decision types affected:      {len(report.blast_radius.decision_types_affected):>15}")

    print("\n" + "-" * 80)
    print("BUSINESS EXPOSURE")
    print("-" * 80)
    exposure = report.estimated_exposure
    if exposure >= 1e7:
        exposure_str = f"₹{exposure/1e7:,.2f} crore"
    else:
        exposure_str = f"₹{exposure:,.2f}"
    print(f"Estimated exposure:           {exposure_str:>15}")

    print("\n" + "-" * 80)
    print("GOVERNANCE ASSESSMENT")
    print("-" * 80)
    print(f"Severity:                     {report.severity:>15}")
    print(f"\nPrimary regression:")
    print(f"  {report.primary_regression}")

    if report.per_decision_explanations:
        print("\n" + "-" * 80)
        print(f"TOP 10 AFFECTED DECISION EXPLANATIONS")
        print("-" * 80)
        items = list(report.per_decision_explanations.items())
        for i, (aid, expl) in enumerate(items[:10]):
            print(f"{i+1}. Decision {aid[:8]}: {expl}")

    print("\n" + "-" * 80)
    print("DECISION")
    print("-" * 80)
    if report.recommendation == "BLOCK":
        print(f"\n                         ❌ {report.recommendation}")
    elif report.recommendation == "REVIEW":
        print(f"\n                         ⚠️  {report.recommendation}")
    else:
        print(f"\n                         ✅ {report.recommendation}")
    print("\n" + "=" * 80 + "\n")


if __name__ == "__main__":
    cli()