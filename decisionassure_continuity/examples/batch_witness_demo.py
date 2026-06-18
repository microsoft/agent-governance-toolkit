#!/usr/bin/env python3
"""
Batch Witness Demo – Process hundreds of traces from multiple frameworks.
Generates a comprehensive report with false witness analysis and optional learning.
"""

import json
import sys
import os
import glob
import argparse
from collections import defaultdict
from datetime import datetime
from src.adapters.auto_gen_adapter import AutoGenAdapter
from src.adapters.lang_graph_adapter import LangGraphAdapter
from src.adapters.crewai_adapter import CrewAIAdapter
from src.adapters.openai_agents_adapter import OpenAIAdapter
from src.adapters.agenttrust_adapter import AgentTrustAdapter
from src.capability_witness_engine import CapabilityWitnessEngine


def get_adapter(framework):
    adapters = {
        "autogen": AutoGenAdapter(),
        "langgraph": LangGraphAdapter(),
        "crewai": CrewAIAdapter(),
        "openai": OpenAIAdapter(),
        "agenttrust": AgentTrustAdapter()
    }
    return adapters.get(framework)


def process_directory(root_dir: str, framework: str, min_samples: int = 3,
                      eps: float = 0.5, confidence_threshold: float = 0.5,
                      learn: bool = False):
    """
    Recursively find all JSON files, parse them, and run the witness engine.
    Returns a summary report.
    """
    print(f"📂 Scanning {root_dir} for {framework} traces...")
    trace_files = glob.glob(os.path.join(root_dir, "**", "*.json"), recursive=True)
    if not trace_files:
        print(f"❌ No JSON files found in {root_dir}")
        return None

    print(f"📁 Found {len(trace_files)} trace files")

    adapter = get_adapter(framework)
    if not adapter:
        print(f"❌ Unknown framework: {framework}")
        return None

    all_traces = []
    all_agent_ids = set()
    parse_errors = 0

    for tf in trace_files:
        try:
            with open(tf, 'r') as f:
                trace_data = json.load(f)
            actions = adapter.parse(trace_data)
            if actions:
                all_traces.append(actions)
                agent_ids = adapter.get_agent_ids(trace_data)
                all_agent_ids.update(agent_ids)
        except Exception as e:
            parse_errors += 1
            print(f"   ⚠️ Error parsing {tf}: {e}")

    print(f"✅ Parsed {len(all_traces)} traces successfully (errors: {parse_errors})")
    print(f"   Agents: {', '.join(sorted(all_agent_ids))}")

    if not all_traces:
        print("❌ No valid traces found.")
        return None

    # Run the Capability Witness Engine
    engine = CapabilityWitnessEngine(min_samples=min_samples, eps=eps,
                                     confidence_threshold=confidence_threshold)
    witnesses = engine.process_traces(all_traces)

    # ===== LEARNING LOOP =====
    if learn:
        from src.capability_learner import CapabilityLearner
        learner = CapabilityLearner()
        print("\n🧠 Governance Learning Loop enabled:")
        for w in witnesses:
            if w.get('classification') == 'unknown' and not w.get('is_false_witness', False):
                suggested = learner.suggest_label(w['required_actions'])
                if suggested:
                    w['suggested_ontology_label'] = suggested
                    print(f"   💡 Suggested label for '{w['capability']}': {suggested}")
        print()
    # ===== END LEARNING LOOP =====

    # Statistics
    stats = {
        "total_traces": len(all_traces),
        "total_witnesses": len(witnesses),
        "recommendations": defaultdict(int),
        "severities": defaultdict(int),
        "confidences": [],
        "witness_details": witnesses,
        "frameworks": {framework: len(all_traces)},
        "agents": list(all_agent_ids),
        "parse_errors": parse_errors,
        "timestamp": datetime.now().isoformat(),
        "confidence_threshold": confidence_threshold
    }

    false_witnesses = []
    valid_witnesses = []

    for w in witnesses:
        stats["recommendations"][w["governance_recommendation"]] += 1
        stats["severities"][w["severity"]] += 1
        stats["confidences"].append(w["confidence"])
        if w.get("is_false_witness", False):
            false_witnesses.append(w)
        else:
            valid_witnesses.append(w)

    if stats["confidences"]:
        stats["avg_confidence"] = sum(stats["confidences"]) / len(stats["confidences"])
    else:
        stats["avg_confidence"] = 0.0

    stats["false_witnesses"] = false_witnesses
    stats["valid_witnesses"] = valid_witnesses

    # Human reviews triggered: HUMAN_REVIEW or DENY
    human_reviews = stats["recommendations"].get("HUMAN_REVIEW", 0) + stats["recommendations"].get("DENY", 0)
    stats["human_reviews_triggered"] = human_reviews

    # False witness analysis
    false_analysis = []
    for w in false_witnesses:
        false_analysis.append({
            "capability": w['capability'],
            "confidence": w['confidence'],
            "reason": w.get('false_witness_reason', 'Unknown reason'),
            "required_actions": w['required_actions'],
            "witness_hash": w['witness_hash'][:16] + "..."
        })
    stats["false_witness_analysis"] = false_analysis
    stats["false_witness_count"] = len(false_witnesses)

    return stats


def generate_report(stats: dict) -> str:
    """Generate a human-readable report from statistics."""
    lines = []
    lines.append("=" * 80)
    lines.append("🧾 Capability Witness Engine – Batch Report")
    lines.append("=" * 80)
    lines.append(f"   Timestamp:                 {stats['timestamp']}")
    lines.append(f"   Total traces processed:    {stats['total_traces']}")
    lines.append(f"   Total witnesses generated: {stats['total_witnesses']}")
    lines.append(f"   Parse errors:              {stats['parse_errors']}")
    lines.append(f"   Agents involved:           {', '.join(stats['agents'])}")
    lines.append(f"   Frameworks:                {', '.join([f'{k}: {v}' for k, v in stats['frameworks'].items()])}")
    lines.append(f"   Confidence threshold:      {stats['confidence_threshold']:.2%}")
    lines.append("")
    lines.append("   Recommendations:")
    for rec, count in stats['recommendations'].items():
        lines.append(f"      {rec}: {count}")
    lines.append("")
    lines.append("   Severities:")
    for sev, count in stats['severities'].items():
        lines.append(f"      {sev}: {count}")
    lines.append("")
    lines.append(f"   Human reviews triggered:   {stats['human_reviews_triggered']}")
    lines.append(f"   Valid witnesses:           {len(stats['valid_witnesses'])}")
    lines.append(f"   False witness claims:      {stats['false_witness_count']}")
    lines.append(f"   Average confidence:        {stats['avg_confidence']:.2%}")
    lines.append("")

    # False Witness Analysis
    if stats['false_witness_analysis']:
        lines.append("   ⚠️ False Witness Analysis:")
        for fw in stats['false_witness_analysis']:
            lines.append(f"      Witness: {fw['capability']}")
            lines.append(f"      Confidence: {fw['confidence']:.2%}")
            lines.append(f"      Reason: {fw['reason']}")
            lines.append(f"      Actions: {', '.join([f'{a['agent']}->{a['action']}' for a in fw['required_actions']])}")
            lines.append(f"      Hash: {fw['witness_hash']}")
            lines.append("")
    else:
        lines.append("   ✅ No false witness claims detected.")
        lines.append("")

    # Check for suggested labels
    suggested_labels = []
    for w in stats['valid_witnesses']:
        if w.get('suggested_ontology_label'):
            suggested_labels.append(f"      {w['capability']} → {w['suggested_ontology_label']}")
    if suggested_labels:
        lines.append("   💡 Suggested Ontology Labels (from learning loop):")
        lines.extend(suggested_labels)
        lines.append("")

    lines.append("   Valid Witnesses:")
    for i, w in enumerate(stats['valid_witnesses'], 1):
        actions_str = ", ".join([f"{a['agent']}->{a['action']}" for a in w['required_actions']])
        label_str = f" (suggested: {w['suggested_ontology_label']})" if w.get('suggested_ontology_label') else ""
        lines.append(f"      #{i}: {w['capability']}{label_str} (conf: {w['confidence']:.2%}, rec: {w['governance_recommendation']})")
        lines.append(f"           Actions: {actions_str}")
        lines.append(f"           Hash: {w['witness_hash'][:16]}...")
        lines.append(f"           Counterfactual: {'✅' if w['counterfactual_verified'] else '❌'}")

    lines.append("=" * 80)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Batch Witness Demo")
    parser.add_argument("traces_root", help="Root directory containing trace files")
    parser.add_argument("--framework", default="autogen",
                        help="Framework: autogen, langgraph, crewai, openai, agenttrust")
    parser.add_argument("--min_samples", type=int, default=3,
                        help="Minimum samples for discovery")
    parser.add_argument("--eps", type=float, default=0.5,
                        help="DBSCAN eps parameter")
    parser.add_argument("--confidence_threshold", type=float, default=0.5,
                        help="Confidence threshold for accepting witnesses")
    parser.add_argument("--learn", action="store_true",
                        help="Enable governance learning loop (suggest labels for unknown capabilities)")
    args = parser.parse_args()

    if not os.path.isdir(args.traces_root):
        print(f"❌ Error: {args.traces_root} is not a directory.")
        sys.exit(1)

    stats = process_directory(args.traces_root, args.framework,
                              args.min_samples, args.eps,
                              args.confidence_threshold, args.learn)
    if stats is None:
        sys.exit(1)

    report = generate_report(stats)
    print(report)

    # Save report to JSON
    report_file = f"witness_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(stats, f, indent=2, default=str)
    print(f"\n✅ Full report saved to {report_file}")

if __name__ == "__main__":
    main()