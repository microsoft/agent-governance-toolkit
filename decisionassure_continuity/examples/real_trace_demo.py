#!/usr/bin/env python3
"""
Real Trace Demo – Process a directory of trace files and output capability witnesses.
Produces professional governance recommendations with confidence scores.
"""

import json
import sys
import os
import glob
from datetime import datetime
from src.adapters.auto_gen_adapter import AutoGenAdapter
from src.adapters.lang_graph_adapter import LangGraphAdapter
from src.adapters.crewai_adapter import CrewAIAdapter
from src.adapters.openai_agents_adapter import OpenAIAdapter
from src.capability_witness_engine import CapabilityWitnessEngine

def main():
    if len(sys.argv) < 2:
        print("Usage: python real_trace_demo.py <traces_directory> [framework] [min_samples] [eps]")
        print("Frameworks: autogen, langgraph, crewai, openai")
        print("The directory should contain JSON trace files.")
        sys.exit(1)

    trace_dir = sys.argv[1]
    framework = sys.argv[2] if len(sys.argv) > 2 else "autogen"
    min_samples = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    eps = float(sys.argv[4]) if len(sys.argv) > 4 else 0.5

    if not os.path.isdir(trace_dir):
        print(f"Error: {trace_dir} is not a directory.")
        sys.exit(1)

    adapters = {
        "autogen": AutoGenAdapter(),
        "langgraph": LangGraphAdapter(),
        "crewai": CrewAIAdapter(),
        "openai": OpenAIAdapter()
    }
    adapter = adapters.get(framework)
    if not adapter:
        print(f"Unknown framework: {framework}")
        sys.exit(1)

    trace_files = glob.glob(os.path.join(trace_dir, "*.json"))
    if not trace_files:
        print(f"No JSON files found in {trace_dir}")
        sys.exit(1)

    print(f"📁 Found {len(trace_files)} trace files in {trace_dir}")

    all_traces = []
    all_agent_ids = set()

    for tf in trace_files:
        with open(tf, 'r') as f:
            trace_data = json.load(f)
        actions = adapter.parse(trace_data)
        agent_ids = adapter.get_agent_ids(trace_data)
        all_agent_ids.update(agent_ids)
        all_traces.append(actions)

    print(f"✅ Parsed {len(all_traces)} traces from {framework}.")
    print(f"   Agents: {', '.join(sorted(all_agent_ids))}")

    # Run the Capability Witness Engine
    engine = CapabilityWitnessEngine(min_samples=min_samples, eps=eps)
    witnesses = engine.process_traces(all_traces)

    if not witnesses:
        print("No capability witnesses generated.")
        print(f"   Try increasing number of traces or adjusting min_samples/eps.")
        return

    print(f"\n🧾 Generated {len(witnesses)} Capability Witness(es):")
    print("=" * 70)

    for i, w in enumerate(witnesses, 1):
        print(f"\n   Witness #{i}: {w['capability']}")
        print(f"   Confidence: {w['confidence']:.2%}")
        print(f"   Required Actions: {', '.join([f'{a['agent']}->{a['action']}' for a in w['required_actions']])}")
        print(f"   Minimal Witness: {w['minimal_witness']}")
        print(f"   Counterfactual Verified: {w['counterfactual_verified']}")
        print(f"   Severity: {w['severity']}")
        print(f"   Governance Recommendation: {w['governance_recommendation']}")
        print(f"   Reason: {w['governance_reason']}")
        print(f"   Witness Hash: {w['witness_hash'][:16]}...")
        print(f"   Occurrences: {w['occurrence_count']}")

        # Print full JSON for the first witness as an example
        if i == 1:
            print("\n   📄 Full Witness (JSON):")
            print(json.dumps(w, indent=2, default=str))

    print("\n" + "=" * 70)
    print("📌 Summary")
    print(f"   Total traces processed: {len(all_traces)}")
    print(f"   Witnesses generated: {len(witnesses)}")
    print(f"   Recommendations: DENY={len([w for w in witnesses if w['governance_recommendation'] == 'DENY'])}, "
          f"HUMAN_REVIEW={len([w for w in witnesses if w['governance_recommendation'] == 'HUMAN_REVIEW'])}, "
          f"MONITOR={len([w for w in witnesses if w['governance_recommendation'] == 'MONITOR'])}, "
          f"ADMIT={len([w for w in witnesses if w['governance_recommendation'] == 'ADMIT'])}")

    print("\n   Capability Witness generated successfully.")

if __name__ == "__main__":
    main()