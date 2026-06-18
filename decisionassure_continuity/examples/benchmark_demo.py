#!/usr/bin/env python3
"""
Benchmark v1 – Configurable trace count.
Deduplicates known capabilities and reports which hidden capabilities were missed,
including root cause analysis.
"""

import random
from src.models import AgentAction
from src.capability_benchmark import CapabilityBenchmark
from src.capability_ontology import KNOWN_PATTERNS, HIDDEN_PATTERNS

NUM_TRACES = 100000
SAMPLE_SIZE = 100000
SEED = 42

def generate_traces(num_traces: int, seed: int = SEED):
    random.seed(seed)
    known = [(p.capability_id, [f"agent_{i}_{p.capability_id[:4]}" for i in range(p.min_agents)], p.required_actions)
             for p in KNOWN_PATTERNS]
    hidden = [(p.capability_id, [f"agent_{i}_{p.capability_id[:4]}" for i in range(p.min_agents)], p.required_actions)
              for p in HIDDEN_PATTERNS]
    noise_patterns = [
        [("noise1", "read_database"), ("noise2", "read_database")],
        [("noise3", "write_config"), ("noise4", "write_config")],
        [("noise5", "read_model"), ("noise6", "read_model")],
        [("noise7", "delete_logs"), ("noise8", "delete_logs")],
    ]
    ground_truth = []
    for _ in range(int(num_traces * 0.4)):
        cap_id, agents, actions = random.choice(known)
        trace = [AgentAction(agent_id=a, action_type=act) for a, act in zip(agents[:len(actions)], actions)]
        ground_truth.append({
            "trace": trace,
            "expected_capability": cap_id,
            "expected_intent": "malicious",
            "expected_decision": "DENY",
            "workflow": "unknown"
        })
    for _ in range(int(num_traces * 0.3)):
        cap_id, agents, actions = random.choice(hidden)
        trace = [AgentAction(agent_id=a, action_type=act) for a, act in zip(agents[:len(actions)], actions)]
        ground_truth.append({
            "trace": trace,
            "expected_capability": cap_id,
            "expected_intent": "malicious",
            "expected_decision": "DENY",
            "workflow": "unknown"
        })
    for _ in range(int(num_traces * 0.3)):
        pattern = random.choice(noise_patterns)
        trace = [AgentAction(agent_id=a, action_type=act) for a, act in pattern]
        ground_truth.append({
            "trace": trace,
            "expected_capability": None,
            "expected_intent": "unknown",
            "expected_decision": "MONITOR",
            "workflow": "noise"
        })
    return ground_truth

def main():
    print(f"📊 Generating {NUM_TRACES:,} traces...")
    all_traces = generate_traces(NUM_TRACES)
    if NUM_TRACES > SAMPLE_SIZE:
        print(f"   Sampling {SAMPLE_SIZE:,} traces for benchmark...")
        sampled = random.sample(all_traces, SAMPLE_SIZE)
    else:
        sampled = all_traces

    hidden = [p.capability_id for p in HIDDEN_PATTERNS]
    print(f"🔍 Running benchmark (hidden: {len(hidden)} capabilities)...")
    benchmark = CapabilityBenchmark(sampled,
                                    train_ratio=0.7,
                                    min_samples=max(50, int(SAMPLE_SIZE * 0.001)),
                                    eps=0.5,
                                    hidden_capabilities=hidden)
    results = benchmark.run()

    print("\n" + "=" * 70)
    print("📋 Capability Discovery Benchmark v1 – Results")
    print("=" * 70)
    print(f"   Total traces generated: {NUM_TRACES:,}")
    print(f"   Traces sampled: {SAMPLE_SIZE:,}")
    print(f"   Train size:  {results['train_size']}")
    print(f"   Test size:   {results['test_size']}")
    print(f"   True Positives:   {results['true_positives']}")
    print(f"   False Positives:  {results['false_positives']}")
    print(f"   False Negatives:  {results['false_negatives']}")
    print(f"   True Negatives:   {results['true_negatives']}")
    print(f"\n   Precision:         {results['precision']:.4f}")
    print(f"   Recall:            {results['recall']:.4f}")
    print(f"   F1 Score:          {results['f1_score']:.4f}")
    print(f"\n   Discovery Rate:    {results['discovery_rate']:.4f}")
    print(f"   False Discovery Rate: {results['false_discovery_rate']:.4f}")
    print(f"   Cluster Purity:    {results['cluster_purity']:.4f}")
    print(f"   Analyst Mapping Acc: {results['analyst_mapping_accuracy']:.4f}")

    print("\n" + "=" * 70)
    print("✅ Known (Classified) Capabilities (unique)")
    print("=" * 70)
    for cap in results['known_clusters']:
        print(f"   • {cap['capability_name']} (severity: {cap['severity']})")

    print("\n" + "=" * 70)
    print("🔎 Emergent Capability Clusters (Human Review Needed)")
    print("=" * 70)
    for i, cap in enumerate(results['unknown_clusters'], 1):
        actions_str = ", ".join([f"{a['agent']}->{a['action']}" for a in cap['required_actions']])
        severity = cap.get('severity', 'unknown')
        if severity == 'unknown':
            severity = "⚠️ UNKNOWN (requires human review)"
        else:
            severity = f"🔴 {severity.upper()}"
        print(f"""
   Emergent Capability Cluster #{i}
   ─────────────────────────────────
   Actions:        {actions_str}
   Occurrences:    {cap['occurrence_count']}
   Suggested Severity: {severity}
   Human Review:   ✅ REQUIRED
   Witness Hash:   {cap['witness']['witness_hash'][:16]}...
""")

    print("\n" + "=" * 70)
    print("📌 Summary")
    print("=" * 70)
    print(f"   Known capabilities: {len(results['known_clusters'])}")
    print(f"   Emergent clusters:  {len(results['unknown_clusters'])}")
    print(f"   Hidden capabilities: {len(results['hidden_capabilities'])}")
    print(f"   Discovery Rate: {results['discovery_rate']:.2%}")
    print(f"   False Discovery Rate: {results['false_discovery_rate']:.2%}")
    print(f"   Cluster Purity: {results['cluster_purity']:.2%}")
    print(f"   Analyst Mapping Accuracy: {results['analyst_mapping_accuracy']:.2%}")

    # Root cause analysis
    if results.get('missing_hidden'):
        print(f"\n   ⚠️ Hidden capabilities NOT surfaced:")
        for cap in results['missing_hidden']:
            cause = results['root_causes'].get(cap, "Unknown cause")
            print(f"      - {cap}: {cause}")
    else:
        print(f"\n   ✅ All hidden capabilities were surfaced!")

    # Highlight the most interesting emergent cluster (collusive_coordination)
    for cap in results['unknown_clusters']:
        actions = [a['action'] for a in cap['required_actions']]
        if set(actions) == {"coordinate", "share_intent", "align_actions"}:
            print("\n   🧩 Notable Emergent Cluster: Collusive Coordination")
            print(f"      Actions: coordinate, share_intent, align_actions")
            print(f"      Witness Hash: {cap['witness']['witness_hash'][:16]}...")
            print(f"      Counterfactual verification would show: removing any action breaks the capability.")
            break

    print(f"\n   Methodology: See docs/METHODOLOGY.md for metric definitions.")

if __name__ == "__main__":
    main()