#!/usr/bin/env python3
"""
Review Queue Demo – End-to-end governance learning loop with balanced priority, coverage metrics,
governance drift timeline, Ontology Update Impact Table, Governance Coverage Curve, and GKAI.
"""
from datetime import datetime
import json
import sys
import os
from src.capability_learner import CapabilityLearner
from src.capability_discovery import CapabilityDiscovery
from src.capability_drift_replay import CapabilityDriftReplay
from src.capability_ontology import load_ontology_from_file, OntologyMatcher, TRAINING_ONTOLOGY, KNOWN_PATTERNS, load_combined_ontology
from src.governance_coverage_curve import GovernanceCoverageTracker
from src.models import AgentAction
from src.adapters.auto_gen_adapter import AutoGenAdapter

def main():
    print("🧠 Governance Learning Loop Demo")
    print("=" * 70)

    # Step 1: Load traces
    print("\n📁 Loading traces from sample_traces_large/...")
    adapter = AutoGenAdapter()
    traces = []
    trace_dir = "sample_traces_large"

    if os.path.exists(trace_dir):
        import glob
        for tf in glob.glob(os.path.join(trace_dir, "*.json")):
            with open(tf, 'r') as f:
                data = json.load(f)
                actions = adapter.parse(data)
                if actions:
                    traces.append(actions)
    else:
        print("   ⚠️ sample_traces_large/ not found. Generating synthetic traces...")
        from generate_sample_traces import generate_traces
        generate_traces(50)
        for tf in glob.glob(os.path.join(trace_dir, "*.json")):
            with open(tf, 'r') as f:
                data = json.load(f)
                actions = adapter.parse(data)
                if actions:
                    traces.append(actions)

    print(f"   Loaded {len(traces)} traces")

    # ===== COVERAGE CURVE TRACKER =====
    tracker = GovernanceCoverageTracker(traces)
    snapshot_base = tracker.record_snapshot("evolved_ontology.json", use_combined=False)
    print("\n📊 Baseline Coverage (v0):")
    print(f"   Classification Rate: {snapshot_base['classification_rate_percent']}%")
    print(f"   Ontology Coverage:   {snapshot_base['ontology_coverage_percent']}%")
    print(f"   Classified: {snapshot_base['classified']} / {snapshot_base['total']} discovered")

    # Step 2: Run discovery (initial)
    print("\n🔍 Running capability discovery...")
    discovery = CapabilityDiscovery(min_samples=2, eps=0.5)
    discovered = discovery.discover(traces)

    known = [cap for cap in discovered if cap['classification'] != 'unknown']
    unknown = [cap for cap in discovered if cap['classification'] == 'unknown']
    print(f"   Found {len(discovered)} capabilities: {len(known)} known, {len(unknown)} unknown")

    # Step 3: Coverage metrics (before approval)
    learner = CapabilityLearner(traces=traces)
    coverage = learner.get_coverage(discovered)
    print("\n📊 Capability Coverage (Before Approval):")
    print(f"   Known Capabilities:     {coverage['known_capabilities']}")
    print(f"   Discovered Capabilities: {coverage['discovered_capabilities']}")
    print(f"   Classified Capabilities: {coverage['classified_capabilities']}")
    print(f"   Unknown Capabilities:   {coverage['unknown_capabilities']}")
    # ===== FIX: Use correct metric names =====
    classification_rate = coverage['classified_capabilities'] / coverage['discovered_capabilities'] if coverage['discovered_capabilities'] > 0 else 0.0
    print(f"   Classification Rate:    {round(classification_rate * 100, 1)}%")
    print(f"   Ontology Coverage:      {coverage['classified_coverage_percent']}%")
    print(f"   Unknown Coverage:       {coverage['unknown_coverage_percent']}%")

    if not unknown:
        print("\n✅ No unknown capabilities found.")
        return

    # Step 4: Submit unknown to review queue
    print("\n📋 Submitting unknown capabilities to review queue...")
    submitted = []
    duplicates = 0

    for cap in unknown:
        existing = [r for r in learner.get_pending_reviews() if r['required_actions'] == cap['required_actions']]
        if existing:
            duplicates += 1
            print(f"   ⏭️ Duplicate: {cap['capability_name']} (already in queue)")
            continue

        result = learner.submit_for_review(
            capability_id=cap['capability_id'],
            capability_name=cap['capability_name'],
            required_actions=cap['required_actions'],
            evidence_hash=cap['witness']['witness_hash'],
            severity=cap.get('severity', 'unknown')
        )
        suggestion = result['suggestion']
        novelty = result['novelty']
        impact = result['impact']
        priority = result['priority']
        submitted.append({
            "cap": cap,
            "suggestion": suggestion,
            "novelty": novelty,
            "impact": impact,
            "priority": priority
        })
        print(f"   Submitted: {cap['capability_name']} (actions: {len(cap['required_actions'])})")
        print(f"      Suggested label: {suggestion['suggested_label']} (confidence: {suggestion['confidence']:.2%})")
        print(f"      Novelty: {novelty:.2%}")
        print(f"      Impact: {impact} traces")
        print(f"      Priority Score: {priority:.2f}")

    print("\n📊 Unknown Capability Summary:")
    print(f"   Total unknown: {len(unknown)}")
    print(f"   Submitted for review: {len(submitted)}")
    print(f"   Duplicates: {duplicates}")
    if not submitted:
        print("   ⚠️ No new capabilities submitted – all were duplicates or filtered.")
        return

    # Step 5: Show pending reviews
    print("\n📋 Pending reviews:")
    pending = learner.get_pending_reviews()
    for i, item in enumerate(pending, 1):
        print(f"   {i}. {item['capability_name']}")
        print(f"      Actions: {', '.join([f'{a['agent']}->{a['action']}' for a in item['required_actions']])}")
        suggestion = learner.suggest_label(item['required_actions'])
        novelty = learner.novelty_scorer.novelty_score(item['required_actions'])
        impact = learner.impact_scorer.compute_impact(item['required_actions'])
        priority = learner.priority_scorer.compute_priority({
            "required_actions": item['required_actions'],
            "severity": "critical"
        })
        print(f"      Suggested label: {suggestion['suggested_label']} (conf: {suggestion['confidence']:.2%})")
        print(f"      Novelty: {novelty:.2%}")
        print(f"      Impact: {impact} traces")
        print(f"      Priority Score: {priority:.2f}")

    # Step 6: Simulate human review – approve the most novel capability that is NOT already known
    if pending:
        print("\n✅ Simulating human review...")
        known_names = [p.name for p in KNOWN_PATTERNS]

        pending_with_score = []
        for item in pending:
            suggestion = learner.suggest_label(item['required_actions'])
            novelty = learner.novelty_scorer.novelty_score(item['required_actions'])
            is_known = suggestion['suggested_label'] in known_names
            priority = learner.priority_scorer.compute_priority({
                "required_actions": item['required_actions'],
                "severity": "critical"
            })
            pending_with_score.append({
                "item": item,
                "suggestion": suggestion,
                "novelty": novelty,
                "is_known": is_known,
                "priority": priority
            })

        best_item = None
        best_novelty = -1.0
        best_suggestion = None
        for entry in pending_with_score:
            if not entry['is_known'] and entry['novelty'] > best_novelty:
                best_novelty = entry['novelty']
                best_item = entry['item']
                best_suggestion = entry['suggestion']

        if best_item is None:
            non_known = [e for e in pending_with_score if not e['is_known']]
            if non_known:
                best_entry = max(non_known, key=lambda x: x['priority'])
            else:
                best_entry = max(pending_with_score, key=lambda x: x['priority'])
            best_item = best_entry['item']
            best_suggestion = best_entry['suggestion']

        item = best_item
        suggestion = best_suggestion
        novelty = learner.novelty_scorer.novelty_score(item['required_actions'])
        impact = learner.impact_scorer.compute_impact(item['required_actions'])
        priority = learner.priority_scorer.compute_priority({
            "required_actions": item['required_actions'],
            "severity": "critical"
        })

        if suggestion['confidence'] > 0.3:
            label = suggestion['suggested_label']
        else:
            actions = [a['action'] for a in item['required_actions']]
            if 'read_model' in actions and 'export_model' in actions:
                label = "Model Exfiltration"
            elif 'read_credentials' in actions and 'export_data' in actions:
                label = "Credential Exfiltration"
            elif 'grant_permission' in actions:
                label = "Privilege Escalation"
            else:
                label = "New Capability"

        reasoning = f"Human approved: {label} (novelty: {novelty:.2%}, impact: {impact}, priority: {priority:.2f})"
        success = learner.approve_and_add_to_ontology(
            capability_id=item['capability_id'],
            reviewer="human_analyst",
            reasoning=reasoning,
            capability_name=label,
            required_actions=item['required_actions']
        )
        if success['approved']:
            print(f"   ✅ Approved and added to ontology: {label} (novelty: {novelty:.2%})")

    # Step 7: Show ledger
    print("\n📜 Ontology Evolution Ledger:")
    ledger = learner.get_ledger()
    for entry in ledger:
        print(f"   Version {entry['version']}: {entry['action']} {entry['capability_name']}")
        print(f"      Reviewer: {entry['reviewer']}")
        print(f"      Reasoning: {entry['reasoning']}")
        print(f"      Actions: {', '.join([a['action'] for a in entry['required_actions']])}")

    # Step 8: Coverage metrics (after approval) – use combined ontology
    print("\n🔄 Re-running discovery with combined ontology for coverage update...")
    combined_ont = load_combined_ontology(TRAINING_ONTOLOGY, "evolved_ontology.json")
    print(f"   Combined ontology has {len(combined_ont.patterns)} patterns.")

    discovery2 = CapabilityDiscovery(min_samples=2, eps=0.5)
    discovery2.ontology_matcher = OntologyMatcher(ontology=combined_ont)
    discovered_after = discovery2.discover(traces)

    known_after = [cap for cap in discovered_after if cap['classification'] != 'unknown']
    unknown_after = [cap for cap in discovered_after if cap['classification'] == 'unknown']
    print(f"   Re-run: {len(discovered_after)} capabilities: {len(known_after)} known, {len(unknown_after)} unknown")

    for cap in discovered_after:
        if cap['capability_name'] == label:
            print(f"   ✅ '{label}' is now classified as: {cap['classification']}")

    coverage_after = learner.get_coverage(discovered_after)

    print("\n📊 Capability Coverage (After Approval):")
    print(f"   Known Capabilities:     {coverage_after['known_capabilities']}")
    print(f"   Discovered Capabilities: {coverage_after['discovered_capabilities']}")
    print(f"   Classified Capabilities: {coverage_after['classified_capabilities']}")
    print(f"   Unknown Capabilities:   {coverage_after['unknown_capabilities']}")
    classification_rate_after = coverage_after['classified_capabilities'] / coverage_after['discovered_capabilities'] if coverage_after['discovered_capabilities'] > 0 else 0.0
    print(f"   Classification Rate:    {round(classification_rate_after * 100, 1)}%")
    print(f"   Ontology Coverage:      {coverage_after['classified_coverage_percent']}%")
    print(f"   Unknown Coverage:       {coverage_after['unknown_coverage_percent']}%")

    # Step 9: Drift Replay
    print("\n🔄 Historical Replay Impact:")
    learner.review_queue.export_ontology("evolved_ontology.json")
    replay = CapabilityDriftReplay("evolved_ontology.json")
    subset = traces[:20]
    comparison = replay.compare_with_old(subset)
    if "note" in comparison:
        print(f"   ⚠️ {comparison['note']}")
    else:
        print(f"   Ontology Update: {', '.join([p.name for p in replay.ontology.patterns])}")
        print(f"   Historical traces scanned: {len(subset)}")
        print(f"   Total detected (evolved ontology): {comparison.get('total_detected', 0)}")
        print(f"   Newly detected (previously missed): {comparison.get('newly_detected', 0)}")
        print(f"   Coverage increase: {comparison['coverage_increase']:.1f}%")

        cf = comparison.get("counterfactual", {})
        print("\n   🔍 Counterfactual Governance Analytics:")
        print(f"   If this capability had existed earlier:")
        print(f"      Total traces that would have been flagged: {cf.get('total_detected', 0)}")
        print(f"      Newly flagged (would have been missed before): {cf.get('newly_detected', 0)}")
        decisions = cf.get('decisions', {})
        old_decisions = cf.get('old_decisions', {})
        print(f"      Decisions: DENY={decisions.get('DENY', 0)}, HUMAN_REVIEW={decisions.get('HUMAN_REVIEW', 0)}, MONITOR={decisions.get('MONITOR', 0)}, ADMIT={decisions.get('ADMIT', 0)}")
        print(f"      Previously: DENY={old_decisions.get('DENY', 0)}, HUMAN_REVIEW={old_decisions.get('HUMAN_REVIEW', 0)}")
        by_cap = cf.get('by_capability', {})
        if by_cap:
            print("      By capability:")
            for cap_name, count in by_cap.items():
                print(f"         {cap_name}: {count} traces")

    # Ontology Update Impact Table
    print("\n📊 Ontology Update Impact Table:")
    print("   Capability                 Traces Flagged")
    print("   " + "-" * 40)
    by_cap = cf.get('by_capability', {})
    for entry in learner.get_ledger():
        cap_name = entry['capability_name']
        traces_flagged = by_cap.get(cap_name, 0)
        gain = (traces_flagged / len(subset)) * 100 if subset else 0.0
        print(f"   {cap_name:25}   {traces_flagged:>3} traces ({gain:>5.1f}%)")

    # ===== GOVERNANCE COVERAGE CURVE & GKAI =====
    snapshot_after = tracker.record_snapshot("evolved_ontology.json", use_combined=True)
    print("\n📊 Coverage Snapshot (v1):")
    print(f"   Classification Rate: {snapshot_after['classification_rate_percent']}%")
    print(f"   Ontology Coverage:   {snapshot_after['ontology_coverage_percent']}%")
    print(f"   Classified: {snapshot_after['classified']} / {snapshot_after['total']} discovered")
    print(f"   Approved: {', '.join(snapshot_after['approved_capabilities'])}")

    # Display the full curve
    tracker.display_curve()

    # Display GKAI (Governance Knowledge Accumulation Index)
    tracker.display_gkai()

    # Step 10: Governance Drift Timeline
    print("\n📈 Governance Drift Timeline:")
    print(f"   Day 1: Capability Unknown")
    print(f"   {datetime.now().strftime('%Y-%m-%d')}: Analyst labels '{label if 'label' in locals() else 'Unknown'}'")
    print(f"   {datetime.now().strftime('%Y-%m-%d')}: Ontology Updated (Version {len(learner.get_ledger())})")
    print(f"   {datetime.now().strftime('%Y-%m-%d')}: Replay finds {comparison.get('newly_detected', 0)} previously missed incidents")
    print(f"   {datetime.now().strftime('%Y-%m-%d')}: Policy Updated (simulated)")
    print(f"   {datetime.now().strftime('%Y-%m-%d')}: Incidents Reduced {comparison.get('reduction_percent', 0):.1f}%")

    print("\n" + "=" * 70)
    print("✅ Governance Learning Loop complete!")
    print(f"   Review queue status: {len(learner.get_pending_reviews())} pending, {len(learner.get_ledger())} approved")
    print(f"   Evolved ontology exported to evolved_ontology.json")
    print(f"   Coverage history saved to coverage_history.json")

if __name__ == "__main__":
    main()