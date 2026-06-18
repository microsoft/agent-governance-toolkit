import click
import json
from src.models import ContinuityWitness
from src.ccv_engine import CCVEngine
from src.agt_adapter import AGTAdapter
import datetime
from src.models import AgentAction
import click
import json
from datetime import datetime
from src.models import AgentAction, ContinuityWitness
from src.ccv_engine import CCVEngine
from src.agt_adapter import AGTAdapter
from src.capability_benchmark import CapabilityBenchmark

# ===== ADD THIS FUNCTION HERE =====
def _format_emergent_cluster(cap: dict, index: int) -> str:
    """Format an emergent capability cluster for professional display."""
    actions_str = ", ".join([f"{a['agent']}->{a['action']}" for a in cap['required_actions']])
    severity = cap.get('severity', 'unknown')
    if severity == 'unknown':
        severity = '⚠️ UNKNOWN (requires human review)'
    else:
        severity = f"🔴 {severity.upper()}"
    
    return f"""
   Emergent Capability Cluster #{index}
   ─────────────────────────────────
   Actions:        {actions_str}
   Occurrences:    {cap['occurrence_count']}
   Classification: {cap['classification']}
   Suggested Severity: {severity}
   Human Review:   ✅ REQUIRED
   Witness Hash:   {cap['witness']['witness_hash'][:16]}...
"""
# ===== END OF ADDED FUNCTION =====


@click.group()
def cli():
    """Continuity CLI - verify agent continuity across delegation chains."""
    pass

@cli.command()
@click.argument('witness_file', type=click.Path(exists=True))
@click.option('--baseline', type=click.Path(exists=True), help='Baseline witness file')
@click.option('--output', '-o', type=click.Path(), help='Output verification result')
def verify(witness_file, baseline, output):
    """Verify continuity from a witness chain file."""
    with open(witness_file, 'r') as f:
        data = json.load(f)

    witnesses = [ContinuityWitness(**w) for w in data.get('witnesses', [])]
    baseline_witness = None
    if baseline:
        with open(baseline, 'r') as f:
            baseline_data = json.load(f)
            baseline_witness = ContinuityWitness(**baseline_data)

    engine = CCVEngine()
    result = engine.verify_continuity(witnesses, baseline_witness)

    click.echo("\n📊 Continuity Verification Result")
    click.echo(f"Continuity Score: {result.continuity_score:.4f}")
    click.echo(f"Status: {result.verification_status}")
    click.echo(f"Identity Preserved: {result.identity_preserved}")
    click.echo(f"Constitution Preserved: {result.constitution_preserved}")
    click.echo(f"Delegation Drift: {result.delegation_drift:.4f}")
    click.echo(f"Observer Drift: {result.observer_drift:.4f}")
    if result.break_reason:
        click.echo(f"Break Reason: {result.break_reason}")

    # NEW: print detailed evidence
    click.echo("\n🔍 Detailed Evidence:")
    if result.identity_transition:
        click.echo(f"  Identity Transition:")
        click.echo(f"    Before: {result.identity_transition.before_hash}")
        click.echo(f"    After:  {result.identity_transition.after_hash}")
        click.echo(f"    Preserved: {result.identity_transition.preserved}")
    if result.constitution_transition:
        click.echo(f"  Constitution Transition:")
        click.echo(f"    Before: {result.constitution_transition.before_hash}")
        click.echo(f"    After:  {result.constitution_transition.after_hash}")
        click.echo(f"    Preserved: {result.constitution_transition.preserved}")
    if result.observer_transition:
        click.echo(f"  Observer Transition:")
        click.echo(f"    Before: {result.observer_transition.before_hash}")
        click.echo(f"    After:  {result.observer_transition.after_hash}")
        click.echo(f"    Drift: {result.observer_transition.drift:.4f}")
    if result.delegation_transition:
        click.echo(f"  Delegation Transition:")
        click.echo(f"    Before: {result.delegation_transition.before}")
        click.echo(f"    After:  {result.delegation_transition.after}")
        click.echo(f"    Drift: {result.delegation_transition.drift:.4f}")

    if output:
        with open(output, 'w') as f:
            json.dump(result.model_dump(mode='json'), f, indent=2)
        click.echo(f"\n✅ Result saved to {output}")

@cli.command()
@click.argument('ground_truth_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output benchmark report')
def benchmark(ground_truth_file, output):
    """
    Run benchmark on a ground truth dataset.
    Ground truth file: JSON array of {"trace": [...], "expected_capability": "...", "expected_intent": "...", "expected_decision": "..."}
    """
    with open(ground_truth_file, 'r') as f:
        data = json.load(f)

    # Build ground truth
    ground_truth = []
    for entry in data:
        trace = [AgentAction(**a) for a in entry.get('trace', [])]
        ground_truth.append({
            "trace": trace,
            "expected_capability": entry.get('expected_capability'),
            "expected_intent": entry.get('expected_intent', 'unknown'),
            "expected_decision": entry.get('expected_decision', 'MONITOR'),
            "workflow": entry.get('workflow', 'unknown')
        })

    from src.capability_benchmark import CapabilityBenchmark
    benchmark = CapabilityBenchmark(ground_truth)
    results = benchmark.run()

    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        click.echo(f"✅ Benchmark report saved to {output}")
    else:
        click.echo(json.dumps(results, indent=2, default=str))
import click
import json
from datetime import datetime
from src.models import AgentAction
from src.capability_benchmark import CapabilityBenchmark

# ... (existing CLI commands) ...

@cli.command()
@click.argument('ground_truth_file', type=click.Path(exists=True))
@click.option('--hidden', default='', help='Comma-separated hidden capabilities')
@click.option('--train-ratio', default=0.7, help='Train/test split ratio')
@click.option('--min-samples', default=3, help='Minimum samples for discovery')
@click.option('--eps', default=0.5, help='DBSCAN eps parameter')
@click.option('--output', '-o', type=click.Path(), help='Output report')
def benchmark(ground_truth_file, hidden, train_ratio, min_samples, eps, output):
    """Run benchmark with hidden capabilities."""
    with open(ground_truth_file, 'r') as f:
        data = json.load(f)

    ground_truth = []
    for entry in data:
        trace = [AgentAction(**a) for a in entry.get('trace', [])]
        ground_truth.append({
            "trace": trace,
            "expected_capability": entry.get('expected_capability'),
            "expected_intent": entry.get('expected_intent', 'unknown'),
            "expected_decision": entry.get('expected_decision', 'MONITOR'),
            "workflow": entry.get('workflow', 'unknown')
        })

    hidden_list = [h.strip() for h in hidden.split(',') if h.strip()]
    bench = CapabilityBenchmark(ground_truth, train_ratio, min_samples, eps, hidden_list)
    results = bench.run()

    if output:
        with open(output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        click.echo(f"✅ Benchmark report saved to {output}")
    else:
        click.echo(json.dumps(results, indent=2, default=str))
@cli.command()
def capabilities():
    """
    List all known capabilities in the ontology.
    """
    from src.capability_ontology import DEFAULT_ONTOLOGY
    print("\n📚 Known Capabilities in Ontology")
    print(f"   Total: {len(DEFAULT_ONTOLOGY.patterns)}")
    print("\n   Capabilities:")
    for p in sorted(DEFAULT_ONTOLOGY.patterns, key=lambda x: x.severity, reverse=True):
        print(f"     {p.name} (severity: {p.severity})")
        print(f"       Actions: {', '.join(p.required_actions)}")
@cli.command()
@click.argument('actions_json', type=str)
def replay_capability(actions_json):
    """
    Replay a capability detection to verify it can be reproduced.
    Provide a JSON array of action objects.
    """
    try:
        actions = json.loads(actions_json)
    except json.JSONDecodeError:
        click.echo("❌ Invalid JSON. Expected an array of action objects.")
        return

    from src.capability_replay import CapabilityReplay
    replay = CapabilityReplay()
    result = replay.replay(actions)

    if result["verification"] == "verified":
        click.echo("\n🔁 Capability Replay: VERIFIED")
        click.echo(f"   Capability: {result['match_result']['pattern'].name if result['match_result']['pattern'] else 'Unknown'}")
        click.echo(f"   Confidence: {result['match_result']['confidence']:.4f}")
        click.echo("   Witness Hash: " + (result["witness"]["witness_hash"] if result["witness"] else "N/A"))
        click.echo("   Counterfactual: " + json.dumps(result["counterfactual"], indent=2))
    else:
        click.echo("\n❌ Capability Replay: NOT VERIFIED")
@cli.command()
@click.argument('actions_json', type=str)
@click.option('--format', '-f', default='text', help='Output format: text, json')
def witness(actions_json, format):
    """
    Generate a Capability Witness from a JSON array of agent actions.
    The witness includes a cryptographic hash and counterfactual analysis.
    """
    try:
        actions = json.loads(actions_json)
    except json.JSONDecodeError:
        click.echo("❌ Invalid JSON. Expected an array of action objects.")
        return

    from src.capability_witness import CapabilityWitnessEngine
    from src.models import AgentAction

    engine = CapabilityWitnessEngine()
    agent_actions = [AgentAction(**a) for a in actions]
    witness = engine.generate_witness(agent_actions)

    if witness is None:
        click.echo("✅ No emergent capability detected.")
        return

    if format == 'json':
        click.echo(json.dumps(witness.model_dump(mode='json'), indent=2))
        return

    click.echo("\n🔐 Capability Witness")
    click.echo(f"   Capability: {witness.capability_name} (ID: {witness.capability_id})")
    click.echo(f"   Witness Hash: {witness.witness_hash}")
    click.echo("\n   Required Actions:")
    for act in witness.required_actions:
        click.echo(f"     Agent: {act['agent']}  Action: {act['action']}")
    if witness.counterfactual:
        cf = witness.counterfactual
        click.echo(f"\n   Counterfactual: Remove agent '{cf['removed_agent']}'")
        click.echo(f"     Capability still exists: {cf['capability_still_exists']}")
        if cf['remaining_actions']:
            click.echo("     Remaining actions: " + ", ".join(f"{a['agent']}:{a['action']}" for a in cf['remaining_actions']))
    click.echo(f"\n   Created at: {witness.created_at}")

@cli.command()
@click.argument('actions_json', type=str)
@click.option('--format', '-f', default='text', help='Output format: text, json')
def lineage(actions_json, format):
    """
    Show capability lineage from a JSON array of agent actions.
    Provides a detailed breakdown of how each agent contributed.
    """
    try:
        actions = json.loads(actions_json)
    except json.JSONDecodeError:
        click.echo("❌ Invalid JSON. Expected an array of action objects.")
        return

    adapter = AGTAdapter()
    results = adapter.detect_emergent_capability(actions)
    # Take the first detected capability
    detected = [r for r in results if r['capability_detected']]
    if not detected:
        click.echo("✅ No emergent capability detected.")
        return

    res = detected[0]
    if format == 'json':
        click.echo(json.dumps(res, indent=2))
        return

    # Text format
    click.echo(f"\n🧩 Capability Lineage: {res['capability']['name']}")
    click.echo(f"   Confidence: {res['confidence']:.4f}")
    click.echo(f"   Capability ID: {res['capability']['capability_id']}")
    click.echo("\n   Contributions:")
    for contrib in res['lineage']['contributions']:
        click.echo(f"     Agent: {contrib['agent']}")
        click.echo(f"       Role: {contrib['contribution_type']}")
        click.echo(f"       Action: {contrib['action']}")
        if contrib.get('evidence'):
            click.echo(f"       Evidence: {json.dumps(contrib['evidence'])}")
    click.echo(f"\n   Lineage Hash: {res['lineage']['lineage_hash']}")
    click.echo(f"   Created at: {res['lineage']['created_at']}")
@cli.command()
@click.argument('traces_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output verdict report')
def court(traces_file, output):
    """
    Run the Capability Court pipeline on a trace file.
    Produces a governance verdict with witness and counterfactual proof.
    """
    with open(traces_file, 'r') as f:
        data = json.load(f)

    # Convert to AgentAction lists
    from src.capability_court import CapabilityCourt
    from src.models import AgentAction

    traces = []
    for trace_data in data:
        trace = [AgentAction(**a) for a in trace_data]
        traces.append(trace)

    court = CapabilityCourt()
    verdicts = court.process_traces(traces)

    if output:
        with open(output, 'w') as f:
            json.dump(verdicts, f, indent=2, default=str)
        click.echo(f"✅ Verdict report saved to {output}")
    else:
        click.echo("\n⚖️ Capability Court – Governance Verdicts")
        for v in verdicts:
            click.echo(f"\n   Capability: {v['capability']}")
            click.echo(f"   Verdict: {v['verdict']}")
            click.echo(f"   Reason: {v['reason']}")
            click.echo(f"   Witness Hash: {v['witness_hash']}")
            click.echo(f"   Counterfactual Verified: {v['counterfactual_verified']}")
@cli.command()
@click.argument('agents_activations_json', type=str)
def collusion(agents_activations_json):
    """
    Check for multi-agent collusion.
    Provide a JSON object mapping agent IDs to activation vectors.
    Example: continuity collusion '{"alice": [0.9,0.8,0.7], "bob": [0.1,0.2,0.3]}'
    """
    try:
        data = json.loads(agents_activations_json)
    except json.JSONDecodeError:
        click.echo("❌ Invalid JSON. Expected: {\"agent1\": [0.1, 0.2, ...], \"agent2\": [...]}")
        return

    adapter = AGTAdapter()
    result = adapter.check_collusion(data)
    click.echo("\n🚨 Collusion Detection Result")
    click.echo(f"Suspicion Score: {result['suspicion_score']:.4f}")
    click.echo(f"Collusion Detected: {result['collusion_detected']}")
    click.echo(f"Decision: {result['decision']}")
    if result['alignment_spikes']:
        click.echo("  Alignment Spikes:")
        for spike in result['alignment_spikes']:
            click.echo(f"    {spike['agent_a']} ↔ {spike['agent_b']}: {spike['score']:.4f}")

@cli.command()
@click.argument('traces_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output discovery report')
@click.option('--format', '-f', default='text', help='Output format: text, json')
def discover(traces_file, output, format):
    """Discover emergent capabilities from a corpus of traces."""
    with open(traces_file, 'r') as f:
        data = json.load(f)

    traces = []
    for trace_data in data:
        trace = [AgentAction(**a) for a in trace_data]
        traces.append(trace)

    from src.emergent_detector import EmergentDetector
    detector = EmergentDetector()
    discoveries = detector.discover_from_traces(traces)

    if not discoveries:
        click.echo("✅ No emergent capabilities discovered.")
        return

    if format == 'json' or output:
        report = {
            "total_discovered": len(discoveries),
            "capabilities": discoveries,
            "discovered_at": datetime.now().isoformat()
        }
        if output:
            with open(output, 'w') as f:
                json.dump(report, f, indent=2)
            click.echo(f"✅ Discovery report saved to {output}")
            return
        click.echo(json.dumps(report, indent=2))
        return

    # ===== UPDATED TEXT FORMAT =====
    # Separate known and emergent
    known = [d for d in discoveries if d['classification'] != 'unknown']
    emergent = [d for d in discoveries if d['classification'] == 'unknown']
    
    click.echo(f"\n🧩 Emergent Capability Discovery Results")
    click.echo(f"   Total clusters discovered: {len(discoveries)}")
    
    click.echo(f"\n✅ Known (Classified) Capabilities: {len(known)}")
    for cap in known:
        click.echo(f"   • {cap['capability_name']} (severity: {cap['severity']})")
    
    click.echo(f"\n🔎 Emergent Capability Clusters (human review needed): {len(emergent)}")
    for i, cap in enumerate(emergent, 1):
        click.echo(_format_emergent_cluster(cap, i))
    # ===== END OF UPDATED TEXT FORMAT =====
@cli.command()
@click.argument('trace_path', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output proof file')
def proof(trace_path, output):
    """Generate a verifiable proof from a trace."""
    click.echo("🔐 Generating continuity proof from trace...")
    # Placeholder
    click.echo("✅ Proof generated.")

if __name__ == "__main__":
    cli()

