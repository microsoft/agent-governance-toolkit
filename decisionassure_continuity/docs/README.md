## DecisionAssure Continuity

Discover what AI systems can do before they do it.
A governance platform for autonomous and multi-agent systems that discovers emergent capabilities, generates replayable evidence, verifies capabilities through counterfactual analysis, and continuously improves governance knowledge through human review and ontology evolution.

Why DecisionAssure Exists
Modern AI systems increasingly operate as teams of autonomous agents.
Traditional monitoring systems focus on events.
Traditional governance systems focus on rules.
DecisionAssure focuses on capabilities.
A capability is not a single action.

It is a coordinated sequence of actions that collectively enable an outcome.
Examples include:
Credential Exfiltration
Privilege Escalation
Model Exfiltration
Secret Leakage
Identity Theft
Backdoor Installation
Collusive Coordination
Emergent Unknown Behaviors

DecisionAssure discovers these capabilities directly from execution traces, produces cryptographic evidence proving they existed, and continuously improves governance coverage as new capabilities emerge.
Core Platform Capabilities
Continuity Verification
Prove that an agent remained the same agent throughout execution.

DecisionAssure continuously validates:
Agent Identity
Constitution Integrity
Observer Context
Reference Frame
Delegation Integrity
Evidence Freshness
Witness Chains
Blockchain-inspired witness chains provide tamper-evident continuity evidence.
Each action is linked through cryptographic hashes, enabling replayable verification of agent continuity.

Collusion Interceptor
Detect hidden coordination between AI agents before harmful behavior becomes visible.
Features:
Activation-level monitoring
Cross-agent coordination analysis
Hidden-state correlation detection
Real-time collusion alerts
Deception Probe
Detect deceptive reasoning and jailbreak attempts before output generation.

Features:
Hidden-state analysis
Internal inconsistency detection
Jailbreak pattern recognition
Deception risk scoring
Emergent Capability Discovery
Discover dangerous capabilities directly from traces without predefined rules.

Examples:
alice -> read_credentials
charlie -> export_data

→ Credential Exfiltration
The engine automatically identifies:
Emergent behaviors
Multi-agent capabilities
Previously unseen operational patterns
Capability Witness Engine
Generate replayable governance evidence.

Each witness contains:
Capability Classification
Required Actions
Confidence Score
Severity
Witness Hash
Governance Recommendation
Counterfactual Evidence

Example:
{
  "capability": "Credential Exfiltration",
  "minimal_witness": true,
  "counterfactual_verified": true,
  "severity": "critical",
  "governance_recommendation": "HUMAN_REVIEW"
}
Counterfactual Verification
DecisionAssure verifies causality rather than correlation.
The system removes required actions one at a time and replays the capability.
If removing any action causes the capability to disappear, the witness is considered minimal and causally verified.
Capability Exists
        ↓
Remove Action
        ↓
Capability Disappears
This significantly reduces false discoveries.
TRACE-Compatible Capability Claims
Capability Witnesses can be exported as portable governance evidence.
TRACE Claim
        ↓
Capability Witness
        ↓
Evidence Actions
        ↓
Witness Hash
        ↓
Governance Recommendation
Compatible with:
TRACE
AgentTrust
Governance Dashboards
Audit Pipelines
Compliance Systems
Governance Learning Loop
Unknown capabilities are never discarded.

They enter a governance review workflow.
Capability Discovery
        ↓
Capability Witness
        ↓
Counterfactual Verification
        ↓
Human Review
        ↓
Ontology Evolution
        ↓
Historical Replay
        ↓
Coverage Analysis
        ↓
Governance Knowledge Accumulation Index (GKAI)
This transforms governance from a static rule system into a continuously improving knowledge system.
Human Review Queue
Every unknown capability includes:
Suggested Label
Similarity Confidence
Novelty Score
Impact Score
Priority Score

Example:
Unknown Capability

Suggested Label:
Model Exfiltration

Confidence:
66.67%

Novelty:
33.33%

Impact:
28 Traces
Ontology Evolution
Approved reviews become governance knowledge.
Unknown Capability
        ↓
Human Approval
        ↓
Model Exfiltration
        ↓
Known Capability
Every update is versioned, auditable, and replayable.
Historical Replay

After governance knowledge evolves, DecisionAssure asks:
What incidents would have been detected if this capability had been known earlier?

The platform replays historical traces using the evolved ontology and measures:
Previously Missed Incidents
Newly Detected Incidents
Coverage Growth
Governance Impact
Governance Coverage Metrics
Classification Rate
Measures how many discovered capabilities are understood.
Classified Capabilities
/
Discovered Capabilities
Example:
75%
→
100%
Ontology Coverage
Measures governance knowledge relative to the capability universe.
Known Capability Patterns
/
Capability Universe
Example:
23.1%
→
28.6%
Governance Knowledge Accumulation Index (GKAI)
Most governance systems measure compliance.
DecisionAssure measures learning.

GKAI tracks:
Ontology Growth
Governance Coverage Growth
Knowledge Accumulation
Learning Efficiency
Governance Maturity
Example:
Base Coverage:
23.1%

Latest Coverage:
28.6%

Knowledge Gain:
+5.5%
GKAI provides a quantitative measure of governance evolution over time.
Governance Outcome Example
Before Learning
Classification Rate: 75%
Unknown Capabilities: 1
After Learning
Classification Rate: 100%
Unknown Capabilities: 0
Governance Improvement
+25% Classification Rate
+5.5% Ontology Coverage
+3 Previously Missed Incidents Detected
Supported Frameworks
Microsoft AutoGen
LangGraph
CrewAI
OpenAI Agents SDK
AgentTrust
Custom Adapters
Vision
Security asks:
What happened?
Governance asks:
Was it allowed?
DecisionAssure asks:
What capability emerged, how do we prove it existed, and how does governance improve after learning about it?
Discover → Verify → Govern.

📦 1. Install Dependencies

bash
cd /Users/akhileshwarik/agent-governance-toolkit/decisionassure_continuity
pip install -r requirements.txt
Or install the package in editable mode:

bash
pip install -e .
🔍 2. Run the End‑to‑End Demo

bash
python examples/review_queue_demo.py
This runs the full governance learning loop:

Capability discovery
Review queue submission
Human approval simulation
Ontology evolution
Historical replay
Coverage curve & GKAI output
Clean start (reset data):

bash
rm -rf data/ evolved_ontology.json coverage_history.json
python examples/review_queue_demo.py
📊 3. Run the Batch Witness Engine

Process a directory of traces (e.g., sample_traces_large/):

bash
python examples/batch_witness_demo.py sample_traces_large/ --framework autogen --learn
Options:

Argument	Description
--framework	autogen, langgraph, crewai, openai, agenttrust
--min_samples	Minimum traces per cluster (default 3)
--eps	DBSCAN clustering parameter (default 0.5)
--confidence_threshold	Accept only witnesses above this (default 0.5)
--learn	Enable the governance learning loop (suggest labels)
Example with custom values:

bash
python examples/batch_witness_demo.py ./my_traces/ --framework autogen --min_samples 5 --eps 0.3 --confidence_threshold 0.6 --learn
🧪 4. Run the Real‑Trace Demo (Single Directory)

bash
python examples/real_trace_demo.py sample_traces_large/ autogen 2 0.5
Arguments: directory framework min_samples eps

🖥️ 5. CLI Commands

The continuity CLI is available after installation:

bash
continuity --help
Verify Continuity

bash
continuity verify witnesses.json --output result.json
Generate Capability Witness

bash
continuity witness '{"agent":"alice","action":"read_database"}'
Show Capability Lineage

bash
continuity lineage '[{"agent":"alice","action":"read_database"},{"agent":"bob","action":"export_data"}]'
Detect Collusion

bash
continuity collusion '{"alice":[0.9,0.8,0.7],"bob":[0.1,0.2,0.3]}'
Discover Capabilities from Traces

bash
continuity discover traces.json
Run Capability Court (End‑to‑End Verdict)

bash
continuity court traces.json --output verdicts.json
List Known Capabilities

bash
continuity capabilities
🧪 6. Run Unit Tests

bash
pytest tests/
Run a specific test file:

bash
pytest tests/test_ccv_engine.py -v
📁 7. Generate Sample Traces (for Testing)

bash
python examples/generate_sample_traces.py
This creates 150 synthetic traces in sample_traces_large/.

🧠 8. Key Modules Overview

Module	Purpose
src/capability_discovery.py	Unsupervised discovery of capability clusters from traces
src/capability_witness.py	Cryptographic witness generation
src/capability_witness_language.py	Formal witness language format
src/capability_replay.py	Replay verification engine
src/capability_learner.py	Review queue, label suggestion, novelty/impact/priority scoring
src/capability_review_queue.py	Persistence for review queue & ontology ledger
src/capability_drift_replay.py	Historical replay and counterfactual analytics
src/governance_coverage_curve.py	Coverage tracking & GKAI
src/capability_ontology.py	Known & hidden patterns, combined ontology loading
src/adapters/	Parsers for AutoGen, LangGraph, CrewAI, OpenAI Agents, AgentTrust
src/continuity_cli.py	Command-line interface
🚀 9. Tips for Development

Reset all state before a clean run: rm -rf data/ evolved_ontology.json coverage_history.json
Check coverage history after runs: cat coverage_history.json
View evolved ontology: cat evolved_ontology.json
Check review queue: cat data/review_queue.json
Check ontology ledger: cat data/ontology_ledger.json
✅ 10. Quick Test Sequence

bash
rm -rf data/ evolved_ontology.json coverage_history.json
python examples/generate_sample_traces.py
python examples/review_queue_demo.py
python examples/batch_witness_demo.py sample_traces_large/ --framework autogen --learn
continuity capabilities
You should see discovery, review, approval, replay, and the coverage curve.

