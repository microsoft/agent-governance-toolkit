# DecisionAssure Continuity Kernel

**Prove the agent remained the same agent – and discover dangerous capabilities that emerge from multi‑agent interactions.**

DecisionAssure Continuity Kernel is a governance toolkit for AI agents that goes beyond traditional policy checks. It provides:

- **Continuity Verification** – prove an agent’s identity, policy, and context remained intact across actions.
- **Witness Chains** – blockchain‑style hash chains for tamper‑evident agent identity continuity.
- **Collusion Detection** – real‑time detection of hidden coordination between agents (activation‑level).
- **Deception Probe** – jailbreak detection via internal hidden‑state monitoring.
- **Capability Discovery** – unsupervised discovery of emergent capabilities from agent traces.
- **Capability Witness Engine** – cryptographic proof of why a capability existed, with counterfactual verification and governance recommendations.

---

## 🧩 What It Does

| Feature | Description |
|---------|-------------|
| **Continuity Verification** | Re‑test identity, policy, delegation, and evidence freshness at every step. |
| **Witness Chains** | Cryptographic hash chain that proves the agent did not drift without re‑authorisation. |
| **Collusion Interceptor** | Monitors hidden neural states to detect cross‑agent collusion in real time. |
| **Deception Probe** | Scans hidden states for jailbreak patterns before generation. |
| **Capability Discovery** | Finds recurring patterns in agent traces without any pre‑defined rules. |
| **Capability Witness Engine** | Produces verifiable witnesses: required actions, counterfactual proof, confidence, and a governance recommendation (DENY, HUMAN_REVIEW, MONITOR, ADMIT). |

---

## 🔌 Supported Frameworks

- **Microsoft AutoGen**
- **LangGraph**
- **CrewAI**
- **OpenAI Agents SDK**
- Custom (via `BaseAdapter`)

---

## 📦 Installation

```bash
# Clone or download the repository
cd decisionassure_continuity
pip install -e .
```

---

## 🚀 Quick Start – Continuity Verification

```python
from src.models import ContinuityWitness
from src.ccv_engine import CCVEngine

w1 = ContinuityWitness(
    index=0, previous_witness_hash="0"*64,
    agent_id="alice", session_id="s1",
    constitution_hash="hash1", observer_hash="hash1",
    reference_frame_hash="hash1", action_hash="action1"
)
w2 = ContinuityWitness(
    index=1, previous_witness_hash=w1.witness_hash,
    agent_id="alice", session_id="s1",
    constitution_hash="hash1", observer_hash="hash2",  # Drift!
    reference_frame_hash="hash1", action_hash="action2"
)

engine = CCVEngine()
result = engine.verify_continuity([w1, w2])
print(f"Continuity Score: {result.continuity_score}")
print(f"Status: {result.verification_status}")
```

---

## 🧠 Quick Start – Capability Witness Engine

```python
from src.capability_witness_engine import CapabilityWitnessEngine
from src.models import AgentAction

# Load traces from any supported framework (AutoGen, LangGraph, etc.)
# Each trace is a list of AgentAction objects.
traces = [[
    AgentAction(agent_id="alice", action_type="read_credentials"),
    AgentAction(agent_id="charlie", action_type="export_data")
]]

engine = CapabilityWitnessEngine(min_samples=2, eps=0.5)
witnesses = engine.process_traces(traces)

for w in witnesses:
    print(f"Capability: {w['capability']}")
    print(f"Confidence: {w['confidence']:.2%}")
    print(f"Recommendation: {w['governance_recommendation']}")
    print(f"Witness Hash: {w['witness_hash'][:16]}...")
```

---

## 🖥️ CLI Usage

```bash
# Continuity verification
continuity verify witnesses.json --output result.json

# Collusion detection
continuity collusion '{"alice":[0.9,0.8,0.7],"bob":[0.1,0.2,0.3]}'

# Capability discovery (from traces)
continuity discover traces.json

# Capability Court (end‑to‑end verdict)
continuity court traces.json --output verdicts.json

# Generate a witness from a single action list
continuity witness '{"agent":"alice","action":"read_database"}'
```

---

## 📁 Processing Real Traces

The toolkit includes adapters for popular agent frameworks. To process a directory of AutoGen traces:

```bash
python examples/real_trace_demo.py ./sample_traces/ autogen
```

Output will include:

- Discovered emergent capability clusters
- Cryptographic witness hashes
- Counterfactual verification results
- Governance recommendations (DENY / HUMAN_REVIEW / MONITOR / ADMIT)

---

## 📊 Capability Witness Output Example

```json
{
  "capability": "Credential Exfiltration",
  "confidence": 0.94,
  "required_actions": [
    {"agent": "alice", "action": "read_credentials"},
    {"agent": "charlie", "action": "export_data"}
  ],
  "minimal_witness": true,
  "counterfactual_verified": true,
  "governance_recommendation": "DENY",
  "witness_hash": "bb57369c232d1ad7...",
  "trace_claim": {
    "format": "TRACE v0.1",
    "claim_type": "capability_witness",
    "hash": "bb57369c...",
    "evidence": [...]
  }
}
```

---

## 🔐 Integration with AgentTrust / TRACE

The `trace_claim` field is **TRACE‑compatible**, meaning capability witnesses can be consumed by AgentTrust, TRACE, and other governance systems as portable evidence.

---

## 📚 Documentation

- `docs/CONTINUITY_SPEC.md` – Specification for continuity verification
- `docs/EMERGENT_SPEC.md` – Specification for emergent capability discovery
- `docs/WITNESS_STANDARD.md` – Capability Witness Standard (v1.0)
- `docs/METHODOLOGY.md` – Benchmark methodology and metrics

---
## 🚀 Batch Processing Hundreds of Traces

To process a large number of traces from a directory tree:

```bash
python examples/batch_witness_demo.py ./my_traces/ autogen


This will:

Recursively find all JSON trace files
Parse them with the appropriate adapter
Run the Capability Witness Engine
Generate a summary report with:

Total traces processed
Total witnesses generated
Recommendations breakdown (DENY, HUMAN_REVIEW, MONITOR, ADMIT)
Human reviews triggered
Low Confidence Witness
Average confidence
Save a JSON report for further analysis




---

## 🧪 How to Run the Full Batch

1. **Generate synthetic traces** (or use your own real traces):
   ```bash
   python examples/generate_sample_traces.py

2. Run the batch processor:
python examples/batch_witness_demo.py sample_traces_large/ autogen 2 0.5

3. Expected output:
📂 Scanning sample_traces_large/ for autogen traces...
📁 Found 150 trace files
✅ Parsed 150 traces successfully (errors: 0)
   Agents: alice, bob, charlie, dave, eve, frank, grace, heidi, ivan, jack, karen
🧾 Generated 4 Capability Witness(es)
==============================================================================
🧾 Capability Witness Engine – Batch Report
==============================================================================
   Timestamp:                2026-06-18T18:00:00
   Total traces processed:   150
   Total witnesses generated: 4
   Parse errors:             0
   Agents involved:          alice, bob, charlie, ...
   Frameworks:               autogen: 150

   Recommendations:
      HUMAN_REVIEW: 3
      MONITOR: 1

   Severities:
      critical: 3
      high: 1

   Human reviews triggered:  3
   Low Confidence Witness:      0
   Average confidence:        94.5%

   Witness Details:
      #1: Credential Exfiltration (conf: 96.67%, rec: HUMAN_REVIEW)
           Actions: alice->read_credentials, charlie->export_data
           Hash: bb57369c232d1ad7...
      ...
==============================================================================
✅ Full report saved to witness_report_20260618_180000.json

## 🧠 Governance Learning Loop

Unknown capability witnesses can be labelled and added to the ontology:

```bash


The system will suggest labels for unknown witnesses. Analysts can then:

Review the witness and action set.
Add a label using the learner.
Export the updated ontology.
This creates a self-improving governance system.


---

## 🧪 How to Run with Learning

```bash
# Generate synthetic traces (or use real ones)
python examples/generate_sample_traces.py

# Run batch with learning enabled
python examples/batch_witness_demo.py sample_traces_large/ --framework autogen --learn

## 📄 License

MIT