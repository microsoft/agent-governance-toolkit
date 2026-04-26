# CMVK Concept Demo: Carbon Credit Verification

> Demonstration of how CMVK verification could detect inconsistencies in carbon credit claims.

## Concept

CMVK verifies claims by requiring consensus across multiple LLM models. If models disagree significantly, the claim is flagged for review.

## How It Works

```
Input: Carbon credit claim (PDF + satellite coordinates)

┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│   Model A   │   │   Model B   │   │   Model C   │
│ (PDF Parse) │   │ (Validate)  │   │ (Cross-ref) │
└──────┬──────┘   └──────┬──────┘   └──────┬──────┘
       │                 │                 │
       ▼                 ▼                 ▼
┌─────────────────────────────────────────────────┐
│            Consensus Engine                      │
│                                                  │
│  If models agree → PASS                         │
│  If models disagree → FLAG FOR REVIEW           │
└─────────────────────────────────────────────────┘
```

## Example Code

```python
from cmvk import CrossModelVerifier

verifier = CrossModelVerifier(
    models=["gpt-4", "claude-sonnet-4", "gemini-pro"],
    consensus_threshold=0.85
)

# Compare claimed values against observed values
result = verifier.verify(
    claim_vector=[0.82, 0.95],      # Claimed NDVI, forest cover
    observation_vector=[0.45, 0.52] # Observed values
)

print(f"Drift Score: {result.drift_score}")
print(f"Consensus: {result.consensus}")
```

## Technical Approach

The verification uses mathematical comparison (e.g., Euclidean distance) rather than asking an LLM to make a judgment. This makes the decision deterministic and auditable.

```python
def verify(claim_vector, observation_vector, threshold=0.15):
    # Normalize vectors
    claim_norm = normalize(claim_vector)
    obs_norm = normalize(observation_vector)
    
    # Calculate drift (mathematical, not LLM inference)
    drift = np.linalg.norm(claim_norm - obs_norm)
    
    if drift > threshold:
        return "FLAGGED"
    return "PASSED"
```

## Limitations

- This is a demonstration, not a production system
- Real carbon credit verification requires domain expertise
- The multi-model approach increases API costs
- Consensus doesn't guarantee correctness

## Running the Demo

```bash
cd examples/carbon-auditor
python demo.py --scenario fraud
```

---

See [CMVK Package](../../packages/cmvk/) for implementation details.
