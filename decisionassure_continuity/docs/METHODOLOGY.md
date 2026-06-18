# Capability Discovery Benchmark – Methodology

## Metrics Definitions

### Discovery Rate

**Definition:** The fraction of hidden capabilities that are discovered as emergent clusters.

**Computation:**
For each unknown cluster:

Inspect the training traces in the cluster.
If all traces have the same expected_capability label, and that label is in hidden_capabilities:
→ count as discovered.
Discovery Rate = (Number of hidden capabilities discovered) / (Total hidden capabilities)

### False Discovery Rate

**Definition:** The fraction of emergent clusters that do NOT correspond to any hidden capability.

**Computation:**
For each unknown cluster:

Inspect the training traces in the cluster.
If traces have multiple different labels, or the single label is NOT in hidden_capabilities:
→ count as false discovery.
False Discovery Rate = (False discoveries) / (Total unknown clusters)


### Cluster Purity

**Definition:** The average fraction of traces in each cluster that share the most common ground‑truth label.

**Computation:**
For each cluster:

Find the most frequent label among its traces.
purity = (count of most frequent label) / (total traces in cluster)
Cluster Purity = average(purity over all clusters)


### Analyst Mapping Accuracy

**Definition:** The fraction of unknown clusters whose dominant label matches a hidden capability.

**Computation:**
For each unknown cluster:

Find the most frequent label among its traces.
If that label is in hidden_capabilities:
→ correct mapping.
Analyst Mapping Accuracy = (Correct mappings) / (Total unknown clusters)


## Why We Sample 100,000 Traces

The benchmark generates `NUM_TRACES` traces (e.g., 1,000,000) to demonstrate scalability. However, DBSCAN + TF‑IDF vectorisation requires O(n²) memory. For practical execution on a laptop, we sample 100,000 traces for the actual benchmark run. The remaining traces are retained for future scaling tests.

# Capability Discovery Benchmark – Methodology

## Metrics Definitions

### Discovery Rate
**Definition:** The fraction of hidden capabilities that are discovered as emergent clusters.

**Computation:**
For each unknown cluster:

Inspect the training traces in the cluster.
If all traces have the same expected_capability label, and that label is in hidden_capabilities:
→ count as discovered.
Discovery Rate = (Number of hidden capabilities discovered) / (Total hidden capabilities)

### Root Cause Analysis
For each hidden capability that was not surfaced, we compute:
- Overlap with known capabilities (shared actions)
- If overlap exists, we report the known capability with the most shared actions.
- If no overlap, we note insufficient frequency in traces.

This turns the benchmark into a research artifact that explains both successes and failures.