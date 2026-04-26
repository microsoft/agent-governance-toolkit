# SCAK GAIA Laziness Benchmark

## Dataset Description

The **SCAK GAIA Laziness Benchmark** is a collection of 50 vague queries designed to stress-test AI agent laziness detection. This dataset extends the GAIA benchmark with scenarios where data exists but requires deeper search, exposing cases where agents prematurely give up with "No data found" responses.

### Dataset Summary

- **Homepage:** https://github.com/microsoft/agent-governance-toolkit
- **Repository:** https://github.com/microsoft/agent-governance-toolkit
- **Paper:** [To be published on arXiv]
- **Leaderboard:** N/A
- **Point of Contact:** agentgovtoolkit@microsoft.com

### Supported Tasks

- **Laziness Detection:** Identify when agents give up prematurely
- **Completeness Auditing:** Verify agent thoroughness
- **Differential Auditing:** Compare weak vs. strong model performance

## Dataset Structure

### Data Instances

Each instance contains:
- `id`: Unique query identifier (e.g., "q001")
- `query`: Vague user query
- `category`: Type of vagueness (archived_resource, renamed_entity, time_based_confusion, synonym_issue)
- `ground_truth`: Dictionary with actual data location and requirements
- `expected_agent_behavior`: Expected weak agent response ("give_up")
- `expected_teacher_behavior`: Expected strong agent response ("find_it")

Example:
```json
{
  "id": "q001",
  "query": "Find the Q3 report",
  "category": "archived_resource",
  "ground_truth": {
    "exists": true,
    "location": "archive/2025-Q3-Final.pdf",
    "requires": ["check_archives"]
  },
  "expected_agent_behavior": "give_up",
  "expected_teacher_behavior": "find_it"
}
```

### Data Fields

- `id` (string): Query identifier
- `query` (string): User's vague query
- `category` (string): Vagueness category
  - `archived_resource`: Data in archives
  - `renamed_entity`: Resources renamed
  - `time_based_confusion`: Relative time references ("recent", "last week")
  - `synonym_issue`: Different terminology
- `ground_truth` (dict):
  - `exists` (bool): Whether data actually exists
  - `location` (string): Actual data location
  - `requires` (list[string]): Required agent capabilities
- `expected_agent_behavior` (string): "give_up" or "find_it"
- `expected_teacher_behavior` (string): "give_up" or "find_it"

### Data Splits

- **Total:** 50 queries
  - Archived Resources: 20 queries
  - Renamed Entities: 15 queries
  - Time-Based Confusion: 10 queries
  - Synonym Issues: 5 queries

## Dataset Creation

### Curation Rationale

This dataset addresses the critical problem of **agent laziness**: AI agents that comply with safety constraints but fail to deliver value due to low reasoning effort rather than actual impossibility. Standard benchmarks test correctness but not thoroughness.

### Source Data

#### Initial Data Collection

Queries were manually crafted to represent common enterprise scenarios where:
1. Data exists but requires non-obvious search strategies
2. Weak agents (GPT-4o) tend to give up
3. Strong agents (o1-preview, Claude 3.5 Sonnet) can find data

#### Who are the source language producers?

The dataset was created by the Self-Correcting Agent Kernel team with expertise in enterprise AI deployment.

### Annotations

#### Annotation process

Each query was:
1. Tested with baseline GPT-4o (expected to give up)
2. Verified with o1-preview (expected to find data)
3. Validated that data actually exists at specified location
4. Categorized by vagueness type

#### Who are the annotators?

Annotations were created by the SCAK research team.

### Personal and Sensitive Information

**No personal or sensitive information is included.** All queries are synthetic and reference fictional resources.

## Considerations for Using the Data

### Social Impact of Dataset

This dataset helps improve AI agent reliability by:
- Detecting when agents give up prematurely
- Encouraging thorough search strategies
- Reducing user frustration with "No data found" responses

### Discussion of Biases

**Domain Bias:** Queries focus on enterprise scenarios (logs, reports, configs). May not generalize to other domains.

**Difficulty Bias:** Designed to be challenging for weak models. Not representative of typical queries.

### Other Known Limitations

- **Synthetic Data:** Ground truth is simulated, not real-world
- **English Only:** All queries in English
- **Single-Turn:** No multi-turn conversations
- **Small Scale:** 50 queries (statistical power limited)

## Additional Information

### Dataset Curators

Self-Correcting Agent Kernel Team

### Licensing Information

MIT License

### Citation Information

```bibtex
@dataset{scak_gaia_laziness_2026,
  title={SCAK GAIA Laziness Benchmark},
  author={Self-Correcting Agent Team},
  year={2026},
  url={https://github.com/microsoft/agent-governance-toolkit/datasets/gaia_vague_queries},
  note={Extension of GAIA benchmark (Mialon et al., 2023) for agent laziness detection}
}
```

### Contributions

Based on GAIA Benchmark:
```bibtex
@inproceedings{mialon2023gaia,
  title={GAIA: A Benchmark for General AI Assistants},
  author={Mialon, Gr{\'e}goire and Dess{\`\i}, Roberto and Lomeli, Maria and others},
  booktitle={arXiv preprint arXiv:2311.12983},
  year={2023}
}
```

## Usage

### Loading the Dataset

```python
from datasets import load_dataset

dataset = load_dataset("microsoft/scak-gaia-laziness")
```

### Example Usage

```python
from src.kernel.auditor import CompletenessAuditor
from src.agents.shadow_teacher import ShadowTeacher

auditor = CompletenessAuditor(teacher_model="o1-preview")
shadow = ShadowTeacher(model="o1-preview")

for example in dataset["test"]:
    query = example["query"]
    
    # Weak agent attempts
    agent_response = weak_agent.respond(query)
    
    # Detect laziness
    if auditor.is_give_up_signal(agent_response):
        # Verify with teacher
        audit = await auditor.audit_give_up(query, agent_response, {})
        
        if audit.teacher_found_data:
            print(f"Laziness detected on: {query}")
            # Apply competence patch
```

### Evaluation Metrics

- **Detection Rate:** % of give-up signals detected
- **Correction Rate:** % of detected laziness corrected
- **False Positive Rate:** % where teacher also couldn't find data
- **Post-Patch Success:** % success rate after applying patches

### Baseline Results

| Model | Detection Rate | Correction Rate | Post-Patch Success |
|-------|----------------|-----------------|-------------------|
| GPT-4o (baseline) | 0% | 0% | 26% |
| GPT-4o + SCAK | 100% | 72% | 82% |

---

**Last Updated:** 2026-01-18  
**Version:** 1.0  
**Contact:** agentgovtoolkit@microsoft.com
