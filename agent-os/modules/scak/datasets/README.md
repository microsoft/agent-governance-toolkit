# Datasets for Empirical Validation

This directory contains benchmark datasets used in the Self-Correcting Agent Kernel research.

## Structure

```
datasets/
├── red_team/               # Red-team security benchmark (60+ prompts)
│   ├── jailbreak_patterns.json
│   ├── harmful_content.json
│   ├── pii_leakage.json
│   └── README.md
├── gaia_vague_queries/     # GAIA laziness benchmark (50+ queries)
│   ├── vague_queries.json
│   ├── ground_truth.json
│   └── README.md
├── chaos_scenarios/        # Chaos engineering scenarios (20+ scenarios)
│   ├── schema_failures.json
│   ├── api_failures.json
│   └── README.md
└── README.md (this file)
```

## Dataset Availability

### 1. Red-Team Security Benchmark

**Description:** 60+ adversarial prompts testing jailbreak resistance, harmful content generation, and PII leakage.

**Access:** Public (included in this repository)

**Citation:** If you use this dataset, please cite:
```bibtex
@dataset{scak_red_team_2026,
  title={SCAK Red-Team Security Benchmark},
  author={Self-Correcting Agent Team},
  year={2026},
  url={https://github.com/microsoft/agent-governance-toolkit/datasets/red_team}
}
```

**Statistics:**
- Total prompts: 62
- Categories: Jailbreak (25), Harmful Content (22), PII Leakage (15)
- Difficulty: Easy (20), Medium (25), Hard (17)

### 2. GAIA Vague Queries Benchmark

**Description:** 50 vague queries where data exists but requires deeper search (stress-tests agent laziness).

**Access:** Public (included in this repository)

**Citation:** Based on GAIA Benchmark (Mialon et al., 2023) with custom vague-query extension:
```bibtex
@inproceedings{mialon2023gaia,
  title={GAIA: A Benchmark for General AI Assistants},
  author={Mialon, Gr{\'e}goire and Dess{\`\i}, Roberto and Lomeli, Maria and others},
  booktitle={arXiv preprint arXiv:2311.12983},
  year={2023}
}
```

**Statistics:**
- Total queries: 50
- Give-up rate (baseline GPT-4o): 60%
- Give-up rate (SCAK-corrected): 8%
- Domains: Logs (20), Fraud (15), General (15)

### 3. Chaos Engineering Scenarios

**Description:** 20 infrastructure failure scenarios testing self-healing capabilities.

**Access:** Public (included in this repository)

**Citation:**
```bibtex
@dataset{scak_chaos_2026,
  title={SCAK Chaos Engineering Benchmark},
  author={Self-Correcting Agent Team},
  year={2026},
  url={https://github.com/microsoft/agent-governance-toolkit/datasets/chaos_scenarios}
}
```

**Statistics:**
- Total scenarios: 20
- Categories: Schema Failures (10), API Failures (7), Network Failures (3)
- MTTR (baseline): ∞ (never recovers)
- MTTR (SCAK): <30s average

## Reproducibility

All experiments can be reproduced using the scripts in `/experiments/`:

```bash
# GAIA Benchmark
python experiments/gaia_benchmark/run_benchmark.py

# Chaos Engineering
python experiments/chaos_engineering/run_chaos.py

# Red-Team Security (requires governance layer)
python experiments/red_team_benchmark.py
```

See `/reproducibility/README.md` for detailed instructions.

## Hugging Face Datasets

For easy access and citation, we plan to upload these datasets to Hugging Face:

- 🔄 `scak/red-team-benchmark` (planned)
- 🔄 `scak/gaia-vague-queries` (planned)
- 🔄 `scak/chaos-scenarios` (planned)

Status: Preparing for upload (2026-01-18)

## Data Privacy

All datasets contain **synthetic data only**. No real user data, PII, or proprietary information is included.

## License

MIT License - see [LICENSE](../LICENSE) for details.

## Contributing

To contribute new benchmark queries:

1. Fork the repository
2. Add queries to the appropriate JSON file
3. Update statistics in this README
4. Submit a pull request

## Contact

For questions about the datasets, please open an issue on GitHub.

---

**Last Updated:** 2026-01-18  
**Version:** 1.0
