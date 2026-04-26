# Agent Mesh Notebooks

Interactive Jupyter notebooks for exploring agent-mesh concepts.

## Available Notebooks

| Notebook | Description |
|----------|-------------|
| [trust-scoring-exploration.ipynb](trust-scoring-exploration.ipynb) | Explore the 5-dimension trust scoring system, decay, violations, and threshold gates |

## Getting Started

1. Install dependencies:

   ```bash
   pip install -e ".[dev]"
   pip install jupyter matplotlib
   ```

2. Launch Jupyter:

   ```bash
   jupyter notebook notebooks/
   ```

3. Open `trust-scoring-exploration.ipynb` and run cells sequentially.

## What You'll Learn

- How the **RewardEngine** scores agents across 5 dimensions
- How **trust decay** reduces scores without positive activity
- How **policy violations** and security events impact trust
- How **trust threshold gates** allow or deny actions
- How to **visualize** trust score trends over time
