# Agent OS Notebooks

> **Interactive tutorials for learning Agent OS step-by-step.**

## 🚀 Getting Started

```bash
pip install agent-os-kernel[full] jupyter
jupyter notebook
```

## 📚 Notebook Index

| # | Notebook | Description | Time | Prerequisites |
|---|----------|-------------|------|---------------|
| 01 | [Hello Agent OS](01-hello-agent-os.ipynb) | Your first governed agent | 5 min | None |
| 02 | [Episodic Memory](02-episodic-memory-demo.ipynb) | Persistent agent memory | 15 min | 01 |
| 03 | [Time-Travel Debugging](03-time-travel-debugging.ipynb) | Replay and debug decisions | 20 min | 01 |
| 04 | [Verification](04-verification.ipynb) | Detect hallucinations with CMVK | 15 min | 01 |
| 05 | [Multi-Agent Coordination](05-multi-agent-coordination.ipynb) | Trust between agents (IATP) | 20 min | 01 |
| 06 | [Policy Engine](06-policy-engine.ipynb) | Deep dive into policies | 15 min | 01 |

## 🎯 Learning Paths

### Path 1: Quick Start (30 min)
For developers who want to get up and running fast:
1. [01 - Hello Agent OS](01-hello-agent-os.ipynb)
2. [06 - Policy Engine](06-policy-engine.ipynb)

### Path 2: Agent Memory & Debugging (50 min)
For developers building agents that learn:
1. [01 - Hello Agent OS](01-hello-agent-os.ipynb)
2. [02 - Episodic Memory](02-episodic-memory-demo.ipynb)
3. [03 - Time-Travel Debugging](03-time-travel-debugging.ipynb)

### Path 3: Multi-Agent Systems (55 min)
For developers building complex agent systems:
1. [01 - Hello Agent OS](01-hello-agent-os.ipynb)
2. [04 - Verification](04-verification.ipynb)
3. [05 - Multi-Agent Coordination](05-multi-agent-coordination.ipynb)

### Path 4: Complete Course (1.5 hours)
All notebooks in order for comprehensive understanding.

## 📦 Installation by Notebook

Each notebook lists its specific dependencies, but here's a quick reference:

```bash
# Minimal (notebooks 01, 06)
pip install agent-os-kernel

# Episodic Memory (notebook 02)
pip install agent-os-kernel emk

# Verification (notebook 04)
pip install agent-os-kernel[cmvk]

# Multi-Agent Coordination (notebook 05)
pip install agent-os-kernel[iatp]

# Everything
pip install agent-os-kernel[full]
```

## 🔧 Running Notebooks

### Option 1: Jupyter Notebook
```bash
jupyter notebook
```

### Option 2: JupyterLab
```bash
pip install jupyterlab
jupyter lab
```

### Option 3: VS Code
1. Install the [Jupyter extension](https://marketplace.visualstudio.com/items?itemName=ms-toolsai.jupyter)
2. Open any `.ipynb` file

### Option 4: Google Colab
Upload notebooks to [Google Colab](https://colab.research.google.com/) for cloud execution.

## 📖 What You'll Learn

### Core Concepts
- **Kernel Space vs User Space**: How Agent OS enforces policies
- **Policy Engine**: Defining what agents can and cannot do
- **Signals**: SIGKILL, SIGSTOP, SIGCONT for agent control

### Memory Systems
- **Episodic Memory (EMK)**: Immutable record of agent experiences
- **Memory Compression**: Sleep cycles to distill knowledge
- **Negative Memory**: Tracking failures to avoid repeating mistakes

### Verification & Trust
- **CMVK**: Verification for hallucination detection
- **IATP**: Cryptographic signing for multi-agent trust
- **Consensus**: Multi-model agreement protocols

### Debugging
- **Flight Recorder**: Capture every decision point
- **Time-Travel**: Replay agent state at any moment
- **Audit Trails**: Complete logging of policy decisions

## 💡 Tips

1. **Run cells in order**: Each notebook builds on previous cells
2. **Read the output**: Explanations are in the output, not just the code
3. **Experiment**: Modify the code and re-run to see what happens
4. **Check the docs**: Each notebook links to detailed documentation

## 🤝 Contributing

Found an issue or want to add a notebook? 
- [Open an issue](https://github.com/microsoft/agent-governance-toolkit/issues)
- [Submit a PR](https://github.com/microsoft/agent-governance-toolkit/pulls)

## 📚 Additional Resources

- [5-Minute Quickstart](../docs/tutorials/5-minute-quickstart.md)
- [30-Minute Deep Dive](../docs/tutorials/30-minute-deep-dive.md)
- [Full Documentation](../docs/)
- [Production Examples](../examples/)
