# Prerequisites — Introduction to AI Agent Governance Workshop

> Share this file with participants **at least 48 hours before** the session.
> Everyone should complete all steps before arriving.

---

## Hardware & OS

- [ ] Laptop with internet access
- [ ] macOS, Linux, or Windows 10/11 (WSL2 strongly recommended on Windows)
- [ ] At least 2 GB of free disk space

---

## Software

### Python 3.10 or later

Check your version:

```bash
python --version   # should print Python 3.10.x or higher
```

If you need to install or upgrade Python, visit <https://www.python.org/downloads/>.

> **Windows users:** install Python from python.org and tick "Add Python to PATH" during
> setup. Alternatively, use `winget install Python.Python.3.11` in PowerShell.

### A code editor

Any editor works. Recommended options:

- [Visual Studio Code](https://code.visualstudio.com/) with the Python extension
- [PyCharm Community](https://www.jetbrains.com/pycharm/download/) (free)

---

## Python Packages

Create a virtual environment and install the required packages:

```bash
# 1. Create a virtual environment (do this once)
python -m venv agt-workshop
source agt-workshop/bin/activate          # macOS / Linux
# agt-workshop\Scripts\activate           # Windows PowerShell

# 2. Install packages
pip install agent-os-kernel agentmesh-platform agent-governance-toolkit
```

Verify the install:

```bash
python -c "from agent_os.policies import PolicyEvaluator; print('✅ agent-os-kernel OK')"
python -c "from agentmesh import AgentIdentity; print('✅ agentmesh-platform OK')"
python -c "import agent_governance; print('✅ agent-governance-toolkit OK')"
```

All three lines should print ✅ with no errors.

---

## Download Lab Templates

Clone or download the workshop lab files:

```bash
# Option A — clone the full repository
git clone https://github.com/microsoft/agent-governance-toolkit.git
cd agent-governance-toolkit/docs/workshop/labs

# Option B — download only the labs folder
# (ask your facilitator for a zip if git is unavailable)
```

---

## Knowledge Prerequisites

No prior knowledge of AI governance is required. You should be comfortable with:

- [ ] Running Python scripts from the command line (`python script.py`)
- [ ] Reading and editing Python files (variables, functions, dictionaries)
- [ ] Installing packages with `pip`
- [ ] Basic YAML syntax (key: value pairs, lists with `-`)

---

## Quick Self-Test

Run this script to confirm everything is working:

```bash
python -c "
from agent_os.policies import PolicyEvaluator
e = PolicyEvaluator()
print('Policy engine:', type(e).__name__)

from agentmesh import AgentIdentity, RiskScorer
a = AgentIdentity.create(name='TestAgent', sponsor='you@example.com', capabilities=[])
print('Agent DID:', a.did)

from agentmesh.governance.audit import AuditLog
log = AuditLog()
print('Audit log:', type(log).__name__)
print()
print('All prerequisites satisfied. See you at the workshop!')
"
```

Expected output (DIDs will differ):

```
Policy engine: PolicyEvaluator
Agent DID: did:mesh:...
Audit log: AuditLog

All prerequisites satisfied. See you at the workshop!
```

---

## Questions?

Open a discussion in the repository or contact your facilitator before the session.
