# OpenShell AgentMesh integration

This adapter applies Agent Control Specification policy to process creation by
Python agents hosted in an OpenShell sandbox. It intercepts `subprocess.run`,
`subprocess.Popen`, `os.system`, and `os.popen` in an explicit context and
evaluates each command at the `pre_tool_call` intervention point as the
`shell.execute` tool.

```python
import subprocess

from openshell_agentmesh import GovernanceSkill, governed_shell

skill = GovernanceSkill.from_manifest("openshell-policy.yaml")
with governed_shell(skill):
    subprocess.run(["git", "status"], check=True)
```

The ACS policy target contains `executable`, `argv`, `command`, `shell`, `api`,
`cwd`, OpenShell sandbox metadata, and caller-supplied context. Deny and
unresolved escalation verdicts stop execution. Transform verdicts may replace
the command. Policy evaluation errors fail closed.

`executable` names the program that will actually run. When the caller passes
`executable=`, by keyword or positionally, that program is reported. For
`shell=True`, `os.system`, and `os.popen` the executable is the shell, so a rule
keyed on `executable` alone does not see the program named in the string;
match on `command` instead. When a transform replaces the command, any
caller-supplied `executable=` is dropped so the transformed argv[0] (or the
default shell) runs.

Install the adapter through the consolidated integrations distribution.

```bash
pip install "agent-governance-toolkit-integrations[openshell]"
```
