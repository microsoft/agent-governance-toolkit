# Dependency audit — remove mute-agent and scak modules

## Which dependencies changed and why

- `agent-governance-python/agent-os/modules/mute-agent/requirements.txt` was deleted.
- `agent-governance-python/agent-os/modules/scak/requirements.txt` was deleted.
- Reason: both modules are legacy in-tree experiments with no PyPI distribution and no downstream consumers in the AGT toolkit. The directories are being removed in full, so their pinned requirements files are removed alongside them.

## Security advisory relevance

- No advisory-driven upgrade is involved. The change is a pure deletion of unused experimental modules.
- No CVE-specific remediation is claimed by this lockfile change.
- Removing unused requirements files reduces the attack surface for transitive-dependency confusion and lockfile drift.

## Breaking change risk assessment

- `agent-governance-python/agent-os/modules/mute-agent/requirements.txt` — deletion. Risk: none. The package is not published, has no public import path that the rest of AGT depends on, and the module directory is removed in the same change.
- `agent-governance-python/agent-os/modules/scak/requirements.txt` — deletion. Risk: none. Same rationale as above.
- Overall assessment: acceptable. The lockfile removals are bookkeeping that follows the module deletion; nothing in the supported AGT surface area depends on these requirements.
