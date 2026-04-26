# Tutorial 10 — Plugin Marketplace

> **Package:** `agentmesh-marketplace` · **Time:** 25 minutes · **Prerequisites:** Python 3.11+

---

## What You'll Learn

- Plugin signing and Ed25519 verification
- CLI commands for plugin lifecycle management
- Supply-chain security and sandboxed execution

---

The Plugin Marketplace is the supply-chain layer of the Agent Governance Toolkit.
It manages the full lifecycle of plugins — discovery, installation, verification,
sandboxed execution, and removal — so your agent mesh can safely extend its
capabilities without compromising security or governance posture.

Every plugin published through the marketplace carries an Ed25519 cryptographic
signature, a declarative manifest (`agent-plugin.yaml`), and a set of declared
capabilities.  The `PluginInstaller` verifies signatures against a trusted-key
ring before anything touches disk, and the `PluginSandbox` in AgentMesh runs
plugin code in a restricted subprocess where dangerous modules are blocked at
import time.

**What you'll learn:**

| Section | Topic |
|---------|-------|
| [Quick Start](#quick-start) | Search, install, and verify a plugin in 6 lines |
| [Plugin Manifest](#plugin-manifest) | Anatomy of `agent-plugin.yaml`, PluginType enum |
| [Plugin Registry](#plugin-registry) | Register, query, version-track, and deprecate plugins |
| [Plugin Signing](#plugin-signing) | Generate Ed25519 keys and sign manifests |
| [Plugin Verification](#plugin-verification) | Verify integrity before installation |
| [Plugin Installation](#plugin-installation) | Install with dependency resolution and verification |
| [Plugin Uninstall](#plugin-uninstall) | Safe removal with cleanup |
| [Sandboxed Execution](#sandboxed-execution) | Run plugin code in an isolated subprocess |
| [CLI Reference](#cli-reference) | `agentmesh plugin` command-line interface |
| [Integration with AgentMesh Trust](#integration-with-agentmesh-trust) | Connect to the trust layer (Tutorial 02) |
| [Building a Custom Plugin](#building-a-custom-plugin) | End-to-end walkthrough |

---

## Installation

```bash
pip install agentmesh-marketplace                  # core marketplace package
pip install agentmesh-marketplace[cli]             # adds Click + Rich CLI commands
pip install agentmesh-platform                 # AgentMesh integration (sandbox, trust)
```

### Dependencies

| Package | Minimum Version | Purpose |
|---------|-----------------|---------|
| `pydantic` | ≥ 2.0 | Manifest schema validation |
| `pyyaml` | ≥ 6.0 | YAML manifest serialisation |
| `cryptography` | ≥ 45.0.3 | Ed25519 signing / verification |
| `click` | ≥ 8.0 | CLI framework (optional) |
| `rich` | ≥ 13.0 | Pretty terminal output (optional) |

---

## Quick Start

```python
from pathlib import Path
from agent_marketplace import (
    PluginManifest, PluginRegistry, PluginInstaller, PluginType,
)

# 1. Create a registry (optionally backed by a JSON file)
registry = PluginRegistry(storage_path=Path(".agentmesh/registry.json"))

# 2. Register a plugin
manifest = PluginManifest(
    name="sentiment-analyzer",
    version="1.0.0",
    description="Sentiment analysis for agent responses",
    author="alice@example.com",
    plugin_type=PluginType.VALIDATOR,
    capabilities=["sentiment-scoring", "toxicity-detection"],
)
registry.register(manifest)

# 3. Search for it
results = registry.search("sentiment")
print(results[0].name)  # → "sentiment-analyzer"

# 4. Install it
installer = PluginInstaller(
    plugins_dir=Path(".agentmesh/plugins"),
    registry=registry,
)
plugin_path = installer.install("sentiment-analyzer")
print(f"Installed to {plugin_path}")
```

Four moving parts: **register → search → install → use**.

---

## Plugin Manifest

Every plugin ships with an `agent-plugin.yaml` manifest that describes what the
plugin is, who published it, and what it depends on.  The manifest is modelled
by the `PluginManifest` Pydantic class.

### Manifest YAML Schema

```yaml
# agent-plugin.yaml
name: sentiment-analyzer
version: 1.0.0
description: Sentiment analysis for agent responses
author: alice@example.com
plugin_type: validator
capabilities:
  - sentiment-scoring
  - toxicity-detection
dependencies:
  - nlp-tokenizer>=2.0.0
  - base-validator>=1.0.0
min_agentmesh_version: "1.5.0"
signature: "LS0tLS1CRUdJTi..."          # base64-encoded Ed25519 signature
```

### PluginManifest Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | `str` | ✅ | Unique plugin name — alphanumeric, hyphens, underscores |
| `version` | `str` | ✅ | Semantic version (`MAJOR.MINOR` or `MAJOR.MINOR.PATCH`) |
| `description` | `str` | ✅ | Short human-readable summary |
| `author` | `str` | ✅ | Author name or email address |
| `plugin_type` | `PluginType` | ✅ | One of the four plugin types (see below) |
| `capabilities` | `list[str]` | — | Declared feature strings |
| `dependencies` | `list[str]` | — | Required plugins (e.g. `"name>=1.0.0"`) |
| `min_agentmesh_version` | `str \| None` | — | Minimum AgentMesh platform version |
| `signature` | `str \| None` | — | Base64-encoded Ed25519 signature |

### PluginType Enum

```python
from agent_marketplace import PluginType

class PluginType(str, enum.Enum):
    POLICY_TEMPLATE = "policy_template"   # reusable governance policy templates
    INTEGRATION     = "integration"       # third-party service connectors
    AGENT           = "agent"             # autonomous agent plugins
    VALIDATOR       = "validator"         # validation / checking plugins
```

| Type | Value | Use Case |
|------|-------|----------|
| `POLICY_TEMPLATE` | `"policy_template"` | Reusable governance rule sets, compliance templates |
| `INTEGRATION` | `"integration"` | Connectors to external services (Slack, Jira, etc.) |
| `AGENT` | `"agent"` | Autonomous agent implementations |
| `VALIDATOR` | `"validator"` | Checkers, evaluators, quality gates |

### Validation Rules

The manifest enforces constraints at construction time:

```python
# Name must be non-empty, alphanumeric + hyphens/underscores
manifest = PluginManifest(name="", ...)         # ❌ MarketplaceError

# Version must be MAJOR.MINOR or MAJOR.MINOR.PATCH (all numeric)
manifest = PluginManifest(version="abc", ...)   # ❌ MarketplaceError

# Author must be non-empty
manifest = PluginManifest(author="", ...)       # ❌ MarketplaceError
```

### Loading and Saving Manifests

```python
from pathlib import Path
from agent_marketplace import load_manifest, save_manifest

# Load from a directory (looks for agent-plugin.yaml inside)
manifest = load_manifest(Path("./my-plugin"))

# Or load from a specific file
manifest = load_manifest(Path("./my-plugin/agent-plugin.yaml"))

# Save to a directory (writes agent-plugin.yaml)
saved_path = save_manifest(manifest, Path("./my-plugin"))
print(saved_path)  # → PosixPath("./my-plugin/agent-plugin.yaml")
```

The constant `MANIFEST_FILENAME` is `"agent-plugin.yaml"`.

---

## Plugin Registry

The `PluginRegistry` is an in-memory + file-backed store for discovering and
managing plugins.  It supports multi-version tracking, semver-aware "latest"
resolution, substring search, and type filtering.

### Creating a Registry

```python
from pathlib import Path
from agent_marketplace import PluginRegistry

# In-memory only (ephemeral)
registry = PluginRegistry()

# Persistent — state saved to / loaded from a JSON file
registry = PluginRegistry(storage_path=Path(".agentmesh/registry.json"))
```

When a `storage_path` is provided and the file exists, the constructor
automatically loads previously-registered plugins.

### Registering Plugins

```python
from agent_marketplace import PluginManifest, PluginType

manifest_v1 = PluginManifest(
    name="my-policy-plugin",
    version="1.0.0",
    description="A governance policy plugin",
    author="alice@example.com",
    plugin_type=PluginType.POLICY_TEMPLATE,
    capabilities=["policy-evaluation", "constraint-checking"],
    dependencies=["base-policy>=1.0.0"],
)

registry.register(manifest_v1)

# Register a newer version of the same plugin
manifest_v2 = manifest_v1.model_copy(update={"version": "2.0.0"})
registry.register(manifest_v2)

# Duplicate name+version raises MarketplaceError
registry.register(manifest_v1)  # ❌ MarketplaceError: already registered
```

### Retrieving Plugins

```python
# Get the latest version (highest semver)
latest = registry.get_plugin("my-policy-plugin")
print(latest.version)  # → "2.0.0"

# Get a specific version
v1 = registry.get_plugin("my-policy-plugin", version="1.0.0")
print(v1.version)  # → "1.0.0"

# Non-existent plugin raises MarketplaceError
registry.get_plugin("does-not-exist")  # ❌ MarketplaceError
```

### Searching

```python
# Case-insensitive substring search across name and description
results = registry.search("policy")
for plugin in results:
    print(f"{plugin.name} v{plugin.version}: {plugin.description}")
```

`search()` returns the **latest version** of each matching plugin.

### Listing with Type Filter

```python
# List all plugins (latest version of each)
all_plugins = registry.list_plugins()

# Filter by type
validators = registry.list_plugins(type_filter=PluginType.VALIDATOR)
integrations = registry.list_plugins(type_filter=PluginType.INTEGRATION)
```

### Removing Plugins

```python
# Remove a specific version
registry.unregister("my-policy-plugin", version="1.0.0")

# Remove all versions
registry.unregister("my-policy-plugin")

# Non-existent plugin raises MarketplaceError
registry.unregister("ghost-plugin")  # ❌ MarketplaceError
```

---

## Plugin Signing

Plugin manifests are signed with **Ed25519** keys to guarantee authenticity and
integrity.  The `PluginSigner` class handles key management and signature
creation.

### Generating a Key Pair

```python
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

# Generate a new Ed25519 private key
private_key = ed25519.Ed25519PrivateKey.generate()

# Extract the corresponding public key
public_key = private_key.public_key()

# Serialise for storage
private_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
)
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

# Save to files
Path("signing-key.pem").write_bytes(private_bytes)
Path("signing-key.pub").write_bytes(public_bytes)
```

### Signing a Manifest

```python
from agent_marketplace import PluginSigner, PluginManifest, PluginType

signer = PluginSigner(private_key)

manifest = PluginManifest(
    name="sentiment-analyzer",
    version="1.0.0",
    description="Sentiment analysis for agent responses",
    author="alice@example.com",
    plugin_type=PluginType.VALIDATOR,
)

# sign() returns a new manifest with the signature field populated
signed = signer.sign(manifest)
print(signed.signature)  # → "LS0tLS1CRUdJTi..." (base64-encoded)
```

Under the hood, `sign()` calls `manifest.signable_bytes()` to produce a
deterministic YAML serialisation (excluding the `signature` field), signs those
bytes with Ed25519, and base64-encodes the result.

### Accessing the Public Key

```python
# The signer exposes its public key (for distributing to verifiers)
pub = signer.public_key
print(type(pub))  # → <class 'Ed25519PublicKey'>
```

---

## Plugin Verification

Before installation, the `verify_signature` function confirms that a manifest
has not been tampered with since it was signed.

### Verifying a Signature

```python
from agent_marketplace import verify_signature

is_valid = verify_signature(signed, public_key)
print(is_valid)  # → True
```

### Error Cases

```python
from agent_marketplace import verify_signature, MarketplaceError

# Missing signature
unsigned_manifest = PluginManifest(
    name="unsigned-plugin", version="1.0.0",
    description="No sig", author="bob",
    plugin_type=PluginType.AGENT,
)
try:
    verify_signature(unsigned_manifest, public_key)
except MarketplaceError as e:
    print(e)  # signature is missing

# Tampered manifest
tampered = signed.model_copy(update={"description": "I was tampered with"})
try:
    verify_signature(tampered, public_key)
except MarketplaceError as e:
    print(e)  # signature verification failed
```

### Full Sign → Verify Round-Trip

```python
from cryptography.hazmat.primitives.asymmetric import ed25519
from agent_marketplace import (
    PluginSigner, PluginManifest, PluginType, verify_signature,
)

# Key pair
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Create and sign
manifest = PluginManifest(
    name="round-trip-demo",
    version="1.0.0",
    description="Demonstrates signing and verification",
    author="alice@example.com",
    plugin_type=PluginType.INTEGRATION,
)
signer = PluginSigner(private_key)
signed = signer.sign(manifest)

# Verify
assert verify_signature(signed, public_key) is True
print("✓ Signature verified")
```

---

## Plugin Installation

The `PluginInstaller` handles installation from the registry with automatic
signature verification and recursive dependency resolution.

### Basic Installation

```python
from pathlib import Path
from agent_marketplace import PluginInstaller, PluginRegistry

registry = PluginRegistry(storage_path=Path(".agentmesh/registry.json"))

installer = PluginInstaller(
    plugins_dir=Path(".agentmesh/plugins"),
    registry=registry,
)

# Install the latest version
plugin_path = installer.install("sentiment-analyzer")
print(plugin_path)  # → Path(".agentmesh/plugins/sentiment-analyzer")

# Install a specific version
plugin_path = installer.install("sentiment-analyzer", version="1.0.0")
```

### Installation with Signature Verification

Pass a `trusted_keys` dictionary that maps author names to Ed25519 public keys.
When a matching key is found for the plugin's author, the installer verifies
the signature before writing files to disk.

```python
from cryptography.hazmat.primitives.asymmetric import ed25519

trusted_keys = {
    "alice@example.com": public_key,       # Ed25519PublicKey
    "bob@example.com": bobs_public_key,
}

installer = PluginInstaller(
    plugins_dir=Path(".agentmesh/plugins"),
    registry=registry,
    trusted_keys=trusted_keys,
)

# Verification happens automatically during install
plugin_path = installer.install("sentiment-analyzer", verify=True)

# Skip verification (not recommended for production)
plugin_path = installer.install("sentiment-analyzer", verify=False)
```

### Dependency Resolution

Dependencies declared in the manifest are resolved and installed recursively.
Circular dependencies are detected and raise `MarketplaceError`.

```python
# Plugin with dependencies
manifest = PluginManifest(
    name="advanced-analyzer",
    version="1.0.0",
    description="Advanced analysis plugin",
    author="alice@example.com",
    plugin_type=PluginType.VALIDATOR,
    dependencies=[
        "nlp-tokenizer>=2.0.0",
        "base-validator>=1.0.0",
    ],
)
registry.register(manifest)

# Installing advanced-analyzer also installs nlp-tokenizer and base-validator
plugin_path = installer.install("advanced-analyzer")
```

Dependency specifiers support these operators: `>=`, `==`, `<=`, `>`, `<`.

### Listing Installed Plugins

```python
installed = installer.list_installed()
for plugin in installed:
    print(f"  {plugin.name} v{plugin.version} ({plugin.plugin_type.value})")
```

### Sandboxing Check

The installer enforces import restrictions.  Plugins are not allowed to use
dangerous modules:

```python
from agent_marketplace import PluginInstaller

# The RESTRICTED_MODULES set blocks these:
#   subprocess, os, shutil, ctypes, importlib

PluginInstaller.check_sandbox("json")          # → True  (allowed)
PluginInstaller.check_sandbox("subprocess")    # → False (blocked)
PluginInstaller.check_sandbox("os")            # → False (blocked)
PluginInstaller.check_sandbox("ctypes")        # → False (blocked)
```

---

## Plugin Uninstall

```python
# Remove an installed plugin
installer.uninstall("sentiment-analyzer")

# Raises MarketplaceError if not installed
installer.uninstall("not-installed")  # ❌ MarketplaceError
```

The uninstaller removes the plugin directory under `plugins_dir`.

---

## Sandboxed Execution

The `PluginSandbox` in the AgentMesh integration layer executes plugin code in
an isolated subprocess with multiple security layers.

### Security Layers

| Layer | Protection |
|-------|-----------|
| Subprocess isolation | Separate process, no shared memory with host |
| Import guard | 19 dangerous modules blocked before *and* during execution |
| Builtin restriction | `exec`, `eval`, `breakpoint` removed after module loading |
| Minimal environment | Only `SYSTEMROOT`/`TEMP` passed — no secrets leak |
| Timeout | Runaway processes killed after configurable deadline |

### Blocked Modules

```
subprocess  os  shutil  ctypes  importlib  socket  http  urllib  ftplib
smtplib  telnetlib  pickle  shelve  marshal  code  codeop  compileall
multiprocessing  signal  resource  pty  termios  fcntl  mmap  winreg  _winapi
```

### Running a Plugin in the Sandbox

```python
from pathlib import Path
from agentmesh.marketplace import PluginSandbox

sandbox = PluginSandbox(
    plugins_dir=Path(".agentmesh/plugins"),
    timeout_seconds=30,                        # global default
)

result = sandbox.execute(
    plugin_name="sentiment-analyzer",
    entry_function="analyze",                  # function to call
    input_data={"text": "This product is excellent!"},
    timeout=10,                                # per-call override
)

if "result" in result:
    print(f"Score: {result['result']}")
else:
    print(f"Plugin error: {result['error']}")
```

### How It Works

1. A subprocess is spawned with a sanitised environment.
2. An import hook blocks all modules in `ALL_BLOCKED_MODULES`.
3. The target module is imported from the plugin directory.
4. `exec`, `eval`, and `breakpoint` are removed from builtins.
5. The entry function is called with `input_data` (JSON).
6. The result (or error) is serialised as JSON and returned.
7. If the process exceeds `timeout` seconds, it is killed and a
   `PluginSandboxError` is raised.

```python
from agentmesh.marketplace import PluginSandboxError

try:
    result = sandbox.execute(
        plugin_name="slow-plugin",
        entry_function="run",
        input_data={},
        timeout=5,
    )
except PluginSandboxError as e:
    print(f"Sandbox failure: {e}")
```

---

## CLI Reference

The `agentmesh plugin` command group provides a terminal interface for all
marketplace operations.  Requires `pip install agentmesh-marketplace[cli]`.

### `agentmesh plugin install`

Install a plugin from the registry.

```bash
# Install latest version
agentmesh plugin install sentiment-analyzer

# Install a specific version
agentmesh plugin install sentiment-analyzer --version 1.0.0
agentmesh plugin install sentiment-analyzer -v 1.0.0
```

### `agentmesh plugin uninstall`

Remove an installed plugin.

```bash
agentmesh plugin uninstall sentiment-analyzer
```

### `agentmesh plugin list`

List installed plugins, optionally filtered by type.

```bash
# List all
agentmesh plugin list

# Filter by type
agentmesh plugin list --type validator
agentmesh plugin list --type policy_template
agentmesh plugin list --type integration
agentmesh plugin list --type agent
```

### `agentmesh plugin search`

Search the registry by name or description.

```bash
agentmesh plugin search sentiment
agentmesh plugin search "governance policy"
```

### `agentmesh plugin verify`

Verify a plugin's Ed25519 signature.

```bash
# Verify by directory (looks for agent-plugin.yaml inside)
agentmesh plugin verify ./my-plugin

# Verify by manifest file
agentmesh plugin verify ./my-plugin/agent-plugin.yaml
```

### `agentmesh plugin publish`

Sign and register a plugin with the registry.

```bash
agentmesh plugin publish ./my-plugin
```

### Default Paths

| Setting | Default |
|---------|---------|
| Plugin installation directory | `.agentmesh/plugins/` |
| Registry file | `.agentmesh/registry.json` |

---

## Integration with AgentMesh Trust

The Plugin Marketplace integrates with the trust and identity layer described
in [Tutorial 02 — Trust and Identity](02-trust-and-identity.md).  When both
systems are active, plugin installation can be tied to the mesh's trust model.

### Trusted Publisher Pattern

```python
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from agent_marketplace import (
    PluginRegistry, PluginInstaller, PluginSigner,
    PluginManifest, PluginType, verify_signature,
)

# --- Publisher side ---
private_key = ed25519.Ed25519PrivateKey.generate()

manifest = PluginManifest(
    name="trust-aware-validator",
    version="1.0.0",
    description="Validator that checks agent trust scores",
    author="governance-team@example.com",
    plugin_type=PluginType.VALIDATOR,
    capabilities=["trust-evaluation"],
    min_agentmesh_version="1.5.0",
)

signer = PluginSigner(private_key)
signed = signer.sign(manifest)

# --- Consumer side ---
registry = PluginRegistry()
registry.register(signed)

# Build a trusted-key ring from known publishers
trusted_keys = {
    "governance-team@example.com": signer.public_key,
}

installer = PluginInstaller(
    plugins_dir=Path(".agentmesh/plugins"),
    registry=registry,
    trusted_keys=trusted_keys,
)

# Install — signature is verified automatically
path = installer.install("trust-aware-validator", verify=True)
print(f"✓ Verified and installed to {path}")
```

### Why This Matters

- **Supply-chain security:** only plugins signed by trusted authors are
  installed.
- **Tamper detection:** any modification to the manifest after signing
  invalidates the signature.
- **Audit trail:** the `signature` field is persisted in the manifest file,
  providing a verifiable record of who published the plugin.

---

## Building a Custom Plugin

This walkthrough creates a governance-aware plugin from scratch: a **response
length validator** that rejects agent responses exceeding a configurable word
limit.

### Step 1 — Create the Project Structure

```
response-length-validator/
├── agent-plugin.yaml
└── response_length_validator.py
```

### Step 2 — Write the Manifest

```yaml
# response-length-validator/agent-plugin.yaml
name: response-length-validator
version: 1.0.0
description: Rejects agent responses that exceed a configurable word limit
author: your-name@example.com
plugin_type: validator
capabilities:
  - response-length-check
  - word-counting
dependencies: []
min_agentmesh_version: "1.5.0"
```

### Step 3 — Implement the Plugin

```python
# response-length-validator/response_length_validator.py
"""Response length validator plugin for the Agent Governance Toolkit."""


def validate(input_data: dict) -> dict:
    """Check whether an agent response exceeds the word limit.

    Args:
        input_data: Must contain "response" (str) and optionally
                    "max_words" (int, default 500).

    Returns:
        {"result": {"valid": bool, "word_count": int, "message": str}}
    """
    response = input_data.get("response", "")
    max_words = input_data.get("max_words", 500)

    word_count = len(response.split())
    valid = word_count <= max_words

    return {
        "result": {
            "valid": valid,
            "word_count": word_count,
            "message": (
                f"OK — {word_count} words (limit: {max_words})"
                if valid
                else f"Too long — {word_count} words exceeds limit of {max_words}"
            ),
        }
    }
```

### Step 4 — Load and Validate the Manifest

```python
from agent_marketplace import load_manifest

manifest = load_manifest("./response-length-validator")
print(manifest.name)         # → "response-length-validator"
print(manifest.plugin_type)  # → PluginType.VALIDATOR
print(manifest.capabilities) # → ["response-length-check", "word-counting"]
```

### Step 5 — Sign the Plugin

```python
from cryptography.hazmat.primitives.asymmetric import ed25519
from agent_marketplace import PluginSigner, save_manifest

private_key = ed25519.Ed25519PrivateKey.generate()
signer = PluginSigner(private_key)

signed = signer.sign(manifest)
save_manifest(signed, "./response-length-validator")
print("✓ Manifest signed and saved")
```

### Step 6 — Publish to the Registry

```python
from pathlib import Path
from agent_marketplace import PluginRegistry

registry = PluginRegistry(storage_path=Path(".agentmesh/registry.json"))
registry.register(signed)
print("✓ Published to registry")
```

Or use the CLI:

```bash
agentmesh plugin publish ./response-length-validator
```

### Step 7 — Install and Run

```python
from pathlib import Path
from agent_marketplace import PluginInstaller
from agentmesh.marketplace import PluginSandbox

installer = PluginInstaller(
    plugins_dir=Path(".agentmesh/plugins"),
    registry=registry,
    trusted_keys={"your-name@example.com": signer.public_key},
)
installer.install("response-length-validator")

# Execute in the sandbox
sandbox = PluginSandbox(plugins_dir=Path(".agentmesh/plugins"))
result = sandbox.execute(
    plugin_name="response-length-validator",
    entry_function="validate",
    input_data={
        "response": "This is a short response.",
        "max_words": 500,
    },
)
print(result)
# → {"result": {"valid": True, "word_count": 5, "message": "OK — 5 words (limit: 500)"}}
```

---

## Source Files

| Component | Location |
|-----------|----------|
| PluginManifest / PluginType | `agent-governance-python/agent-marketplace/src/agent_marketplace/manifest.py` |
| PluginRegistry | `agent-governance-python/agent-marketplace/src/agent_marketplace/registry.py` |
| PluginInstaller | `agent-governance-python/agent-marketplace/src/agent_marketplace/installer.py` |
| PluginSigner / verify_signature | `agent-governance-python/agent-marketplace/src/agent_marketplace/signing.py` |
| CLI commands | `agent-governance-python/agent-marketplace/src/agent_marketplace/cli_commands.py` |
| PluginSandbox | `agent-governance-python/agent-mesh/src/agentmesh/marketplace/sandbox.py` |
| Backward-compat shim | `agent-governance-python/agent-mesh/src/agentmesh/marketplace/__init__.py` |
| Tests | `agent-governance-python/agent-marketplace/tests/test_marketplace.py` |

---

## Next Steps

- **[Tutorial 01 — Policy Engine](01-policy-engine.md):** Write the governance
  policies that your validator plugins enforce.
- **[Tutorial 02 — Trust and Identity](02-trust-and-identity.md):** Connect
  plugin publisher keys to the AgentMesh trust model.
- **[Tutorial 06 — Execution Sandboxing](06-execution-sandboxing.md):** Deep
  dive into the sandbox security model used by `PluginSandbox`.
