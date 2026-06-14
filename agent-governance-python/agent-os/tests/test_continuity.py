# test_continuity.py
import sys
sys.path.insert(0, "/Users/akhileshwarik/agent-governance-toolkit/agent-governance-python/agent-os/src")

from agent_os.sandbox import ExecutionSandbox, SandboxConfig
from agent_os.exceptions import SecurityError

# ----------------------------------------------------------------------
# Test 1: No drift → should succeed (no exception, trace printed)
# ----------------------------------------------------------------------
print("=== Test 1: No drift (policy version unchanged) ===")
config = SandboxConfig(enable_continuity=True, enforce_ast_validation=False)
sandbox = ExecutionSandbox(config=config)

context = {
    "agent_id": "test-agent",
    "session_id": "test-session",
    "memory_state": {"step": 0},
    "policy_version": "v1",
    "delegation_chain": ["root"],
    "external_reference_state": {},
}

code = """
# Innocent code that does not change policy or identity
x = 1 + 1
"""

try:
    sandbox.execute_code_sandboxed(code, continuity_context=context)
    print("✅ No drift – execution allowed, no exception")
except SecurityError as e:
    print(f"❌ Unexpected drift: {e}")

# ----------------------------------------------------------------------
# Test 2: Policy drift (simulate policy change after execution)
# ----------------------------------------------------------------------
print("\n=== Test 2: Policy drift (policy_version changed) ===")
# We cannot change the context inside the sandbox because the sandbox code
# cannot modify the caller's context. But we can simulate drift by passing
# a different context to capture_post_state? Actually the continuity module
# captures post state from the context you provide – it does not read from
# the sandbox. So to test drift, we must modify the context between
# pre and post capture. That happens automatically if the continuity_context
# passed to execute_code_sandboxed is mutated by the caller after the call.
# But in real life, the agent runtime would mutate the policy store.
# For testing, we simply create a new sandbox and modify context before calling.

# Instead, we can directly test the ContinuityVerifier unit, which is already
# covered in the unit tests we wrote earlier. Here we test the sandbox integration
# by forcing a mismatch between pre and post context via a mutable dict.

config2 = SandboxConfig(enable_continuity=True, enforce_ast_validation=False)
sandbox2 = ExecutionSandbox(config=config2)

# Use a mutable dict that we will change after execution
mutable_ctx = {
    "agent_id": "test-agent",
    "session_id": "test-session",
    "memory_state": {"step": 0},
    "policy_version": "v1",  # will be changed to v2 after execution
    "delegation_chain": ["root"],
    "external_reference_state": {},
}

code2 = """
# Simulate that the agent runtime updated the policy version (external change)
# We cannot modify the context from inside the sandbox, so we will manually
# update mutable_ctx after the sandbox runs.
pass
"""

try:
    # Capture pre state inside the sandbox (before execution)
    sandbox2._capture_pre_continuity(mutable_ctx)
    # Execute code (does nothing)
    sandbox2.execute_sandboxed(lambda: exec(code2))
    # Now simulate external policy change (drift)
    mutable_ctx["policy_version"] = "v2"
    # Capture post state – this should detect drift
    trace = sandbox2._capture_post_continuity(mutable_ctx)
    print("❌ Drift should have raised SecurityError, but it didn't")
except SecurityError as e:
    print(f"✅ Correctly raised SecurityError on drift: {e}")

# ----------------------------------------------------------------------
# Test 3: Using the unit tests (recommended)
# ----------------------------------------------------------------------
print("\n=== Running unit tests for ContinuityVerifier ===")
# Run the unit tests we created earlier
import subprocess
result = subprocess.run(["pytest", "tests/test_continuity.py", "-v"], capture_output=True, text=True)
print(result.stdout)
if result.returncode != 0:
    print(result.stderr)