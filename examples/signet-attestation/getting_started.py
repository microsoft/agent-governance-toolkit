"""AGT + Signet: Policy enforcement with cryptographic attestation.

AGT decides whether an action is allowed.
Signet signs the allowed action and embeds the policy decision in the receipt.
"""

from signet_auth import SigningAgent
from signet_auth._signet import parse_policy_yaml, evaluate_policy, sign_with_policy
import json

# --- Setup ---
agent = SigningAgent.create("agt-demo", owner="demo-team")
print(f"Agent: {agent.key_info.name} ({agent.key_info.pubkey[:20]}...)")

# --- Define policy (same YAML format, compatible with AGT's policy model) ---
policy_yaml = """
version: 1
name: agt-demo-policy
default_action: deny
rules:
  - id: allow-read
    match:
      tool:
        one_of: ["web_search", "file_read", "list_files"]
    action: allow
  - id: deny-destructive
    match:
      tool:
        one_of: ["file_delete", "drop_database", "execute_code"]
    action: deny
    reason: Destructive operations blocked by policy
"""
policy_json = parse_policy_yaml(policy_yaml)
policy = json.loads(policy_json)
print(f"Policy: {policy['name']} ({len(policy['rules'])} rules)")

# --- Allowed action: web_search ---
print("\n--- Allowed Action ---")
action = {
    "tool": "web_search",
    "params": {"query": "AI agent security"},
    "params_hash": "",
    "target": "mcp://search",
    "transport": "stdio",
}
eval_json = evaluate_policy(json.dumps(action), "agt-demo", policy_json)
eval_result = json.loads(eval_json)
print(f"Policy decision: {eval_result['decision']} (rule: {eval_result['matched_rules']})")

receipt_json, _ = sign_with_policy(
    agent._sk_b64, json.dumps(action), "agt-demo", "demo-team", policy_json,
)
receipt = json.loads(receipt_json)
print(f"Receipt: {receipt['id']}")
print(f"Policy attestation: {receipt['policy']['policy_name']} → {receipt['policy']['decision']}")
print(f"Signature: {receipt['sig'][:40]}...")

# --- Denied action: file_delete ---
print("\n--- Denied Action ---")
denied_action = {
    "tool": "file_delete",
    "params": {"path": "/etc/hosts"},
    "params_hash": "",
    "target": "mcp://filesystem",
    "transport": "stdio",
}
eval_json = evaluate_policy(json.dumps(denied_action), "agt-demo", policy_json)
eval_result = json.loads(eval_json)
print(f"Policy decision: {eval_result['decision']} (reason: {eval_result['reason']})")
print("No receipt produced — action was blocked by policy.")

# --- Verify ---
print("\n--- Verification ---")
verified = agent.verify(agent._last_receipt) if hasattr(agent, '_last_receipt') else True
print(f"Audit log: {agent.key_info.name}")
records = agent.audit_query(since="1h")
print(f"Records in last hour: {len(records)}")
for r in records[-3:]:
    tool = r.receipt.get("action", {}).get("tool", "?")
    pol = r.receipt.get("policy", {}).get("decision", "n/a") if r.receipt.get("policy") else "no policy"
    print(f"  {tool} → {pol}")

print("\nDone. Run 'signet audit --since 1h' for the full trail.")
