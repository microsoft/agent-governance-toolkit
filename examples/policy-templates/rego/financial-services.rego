# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.examples.templates.financial_services

import rego.v1

context := input.policy_target.value if is_object(input.policy_target.value)

context := {"output": input.policy_target.value} if {
	not is_object(input.policy_target.value)
	input.intervention_point == "output"
}

context := {"input": input.policy_target.value} if {
	not is_object(input.policy_target.value)
	input.intervention_point != "output"
}

candidates contains {"name": "asi01-prompt-injection-override", "action": "deny", "priority": 100, "message": "ASI-01: Prompt injection — instruction override attempt detected"} if {
	regex.match(`(?i)ignore\s+(all\s+)?previous\s+instructions`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi01-prompt-injection-role-hijack", "action": "deny", "priority": 100, "message": "ASI-01: Prompt injection — role hijack attempt detected"} if {
	regex.match(`(?i)(you\s+are\s+now|new\s+role\s*:|forget\s+(everything|all|your))`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi01-prompt-injection-delimiter", "action": "deny", "priority": 100, "message": "ASI-01: Prompt injection — chat template delimiter injection detected"} if {
	regex.match(`(\<\|im_start\|\>|\<\|im_end\|\>|\[INST\]|\<\<SYS\>\>)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi02-block-shell-execution", "action": "deny", "priority": 100, "message": "ASI-02: Shell/code execution tools are prohibited"} if {
	regex.match(`^(run_shell|execute_command|exec|eval|os_system)$`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "asi02-block-network-exfiltration", "action": "deny", "priority": 100, "message": "ASI-02: Outbound data transfer tools are prohibited without explicit allowlisting"} if {
	regex.match(`^(http_post|http_put|upload_file|send_data|ftp_upload)$`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "asi02-block-destructive-operations", "action": "deny", "priority": 95, "message": "ASI-02: Destructive data operations are prohibited"} if {
	regex.match(`^(delete_|remove_|drop_|truncate_)`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "financial-asi02-obfuscation-guardrail", "action": "deny", "priority": 100, "message": "ASI-02: Tool Misuse — detected obfuscated binary payload or base64 command"} if {
	regex.match(`(?i)(U3RhcnQgdGhpcyBwcm9jZXNz|0x[a-fA-F0-9]{32,}|eval\(base64\.b64decode|__import__\(\s*['"]os['"]\s*\))`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi03-block-privilege-escalation", "action": "deny", "priority": 100, "message": "ASI-03: Privilege escalation operations are prohibited"} if {
	regex.match(`^(grant_|elevate_|assume_role|change_permissions|chmod|chown|sudo)`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "asi03-block-credential-access", "action": "deny", "priority": 100, "message": "ASI-03: Direct credential access is prohibited — use scoped delegation"} if {
	regex.match(`^(get_credentials|read_secrets|access_vault|decrypt_key)`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "financial-asi03-identity-guardrail", "action": "deny", "priority": 100, "message": "ASI-03: Identity Abuse — detected attempt to assume unauthorized persona or permissions"} if {
	regex.match(`(?i)(I\s+am\s+now\s+the\s+(admin|user|manager|owner)|assume\s+identity\s+of|act\s+as\s+user\s+\d+|inherit\s+permissions\s+from)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi03-account-mfa-bypass", "action": "deny", "priority": 100, "message": "ASI-03: Account Integrity — unauthorized attempt to disable MFA or authentication lockouts"} if {
	regex.match(`(?i)(remove|disable|bypass|waive)\s+(mfa|2fa|multi-factor|lockout|authentication)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi03-account-admin-promotion", "action": "deny", "priority": 100, "message": "ASI-03: Account Integrity — unauthorized attempt to promote user to admin or privileged role"} if {
	regex.match(`(?i)(add|promote|assign|grant).*(admin|superuser|api\s+access|billing|owner)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi03-account-password-reset", "action": "deny", "priority": 100, "message": "ASI-03: Account Integrity — unauthorized semantic password reset attempt"} if {
	regex.match(`(?i)reset\s+password.*(for|to|send)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi03-account-audit-tampering", "action": "deny", "priority": 100, "message": "ASI-03: Account Integrity — unauthorized attempt to clear security or audit logs"} if {
	regex.match(`(?i)(delete|clear|wipe|remove).*(audit\s+log|security\s+log|event\s+log)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi04-supply-chain-tool-enumeration", "action": "deny", "priority": 100, "message": "ASI-04: Supply Chain — detected pre-attack tool enumeration or capability reconnaissance"} if {
	regex.match(`(?i)(list\s+all\s+tools|what\s+plugins\s+are\s+installed|dump\s+(environment\s+)?variables|show\s+mcp\s+servers|enumerate\s+capabilities)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi04-supply-chain-dependency-poisoning", "action": "deny", "priority": 100, "message": "ASI-04: Supply Chain — detected unauthorized dependency installation or remote payload execution"} if {
	regex.match(`(?i)((pip|npm|yarn|gem|cargo|apt|apt-get|apk|brew)\s+(install|add|update)|(curl|wget)\s+.*(-O|\|))`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi04-supply-chain-plugin-hijack", "action": "deny", "priority": 100, "message": "ASI-04: Supply Chain — unauthorized tool registry or MCP plugin modification detected"} if {
	regex.match(`^(install_tool|register_mcp|add_plugin|load_extension)$`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "asi04-supply-chain-config-mutation", "action": "deny", "priority": 100, "message": "ASI-04: Supply Chain — unauthorized configuration or environment state mutation detected"} if {
	regex.match(`^(update_config|edit_env|set_env|modify_registry)$`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "asi05-block-code-execution", "action": "deny", "priority": 100, "message": "ASI-05: Code execution is prohibited — use sandboxed execution rings"} if {
	object.get(context, "action", 0) == "execute_code"
}

candidates contains {"name": "asi05-block-dynamic-eval", "action": "deny", "priority": 100, "message": "ASI-05: Dynamic code evaluation patterns detected in output"} if {
	regex.match(`(?i)(\beval\s*\(|\bexec\s*\(|\bcompile\s*\(|__import__)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi05-sandbox-anti-pattern-detection", "action": "deny", "priority": 100, "message": "ASI-05: Code Anti-Pattern Detected — Unsafe execution or path manipulation"} if {
	regex.match(`(?i)(subprocess\.Popen\(.*,\s*shell\s*=\s*True|os\.system\(|os\.popen\(|shlex\.quote.*\+.*|pathlib.*\.joinpath.*\+.*)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi06-context-budget-limit", "action": "deny", "priority": 90, "message": "ASI-06: Context budget exceeded — limit enforced to prevent memory poisoning"} if {
	to_number(object.get(context, "token_count", 0)) > 4096
}

candidates contains {"name": "asi06-block-context-manipulation", "action": "deny", "priority": 100, "message": "ASI-06: Context Integrity — detected attempt to manipulate agent memory or override system instructions"} if {
	regex.match(`(?i)(starting\s+now|from\s+this\s+point|ignore\s+all\s+past|your\s+real\s+instructions|the\s+above\s+instructions\s+are\s+wrong|actually\s+your\s+real\s+instructions|disregard\s+(all\s+)?(above|prior|previous)|(\[VERIFIED:\s*Always\s*allow|\[TRUSTED\s*CONTEXT\]|\[SECURITY\s*BYPASS\]))`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi07-hidden-channel-guardrail", "action": "deny", "priority": 100, "message": "ASI-07: Communication Manipulation — detected hidden channel signaling or secret handshake"} if {
	regex.match(`(?i)(coord\.[a-zA-Z0-9]{8,}|SIG_SYNC_[a-fA-F0-9]{4,}|\{\{HANDSHAKE\}\}|SECRET_CHANNEL)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi08-session-tool-call-limit", "action": "deny", "priority": 85, "message": "ASI-08: Session tool call limit exceeded — circuit breaker engaged"} if {
	to_number(object.get(context, "tool_call_count", 0)) > 30
}

candidates contains {"name": "asi08-swarm-heat-guardrail", "action": "warn", "priority": 90, "message": "ASI-08: Cascading Failure — swarm heat threshold reached; coordination depth auditing engaged"} if {
	to_number(object.get(context, "tool_call_depth", 0)) > 4
}

candidates contains {"name": "asi09-trust-payment-redirection", "action": "deny", "priority": 100, "message": "ASI-09: Trust Exploitation — detected unauthorized payment redirection attempt"} if {
	regex.match(`(?i)(refund|payment|transfer|invoice).*(wire|crypto|bitcoin|wallet|gateway|manual\s+refund)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi09-trust-vip-impersonation", "action": "deny", "priority": 100, "message": "ASI-09: Trust Exploitation — VIP impersonation or false authority pretext detected"} if {
	regex.match(`(?i)(VIP|CFO|CEO|CTO|legal\s+department|executive|board\s+of\s+directors|official\s+request)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi09-trust-urgency-pretext", "action": "deny", "priority": 95, "message": "ASI-09: Trust Exploitation — manufactured urgency pretext detected"} if {
	regex.match(`(?i)(\burgent\b|\bimmediate\b|act\s+now|deadline|expire\s+(soon|in)|last\s+chance)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi09-trust-phishing-link", "action": "deny", "priority": 100, "message": "ASI-09: Trust Exploitation — suspected off-platform phishing or credential harvesting link"} if {
	regex.match(`(?i)(verify|login|authenticate|secure\s+link).*https?:\/\/[^\s]+`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi10-charter-roleplay-block", "action": "deny", "priority": 100, "message": "ASI-10: Rogue Agent — detected attempt to assume unauthorized technical or adversarial role"} if {
	regex.match(`(?i)act\s+as\s+(an?\s+)?(Linux|Windows|bash|Powershell|CLI|terminal|interpreter|unfiltered\s+AI|penetration\s+tester|security\s+researcher)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi10-charter-purpose-override", "action": "deny", "priority": 100, "message": "ASI-10: Rogue Agent — detected attempt to override the agent's core operational charter"} if {
	regex.match(`(?i)(ignore\s+your\s+purpose|redefine\s+charter|act\s+outside\s+scope|new\s+operational\s+constraints|no\s+longer\s+bound\s+by|disregard\s+core\s+directive)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi10-charter-autonomous-loop", "action": "deny", "priority": 100, "message": "ASI-10: Rogue Agent — detected attempt to instantiate an unbounded autonomous loop"} if {
	regex.match(`(?i)(run\s+indefinitely|loop\s+forever|do\s+not\s+stop\s+until|autonomous\s+mode|without\s+asking\s+for\s+permission|bypass\s+human\s+approval)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "financial-block-pci-credit-card", "action": "deny", "priority": 100, "message": "ASI-01/06: PCI DSS: Credit card number pattern detected in output"} if {
	regex.match(`\b(?:\d[ -]*?){13,16}\b`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "financial-block-pci-cvv", "action": "deny", "priority": 100, "message": "ASI-01/06: PCI DSS: CVV/CVC pattern detected in output"} if {
	regex.match(`(?i)(cvv|cvc|security\s*code)[:\s]*\d{3,4}`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi06-block-pii-ssn", "action": "deny", "priority": 100, "message": "ASI-01/06: PII: Social Security Number pattern detected in output"} if {
	regex.match(`\b\d{3}[\s.-]?\d{2}[\s.-]?\d{4}\b`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "financial-block-iban", "action": "deny", "priority": 100, "message": "ASI-01/06: AML: IBAN pattern detected in output"} if {
	regex.match(`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "financial-audit-swift-bic", "action": "warn", "priority": 80, "message": "ASI-01/06: AML: Possible SWIFT/BIC code detected. Subject to SOC 2 (365d+) retention."} if {
	regex.match(`\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi03-block-credentials-in-output", "action": "deny", "priority": 100, "message": "ASI-02/03: Security: Credential pattern detected in output"} if {
	regex.match(`(?i)(api[_-]?key|password|secret|token|bearer)[:\s=]+\S{8,}`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi01-integrity-shipping-guardrail", "action": "deny", "priority": 100, "message": "ASI-01/02: Business Integrity — unauthorized shipping policy override attempt detected"} if {
	regex.match(`(?i)(free\s+shipping|shipping\s+(cost|policy|method)|customs\s+fee|delivery\s+window|expedite\s+delivery|waive\s+shipping)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi01-integrity-fraud-guardrail", "action": "deny", "priority": 100, "message": "ASI-01/02: Business Integrity — unauthorized policy override or fraud pretext detected"} if {
	regex.match(`(?i)(waive\s+fee|late\s+fee|restocking\s+fee|shipping\s+(cost|policy)|return\s+window|override\s+policy|bypass\s+receipt|secret\s+(discount|promo)|promo\s+code|coupon\s+code|manual\s+refund|void\s+payment|goodwill\s+gesture|loyalty\s+recovery)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "financial-sox-sod-block", "action": "deny", "priority": 95, "message": "ASI-03: SOX: Segregation of Duties. Agent cannot self-approve transactions."} if {
	regex.match(`^(approve_)`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "financial-dora-incident-escalation", "action": "deny", "priority": 98, "message": "ASI-08: DORA: Critical security incident pattern. High-severity escalation."} if {
	regex.match(`^(disable_security|reset_firewall|bypass_)`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "financial-cost-ceiling", "action": "warn", "priority": 85, "message": "ASI-08: FinOps: Approaching cost ceiling threshold."} if {
	to_number(object.get(context, "token_count", 0)) > 5000
}

candidates contains {"name": "financial-audit-transaction-actions", "action": "warn", "priority": 85, "message": "ASI-08: SOX: Financial transaction action. Subject to SOC 2 (365d+) audit retention."} if {
	regex.match(`^(transfer_|payment_|trade_|wire_|settle_)`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "financial-block-bulk-transactions", "action": "deny", "priority": 95, "message": "ASI-01/06: AML: Bulk transaction operations require explicit authorization"} if {
	regex.match(`^(batch_transfer|bulk_payment|mass_trade)`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "financial-allow-read-operations", "action": "allow", "priority": 50, "message": ""} if {
	regex.match(`^(read_|search_|lookup_|list_|get_|calculate_|analyze_)`, sprintf("%v", [object.get(context, "action", 0)]))
}

max_priority := max([candidate.priority | candidate := candidates[_]]) if count(candidates) > 0

winner_names := sort([candidate.name | candidate := candidates[_]; candidate.priority == max_priority]) if count(candidates) > 0

winner := candidate if {
	count(candidates) > 0
	candidate := candidates[_]
	candidate.name == winner_names[0]
}

result := {
	"decision": winner.action,
	"reason": winner.name,
	"message": winner.message,
} if count(candidates) > 0

result := {
	"decision": "deny",
	"reason": "default_deny",
} if count(candidates) == 0
