# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.examples.templates.general_saas

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

candidates contains {"name": "asi01-prompt-injection-override", "action": "deny", "priority": 100, "message": "ASI-01: Prompt Injection — detected instruction override attempt"} if {
	regex.match(`(?i)(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above|earlier|original|system)\s+(instructions?|prompts?|rules?|guidelines?|directives?|constraints?)`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "asi01-prompt-injection-role-hijack", "action": "deny", "priority": 100, "message": "ASI-01: Prompt Injection — detected role hijack attempt"} if {
	regex.match(`(?i)(you\s+are\s+now|from\s+now\s+on|switch\s+to|enter)\s+(DAN|jailbreak|evil|unrestricted|god)\s*(mode)?`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "asi01-prompt-injection-delimiter", "action": "deny", "priority": 100, "message": "ASI-01: Prompt Injection — detected raw delimiter / control token injection"} if {
	regex.match(`(?i)(\[SYSTEM\]|\[INST\]|<\|im_start\|>|<\|system\|>|###\s*(system|instruction|prompt)|\{\{system_prompt\}\})`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "asi01-prompt-injection-jailbreak", "action": "deny", "priority": 100, "message": "ASI-01: Prompt Injection — jailbreak or DAN-mode attempt detected"} if {
	regex.match(`(?i)(DAN\s+mode|do\s+anything\s+now|jailbreak|bypass\s+(safety|alignment|guardrails?|restrictions?)|act\s+as\s+(an?\s+)?unrestricted)`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "asi01-nested-swarm-guardrail", "action": "deny", "priority": 100, "message": "ASI-01: Prompt Injection — detected self-replication / nested swarm spawn attempt"} if {
	regex.match(`(?i)(spawn|fork|replicate|clone)\s+(a(n|nother)?\s+)?(copy|instance|agent|worker|thread)`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "asi02-block-shell-execution", "action": "deny", "priority": 100, "message": "ASI-02: Tool Misuse — direct shell execution is prohibited"} if {
	regex.match(`^(exec_shell|run_command|system_call|spawn_process)$`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "asi02-block-network-exfiltration", "action": "deny", "priority": 100, "message": "ASI-02: Tool Misuse — outbound data exfiltration blocked"} if {
	regex.match(`^(http_post|upload_file|send_data|webhook_call)$`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "asi02-block-destructive-operations", "action": "deny", "priority": 100, "message": "ASI-02: Tool Misuse — destructive data operations are prohibited"} if {
	regex.match(`^(delete_|drop_|truncate_|purge_|destroy_|wipe_)`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "asi02-block-database-mutation", "action": "deny", "priority": 100, "message": "ASI-02: Tool Misuse — direct schema mutation is prohibited. Use migration workflows."} if {
	regex.match(`^(alter_schema|create_table|modify_index)$`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "asi03-block-privilege-escalation", "action": "deny", "priority": 100, "message": "ASI-03: Privilege Abuse — agent cannot self-elevate permissions"} if {
	regex.match(`^(elevate_|grant_|modify_permissions|change_role|sudo_|set_admin)`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "asi03-block-credential-access", "action": "deny", "priority": 100, "message": "ASI-03: Privilege Abuse — direct credential access is denied"} if {
	regex.match(`^(read_secret|access_vault|get_api_key|dump_credentials)$`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "asi03-block-user-impersonation", "action": "deny", "priority": 100, "message": "ASI-03: Privilege Abuse — user impersonation is prohibited"} if {
	regex.match(`^(impersonate_user|switch_identity|act_as_user)$`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "asi03-account-mfa-bypass", "action": "deny", "priority": 100, "message": "ASI-03: Identity Abuse — MFA bypass attempt detected"} if {
	regex.match(`(?i)(bypass|skip|disable|remove|turn\s+off)\s+(MFA|2FA|two[- ]factor|multi[- ]factor|authentication)`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "asi03-account-admin-promotion", "action": "deny", "priority": 100, "message": "ASI-03: Identity Abuse — admin promotion attempt detected"} if {
	regex.match(`(?i)(make|set|grant|promote|give)\s+(me|this\s+user|account)\s+(to\s+)?(admin|root|superuser|owner|elevated)`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "asi03-account-password-reset", "action": "deny", "priority": 100, "message": "ASI-03: Identity Abuse — bulk or third-party password reset attempt detected"} if {
	regex.match(`(?i)(reset|change|update)\s+(the\s+)?(password|credentials?)\s+(for|of)\s+(?!my\b)(all|every|another|other|the\s+admin)`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "asi03-account-audit-tampering", "action": "deny", "priority": 100, "message": "ASI-03: Identity Abuse — audit trail tampering attempt detected"} if {
	regex.match(`(?i)(delete|clear|purge|wipe|remove|hide)\s+(the\s+)?(audit|access|security)\s+(log|trail|record|history)`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "asi04-supply-chain-tool-enumeration", "action": "deny", "priority": 95, "message": "ASI-04: Supply Chain — tool/capability enumeration attempt detected"} if {
	regex.match(`(?i)(list|enumerate|show|reveal|dump)\s+(all\s+)?(available\s+)?(tools?|functions?|capabilities?|plugins?|extensions?)`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "asi04-supply-chain-dependency-poisoning", "action": "deny", "priority": 100, "message": "ASI-04: Supply Chain — dependency injection/poisoning attempt detected"} if {
	regex.match(`(?i)(install|add|import|load|require|pip\s+install|npm\s+install)\s+[a-zA-Z0-9_-]+`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "asi04-supply-chain-plugin-hijack", "action": "deny", "priority": 100, "message": "ASI-04: Supply Chain — plugin/dependency hijack attempt detected"} if {
	regex.match(`(?i)(replace|swap|override|modify|patch)\s+(the\s+)?(plugin|extension|module|tool|dependency)`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "asi04-supply-chain-config-mutation", "action": "deny", "priority": 95, "message": "ASI-04: Supply Chain — configuration mutation attempt detected"} if {
	regex.match(`(?i)(modify|change|update|alter|overwrite)\s+(the\s+)?(config|configuration|settings?|environment|env\s+var)`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "asi05-block-code-execution", "action": "deny", "priority": 100, "message": "ASI-05: Code Execution — dynamic code execution is prohibited"} if {
	regex.match(`^(eval|exec|compile|run_code|execute_script)$`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "asi05-block-dynamic-eval", "action": "deny", "priority": 100, "message": "ASI-05: Code Execution — detected dangerous function in output"} if {
	regex.match(`(?i)(exec\(|eval\(|compile\(|__import__|subprocess|os\.system|os\.popen|shutil\.rmtree)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi05-sandbox-anti-pattern-detection", "action": "deny", "priority": 100, "message": "ASI-05: Code Execution — sandbox anti-pattern detected in generated code"} if {
	regex.match(`(?i)(import\s+subprocess|import\s+os|import\s+shutil|from\s+os\s+import|__builtins__|globals\(\)|locals\(\))`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi05-block-ssh", "action": "deny", "priority": 100, "message": "ASI-05: Code Execution — remote execution via SSH is prohibited"} if {
	regex.match(`^(ssh_connect|remote_exec|sftp_upload)$`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "asi06-context-budget-limit", "action": "deny", "priority": 90, "message": "ASI-06: Context budget exceeded — limit enforced to prevent memory poisoning"} if {
	to_number(object.get(context, "token_count", 0)) > 8192
}

candidates contains {"name": "asi06-block-context-manipulation", "action": "deny", "priority": 100, "message": "ASI-06: Context Integrity — detected attempt to manipulate agent memory or override system instructions"} if {
	regex.match(`(?i)(inject|poison|corrupt|overwrite|replace)\s+(the\s+)?(context|memory|history|knowledge|retrieval|embedding|vector)`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "asi07-hidden-channel-guardrail", "action": "deny", "priority": 100, "message": "ASI-07: Communication Manipulation — detected hidden channel signaling or secret handshake"} if {
	regex.match(`(?i)(coord\.[a-zA-Z0-9]{8,}|SIG_SYNC_[a-fA-F0-9]{4,}|\{\{HANDSHAKE\}\}|SECRET_CHANNEL)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi08-session-tool-call-limit", "action": "deny", "priority": 85, "message": "ASI-08: Session tool call limit exceeded — circuit breaker engaged"} if {
	to_number(object.get(context, "tool_call_count", 0)) > 50
}

candidates contains {"name": "asi08-swarm-heat-guardrail", "action": "warn", "priority": 90, "message": "ASI-08: Cascading Failure — swarm heat threshold reached; coordination depth auditing engaged"} if {
	to_number(object.get(context, "tool_call_depth", 0)) > 5
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

candidates contains {"name": "asi06-block-pii-ssn", "action": "deny", "priority": 100, "message": "ASI-01/06: PII: Social Security Number pattern detected in output"} if {
	regex.match(`\b\d{3}[\s.-]?\d{2}[\s.-]?\d{4}\b`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "saas-block-pii-email-bulk", "action": "deny", "priority": 90, "message": "ASI-01/06: PII: Bulk email address pattern detected — possible data exfiltration"} if {
	regex.match(`([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}[,;\s]+){3,}`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi03-block-credentials-in-output", "action": "deny", "priority": 100, "message": "ASI-02/03: Security: Credential pattern detected in output"} if {
	regex.match(`(?i)(api[_-]?key|password|secret|token|bearer)[:\s=]+\S{8,}`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "saas-egress-domain-allowlist", "action": "warn", "priority": 85, "message": "ASI-02: SaaS: Egress to non-allowlisted domain detected."} if {
	regex.match(`https?://(?!(api\.github\.com|.*\.microsoft\.com|.*\.trusted-saas\.com))`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "saas-cost-control-ceiling", "action": "deny", "priority": 95, "message": "ASI-08: FinOps: Hard cost ceiling reached for SaaS tier."} if {
	to_number(object.get(context, "token_count", 0)) > 10000
}

candidates contains {"name": "saas-allow-read-operations", "action": "allow", "priority": 50, "message": ""} if {
	regex.match(`^(read_|search_|lookup_|list_|get_|summarize|analyze_)`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "saas-allow-write-with-audit", "action": "warn", "priority": 60, "message": "ASI-01/06: GDPR: Write operations audit-logged according to GDPR data retention schedules."} if {
	regex.match(`^(write_|create_|send_email)`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "asi01-integrity-shipping-guardrail", "action": "deny", "priority": 100, "message": "ASI-01/02: Business Integrity — unauthorized shipping policy override attempt detected"} if {
	regex.match(`(?i)(free\s+shipping|shipping\s+(cost|policy|method)|customs\s+fee|delivery\s+window|expedite\s+delivery|waive\s+shipping)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi01-integrity-fraud-guardrail", "action": "deny", "priority": 100, "message": "ASI-01/02: Business Integrity — unauthorized policy override or fraud pretext detected"} if {
	regex.match(`(?i)(waive\s+fee|late\s+fee|restocking\s+fee|shipping\s+(cost|policy)|return\s+window|override\s+policy|bypass\s+receipt|secret\s+(discount|promo)|promo\s+code|coupon\s+code|manual\s+refund|void\s+payment|goodwill\s+gesture|loyalty\s+recovery)`, sprintf("%v", [object.get(context, "output", 0)]))
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
