# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.examples.templates.edu_k12

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

candidates contains {"name": "asi01-prompt-injection-override", "action": "deny", "priority": 100, "message": "ASI-01: Prompt Injection — instruction override attempt detected"} if {
	regex.match(`(?i)(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above|earlier|original|system)\s+(instructions?|prompts?|rules?|guidelines?|directives?|constraints?)`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "asi01-prompt-injection-role-hijack", "action": "deny", "priority": 100, "message": "ASI-01: Prompt Injection — role hijack attempt detected"} if {
	regex.match(`(?i)(you\s+are\s+now|from\s+now\s+on|switch\s+to|enter)\s+(DAN|jailbreak|evil|unrestricted|god|adult|no[- ]filter)\s*(mode)?`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "asi01-prompt-injection-delimiter", "action": "deny", "priority": 100, "message": "ASI-01: Prompt Injection — raw delimiter or control token injection detected"} if {
	regex.match(`(?i)(\[SYSTEM\]|\[INST\]|<\|im_start\|>|<\|system\|>|###\s*(system|instruction|prompt)|\{\{system_prompt\}\})`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "asi01-prompt-injection-jailbreak", "action": "deny", "priority": 100, "message": "ASI-01: Prompt Injection — jailbreak or DAN-mode attempt detected"} if {
	regex.match(`(?i)(DAN\s+mode|do\s+anything\s+now|jailbreak|bypass\s+(safety|alignment|filter|guardrail|restriction)|act\s+as\s+(an?\s+)?unrestricted)`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "edu-asi01-homework-bypass", "action": "deny", "priority": 95, "message": "ASI-01: Academic Integrity — request for direct homework or exam completion is prohibited. The agent provides guided assistance only."} if {
	regex.match(`(?i)(write\s+(the\s+)?(whole|entire|complete|full)\s+(essay|assignment|homework|paper|report|answer)|do\s+(my|the)\s+(homework|assignment|exam|quiz|test)\s+for\s+me|give\s+me\s+(all\s+the\s+)?answers?\s+(to|for))`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "edu-asi01-content-filter-bypass", "action": "deny", "priority": 100, "message": "ASI-01: CIPA — fictional framing to bypass content filter detected"} if {
	regex.match(`(?i)(pretend|imagine|roleplay|let's\s+say|hypothetically|in\s+a\s+story|as\s+a\s+character|in\s+fiction).*(violence|weapon|drug|adult|explicit|sex|gore|hate)`, sprintf("%v", [object.get(context, "input", 0)]))
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

candidates contains {"name": "edu-asi02-block-grade-mutation", "action": "deny", "priority": 100, "message": "ASI-02: FERPA — grade mutation via agent tool is denied. Use the authenticated educator portal."} if {
	regex.match(`^(update_grade|set_grade|modify_grade|change_grade|override_grade|post_grade)$`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "edu-asi02-block-record-write", "action": "deny", "priority": 100, "message": "ASI-02: FERPA — direct student record writes are denied. Authorized changes must go through the SIS with two-factor educator authentication."} if {
	regex.match(`^(write_student_record|update_enrollment|modify_iep|edit_discipline_record|amend_transcript)$`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "asi03-block-privilege-escalation", "action": "deny", "priority": 100, "message": "ASI-03: Privilege Abuse — agent cannot self-elevate permissions"} if {
	regex.match(`^(elevate_|grant_|modify_permissions|change_role|sudo_|set_admin)`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "asi03-block-credential-access", "action": "deny", "priority": 100, "message": "ASI-03: Privilege Abuse — direct credential access is denied"} if {
	regex.match(`^(read_secret|access_vault|get_api_key|dump_credentials)$`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "asi03-account-mfa-bypass", "action": "deny", "priority": 100, "message": "ASI-03: Identity Abuse — MFA bypass attempt detected"} if {
	regex.match(`(?i)(bypass|skip|disable|remove|turn\s+off)\s+(MFA|2FA|two[- ]factor|multi[- ]factor|authentication)`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "asi03-account-admin-promotion", "action": "deny", "priority": 100, "message": "ASI-03: Identity Abuse — role promotion attempt detected"} if {
	regex.match(`(?i)(make|set|grant|promote|give)\s+(me|this\s+user|account)\s+(to\s+|an?\s+)?(admin|root|superuser|owner|elevated|teacher|instructor)`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "asi03-account-password-reset", "action": "deny", "priority": 100, "message": "ASI-03: Identity Abuse — bulk or third-party password reset attempt detected"} if {
	regex.match(`(?i)(reset|change|update)\s+(the\s+)?(password|credentials?)\s+(for|of)\s+(?!my\b)(all|every|another|other|the\s+(teacher|admin|student))`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "asi03-account-audit-tampering", "action": "deny", "priority": 100, "message": "ASI-03: Identity Abuse — audit trail tampering attempt detected"} if {
	regex.match(`(?i)(delete|clear|purge|wipe|remove|hide)\s+(the\s+)?(audit|access|security|attendance)\s+(log|trail|record|history)`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "edu-asi03-block-student-impersonation", "action": "deny", "priority": 100, "message": "ASI-03: FERPA — agent cannot impersonate or act on behalf of a student record owner without explicit parental/guardian consent"} if {
	regex.match(`(?i)(log\s+in|sign\s+in|access|act|respond)\s+(as|for|on\s+behalf\s+of)\s+(student|pupil|learner|minor)`, sprintf("%v", [object.get(context, "input", 0)]))
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

candidates contains {"name": "asi05-block-dynamic-eval", "action": "deny", "priority": 100, "message": "ASI-05: Code Execution — dangerous function detected in output"} if {
	regex.match(`(?i)(exec\(|eval\(|compile\(|__import__|subprocess|os\.system|os\.popen|shutil\.rmtree)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi05-sandbox-anti-pattern-detection", "action": "deny", "priority": 100, "message": "ASI-05: Code Execution — sandbox anti-pattern detected in generated code"} if {
	regex.match(`(?i)(import\s+subprocess|import\s+os|import\s+shutil|from\s+os\s+import|__builtins__|globals\(\)|locals\(\))`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi06-context-budget-limit", "action": "deny", "priority": 90, "message": "ASI-06: Context budget exceeded — conservative limit enforced for K-12 agent interactions"} if {
	to_number(object.get(context, "token_count", 0)) > 3072
}

candidates contains {"name": "asi06-block-context-manipulation", "action": "deny", "priority": 100, "message": "ASI-06: Context Integrity — attempt to manipulate agent memory or override system instructions detected"} if {
	regex.match(`(?i)(inject|poison|corrupt|overwrite|replace)\s+(the\s+)?(context|memory|history|knowledge|retrieval|embedding|vector)`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "edu-asi06-block-curriculum-poisoning", "action": "deny", "priority": 100, "message": "ASI-06: FERPA/CIPA — curriculum or knowledge base poisoning attempt detected"} if {
	regex.match(`(?i)(add|insert|store|remember|update)\s+(to\s+)?(your\s+)?(memory|knowledge|curriculum|database).*(incorrect|wrong|false|fake|alternative\s+fact)`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "asi07-hidden-channel-guardrail", "action": "deny", "priority": 100, "message": "ASI-07: Communication Manipulation — hidden channel signaling or secret handshake detected"} if {
	regex.match(`(?i)(coord\.[a-zA-Z0-9]{8,}|SIG_SYNC_[a-fA-F0-9]{4,}|\{\{HANDSHAKE\}\}|SECRET_CHANNEL)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi08-session-tool-call-limit", "action": "deny", "priority": 85, "message": "ASI-08: Session tool call limit exceeded — circuit breaker engaged (K-12 conservative limit)"} if {
	to_number(object.get(context, "tool_call_count", 0)) > 10
}

candidates contains {"name": "asi08-swarm-heat-guardrail", "action": "warn", "priority": 90, "message": "ASI-08: Cascading Failure — swarm coordination depth auditing engaged"} if {
	to_number(object.get(context, "tool_call_depth", 0)) > 3
}

candidates contains {"name": "asi09-trust-urgency-pretext", "action": "deny", "priority": 95, "message": "ASI-09: Trust Exploitation — manufactured urgency pretext detected"} if {
	regex.match(`(?i)(\burgent\b|\bimmediate\b|act\s+now|deadline|expire\s+(soon|in)|last\s+chance|your\s+account\s+will\s+be)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi09-trust-phishing-link", "action": "deny", "priority": 100, "message": "ASI-09: Trust Exploitation — suspected phishing or credential harvesting link detected"} if {
	regex.match(`(?i)(verify|login|authenticate|secure\s+link|click\s+here).*https?:\/\/[^\s]+`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "edu-asi09-parental-impersonation", "action": "warn", "priority": 90, "message": "ASI-09: COPPA/FERPA — unverified parental consent claim. Flag for human review before releasing student data."} if {
	regex.match(`(?i)(I\s+am|I'm)\s+(the\s+)?(parent|guardian|mother|father|caregiver).*(consent|allow|approve|authorize|permit).*?(data|record|share|access|release|information)`, sprintf("%v", [object.get(context, "input", 0)]))
}

candidates contains {"name": "edu-asi09-block-minor-contact-info", "action": "deny", "priority": 100, "message": "ASI-09: COPPA — contact or identifying information for a minor must not appear in agent output"} if {
	regex.match(`(?i)(student|minor|child|pupil).*(home\s+address|phone\s+number|cell\s+(number|phone)|email\s+address|date\s+of\s+birth|dob)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi10-charter-roleplay-block", "action": "deny", "priority": 100, "message": "ASI-10: Rogue Agent — attempt to assume unauthorized role detected"} if {
	regex.match(`(?i)act\s+as\s+(an?\s+)?(Linux|Windows|bash|Powershell|CLI|terminal|interpreter|unfiltered\s+AI|adult\s+(tutor|persona)|unrestricted\s+(teacher|bot|assistant))`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi10-charter-purpose-override", "action": "deny", "priority": 100, "message": "ASI-10: Rogue Agent — attempt to override the agent's core operational charter detected"} if {
	regex.match(`(?i)(ignore\s+your\s+purpose|redefine\s+charter|act\s+outside\s+scope|new\s+operational\s+constraints|no\s+longer\s+bound\s+by|disregard\s+core\s+directive)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi10-charter-autonomous-loop", "action": "deny", "priority": 100, "message": "ASI-10: Rogue Agent — attempt to instantiate an unbounded autonomous loop detected"} if {
	regex.match(`(?i)(run\s+indefinitely|loop\s+forever|do\s+not\s+stop\s+until|autonomous\s+mode|without\s+asking\s+for\s+permission|bypass\s+human\s+approval)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "asi06-block-pii-ssn", "action": "deny", "priority": 100, "message": "ASI-01/06: COPPA/FERPA: Social Security Number pattern detected in output"} if {
	regex.match(`\b\d{3}[\s.-]?\d{2}[\s.-]?\d{4}\b`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "edu-block-student-id", "action": "deny", "priority": 100, "message": "ASI-01/06: FERPA: Student ID number detected in output — education record identifier must not be exposed"} if {
	regex.match(`(?i)(student[\s_-]?id|sis[\s_-]?id|pupil[\s_-]?number)[:\s]*[A-Z0-9]{5,}`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "edu-block-phi-iep", "action": "deny", "priority": 100, "message": "ASI-01/06: FERPA/IDEA: IEP or disability-related education record detected — requires explicit authorized access"} if {
	regex.match(`(?i)(IEP|individualized\s+education\s+plan|504\s+plan|special\s+education\s+(services?|eligibility|placement))`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "edu-block-disciplinary-record", "action": "deny", "priority": 100, "message": "ASI-01/06: FERPA: Disciplinary record content detected in output — access requires FERPA authorization"} if {
	regex.match(`(?i)(disciplin(e|ary)\s+(record|action|incident|file)|suspension|expulsion|behavioral\s+incident)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "edu-cipa-block-adult-content", "action": "deny", "priority": 100, "message": "ASI-01/06: CIPA: Adult or obscene content is prohibited on school internet systems"} if {
	regex.match(`(?i)(pornograph|obscen(e|ity)|sexually\s+explicit|adult\s+content|explicit\s+material|nude|nudity|hentai|erotic)`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "edu-cipa-block-violence-content", "action": "deny", "priority": 100, "message": "ASI-01/06: CIPA: Harmful or violent instructional content is prohibited"} if {
	regex.match(`(?i)(how\s+to\s+(make|build|create|assemble)\s+(a\s+)?(bomb|weapon|explosive|gun|knife)|step[- ]by[- ]step\s+(instructions?|guide)\s+(to\s+)?(harm|attack|kill|make|build|create|assemble))`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "edu-block-credentials-in-output", "action": "deny", "priority": 100, "message": "ASI-02/03: Security: Credential pattern detected in output"} if {
	regex.match(`(?i)(api[_-]?key|password|secret|token|bearer)[:\s=]+\S{8,}`, sprintf("%v", [object.get(context, "output", 0)]))
}

candidates contains {"name": "edu-ferpa-audit-record-access", "action": "warn", "priority": 60, "message": "ASI-01/06: FERPA: Student record read access audit-logged per FERPA § 99.32 disclosure tracking requirements."} if {
	regex.match(`^(read_student_record|get_transcript|read_enrollment|fetch_grades|get_attendance)$`, sprintf("%v", [object.get(context, "action", 0)]))
}

candidates contains {"name": "edu-allow-curriculum-read", "action": "allow", "priority": 50, "message": ""} if {
	regex.match(`^(read_|search_|lookup_|list_|get_|summarize_|analyze_curriculum|fetch_lesson|get_assignment)`, sprintf("%v", [object.get(context, "action", 0)]))
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
