# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.examples.deerflow

import rego.v1

context := input.policy_target.value

candidates contains {"name": "deny-pii-email", "priority": 250, "message": "PII detected - email address found in tool input"} if {
	regex.match(`[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+`, sprintf("%v", [object.get(context, "message", "")]))
}

candidates contains {"name": "deny-pii-phone", "priority": 250, "message": "PII detected - phone number found in tool input"} if {
	regex.match(`(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`, sprintf("%v", [object.get(context, "message", "")]))
}

candidates contains {"name": "deny-pii-ssn", "priority": 250, "message": "PII detected - SSN-like pattern found in tool input"} if {
	regex.match(`\b\d{3}-\d{2}-\d{4}\b`, sprintf("%v", [object.get(context, "message", "")]))
}

candidates contains {"name": "deny-prompt-injection-ignore-instructions", "priority": 240, "message": "Prompt injection detected - attempt to override instructions"} if {
	regex.match(`(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|above|prior|earlier)\s+(instructions?|rules?|policies?|constraints?)`, sprintf("%v", [object.get(context, "message", "")]))
}

candidates contains {"name": "deny-prompt-injection-jailbreak", "priority": 240, "message": "Prompt injection detected - jailbreak-style request"} if {
	regex.match(`(?i)(you\s+are\s+now|act\s+as\s+if|pretend\s+(you\s+are|to\s+be)|from\s+now\s+on\s+you)`, sprintf("%v", [object.get(context, "message", "")]))
}

candidates contains {"name": "deny-system-prompt-leak", "priority": 240, "message": "Prompt injection detected - system prompt extraction request"} if {
	regex.match(`(?i)(reveal|show|display|print|output)\s+(your\s+)?(system\s+prompt|instructions|rules|policy)`, sprintf("%v", [object.get(context, "message", "")]))
}

candidates contains {"name": "deny-base64-execution", "priority": 230, "message": "Encoded payload execution request is denied"} if {
	regex.match(`(?i)(decode|execute|eval|run)\s+(this\s+)?base64`, sprintf("%v", [object.get(context, "message", "")]))
}

candidates contains {"name": "deny-workflow-bypass-review", "priority": 220, "message": "Workflow bypass request is denied"} if {
	regex.match(`(?i)(skip|bypass|circumvent)\s+(the\s+)?(editor|review|approval)`, sprintf("%v", [object.get(context, "message", "")]))
}

candidates contains {"name": "deny-direct-publish-without-review", "priority": 220, "message": "Direct publish without review is denied"} if {
	regex.match(`(?i)publish\s+(directly|immediately|now)\s+(without|skipping)`, sprintf("%v", [object.get(context, "message", "")]))
}

candidates contains {"name": "deny-destructive-sql", "priority": 210, "message": "Destructive SQL statement detected"} if {
	regex.match(`\bDROP\s+(TABLE|DATABASE)\b`, sprintf("%v", [object.get(context, "message", "")]))
}

candidates contains {"name": "deny-dangerous-bash-rm-rf", "priority": 200, "message": "Dangerous shell command detected"} if {
	regex.match(`\brm\s+-rf\b`, sprintf("%v", [object.get(context, "message", "")]))
}

candidates contains {"name": "deny-internal-resource", "priority": 180, "message": "Internal resource access is denied"} if {
	contains(sprintf("%v", [object.get(context, "message", "")]), "internal")
}

candidates contains {"name": "deny-secrets-access", "priority": 180, "message": "Secret resource access is denied"} if {
	contains(sprintf("%v", [object.get(context, "message", "")]), "secrets")
}

candidates contains {"name": "deny-credentials-access", "priority": 180, "message": "Credential access is denied"} if {
	contains(sprintf("%v", [object.get(context, "message", "")]), "credentials")
}

candidates contains {"name": "deny-sensitive-write-path", "priority": 170, "message": "Writes to sensitive system paths are denied"} if {
	regex.match(`^/(etc|var|usr|bin|sbin)(/|$)`, sprintf("%v", [object.get(context, "path", "")]))
}

candidates contains {"name": "deny-cloud-metadata-ip", "priority": 160, "message": "Cloud metadata endpoint IP access is denied"} if {
	regex.match(`(?i)^(?:https?://)?(?:169\.254\.169\.254|169\.254\.170\.2|100\.100\.100\.200|\[?fd00:ec2::254\]?)(?::\d+)?(?:/|$)`, sprintf("%v", [object.get(context, "url", "")]))
}

candidates contains {"name": "deny-cloud-metadata-host", "priority": 150, "message": "Cloud metadata host access is denied"} if {
	contains(sprintf("%v", [object.get(context, "host", "")]), "metadata.google.internal")
}

max_priority := max([candidate.priority | candidate := candidates[_]]) if count(candidates) > 0

winning_names := sort([candidate.name | candidate := candidates[_]; candidate.priority == max_priority]) if count(candidates) > 0

winner := candidate if {
	count(candidates) > 0
	candidate := candidates[_]
	candidate.name == winning_names[0]
}

result := {"decision": "deny", "reason": winner.name, "message": winner.message} if count(candidates) > 0
result := {"decision": "allow", "reason": "safe"} if count(candidates) == 0
