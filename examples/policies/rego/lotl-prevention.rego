# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

package agt.examples.lotl

import rego.v1

target_text := lower(json.marshal(input.policy_target.value))

denials contains "Potential remote code execution through a piped download" if {
	regex.match(`(curl|wget|powershell)\\s+.*(-s|-fssl|-enc|downloadstring).*\\|.*(bash|sh|python|iex)`, target_text)
}

denials contains "Unauthorized access to sensitive system data" if {
	regex.match(`(/etc/shadow|/etc/passwd|~/.ssh/id_rsa|~/.aws/credentials|/var/run/docker.sock|/etc/kubernetes/admin.conf)`, target_text)
}

result := {
	"decision": "deny",
	"reason": concat("; ", sort([reason | reason := denials[_]])),
} if count(denials) > 0

result := {
	"decision": "allow",
	"reason": "No living-off-the-land pattern matched",
} if count(denials) == 0
