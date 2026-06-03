# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# AGT stock egress gate. Hosts use `input.tool.security_labels` to record the
# domains a tool sink is permitted to reach. When the host annotates the
# snapshot with the destination of a tool call, this library denies any
# destination that the allowlist does not cover. Wildcards follow glob.match
# semantics so callers can list `*.example.com` style patterns.
# `rules.destination_paths` lets callers specify where to look for the
# destination in the policy input.

package agt.egress

import rego.v1

default_destination_paths := [
	["snapshot", "tool_call", "args", "url"],
	["snapshot", "tool_call", "args", "endpoint"],
	["snapshot", "tool_call", "args", "host"],
	["snapshot", "tool_call", "args", "domain"],
	["annotations", "egress", "destination"],
]

destination(rules) := value if {
	paths := destination_paths(rules)
	some path in paths
	value := resolve(input, path)
	is_string(value)
}

destination_paths(rules) := paths if {
	paths := rules.destination_paths
	is_array(paths)
	count(paths) > 0
} else := default_destination_paths

resolve(obj, path) := value if {
	walk(obj, [path, value])
}

host_of(url) := value if {
	is_string(url)
	contains(url, "://")
	after_scheme := split(url, "://")[1]
	value := split(split(after_scheme, "/")[0], ":")[0]
} else := value if {
	is_string(url)
	not contains(url, "://")
	value := split(split(url, "/")[0], ":")[0]
}

allowlist(rules) := value if {
	value := rules.allowlist
	is_array(value)
} else := value if {
	value := input.tool.security_labels
	is_array(value)
} else := []

allowed(dest, patterns) if {
	host := host_of(dest)
	some pattern in patterns
	glob.match(pattern, [".", "/"], host)
}

deny_egress(rules) := verdict if {
	dest := destination(rules)
	patterns := allowlist(rules)
	not allowed(dest, patterns)
	verdict := {
		"decision": "deny",
		"reason": "egress_destination_not_allowed",
		"message": sprintf("destination %v not in allowlist %v", [host_of(dest), patterns]),
	}
}
