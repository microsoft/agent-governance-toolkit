package agentmesh

# Default: deny all actions unless explicitly allowed
default allow = false

# Admin agents can do anything
allow {
    input.agent.role == "admin"
}

# Analyst agents can read data
allow {
    input.agent.role == "analyst"
    input.action == "read"
}

# Deny actions involving PII unless the agent has pii_access
default deny_pii = false
deny_pii {
    input.data.contains_pii == "true"
    not input.agent.pii_access
}

# Deny export actions from untrusted agents
default deny_export = false
deny_export {
    input.action == "export"
    input.agent.trust_score != "high"
}
