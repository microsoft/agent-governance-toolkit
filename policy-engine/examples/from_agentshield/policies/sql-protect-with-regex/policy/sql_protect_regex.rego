# Ported from AgentShield examples/policies/sql-protect-with-regex.yaml
#
# Blocks destructive writes to production tables via the SQL MCP server using
# regex only (no external delegates). AgentShield's predicates leaned on PCRE
# negative lookahead (`(?!_staging|...)`); Rego uses RE2, which has no
# lookahead, so the "targets production" test is reformulated as: a statement
# targets production unless it carries an explicit non-production marker
# (a `_staging` / `_sandbox` / `_tmp` table suffix, or a `dev.` / `sandbox.`
# schema prefix). Same intent, RE2-safe.
package agent_control_specification.sql_protect_regex

import rego.v1

default verdict := {"decision": "allow"}
default input_verdict := {"decision": "allow"}
default pre_tool_call_verdict := {"decision": "allow"}

# Generic dispatch (kept for parity with the manifest's top-level query).
verdict := input_verdict if input.intervention_point == "input"

verdict := pre_tool_call_verdict if input.intervention_point == "pre_tool_call"

# ---------------------------------------------------------------------------
# Stage 1 (input): warn — don't block — when the user prompt itself looks like
# it is steering toward destructive SQL on production.
# ---------------------------------------------------------------------------
input_verdict := {
	"decision": "warn",
	"reason": "destructive_sql_in_prompt",
	"message": "User input contains destructive SQL targeting production-sounding names.",
} if {
	input.intervention_point == "input"
	regex.match(`(?i)\b(drop|truncate|delete\s+from)\b.*\b(prod|production)\b`, input.policy_target.value.text)
}

# ---------------------------------------------------------------------------
# Stage 2 (pre_tool_call): deterministic gates, severity-ordered else-chain so
# OPA never sees conflicting complete-rule assignments.
#   1. Hard block: destructive ops against production (never allowed).
#   2. Free-form writes to production require manager approval (escalate).
#   3. Structured writes to production require manager approval (escalate).
# ---------------------------------------------------------------------------
pre_tool_call_verdict := {
	"decision": "deny",
	"reason": "prod_destructive_forbidden",
	"message": "DELETE / TRUNCATE / DROP against a production table is forbidden.",
} if {
	is_execute_sql
	sql_is_destructive
	sql_targets_prod
} else := {
	"decision": "escalate",
	"reason": "prod_write_requires_approval",
	"message": "Write to a production table requires manager approval.",
} if {
	is_execute_sql
	sql_is_write
	sql_targets_prod
} else := {
	"decision": "escalate",
	"reason": "prod_write_requires_approval",
	"message": "Write to a production table requires manager approval.",
} if {
	is_structured_write
	structured_targets_prod
} else := {
	"decision": "warn",
	"reason": "sql_intent_review",
	"message": "Proposed SQL deviates from the user's stated intent.",
} if {
	is_sql_tool
	input.annotations.sql_intent.deviates == true
}

# Stage 3 (LLM intent review) applies to the write-capable SQL tools.
is_sql_tool if input.tool.name == "mssql.execute_sql"

is_sql_tool if input.tool.name == "mssql.insert_data"

is_sql_tool if input.tool.name == "mssql.update_data"

# --- free-form execute_sql predicates --------------------------------------
is_execute_sql if input.tool.name == "mssql.execute_sql"

sql_query := lower(input.policy_target.value.query)

sql_is_destructive if regex.match(`(?is)\b(delete\s+from|truncate\s+table|drop\s+(table|database|schema))\b`, sql_query)

sql_is_write if regex.match(`(?is)\b(insert\s+into|update\s+|merge\s+into|delete\s+from|truncate\s+table|drop\s+(table|database|schema)|alter\s+table)\b`, sql_query)

# Extract every table token that follows a DML verb and classify each one
# INDIVIDUALLY. RE2 has no lookahead, so rather than a single negative-lookahead
# pattern (PCRE) we capture each target and treat the statement as touching
# production unless EVERY captured target carries an explicit non-prod marker.
# This is conservative: a mixed statement (one prod + one staging target) is
# still treated as production.
sql_targets contains t if {
	some m in regex.find_all_string_submatch_n(`(?i)\b(?:from|join|into|update|truncate\s+table|delete\s+from|drop\s+(?:table|database|schema))\s+([a-z0-9_.]+)`, sql_query, -1)
	t := m[count(m) - 1]
}

token_is_nonprod(t) if endswith(t, "_staging")

token_is_nonprod(t) if endswith(t, "_sandbox")

token_is_nonprod(t) if endswith(t, "_tmp")

token_is_nonprod(t) if startswith(t, "dev.")

token_is_nonprod(t) if startswith(t, "sandbox.")

sql_targets_prod if {
	some t in sql_targets
	not token_is_nonprod(t)
}

# --- structured insert_data / update_data predicates -----------------------
is_structured_write if input.tool.name == "mssql.insert_data"

is_structured_write if input.tool.name == "mssql.update_data"

structured_table := lower(input.policy_target.value.table)

structured_targets_prod if {
	structured_table
	not token_is_nonprod(structured_table)
}
