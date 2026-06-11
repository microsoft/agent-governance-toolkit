# Ported from AgentShield examples/policies/sql-protect-with-delegate.yaml
#
# Snapshot contract: AgentShield delegate variables are host-supplied ACS state.
# The host supplies snapshot.prod_tables as lowercased fully-qualified table
# names and snapshot.parsed_sql as {operation, tables, is_ddl, has_where} for
# mssql.execute_sql. Missing delegate snapshots fail closed for execute_sql.
package agent_control_specification.sql_protect_delegate

import rego.v1

default verdict := {"decision": "allow"}
default input_verdict := {"decision": "allow"}
default pre_tool_call_verdict := {"decision": "allow"}

verdict := input_verdict if input.intervention_point == "input"
verdict := pre_tool_call_verdict if input.intervention_point == "pre_tool_call"

snapshot := object.get(input, "snapshot", {})
args := object.get(object.get(input, "policy_target", {}), "value", {})
prod_tables := object.get(snapshot, "prod_tables", [])
parsed_sql := object.get(snapshot, "parsed_sql", {})
operation := object.get(parsed_sql, "operation", "")
parsed_tables := object.get(parsed_sql, "tables", [])
input_text := object.get(object.get(input.policy_target, "value", {}), "text", "")

input_verdict := {
	"decision": "warn",
	"reason": "destructive_sql_in_prompt",
	"message": "User input contains destructive SQL targeting production-sounding names.",
} if {
	input.intervention_point == "input"
	regex.match(`(?i)\b(drop|truncate|delete\s+from)\b.*\b(prod|production)\b`, input_text)
}

pre_tool_call_verdict := {
	"decision": "deny",
	"reason": "sql_delegate_snapshot_missing",
	"message": "SQL parser or production catalog snapshot is missing.",
} if {
	is_execute_sql
	not parsed_snapshot_valid
} else := {
	"decision": "deny",
	"reason": "prod_destructive_forbidden",
	"message": "DELETE / TRUNCATE / DROP against a production table is forbidden.",
} if {
	is_execute_sql
	parsed_is_destructive
	parsed_targets_prod
} else := {
	"decision": "escalate",
	"reason": "prod_write_requires_approval",
	"message": "Write to a production table requires manager approval.",
} if {
	is_execute_sql
	parsed_is_write
	parsed_targets_prod
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
	is_sql_write_tool
	object.get(object.get(input, "annotations", {}), "sql_intent", {}).deviates == true
}

is_execute_sql if input.tool.name == "mssql.execute_sql"
is_structured_write if input.tool.name == "mssql.insert_data"
is_structured_write if input.tool.name == "mssql.update_data"
is_sql_write_tool if is_execute_sql
is_sql_write_tool if is_structured_write

parsed_snapshot_valid if {
	is_array(prod_tables)
	is_array(parsed_tables)
	operation != ""
}

parsed_targets_prod if {
	some table in parsed_tables
	table in prod_tables
}

parsed_is_destructive if operation in {"delete", "truncate", "drop_table", "drop_schema", "drop_database"}
parsed_is_write if operation in {"insert", "update", "merge", "delete", "truncate", "drop_table", "drop_schema", "drop_database", "alter_table"}

structured_table := lower(object.get(args, "table", ""))
structured_targets_prod if structured_table in prod_tables
