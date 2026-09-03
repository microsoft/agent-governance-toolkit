# Real-data contract

Adapters must map real audit logs explicitly; unknown formats fail rather than guessing. Required: decision ID, timestamp, action, policy version, authority/delegation reference, relevant context, and evidence references. Optional values include monetary amount, model/tool/agent versions, environment, and hashes. Never supply raw sensitive evidence unless it is required; redact secrets before reports.
