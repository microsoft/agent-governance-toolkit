# Production Policy Library
#
# These are production-ready policy sets for common enterprise scenarios.
# Unlike the sample policies in the parent directory, these are designed
# to be deployed as-is or with minimal customization.
#
# Each policy file is self-contained and includes:
# - Action rules (allow/deny/escalate)
# - Content filters (PII/PHI/PCI patterns)
# - Rate limits
# - Human escalation triggers
# - Audit requirements
#
# Choose the policy that matches your risk profile:
#
# | Policy | Risk Profile | Best For |
# |--------|-------------|----------|
# | minimal.yaml | Low | Startups, internal tools, experimentation |
# | enterprise.yaml | Medium | General enterprise, SaaS products |
# | healthcare.yaml | High | HIPAA-regulated, patient data |
# | financial.yaml | High | SOX/PCI-regulated, trading, banking |
# | strict.yaml | Maximum | Defense, critical infrastructure, ITAR |
#
# Usage:
#   from agent_os.policies import PolicyEvaluator
#   evaluator = PolicyEvaluator()
#   evaluator.load_policies("examples/policies/production/enterprise.yaml")
