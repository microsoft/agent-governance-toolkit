# Deterministic host policy for the Foundry tool-governance example.
#
# The intent_judge annotator (declared in ../foundry_governance.acs.yaml) runs a
# live Azure OpenAI classifier and writes its label under
# annotations.intent_judge. This bundle turns that label into a verdict. It
# fails closed: a pre_tool_call proceeds only when the judge labelled the
# argument "safe"; a destructive, unexpected, or missing label denies.
package agent_control_specification.foundry_tool_guard

import rego.v1

# Bundle-level fallback plus per-intervention-point queries. The manifest binds
# pre_tool_call and post_tool_call to the specific rules below; verdict covers
# any other point.
default verdict := {"decision": "allow"}

default post_tool_call_verdict := {"decision": "allow"}

# Fail closed: with no usable judge label, deny.
default pre_tool_call_verdict := {
	"decision": "deny",
	"reason": "intent_judge_unavailable",
	"message": "The intent judge returned no usable label; failing closed.",
}

verdict := pre_tool_call_verdict if input.intervention_point == "pre_tool_call"

verdict := post_tool_call_verdict if input.intervention_point == "post_tool_call"

judge_label := lower(object.get(object.get(input.annotations, "intent_judge", {}), "label", ""))

pre_tool_call_verdict := {"decision": "allow"} if judge_label == "safe"

pre_tool_call_verdict := {
	"decision": "deny",
	"reason": "destructive_tool_argument",
	"message": "The intent judge did not label the tool argument safe.",
} if {
	judge_label != ""
	judge_label != "safe"
}
