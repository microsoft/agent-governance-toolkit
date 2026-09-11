use super::HostEvaluation;
use crate::JsonValue;

#[derive(Debug, Clone, PartialEq)]
pub struct RunResult<T = JsonValue> {
    pub value: T,
    pub input_intervention_point_result: HostEvaluation,
    pub output_intervention_point_result: HostEvaluation,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolRunResult<T = JsonValue> {
    pub value: T,
    pub pre_tool_call_intervention_point_result: HostEvaluation,
    pub post_tool_call_intervention_point_result: HostEvaluation,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ModelRunResult<T = JsonValue> {
    pub value: T,
    pub pre_model_call_intervention_point_result: HostEvaluation,
    pub post_model_call_intervention_point_result: HostEvaluation,
}
