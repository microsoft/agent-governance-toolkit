use crate::{
    AgentControl, AgentControlBlocked, AgentControlInterruption, Decision, InterventionPoint,
    InterventionPointResult, JsonValue, ModelRunResult, RunOptions, Verdict,
};
use serde::Serialize;
use serde_json::{Map, Value};
use std::{collections::BTreeMap, error::Error, fmt};

pub const DEFAULT_MAX_STREAM_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_MAX_STREAM_EVENTS: usize = 10_000;

const DONE: &str = "[DONE]";
const DATA_FIELD: &str = "data:";
const COMMENT_PREFIX: &str = ":";
const CHUNK_OBJECT: &str = "chat.completion.chunk";
const COMPLETION_OBJECT: &str = "chat.completion";
const ASSISTANT_ROLE: &str = "assistant";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamingLimits {
    pub max_stream_bytes: usize,
    pub max_stream_events: usize,
}

impl Default for StreamingLimits {
    fn default() -> Self {
        Self {
            max_stream_bytes: DEFAULT_MAX_STREAM_BYTES,
            max_stream_events: DEFAULT_MAX_STREAM_EVENTS,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ModelStreamRunResult {
    pub value: JsonValue,
    pub bytes: Vec<u8>,
    pub assembled_response: JsonValue,
    pub original_bytes: Vec<u8>,
    pub pre_model_call_intervention_point_result: InterventionPointResult,
    pub post_model_call_intervention_point_result: InterventionPointResult,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamingUnsupportedError {
    message: String,
}

impl StreamingUnsupportedError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for StreamingUnsupportedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for StreamingUnsupportedError {}

impl AgentControl {
    pub fn run_model_stream<F>(
        &self,
        model_request: JsonValue,
        execute: F,
    ) -> Result<ModelStreamRunResult, AgentControlInterruption>
    where
        F: FnOnce(JsonValue) -> Vec<u8>,
    {
        self.run_model_stream_with_options(
            model_request,
            RunOptions::default(),
            StreamingLimits::default(),
            execute,
        )
    }

    pub fn run_model_stream_with_options<F>(
        &self,
        model_request: JsonValue,
        options: RunOptions,
        limits: StreamingLimits,
        execute: F,
    ) -> Result<ModelStreamRunResult, AgentControlInterruption>
    where
        F: FnOnce(JsonValue) -> Vec<u8>,
    {
        let mut original_bytes = None;
        let mut assembled_response = None;
        let run = self.try_run_model_with_options(model_request, options, |effective_request| {
            let bytes = execute(effective_request);
            let assembled = assemble_sse_stream_with_limits(&bytes, limits)?;
            original_bytes = Some(bytes);
            assembled_response = Some(assembled.clone());
            Ok::<JsonValue, StreamingUnsupportedError>(assembled)
        });

        let model_run = match run {
            Ok(model_run) => model_run,
            Err(crate::AgentControlError::Blocked(blocked)) => {
                return Err(AgentControlInterruption::Blocked(blocked));
            }
            Err(crate::AgentControlError::Suspended(suspended)) => {
                return Err(AgentControlInterruption::Suspended(suspended));
            }
            Err(crate::AgentControlError::Execute(error)) => {
                return Err(streaming_fail_closed(error.message()));
            }
        };
        let original_bytes = original_bytes
            .ok_or_else(|| streaming_fail_closed("Streaming response contained no data chunks."))?;
        let assembled_response = assembled_response
            .ok_or_else(|| streaming_fail_closed("Streaming response contained no data chunks."))?;
        let transformed = model_run
            .post_model_call_intervention_point_result
            .transformed_policy_target
            .is_some()
            && model_run
                .post_model_call_intervention_point_result
                .verdict
                .decision
                == Decision::Transform;
        let bytes = if transformed {
            synthesize_sse_stream(&model_run.value, &assembled_response)
                .map_err(|error| streaming_fail_closed(error.message()))?
        } else {
            original_bytes.clone()
        };
        Ok(model_stream_result(
            model_run,
            bytes,
            assembled_response,
            original_bytes,
        ))
    }
}

pub fn assemble_sse_stream(raw: &[u8]) -> Result<JsonValue, StreamingUnsupportedError> {
    assemble_sse_stream_with_limits(raw, StreamingLimits::default())
}

pub fn assemble_sse_stream_with_limits(
    raw: &[u8],
    limits: StreamingLimits,
) -> Result<JsonValue, StreamingUnsupportedError> {
    if raw.len() > limits.max_stream_bytes {
        return Err(StreamingUnsupportedError::new(
            "Streaming response exceeded the buffering byte limit.",
        ));
    }
    let chunks = parse_sse_chunks(raw, limits)?;
    if chunks.is_empty() {
        return Err(StreamingUnsupportedError::new(
            "Streaming response contained no data chunks.",
        ));
    }

    let mut content = String::new();
    let mut finish_reason = JsonValue::Null;
    let mut tool_calls: BTreeMap<i64, ToolCallAccumulator> = BTreeMap::new();
    let mut template = Map::new();

    for chunk in chunks {
        if template.is_empty() {
            for key in ["id", "created", "model"] {
                if let Some(value) = chunk.get(key) {
                    template.insert(key.to_string(), value.clone());
                }
            }
        }
        let choices = match chunk.get("choices") {
            None | Some(JsonValue::Null) => continue,
            Some(JsonValue::Array(choices)) => choices,
            _ => {
                return Err(StreamingUnsupportedError::new(
                    "Streaming chunk choices must be a list.",
                ));
            }
        };
        if choices.is_empty() {
            continue;
        }
        if choices.len() > 1 {
            return Err(StreamingUnsupportedError::new(
                "Multi-choice streaming responses are not guarded.",
            ));
        }
        let choice = choices[0]
            .as_object()
            .ok_or_else(|| StreamingUnsupportedError::new("Streaming choice must be an object."))?;
        if choice.get("index").and_then(JsonValue::as_i64).unwrap_or(0) != 0 {
            return Err(StreamingUnsupportedError::new(
                "Multi-choice streaming responses are not guarded.",
            ));
        }
        if carries_unrepresented_data(choice, &["index", "delta", "finish_reason"]) {
            return Err(StreamingUnsupportedError::new(
                "Streaming choice carried unsupported fields.",
            ));
        }

        let delta = match choice.get("delta") {
            None | Some(JsonValue::Null) => Map::new(),
            Some(JsonValue::Object(delta)) => delta.clone(),
            _ => {
                return Err(StreamingUnsupportedError::new(
                    "Streaming choice delta must be an object.",
                ));
            }
        };
        if carries_unrepresented_data(&delta, &["role", "content", "tool_calls"]) {
            return Err(StreamingUnsupportedError::new(
                "Streaming delta carried unsupported fields.",
            ));
        }
        if let Some(piece) = delta.get("content") {
            if !piece.is_null() {
                let piece = piece.as_str().ok_or_else(|| {
                    StreamingUnsupportedError::new("Streaming delta content must be a string.")
                })?;
                content.push_str(piece);
            }
        }
        merge_tool_call_fragments(delta.get("tool_calls"), &mut tool_calls)?;
        if let Some(reason) = choice.get("finish_reason") {
            if !reason.is_null() {
                finish_reason = reason.clone();
            }
        }
    }

    let mut message = Map::new();
    message.insert(
        "role".to_string(),
        JsonValue::String(ASSISTANT_ROLE.to_string()),
    );
    message.insert("content".to_string(), JsonValue::String(content));
    if !tool_calls.is_empty() {
        message.insert(
            "tool_calls".to_string(),
            JsonValue::Array(
                tool_calls
                    .values()
                    .map(ToolCallAccumulator::as_json)
                    .collect(),
            ),
        );
    }

    let mut choice = Map::new();
    choice.insert("index".to_string(), JsonValue::from(0));
    choice.insert("message".to_string(), JsonValue::Object(message));
    choice.insert("finish_reason".to_string(), finish_reason);

    template.insert(
        "object".to_string(),
        JsonValue::String(COMPLETION_OBJECT.to_string()),
    );
    template.insert(
        "choices".to_string(),
        JsonValue::Array(vec![JsonValue::Object(choice)]),
    );
    Ok(JsonValue::Object(template))
}

pub fn synthesize_sse_stream(
    response: &JsonValue,
    template: &JsonValue,
) -> Result<Vec<u8>, StreamingUnsupportedError> {
    let response = response.as_object().ok_or_else(|| {
        StreamingUnsupportedError::new("Transformed streaming response must be an object.")
    })?;
    let choices = response
        .get("choices")
        .and_then(JsonValue::as_array)
        .ok_or_else(|| {
            StreamingUnsupportedError::new("Transformed streaming response must carry a choice.")
        })?;
    if choices.len() != 1 {
        return Err(StreamingUnsupportedError::new(
            "Transformed streaming response must carry a choice.",
        ));
    }
    let choice = choices[0].as_object().ok_or_else(|| {
        StreamingUnsupportedError::new("Transformed streaming response must carry a choice.")
    })?;
    if choice.get("index").and_then(JsonValue::as_i64).unwrap_or(0) != 0 {
        return Err(StreamingUnsupportedError::new(
            "Transformed streaming response must carry one zero-index choice.",
        ));
    }
    let message = match choice.get("message") {
        None | Some(JsonValue::Null) => Map::new(),
        Some(JsonValue::Object(message)) => message.clone(),
        _ => {
            return Err(StreamingUnsupportedError::new(
                "Transformed streaming choice must carry a message.",
            ));
        }
    };

    let content = match message.get("content") {
        None | Some(JsonValue::Null) => None,
        Some(JsonValue::String(content)) => Some(content.clone()),
        _ => {
            return Err(StreamingUnsupportedError::new(
                "Transformed streaming content must be a string.",
            ));
        }
    };
    let tool_calls = parse_synthetic_tool_calls(message.get("tool_calls"))?;
    let finish_reason = choice
        .get("finish_reason")
        .filter(|value| !value.is_null())
        .cloned()
        .unwrap_or_else(|| {
            if tool_calls.is_some() {
                JsonValue::String("tool_calls".to_string())
            } else {
                JsonValue::String("stop".to_string())
            }
        });
    let template_object = template.as_object();
    let chunk = SseChunk {
        id: passthrough(template_object, "id"),
        created: passthrough(template_object, "created"),
        model: passthrough(template_object, "model"),
        object: CHUNK_OBJECT,
        choices: vec![SseChoice {
            index: 0,
            delta: SseDelta {
                role: ASSISTANT_ROLE,
                content,
                tool_calls,
            },
            finish_reason,
        }],
    };
    let json = serde_json::to_string(&chunk).map_err(|error| {
        StreamingUnsupportedError::new(format!(
            "Transformed streaming response failed to encode: {error}"
        ))
    })?;
    Ok(format!("data: {json}\n\ndata: {DONE}\n\n").into_bytes())
}

#[derive(Default)]
struct ToolCallAccumulator {
    id: Option<String>,
    kind: Option<String>,
    name: Option<String>,
    arguments: String,
}

impl ToolCallAccumulator {
    fn merge(&mut self, fragment: &Map<String, Value>) -> Result<(), StreamingUnsupportedError> {
        self.id = merge_scalar(self.id.take(), fragment.get("id"))?;
        self.kind = merge_scalar(self.kind.take(), fragment.get("type"))?;
        let function = match fragment.get("function") {
            None | Some(JsonValue::Null) => Map::new(),
            Some(JsonValue::Object(function)) => function.clone(),
            _ => {
                return Err(StreamingUnsupportedError::new(
                    "Streaming tool_call.function must be an object.",
                ));
            }
        };
        self.name = merge_scalar(self.name.take(), function.get("name"))?;
        if let Some(arguments) = function.get("arguments") {
            if !arguments.is_null() {
                let arguments = arguments.as_str().ok_or_else(|| {
                    StreamingUnsupportedError::new("Streaming tool_call arguments must be strings.")
                })?;
                self.arguments.push_str(arguments);
            }
        }
        Ok(())
    }

    fn as_json(&self) -> JsonValue {
        serde_json::json!({
            "id": self.id.clone().unwrap_or_default(),
            "type": self.kind.clone().unwrap_or_else(|| "function".to_string()),
            "function": {
                "name": self.name.clone().unwrap_or_default(),
                "arguments": self.arguments,
            },
        })
    }
}

fn parse_sse_chunks(
    raw: &[u8],
    limits: StreamingLimits,
) -> Result<Vec<Map<String, Value>>, StreamingUnsupportedError> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| {
            StreamingUnsupportedError::new("Streaming response contained malformed UTF-8.")
        })?
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let mut chunks = Vec::new();
    let mut done = false;
    for block in text.split("\n\n") {
        let Some(data) = event_data(block) else {
            continue;
        };
        if done {
            return Err(StreamingUnsupportedError::new(
                "Streaming response sent data after [DONE].",
            ));
        }
        if data == DONE {
            done = true;
            continue;
        }
        if chunks.len() >= limits.max_stream_events {
            return Err(StreamingUnsupportedError::new(
                "Streaming response exceeded the buffered event limit.",
            ));
        }
        let chunk: JsonValue = serde_json::from_str(&data).map_err(|_| {
            StreamingUnsupportedError::new("Streaming response contained malformed SSE JSON.")
        })?;
        let chunk = chunk.as_object().cloned().ok_or_else(|| {
            StreamingUnsupportedError::new("Streaming SSE chunk must be a JSON object.")
        })?;
        chunks.push(chunk);
    }
    if !done {
        return Err(StreamingUnsupportedError::new(
            "Streaming response terminated before [DONE].",
        ));
    }
    Ok(chunks)
}

fn event_data(block: &str) -> Option<String> {
    let data_lines = block
        .split('\n')
        .filter(|line| !line.is_empty() && !line.starts_with(COMMENT_PREFIX))
        .filter_map(|line| line.strip_prefix(DATA_FIELD))
        .map(|line| line.strip_prefix(' ').unwrap_or(line))
        .collect::<Vec<_>>();
    if data_lines.is_empty() {
        None
    } else {
        Some(data_lines.join("\n"))
    }
}

fn merge_tool_call_fragments(
    fragments: Option<&JsonValue>,
    accumulators: &mut BTreeMap<i64, ToolCallAccumulator>,
) -> Result<(), StreamingUnsupportedError> {
    let Some(fragments) = fragments else {
        return Ok(());
    };
    if fragments.is_null() {
        return Ok(());
    }
    let fragments = fragments
        .as_array()
        .ok_or_else(|| StreamingUnsupportedError::new("Streaming tool_calls must be a list."))?;
    for fragment in fragments {
        let fragment = fragment.as_object().ok_or_else(|| {
            StreamingUnsupportedError::new("Streaming tool_call fragment must be an object.")
        })?;
        let index = fragment
            .get("index")
            .and_then(JsonValue::as_i64)
            .ok_or_else(|| {
                StreamingUnsupportedError::new(
                    "Streaming tool_call fragments require an integer index.",
                )
            })?;
        accumulators.entry(index).or_default().merge(fragment)?;
    }
    Ok(())
}

fn merge_scalar(
    current: Option<String>,
    incoming: Option<&JsonValue>,
) -> Result<Option<String>, StreamingUnsupportedError> {
    let Some(incoming) = incoming else {
        return Ok(current);
    };
    if incoming.is_null() {
        return Ok(current);
    }
    let incoming = incoming.as_str().ok_or_else(|| {
        StreamingUnsupportedError::new("Streaming tool_call metadata must be strings.")
    })?;
    if let Some(current) = current {
        if current != incoming {
            return Err(StreamingUnsupportedError::new(
                "Streaming tool_call metadata changed mid-stream.",
            ));
        }
        Ok(Some(current))
    } else {
        Ok(Some(incoming.to_string()))
    }
}

fn carries_unrepresented_data(mapping: &Map<String, Value>, known: &[&str]) -> bool {
    mapping
        .iter()
        .any(|(key, value)| !known.contains(&key.as_str()) && !is_empty_represented_value(value))
}

fn is_empty_represented_value(value: &JsonValue) -> bool {
    match value {
        JsonValue::Null => true,
        JsonValue::String(value) => value.is_empty(),
        JsonValue::Array(value) => value.is_empty(),
        JsonValue::Object(value) => value.is_empty(),
        _ => false,
    }
}

fn parse_synthetic_tool_calls(
    tool_calls: Option<&JsonValue>,
) -> Result<Option<Vec<SyntheticToolCall>>, StreamingUnsupportedError> {
    let Some(tool_calls) = tool_calls else {
        return Ok(None);
    };
    if tool_calls.is_null() {
        return Ok(None);
    }
    let tool_calls = tool_calls.as_array().ok_or_else(|| {
        StreamingUnsupportedError::new("Transformed streaming tool_calls must be a list.")
    })?;
    if tool_calls.is_empty() {
        return Ok(None);
    }
    tool_calls
        .iter()
        .enumerate()
        .map(|(order, tool_call)| {
            let order = order as i64;
            let tool_call = tool_call.as_object().ok_or_else(|| {
                StreamingUnsupportedError::new("Transformed streaming tool_call must be an object.")
            })?;
            if let Some(existing) = tool_call.get("index") {
                if existing.as_i64() != Some(order) {
                    return Err(StreamingUnsupportedError::new(
                        "Transformed streaming tool_call index must match its order.",
                    ));
                }
            }
            let function = tool_call
                .get("function")
                .and_then(JsonValue::as_object)
                .ok_or_else(|| {
                    StreamingUnsupportedError::new(
                        "Transformed streaming tool_call function must be an object.",
                    )
                })?;
            let arguments = function
                .get("arguments")
                .and_then(JsonValue::as_str)
                .ok_or_else(|| {
                    StreamingUnsupportedError::new(
                        "Transformed streaming tool_call arguments must be a string.",
                    )
                })?
                .to_string();
            let name = function
                .get("name")
                .and_then(JsonValue::as_str)
                .map(str::to_string);
            Ok(SyntheticToolCall {
                id: tool_call.get("id").cloned(),
                kind: tool_call.get("type").cloned(),
                function: SyntheticFunction { name, arguments },
                index: order,
            })
        })
        .collect::<Result<Vec<_>, StreamingUnsupportedError>>()
        .map(Some)
}

fn passthrough(template: Option<&Map<String, Value>>, key: &str) -> Option<JsonValue> {
    template.and_then(|template| template.get(key).cloned())
}

fn model_stream_result(
    model_run: ModelRunResult,
    bytes: Vec<u8>,
    assembled_response: JsonValue,
    original_bytes: Vec<u8>,
) -> ModelStreamRunResult {
    ModelStreamRunResult {
        value: model_run.value,
        bytes,
        assembled_response,
        original_bytes,
        pre_model_call_intervention_point_result: model_run
            .pre_model_call_intervention_point_result,
        post_model_call_intervention_point_result: model_run
            .post_model_call_intervention_point_result,
    }
}

fn streaming_fail_closed(message: &str) -> AgentControlInterruption {
    AgentControlInterruption::Blocked(AgentControlBlocked::new(
        InterventionPoint::PostModelCall,
        InterventionPointResult {
            verdict: Verdict {
                decision: Decision::Deny,
                reason: Some("runtime_error:streaming_unsupported".to_string()),
                message: Some(message.to_string()),
                transform: None,
                evidence: None,
                result_labels: Vec::new(),
            },
            transformed_policy_target: None,
            policy_input: None,
            action_identity: None,
            input_identity: None,
            enforced_identity: None,
        },
    ))
}

#[derive(Serialize)]
struct SseChunk {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<JsonValue>,
    object: &'static str,
    choices: Vec<SseChoice>,
}

#[derive(Serialize)]
struct SseChoice {
    index: u8,
    delta: SseDelta,
    finish_reason: JsonValue,
}

#[derive(Serialize)]
struct SseDelta {
    role: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<SyntheticToolCall>>,
}

#[derive(Serialize)]
struct SyntheticToolCall {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<JsonValue>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    kind: Option<JsonValue>,
    function: SyntheticFunction,
    index: i64,
}

#[derive(Serialize)]
struct SyntheticFunction {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    arguments: String,
}
