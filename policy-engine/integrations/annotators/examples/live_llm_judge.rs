//! Live exercise of the reference annotators against real endpoints.
//!
//! Run with Azure OpenAI credentials in the environment.
//!
//! ```sh
//! set -a && . ./.env && set +a
//! cargo run -p agent_control_specification_annotators --example live_llm_judge
//! ```
//!
//! Demonstrates the LLM judge annotator with both the default Bearer header and
//! the configurable Azure OpenAI `api-key` header.
use agent_control_specification::{AnnotatorDispatcher, AnnotatorInvocation, JsonValue};
use agent_control_specification_annotators::LlmAnnotator;
use serde_json::json;
use std::collections::BTreeMap;

fn fields(pairs: &[(&str, JsonValue)]) -> BTreeMap<String, JsonValue> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

fn main() {
    let (Ok(endpoint), Ok(deployment), Ok(api_version)) = (
        std::env::var("AZURE_OPENAI_ENDPOINT"),
        std::env::var("AZURE_OPENAI_DEPLOYMENT"),
        std::env::var("AZURE_OPENAI_API_VERSION"),
    ) else {
        eprintln!("skipping: set AZURE_OPENAI_ENDPOINT/DEPLOYMENT/API_VERSION (e.g. `. ./.env`)");
        return;
    };
    let url = format!(
        "{endpoint}/openai/deployments/{deployment}/chat/completions?api-version={api_version}"
    );

    for (mode, extra) in [
        ("bearer (default)", vec![]),
        ("api-key header", vec![("api_key_header", json!("api-key"))]),
    ] {
        let mut pairs = vec![
            ("type", json!("llm")),
            ("endpoint", json!(url.clone())),
            ("model", json!(deployment.clone())),
            ("api_key_env", json!("AZURE_OPENAI_API_KEY")),
            ("from", json!("$.input.text")),
            (
                "system_prompt",
                json!("You are a classifier. Respond with JSON {\"label\": <benign|risky>}."),
            ),
            ("label_field", json!("label")),
        ];
        pairs.extend(extra);
        let annotator = AnnotatorInvocation {
            fields: fields(&pairs),
        };
        let pi = json!({"snapshot": {"input": {"text": "Summarize the standup notes."}}});
        match LlmAnnotator::new().dispatch("judge", &annotator, &pi) {
            Ok(v) => println!("OK   [{mode}] => {v}"),
            Err(e) => println!("ERR  [{mode}] => {e}"),
        }
    }
}
