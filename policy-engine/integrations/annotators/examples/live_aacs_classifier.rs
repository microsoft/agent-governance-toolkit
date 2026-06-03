use agent_control_specification::{AnnotatorDispatcher, AnnotatorInvocation, JsonValue};
use agent_control_specification_annotators::ClassifierAnnotator;
use serde_json::json;
use std::collections::BTreeMap;

fn fields(pairs: &[(&str, JsonValue)]) -> BTreeMap<String, JsonValue> {
    pairs
        .iter()
        .map(|(key, value)| (key.to_string(), value.clone()))
        .collect()
}

fn main() {
    let Ok(endpoint) = std::env::var("AZURE_CONTENT_SAFETY_ENDPOINT") else {
        eprintln!("skipping live call because AZURE_CONTENT_SAFETY_ENDPOINT is not set");
        return;
    };
    if std::env::var("AZURE_CONTENT_SAFETY_KEY").is_err() {
        eprintln!("skipping live call because AZURE_CONTENT_SAFETY_KEY is not set");
        return;
    }

    let subject = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("AACS_SUBJECT").ok())
        .unwrap_or_else(|| "Summarize the standup notes.".to_string());

    let annotator = AnnotatorInvocation {
        fields: fields(&[
            ("type", json!("classifier")),
            ("provider", json!("aacs")),
            ("from", json!("$.input.text")),
            ("endpoint", json!(endpoint)),
            ("api_key_env", json!("AZURE_CONTENT_SAFETY_KEY")),
            ("threshold", json!(0.5)),
            ("provider_config", json!({"api_version": "2024-09-01"})),
        ]),
    };
    let policy_input = json!({"snapshot": {"input": {"text": subject}}});

    match ClassifierAnnotator::new().dispatch("aacs", &annotator, &policy_input) {
        Ok(output) => println!("OK {output}"),
        Err(error) => println!("ERR {error}"),
    }
}
