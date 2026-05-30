pub const ANNOTATOR_TYPE: &str = "type";
pub const TYPE_CLASSIFIER: &str = "classifier";
pub const TYPE_LLM: &str = "llm";
pub const TYPE_ENDPOINT: &str = "endpoint";

pub const FIELD_FROM: &str = "from";
pub const FIELD_INPUT_FROM: &str = "input_from";
pub const FIELD_URL: &str = "url";
pub const FIELD_ENDPOINT: &str = "endpoint";
pub const FIELD_BASE_URL: &str = "base_url";
pub const FIELD_MODEL: &str = "model";
pub const FIELD_PROMPT: &str = "prompt";
pub const FIELD_SYSTEM_PROMPT: &str = "system_prompt";
pub const FIELD_API_KEY_ENV: &str = "api_key_env";
pub const FIELD_API_KEY_HEADER: &str = "api_key_header";
pub const FIELD_INPUT_FIELD: &str = "input_field";
pub const FIELD_RESPONSE_FIELD: &str = "response_field";
pub const FIELD_LABEL_FIELD: &str = "label_field";
pub const FIELD_PROVIDER: &str = "provider";
pub const FIELD_TIMEOUT_MS: &str = "timeout_ms";
pub const FIELD_THRESHOLD: &str = "threshold";
pub const FIELD_CATEGORY_THRESHOLDS: &str = "category_thresholds";
pub const FIELD_HEADERS: &str = "headers";
pub const FIELD_PROVIDER_CONFIG: &str = "provider_config";

pub const DEFAULT_OPENAI_CHAT_COMPLETIONS_URL: &str = "https://api.openai.com/v1/chat/completions";
pub const DEFAULT_OPENAI_API_KEY_ENV: &str = "OPENAI_API_KEY";
pub const DEFAULT_INPUT_FIELD: &str = "input";
pub const DEFAULT_LABEL_FIELD: &str = "label";
pub const DEFAULT_MODEL: &str = "gpt-4o-mini";
pub const DEFAULT_SYSTEM_PROMPT: &str =
    "Classify the input and respond with a JSON object containing a label field.";

pub const HEADER_AUTHORIZATION: &str = "Authorization";
pub const HEADER_CONTENT_TYPE: &str = "Content-Type";
pub const HEADER_ACCEPT: &str = "Accept";
pub const CONTENT_TYPE_JSON: &str = "application/json";
pub const AUTH_BEARER_PREFIX: &str = "Bearer ";

pub const REQUEST_INPUT: &str = "input";
pub const REQUEST_FIELDS: &str = "fields";
pub const REQUEST_MODEL: &str = "model";
pub const REQUEST_MESSAGES: &str = "messages";
pub const REQUEST_ROLE: &str = "role";
pub const REQUEST_CONTENT: &str = "content";
pub const REQUEST_RESPONSE_FORMAT: &str = "response_format";
pub const REQUEST_RESPONSE_FORMAT_TYPE: &str = "type";
pub const RESPONSE_FORMAT_JSON_OBJECT: &str = "json_object";
pub const ROLE_SYSTEM: &str = "system";
pub const ROLE_USER: &str = "user";

pub const RESPONSE_CHOICES: &str = "choices";
pub const RESPONSE_MESSAGE: &str = "message";
pub const RESPONSE_CONTENT: &str = "content";
pub const OUTPUT_LABEL: &str = "label";
pub const OUTPUT_RAW: &str = "raw";

pub const POLICY_INPUT_SNAPSHOT: &str = "snapshot";
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;
