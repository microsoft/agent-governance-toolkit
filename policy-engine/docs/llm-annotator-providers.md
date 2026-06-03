# LLM annotator provider presets

The bundled host side `llm` annotator dispatcher supports several request adapters while preserving one annotation shape. The pure runtime still receives only dispatcher output under `annotations.<name>`.

| Provider | Manifest `provider` | Request shape | Response text source | Default credential |
| --- | --- | --- | --- | --- |
| OpenAI | `openai` | `/v1/chat/completions` with JSON object response format | `choices[0].message.content` | `OPENAI_API_KEY` |
| OpenAI compatible | `openai_compatible` | OpenAI chat completions | `choices[0].message.content` | none unless `api_key_env` or `api_key` is set |
| Azure OpenAI | `azure_openai` | Azure chat completions deployment URL | `choices[0].message.content` | `AZURE_OPENAI_API_KEY` |
| Amazon Bedrock | `bedrock` | Bedrock Converse | `output.message.content[].text` | `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` |
| Gemini | `gemini` | `generateContent` with JSON MIME response | `candidates[0].content.parts[].text` | `GEMINI_API_KEY` |
| Ollama | `ollama` | `/api/chat` with `format: json` and `stream: false` | `message.content` | none |

Every adapter expects the model text to be a JSON object. The dispatcher reads `label` by default or the configured `label_field`, then returns `{"label":"...","raw":"..."}`. Provider transport errors, non 2xx responses, malformed provider JSON, malformed model JSON, and missing labels fail closed as annotator errors.

## Config examples

```yaml
annotators:
  openai_judge:
    type: llm
    provider: openai
    model: gpt-4o-mini
    api_key_env: OPENAI_API_KEY
    system_prompt: Respond only with JSON containing {"label":"allow"} or {"label":"deny"}.

  gateway_judge:
    type: llm
    provider: openai_compatible
    endpoint: http://127.0.0.1:4000/v1/chat/completions
    model: hosted-judge

  azure_judge:
    type: llm
    provider: azure_openai
    endpoint: https://example.openai.azure.com
    deployment: judge-deployment
    api_version: 2024-02-15-preview
    api_key_env: AZURE_OPENAI_API_KEY

  bedrock_judge:
    type: llm
    provider: bedrock
    model: anthropic.claude-3-haiku-20240307-v1:0
    aws_region: us-east-1
    aws_access_key_id_env: AWS_ACCESS_KEY_ID
    aws_secret_access_key_env: AWS_SECRET_ACCESS_KEY
    aws_session_token_env: AWS_SESSION_TOKEN

  gemini_judge:
    type: llm
    provider: gemini
    model: gemini-1.5-flash
    api_key_env: GEMINI_API_KEY

  ollama_judge:
    type: llm
    provider: ollama
    base_url: http://localhost:11434
    model: llama3.1
```

LiteLLM, vLLM, and local gateway deployments should use `openai_compatible` when they expose chat completions. Use `headers` for non secret static headers. Use `provider_config` for provider request fields that are not modeled by ACS, such as Bedrock `inferenceConfig`.
