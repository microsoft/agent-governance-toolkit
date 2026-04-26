# Governed Chatbot with Memory

A conversational chatbot running under Agent OS governance.

## What It Demonstrates

- **Content Policy Enforcement** — PII detection, harmful content blocking
- **Rate Limiting** — Token-bucket limiter (20 requests/minute)
- **Conversation Memory** — Sliding window of last 50 turns, exported as LLM messages
- **Audit Trail** — Every interaction logged with input hash, policy result, timing

## Run It

```bash
pip install agent-os-kernel
python chatbot.py
```

## Use as Library

```python
from chatbot import GovernedChatbot

bot = GovernedChatbot(
    agent_id="support-bot",
    policies=["no_pii", "safe_content", "rate_limit"],
    rate_limit=30,  # requests per minute
)

response = await bot.chat("How do I reset my password?")
print(response)

# Check audit trail
for entry in bot.audit.export():
    print(entry)
```

## Connect to an LLM

```python
async def openai_response(user_input, history):
    """Replace the default response with OpenAI."""
    from openai import AsyncOpenAI
    client = AsyncOpenAI()
    resp = await client.chat.completions.create(
        model="gpt-4o-mini",
        messages=history + [{"role": "user", "content": user_input}],
    )
    return resp.choices[0].message.content

bot = GovernedChatbot(response_fn=openai_response)
```

## Policy Behavior

| Policy | What It Blocks |
|--------|---------------|
| `no_pii` | SSN, credit card numbers, passwords, API keys |
| `safe_content` | Jailbreak attempts, exploit instructions |
| `rate_limit` | More than 20 messages per minute |

All policy violations are logged to the audit trail but never expose raw user input (only SHA-256 hash).

## Related Issues

- [#64](https://github.com/microsoft/agent-governance-toolkit/issues/64) — Original issue
- [#66](https://github.com/microsoft/agent-governance-toolkit/issues/66) — Rate limiting policy template
