<!-- Copyright (c) Microsoft Corporation. -->
<!-- Licensed under the MIT License. -->

# Chapter 3: Rate Limiting

An agent with the right permissions can still cause problems if it runs out of
control — calling the same tool thousands of times, burning through API quotas,
or running up costs. **Rate limiting** caps how often an agent can act.

This chapter covers two approaches:

| Section | Topic |
|---------|-------|
| [max_tool_calls](#approach-1-max_tool_calls-in-yaml) | A simple hard cap defined in YAML |
| [TokenBucket](#approach-2-tokenbucket-for-per-second-limits) | A per-second rate limiter for bursty workloads |
| [Which to use?](#which-approach-should-you-use) | Choosing the right strategy |
| [Try it yourself](#try-it-yourself) | Exercises |

---

## The problem

Without rate limiting, even a well-intentioned agent can:

- **Burn API quotas** — calling a search API 10,000 times in a loop
- **Run up costs** — each LLM call costs money, and runaway agents multiply fast
- **Overload downstream services** — a database can only handle so many queries
  per second

---

## Approach 1: `max_tool_calls` in YAML

The simplest approach. Add a `max_tool_calls` limit to the policy defaults:

```yaml
version: "1.0"
name: rate-limit-policy
description: Policy that limits how many tool calls an agent can make

rules:
  - name: block-delete-database
    condition:
      field: tool_name
      operator: eq
      value: delete_database
    action: deny
    priority: 100
    message: "Deleting databases is not allowed"

defaults:
  action: allow
  max_tool_calls: 3
```

The key line is `max_tool_calls: 3`. The evaluator does not enforce this limit
automatically — it is **metadata** that your application reads and enforces:

```python
from agent_os.policies.schema import PolicyDocument

policy = PolicyDocument.from_yaml("03_rate_limit_policy.yaml")
max_calls = policy.defaults.max_tool_calls  # 3

call_count = 0
for task in agent_tasks:
    if call_count >= max_calls:
        print("Limit reached — stopping agent")
        break
    call_count += 1
    # ... execute the task
```

### Example output

```
  Call 1: ✅ ALLOWED (1/3 used)
  Call 2: ✅ ALLOWED (2/3 used)
  Call 3: ✅ ALLOWED (3/3 used)
  Call 4: 🚫 DENIED — limit of 3 calls reached
  Call 5: 🚫 DENIED — limit of 3 calls reached
```

After three calls, the agent is stopped. Simple and predictable.

---

## Approach 2: TokenBucket for per-second limits

`max_tool_calls` is a total cap. But sometimes you want to allow many calls
*over time*, just not all at once. That's where a **token bucket** helps.

Think of it like a vending machine that holds 3 coins:

- Each request costs 1 coin
- Coins refill at a steady rate (e.g., 1 per second)
- If there are no coins left, the request is denied until one refills

```python
from agent_os.policies.rate_limiting import RateLimitConfig, TokenBucket

# Allow bursts of 3, refilling 1 token per second
config = RateLimitConfig(capacity=3, refill_rate=1.0)
bucket = TokenBucket.from_config(config)

# Try to make a request
if bucket.consume():
    print("Request allowed")
else:
    wait = bucket.time_until_available()
    print(f"Rate limited — retry in {wait:.1f}s")
```

### Example output

```
  Bucket: capacity=3, refill_rate=1.0/sec
  Starting tokens: 3

  Request 1: ✅ ALLOWED (2 tokens left)
  Request 2: ✅ ALLOWED (1 tokens left)
  Request 3: ✅ ALLOWED (0 tokens left)
  Request 4: 🚫 DENIED — retry in 1.0s
  Request 5: 🚫 DENIED — retry in 1.0s
```

The first three requests go through immediately (burst). After that, requests
are denied until tokens refill. If you wait one second, another request will be
allowed.

### How the token bucket works

```
Time 0.0s   [●●●]  3/3 tokens   → Request 1: consume → [●●○]
Time 0.0s   [●●○]  2/3 tokens   → Request 2: consume → [●○○]
Time 0.0s   [●○○]  1/3 tokens   → Request 3: consume → [○○○]
Time 0.0s   [○○○]  0/3 tokens   → Request 4: DENIED
Time 1.0s   [●○○]  1/3 tokens   → (1 token refilled)
Time 2.0s   [●●○]  2/3 tokens   → (another refilled)
```

---

## Which approach should you use?

| Approach | Good for | Example |
|----------|----------|---------|
| `max_tool_calls` | Hard lifetime cap — "agent can do at most N things total" | An agent that should only make 10 tool calls per task |
| `TokenBucket` | Throughput control — "agent can do N things per second" | Protecting a rate-limited external API |

In production, you often use **both**: `max_tool_calls` as a safety net and a
`TokenBucket` for smooth throughput control.

---

## Full example

```bash
python docs/tutorials/policy-as-code/examples/03_rate_limiting.py
```

---

## Try it yourself

1. **Change `max_tool_calls` to 5** in the YAML file and re-run. The agent
   should now get 5 allowed calls before being stopped.
2. **Create a `TokenBucket` with `capacity=1, refill_rate=0.5`**. This means
   only 1 request at a time, refilling every 2 seconds. How does the output
   change?
3. **Combine both approaches**: load the policy to get `max_tool_calls`, create
   a `TokenBucket`, and check both limits before allowing each request.

---

## What's missing?

We can now block dangerous tools, scope permissions by role, and rate-limit
runaway agents. But every rule we've written applies the same way everywhere.
What if a tool should be allowed in dev but blocked in production? And what
happens when the security team and a product team write separate policies
that disagree? That's **conditional policies**.

**Previous:** [Chapter 2 — Capability Scoping](02-capability-scoping.md)
**Next:** [Chapter 4 — Conditional Policies](04-conditional-policies.md) —
environment-aware rules and conflict resolution when policies disagree.
