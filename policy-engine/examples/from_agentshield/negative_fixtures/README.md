# MCP trust-boundary fixtures — why these are not ACS manifest ports

AgentShield's `examples/_shared/mcp_trust_boundary/` fixtures are **loader/transport
conformance fixtures**. Each one asserts that AgentShield's policy *loader* accepts
or rejects a resolver/annotator *connection configuration* at load time:

| Fixture | Asserted guarantee |
| --- | --- |
| `https_required` | non-localhost `http://` endpoint is rejected at load |
| `localhost_no_opt_in` | `http://localhost` rejected unless explicitly opted in |
| `localhost_opt_in` | `http://localhost` accepted with `allow_unencrypted_local: true` |
| `retry_over_cap` | `retry.max_attempts` above the safety cap is rejected at load |
| `timeout_over_cap` | `timeout` above the 300 s cap is rejected at load |
| `trust_anchors_malformed` | a non-PEM `trust_anchor` is rejected at load |
| `response_schema` | resolver responses must validate against a JSON Schema (runtime fail-closed) |
| `response_signature` | resolver responses must be a verifiable JWS (runtime fail-closed) |

## Why there is no ACS artifact equivalent

These guarantees live in the layer that **transports** an annotation/approval request
to an external service. In ACS that layer is **the host's responsibility**, not the
manifest or the core:

- ACS annotators of `type: classifier`/`llm` are dispatched through a host-provided
  `annotator_dispatcher`. The host owns the HTTP client, TLS posture, timeouts,
  retries, trust anchors, and response validation. The ACS core never opens those
  sockets, so a manifest cannot (and should not) assert HTTPS-required, retry caps,
  or PEM validity for them.
- ACS's built-in `endpoint`-type dispatcher exposes a `timeout_ms`, but the core does
  **not** enforce the broader AgentShield posture (HTTPS-required, localhost opt-in,
  retry caps, trust-anchor PEM parsing, JWS response signatures). Those are explicitly
  out of scope for the spec today.

Creating ACS manifests that merely *copy* these `transport:` blocks would be
misleading: validation would pass, but the core would silently **not** enforce the
guarantee the fixture exists to prove. That is a worse outcome than documenting the
gap.

## The faithful ACS mapping: a host-harness contract

For an adopter who needs these guarantees in ACS, the correct home is the host
integration that implements the dispatcher — for example, the Node and .NET adapter
layers (`sdk/*/src/integrations/`) or a custom `annotator_dispatcher`. The equivalent
checks belong there:

- Refuse to construct a dispatcher for a non-HTTPS endpoint unless an explicit
  local-dev opt-in flag is set.
- Clamp/refuse timeouts and retry counts above policy caps.
- Load trust anchors and verify they are valid PEM before first use.
- Validate every resolver response against a schema and/or verify its JWS signature
  before trusting it, failing closed on violation.

These are connection-hardening responsibilities of the embedding application. If/when
the spec grows a normative transport-security section for built-in dispatchers, these
fixtures become the conformance suite for that section. Until then they remain
host-harness fixtures rather than ACS policy artifacts.
