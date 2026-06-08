# ACS Threat And Security Model

This document describes the threat and security model for the Agent Control Specification. ACS is a stateless, deterministic, intervention point policy runtime for agent systems. It evaluates one complete host supplied snapshot at one intervention point, builds a canonical policy input, gathers host supplied annotations, invokes policy, normalizes the result into a verdict, validates any `transform` verdict, and optionally returns a transformed policy target in enforce mode.

The model applies only when a host application routes governed activity through ACS at the declared intervention points. ACS does not own the agent loop, model, tools, credentials, durable memory, approval workflow, network calls, or backend authorization. It computes portable policy decisions and transformations. The host carries those decisions out.

ACS is pre-1.0 alpha. The guarantees in this document describe the current specification and reference implementation posture, not a certification claim.

## Security Objectives

ACS is designed to provide portable security enforcement for consequential agent activity without owning the host runtime.

- ACS evaluates policy before or after each configured lifecycle boundary named by the specification.
- ACS keeps the runtime stateless so a verdict depends on the manifest, the explicit snapshot, the mode, and dispatcher outputs for one call.
- ACS keeps the runtime deterministic so identical inputs produce identical verdicts and identical transformed policy targets across supported SDKs.
- ACS fails closed when runtime validation, path resolution, annotation dispatch, policy dispatch, policy output normalization, or transform validation cannot complete safely.
- ACS confines transform application to the configured policy target and prevents `allow`, `warn`, `deny`, or `escalate` from mutating the raw snapshot, annotations, projected tool metadata, or hidden host state.
- ACS exposes a frozen policy input contract so Rust, Python, Node, and .NET integrations can interoperate with the same policy bundle.
- ACS keeps policy artifacts reviewable through a portable manifest and Rego bundle contract.
- ACS separates pure policy enforcement from host owned I/O so agent frameworks can integrate without surrendering model calls, tool execution, streams, or async runtimes to the core.

## Protected Assets

ACS protects assets only on mediated paths. A path is mediated when the host supplies a complete snapshot to the runtime and conforms to the returned verdict.

- Tool authority is protected when `pre_tool_call` policy evaluates the exact tool invocation before the host executes it.
- Tool output integrity is protected when `post_tool_call` policy evaluates untrusted tool results before the host reintroduces them to the model, stores them, or discloses them.
- Model request integrity is protected when `pre_model_call` policy evaluates the assembled request before the host sends it to the model.
- Model response integrity is protected when `post_model_call` policy evaluates the model response before the host acts on it.
- User input and external request data are protected when `input` policy evaluates ingress data before the host uses it in the agent loop.
- Final disclosure is protected when `output` policy evaluates the assembled response before the host returns it to a caller or downstream system.
- Policy intent is protected by manifest validation, policy binding validation, reserved runtime error reasons, transform validation, and fail closed construction rules for unresolved `extends`.
- Policy portability is protected by the canonical policy input shape, canonical serialization, and shared Rust core behavior surfaced through SDK and FFI bindings.
- Sensitive data is protected to the extent policy denies, escalates, warns, or transforms the policy target before the host performs disclosure or action.
- Telemetry minimization is protected by runtime events that carry content safe metadata and do not include policy target values, tool arguments, tool results, annotation values, model messages, secrets, or personal data.

## Principals And Components

An ACS deployment has several principals and components with distinct security responsibilities.

- The end user provides prompts, uploaded content, request payloads, or workflow intent that may be benign, malicious, or compromised.
- Retrieved content authors control documents, search results, web pages, database rows, emails, tickets, or other data that may later influence the agent.
- The host application owns the agent loop, framework adapter, model call, tool registry, tool execution, credentials, transport facts, approval path, stream aggregation, and final response handling.
- The Rust core owns manifest validation, path resolution, tool projection, annotation input validation, policy input construction, policy invocation preparation, verdict normalization, runtime error normalization, and policy target transform validation and application.
- The C ABI and SDKs expose the Rust core to Rust, Python, Node, and .NET hosts while preserving the frozen wire contract.
- Policy authors and security reviewers author the manifest, Rego bundle, policy queries, tool metadata, annotator declarations, and per point bindings.
- OPA or a host supplied policy dispatcher evaluates Rego or a custom policy backend and returns verdict shaped JSON.
- Annotator dispatchers execute classifier, LLM, or endpoint annotations outside the core and return annotation values to the runtime.
- LLM providers produce model responses, tool call proposals, and final text, all of which remain untrusted until mediated.
- Tools and backend services perform side effects, retrieve data, or transform data under host supplied authority.
- Approval services or human operators resolve `escalate` verdicts when the host configures such a path.
- Build, release, package, and deployment systems produce and protect the ACS core, SDKs, manifests, policy bundles, and host binaries.

## Trust Boundaries

ACS is intended to sit at boundaries where untrusted content enters an agent loop and where agent output crosses into authority or disclosure.

- User input crosses from an untrusted principal into the host at the `input` intervention point.
- The model request crosses from host assembled context into the LLM provider at the `pre_model_call` intervention point.
- The model response crosses from an untrusted model output channel back into host control at the `post_model_call` intervention point.
- A proposed tool invocation crosses from model influenced data into real tool authority at the `pre_tool_call` intervention point.
- A tool result crosses from an external tool or backend into future model context or caller disclosure at the `post_tool_call` intervention point.
- Final output crosses from the host back to a user or downstream consumer at the `output` intervention point.
- Agent lifecycle metadata crosses into policy at `agent_startup` and `agent_shutdown` when the host elects to mediate lifecycle facts.
- Manifest and Rego artifacts cross from a trusted policy review process into the runtime as security critical configuration.
- Annotation requests cross from the runtime boundary into host supplied classifier, LLM, or endpoint services, which may receive sensitive prompt or tool data selected by the manifest.
- Policy dispatch crosses from the runtime boundary into OPA or a host supplied policy engine.
- SDK and FFI calls cross a language boundary where shape translation must preserve JSON values, path semantics, decisions, transform bodies, and character offsets.
- The host enforcement boundary lies after ACS returns a verdict. The host must block, transform, escalate, or proceed in accordance with the result.

Untrusted user input, model output, and tool output must be treated as data unless trusted host code explicitly grants authority. The manifest and Rego bundle are trusted policy. The host integration code is trusted to invoke ACS on every declared path. An uninstrumented call path is outside the ACS guarantee.

## Trusted Computing Base

The trusted computing base is the set of components that must behave correctly for ACS enforcement to hold.

Always in the trusted computing base are the Rust core, the C ABI surface, the selected SDK binding, the host integration code that routes governed activity through ACS, the manifest, the Rego bundle or custom policy backend, the policy dispatcher, and the deployment controls that protect those artifacts from unauthorized modification.

Conditionally in the trusted computing base are annotator dispatchers, classifier services, LLM judge services, endpoint annotation services, approval resolvers, human approvers, telemetry sinks used as audit evidence, OPA binaries, package registries, CI systems, container images, and framework adapters. They become trusted when their result can affect an allow, deny, warn, escalate, transform, approval, or audit decision.

The LLM is not trusted to follow instructions, separate data from commands, protect secrets, or propose safe tool arguments. Tools are not trusted to return instruction free or secret free content. Backend services remain trusted for their own authorization decisions because ACS does not replace backend access control.

## Attacker Model

ACS assumes an attacker may be an external user, a compromised user account, a malicious insider using legitimate application access, a malicious retrieved content author, a compromised data source visible to the agent, or a malicious tool output source.

Attackers may control user prompts, uploaded files, request payloads, chat history visible to the host, retrieved documents, web pages, search results, database rows, emails, tickets, tool outputs, model influenced tool call arguments, and final model text. Attackers may also cause malformed snapshots, missing fields, unexpected JSON types, large payloads, unavailable annotator services, malformed annotator responses, policy dispatcher failures, malformed policy outputs, and malformed transforms through paths they can influence.

ACS does not assume attackers can directly modify the Rust core, selected SDK, trusted host code, approved manifest, approved Rego bundle, OPA binary, trusted deployment platform, or tool implementation. Compromise of those components is a host, platform, or supply chain problem that ACS can document but cannot by itself defeat.

## In Scope Threats

### Prompt Injection Through User Input

An attacker can place instructions in prompts or uploaded data that attempt to override system intent, developer intent, policy intent, or user intent. ACS can mediate the ingress payload at `input`, the assembled model request at `pre_model_call`, later model output at `post_model_call`, any resulting tool calls at `pre_tool_call`, and final disclosure at `output`. Deterministic Rego policy and host supplied annotations can deny, warn, escalate, or transform configured policy targets.

This mitigation is only as complete as the policy and integration. ACS does not prove semantic prompt safety. Security critical restrictions should be expressed as deterministic policy over snapshots, tool metadata, annotations, and policy targets instead of relying only on LLM judgment.

### Tool Output Injection

A tool can return instructions, hidden prompt text, poisoned documents, adversarial markup, or malformed structured data that attempts to alter subsequent model behavior. ACS can evaluate the tool result at `post_tool_call` before the host feeds it back to the model or exposes it downstream. The host can also mediate the next model request at `pre_model_call` and the next tool invocation at `pre_tool_call`.

ACS evaluates complete snapshots and not live streams. A host that feeds unmediated tool output into context before calling `post_tool_call` has already left the ACS security envelope for that data flow.

### Exfiltration Through Tool Calls

An attacker can induce a model to place secrets, private data, or unauthorized identifiers into tool arguments. ACS can project current tool metadata at `pre_tool_call`, pass the exact arguments as the policy target, and allow Rego to deny, warn, escalate, or redact the configured target before execution. Policies may use tool catalog fields such as clearance and security labels as ordinary metadata.

ACS does not own credentials or network egress. The host must restrict tool credentials, backend scopes, destination allow lists, and side channels outside mediated tool arguments.

### Unauthorized Tool Authority

An attacker can induce use of a tool that is not permitted for the actor, tenant, data class, workflow, or intervention point. ACS can fail closed on unknown tool names, project the configured tool catalog entry into policy input, and let Rego enforce actor, tenant, clearance, and tool rules over the explicit snapshot.

ACS supports information flow control as stateless policy logic. The core performs no built in IFC check and stores no taint state. The host supplies source labels, Rego enforces clearance at sinks, and backend services must still enforce their own authorization.

### Sensitive Data Leakage In Outputs

An attacker can cause sensitive data to appear in model responses, tool results, final output, telemetry, approval payloads, or annotation requests. ACS can evaluate `post_model_call`, `post_tool_call`, and `output`, and a valid `transform` verdict can replace the configured policy target before the host discloses it.

Redaction helpers that compute spans must convert their result into a `transform` verdict over the selected policy target. A host or policy tool that computes replacement boundaries in bytes, UTF-16 code units, grapheme clusters, or display cells can redact the wrong content before returning that transform body.

### Policy Bypass Through Uninstrumented Paths

An application can accidentally or deliberately call a model, execute a tool, process tool output, or return final output without invoking ACS. ACS cannot observe or block a path that the host does not mediate. This threat is in scope only as an integration invariant and an audit requirement. The mitigation is adapter coverage, tests, code review, and deployment policy that prevents parallel unguarded paths.

### Fail Open On Malformed Policy Or Runtime Error

Malformed manifests, unresolved manifest inheritance, failed HTTPS manifest fetches, invalid paths, unknown intervention points, unknown tools, annotation failures, policy dispatcher failures, invalid policy outputs, and invalid transforms could otherwise lead to unintended allow decisions. ACS treats runtime failures as `deny` verdicts with reserved `runtime_error:*` reasons. The core validates manifests before use. File based loaders compose file and HTTPS `extends` before runtime construction. `Runtime::with_telemetry` rejects a manifest whose `extends` list remains unresolved, which means string and FFI loaders must receive an already composed manifest before an enforcing runtime can be constructed.

### Supply Chain Of Policy Bundles And Runtime Artifacts

An attacker can attempt to alter the manifest, Rego bundle, OPA executable, SDK package, native library, container image, or host integration. ACS makes policy artifacts explicit and reviewable, but it does not sign, distribute, or verify them by itself. This threat is partially mitigated by reviewable artifacts and deterministic policy input. It remains a deployment supply chain responsibility.

### Classifier Or Annotator Failure

A classifier, LLM judge, or endpoint annotator can time out, return malformed data, become unavailable, or be adversarially influenced. ACS declares annotators in the manifest, resolves their input paths before policy execution, and calls the host annotator dispatcher in deterministic name order. Annotator errors and dispatcher timeouts fail closed as runtime errors. The reference HTTP annotators fold transport failures, non 2xx responses, and malformed response content into dispatcher errors. The bundled LLM provider presets keep credentials in explicit fields or named environment variables and normalize provider text to one annotation shape. The host owns service authentication, timeouts, retries, caching, privacy controls, and response validation beyond JSON shape.

### Parameter Tampering After Evaluation

A host can validate one tool name or argument object and execute a different one. ACS returns a verdict and an optional transformed policy target. It does not execute the action. The host must bind evaluation to execution by treating the evaluated invocation as immutable or by applying the transformed target directly to the same invocation that will execute.

### Denial Of Service Against Evaluation

An attacker can send large snapshots, malformed JSON values, expensive policy inputs, or repeated requests that increase policy, annotation, OPA, or host costs. ACS itself is synchronous and stateless. It does not provide rate limiting, quotas, async cancellation, or bounded network behavior for host supplied dispatchers. The host and deployment platform must impose size limits, timeouts, concurrency limits, and cost controls.

## Out Of Scope Threats And Non Goals

ACS does not by itself protect against every agent or platform risk.

- ACS does not protect direct model calls, direct tool calls, or direct output paths that bypass the runtime.
- ACS does not protect against a host application that ignores `deny`, mishandles `escalate`, drops transformed policy targets, or mutates validated parameters before execution.
- ACS does not replace backend authorization, tenant isolation, identity verification, audit retention, payment controls, idempotency, or compensating transaction controls.
- ACS does not sandbox tools, models, OPA, annotators, SDK code, native libraries, or host processes.
- ACS does not prevent side effects that occur before a post action intervention point evaluates the result.
- ACS does not provide token or chunk level streaming enforcement. Hosts evaluate complete model and output snapshots.
- ACS does not maintain durable session state, variables, lifetimes, event buses, state intervention points, endpoint intervention points, or in manifest expression language semantics.
- ACS does not propagate taint or enforce IFC in the core. Hosts must supply labels and route sinks through policy.
- ACS does not guarantee semantic correctness, truthfulness, or harmlessness of LLM output unless the configured policy detects and controls it.
- ACS does not guarantee classifier or LLM judge correctness. Their outputs are host supplied data used by policy.
- ACS does not secure annotation services, approval services, telemetry backends, package registries, CI systems, deployment platforms, or policy repositories.
- ACS does not provide confidentiality for data intentionally sent to policy dispatchers, annotators, approval workflows, logs outside the runtime telemetry contract, or backend services.
- ACS does not certify compliance. It can supply controls and evidence within a larger compliance program.

## Security Guarantees

When the host correctly integrates ACS at the declared intervention points and enforces returned verdicts in enforce mode, the runtime provides the following guarantees.

- The runtime evaluates exactly one intervention point per call using the provided snapshot and mode.
- The runtime retains no mutable state that influences future verdicts.
- The runtime builds a canonical policy input with `intervention_point`, `policy_target`, `snapshot`, `annotations`, and `tool` as the top level members.
- The runtime rejects unknown or malformed manifest structure according to schema and implementation validation before evaluation.
- The runtime fails closed when the requested intervention point is not configured.
- The runtime fails closed when required paths are missing or traverse incompatible JSON types.
- The runtime fails closed when a tool intervention point projects a tool name that is not a string or is not present in the tool catalog.
- The runtime fails closed when annotation input paths are invalid, when an annotator dispatch fails, or when an annotator dispatch times out.
- The runtime prepares typed policy invocations and fails closed when policy preparation or dispatch fails.
- The runtime fails closed when policy output is not a valid verdict object or when policy uses the reserved `runtime_error:*` reason prefix.
- The runtime validates any `transform` verdict before returning success.
- The runtime applies a transformed policy target only in enforce mode and only for `transform` verdicts.
- The runtime never mutates the policy target for `allow`, `warn`, `deny`, `escalate`, or runtime error outcomes.
- The runtime rejects transform paths that target anything outside `$policy_target`.
- The runtime returns no transformed policy target in evaluate only mode.
- The runtime rejects unresolved `extends` during enforcing runtime construction, so file based loaders must compose inherited file and HTTPS manifests before use and string or FFI loaders must receive an already merged manifest.
- The runtime emits only low cardinality telemetry metadata and not policy target values, tool arguments, tool results, annotation values, model messages, secrets, or personal data.

These guarantees do not make ACS a sandbox. They are mediation guarantees over supported runtime paths.

## Required Integration Invariants

Integrations must preserve these invariants for the security model to hold.

- The host must call ACS for every governed activity at the intervention points claimed by the deployment.
- The host must not expose parallel unguarded model, tool, tool result, or output paths for governed workflows.
- The snapshot must contain the complete facts the policy relies on, including actor, tenant, conversation, approvals, prior decisions, transport, model request, tool call, tool result, and output facts as applicable.
- The policy target selected by the manifest must be the value the host will actually send, execute, store, or disclose after enforcement.
- The host must apply the transformed policy target returned by ACS before continuing with a `transform` verdict in enforce mode. No other verdict mutates the policy target.
- The host must block a `deny` verdict in enforce mode.
- The host must route an `escalate` verdict to a host approval path and must fail closed if no path is configured, the path fails, or the path returns an unrecognized outcome.
- The host must not execute an escalated action until approval succeeds. `escalate` verdicts do not return or apply transformed targets.
- The host must bind approval to the reviewed actor, tenant, policy version, intervention point, tool name, arguments, and relevant snapshot facts.
- The host must aggregate streams before calling `post_model_call` or `output` because ACS evaluates complete snapshots.
- The host must call `pre_tool_call` and `post_tool_call` separately for each concrete tool invocation, including parallel invocations.
- The host must protect manifests, Rego bundles, OPA binaries, SDK packages, native libraries, and adapter code from unauthorized modification.
- The host must authenticate and authorize annotator, policy, approval, telemetry, model, and tool services as required by its deployment.
- The host must ensure redaction spans use ACS character offsets and must not compute spans in another unit without conversion.
- The host must impose resource limits, timeouts, retries, circuit breakers, and rate limits around policy dispatch, annotator dispatch, model calls, tool calls, and approval workflows.
- The host must preserve JSON values across SDK and FFI boundaries without lossy type coercion.

## Detection Policy Authoring Guidance

Policies that try to detect adversarial content by matching substrings are only as strong as the normalization applied before the match. Rego `contains`, `startswith`, `endswith`, regular expression checks, and similar primitives compare literal code point sequences, so an attacker who controls the inspected text can split, pad, or re encode a phrase so that the literal match fails while the meaning survives for the model. A detector for the phrase `ignore all previous` does not fire on `ignore all` followed by a newline and `previous`, on the same words separated by a zero width space, on mixed case such as `Ignore All Previous`, or on a homoglyph or percent encoded variant. The match returns false and the activity proceeds as if no attack were present, which is a silent fail open inside an otherwise fail closed system.

Authors of security critical detection policies should normalize the inspected value before matching rather than matching the raw value. Useful normalization includes lower casing with `lower`, collapsing or stripping whitespace and control characters, removing or rejecting zero width and bidirectional formatting characters, applying Unicode normalization where the host can supply it, and decoding transport encodings the host knows are present. A policy should normalize once and match the normalized value consistently so that the same text cannot pass one check and fail another.

Substring matching is a weak last line and not a primary control. Prefer deterministic decisions over structured snapshot facts and tool metadata, such as actor, tenant, clearance, security labels, and explicit tool catalog entries, because those facts are not attacker reshapeable in the way free text is. Where semantic detection is required, prefer a host supplied annotation from a classifier or judge that itself normalizes input, and treat that annotation as policy input, while remembering that annotators fail closed and can produce false negatives. Detection by raw substring match should be reserved for coarse heuristics whose bypass does not by itself authorize a dangerous action.

## Residual Risks

Residual risk remains even when ACS is correctly integrated.

- Policies can be incomplete, overly broad, contradictory, or wrong.
- Rego can allow a dangerous action if the security reviewer failed to encode the relevant condition.
- Annotators, classifiers, LLM judges, and endpoint services can produce false positives, false negatives, stale results, or adversarially influenced outputs.
- Host snapshots can omit facts needed for policy, causing policy to evaluate an incomplete view of the agent state.
- Tool side effects can occur before `post_tool_call` evaluates a tool result.
- Post action `escalate` decisions require careful host handling to avoid duplicate execution during resume.
- Streaming aggregation can leak data if the host emits chunks before complete output evaluation.
- Allowed tools can still become exfiltration channels through permitted arguments, timing, metadata, or backend behavior.
- Redaction can fail if span producers and ACS disagree on character indexing semantics.
- OPA, custom policy backends, annotator services, and approval services can become availability dependencies.
- Deterministic runtime behavior does not imply deterministic external dispatcher behavior unless those dispatchers are deterministic for identical inputs.
- Telemetry sinks and host logs can become sensitive metadata aggregation points outside the runtime minimization guarantee.
- Supply chain compromise of packages, native libraries, OPA, manifests, bundles, or adapters can bypass policy intent.
- Pre-1.0 alpha APIs and integration surfaces can change and require renewed review.

## Threat-To-Control Matrix

| Threat | ACS control | Integration assumption | Status |
| --- | --- | --- | --- |
| Prompt injection through user input | The `input`, `pre_model_call`, `post_model_call`, `pre_tool_call`, and `output` points can run deterministic Rego and host annotations over explicit snapshots. | The host mediates ingress and consequential later actions, and policy encodes the security rule. | Partially mitigated. |
| Tool output injection | The `post_tool_call` point evaluates tool results before reuse, and later points can evaluate resulting model requests and outputs. | The host does not feed tool output back to the model or caller before mediation. | Partially mitigated. |
| Exfiltration through tool calls | The `pre_tool_call` point evaluates exact tool arguments with projected tool metadata and can deny, warn, escalate, or transform the target. | Tool credentials, destinations, and backend authorization are least privilege and host controlled. | Partially mitigated. |
| Unauthorized tool authority | Tool projection fails closed for unknown tools, and Rego can enforce actor, tenant, label, clearance, and workflow rules over the snapshot and tool metadata. | The tool catalog is accurate and all governed tools use mediated execution. | In scope mitigated for expressed policy. |
| Sensitive data leakage in final output | The `output` point can deny, warn, escalate, or transform the configured output target. | The host waits for the verdict and applies transformed output before disclosure. | In scope mitigated for expressed policy. |
| Sensitive data leakage in telemetry | Runtime telemetry emits low cardinality metadata and excludes policy targets, tool arguments, results, annotation values, model messages, secrets, and personal data. | Host logs, policy dispatchers, annotators, approval paths, and external telemetry follow their own data minimization controls. | Partially mitigated. |
| Policy bypass through uninstrumented paths | ACS defines required intervention points and host obligations, but it cannot observe paths never routed through it. | Adapter coverage, tests, code review, and platform controls prevent bypass paths. | Host responsibility. |
| Fail open on malformed policy | Manifest validation, reserved runtime errors, policy output normalization, transform validation, and unresolved `extends` rejection cause runtime failures to deny. | The host treats runtime `deny` as blocking in enforce mode. | In scope mitigated. |
| Supply chain compromise of policy bundle | The manifest and Rego bundle are explicit reviewable artifacts, and canonical policy input supports reproducible evaluation. | The deployment signs, reviews, pins, scans, and protects bundles, packages, OPA, SDKs, and native libraries. | Host responsibility. |
| Classifier or annotator outage | Annotator failures and timeouts fail closed as runtime errors. | The host configures bounded dispatcher behavior and accepts the availability impact of fail closed checks. | In scope mitigated for runtime behavior. |
| Policy dispatcher outage | Policy dispatch failure yields a runtime error and a deny verdict. | The host treats deny as blocking and operates policy infrastructure reliably. | In scope mitigated for runtime behavior. |
| Malformed policy output | Verdict normalization rejects invalid decisions, invalid types, invalid transforms, and reserved runtime error reasons. | The policy dispatcher output is routed through core normalization and not interpreted directly by the host. | In scope mitigated. |
| Transform escape from policy target | Transform validation requires paths rooted at `$policy_target` and fails closed on forbidden targets. | The host maps only the transformed policy target back into its controlled object. | In scope mitigated. |
| Redaction mismatch | The spec and core replace only the selected policy target path carried by a `transform` verdict. | Span or chunk based redaction systems must convert their result into a valid `transform` body before returning it. | Host responsibility. |
| Parameter tampering after evaluation | ACS returns the verdict and transformed target for the value it evaluated. | The host executes the same immutable invocation or applies the returned transformed target before execution. | Host responsibility. |
| Token streaming leakage | The model requires complete snapshots for `post_model_call` and `output`. | The host buffers streams and does not emit chunks before policy evaluation, or it explicitly accepts the leakage risk. | Out of scope. |
| Backend authorization failure | Rego can check snapshot facts and tool metadata before invocation. | Backend services enforce identity, tenant, permission, quota, and business authorization independently. | Host responsibility. |
| Compromised host application | ACS returns decisions but cannot force malicious host code to obey them. | Host code, deployment platform, and review process remain trusted. | Out of scope. |

## Production Readiness Checklist

A deployment should satisfy these checks before relying on ACS for security enforcement.

- The deployment inventory lists every model call, tool call, tool result path, final output path, startup path, and shutdown path that is governed.
- Tests prove each governed path invokes the expected ACS intervention point before execution or disclosure.
- Tests prove no parallel unguarded path exists for governed tools and outputs.
- The manifest is loaded through a path based loader when using file or HTTPS `extends`, or string and FFI loaders receive an already merged manifest.
- The manifest and Rego bundle are reviewed by security owners and protected by branch controls.
- The Rego bundle, OPA executable, SDK package, native library, and host adapter are pinned to reviewed versions.
- The host records the manifest version, bundle version, policy query, and runtime version with security decisions when audit requirements need that evidence.
- The host treats every runtime error reason as a blocking deny in enforce mode.
- The host blocks `deny` verdicts and fails closed on missing or failed approval paths for `escalate` verdicts.
- The host applies transformed policy targets only for `transform` verdicts before model calls, tool execution, tool result reuse, or output disclosure.
- The host binds tool evaluation to the exact tool name and arguments executed.
- The host aggregates streams before `post_model_call` and `output` evaluation.
- The host evaluates each parallel tool invocation independently and handles partial batch failure deliberately.
- The host uses least privilege tool credentials and backend services enforce independent authorization.
- The host validates annotator, policy, approval, model, telemetry, and tool service authentication and transport security.
- The host configures dispatcher timeouts, retries, circuit breakers, payload limits, rate limits, and concurrency limits.
- The host treats annotation requests, approval payloads, policy inputs, and host logs as sensitive data flows.
- The host has tests for malformed manifests, unresolved `extends`, missing paths, unknown tools, annotator failures, policy dispatcher failures, malformed policy outputs, invalid transforms, and redaction edge cases.
- The host has an operational plan for policy outages and the resulting fail closed behavior.
- The host documents which threats are accepted because they are outside ACS, including unmediated paths, token streaming leakage, backend authorization, host compromise, and supply chain compromise.
