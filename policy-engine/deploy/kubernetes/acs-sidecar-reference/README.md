# ACS embedded SDK with OPA and Istio sidecars

This is a reference architecture for an application that embeds an ACS SDK and runs inside an Istio service mesh with OPA and Envoy sidecars. ACS is not a sidecar in this topology. It is not a tested cluster recipe and it is not CI verified. Adapt image names, host adapter code, OPA wiring, probes, resource limits, and policy content before production use.

## Architecture

```text
Caller
  |
  v
Istio ingress or east west mesh
  |
  v
Pod in acs-agents
  - app container with ACS SDK integration
  - OPA sidecar on 127.0.0.1:8181
  - Envoy sidecar injected by Istio
  - ConfigMap mounted at /etc/acs and /policy
```

ACS enforcement is inside the app process. The host calls the ACS runtime at `input`, `pre_model_call`, `post_model_call`, `pre_tool_call`, `post_tool_call`, and `output` with complete snapshots. A deny verdict blocks the wrapped operation before the model call, tool call, tool result reuse, or final disclosure proceeds. Runtime validation, missing paths, dispatcher failure, malformed policy output, and invalid effects fail closed.

Istio provides encrypted workload to workload transport, SPIFFE identity, sidecar telemetry, and mesh policy attachment points. Istio does not understand ACS snapshots, policy targets, tool metadata, effects, or intervention points. The mesh does not replace adapter mediation. An unguarded model or tool path inside the app remains outside the ACS envelope even when the pod uses mTLS.

OPA runs as a sidecar in the same pod. The app policy dispatcher reaches OPA over loopback at `http://127.0.0.1:8181`. The manifest declares the Rego bundle path as `/policy` and each intervention point binds a query under `data.agent_control_specification.acs_sidecar_reference`. The example mounts the same ConfigMap into the app for the manifest and into OPA for the Rego module.

## Files

- `namespace.yaml` creates `acs-agents` with Istio injection enabled.
- `acs-policy-configmap.yaml` contains `manifest.yaml` and `acs_sidecar_reference.rego`.
- `deployment.yaml` runs the ACS mediated app with an OPA sidecar.
- `service.yaml` exposes the app as a ClusterIP service.
- `peer-authentication.yaml` requires STRICT mTLS in the namespace.
- `destination-rule.yaml` requests ISTIO_MUTUAL TLS for in mesh callers.
- `kustomization.yaml` applies the reference resources.
- `setup-kind-istio.sh` is an untested illustrative bootstrap script.
- `test.sh` is an untested illustrative probe script.

## App integration contract

The placeholder image must be replaced with an app image that embeds one ACS SDK. The app loads `/etc/acs/manifest.yaml`, builds an enforcing runtime, and supplies a policy dispatcher that invokes OPA. The app must publish only guarded model, tool, runner, middleware, hook, provider, or filter objects. Retaining unwrapped references creates a bypass path that Kubernetes and Istio cannot detect.

At `pre_tool_call`, the host passes the exact tool name and arguments that will execute. At `post_tool_call`, the host evaluates the tool result before model reuse, storage, or caller disclosure. At `output`, the host buffers the complete final response before releasing it. Streaming implementations should use a buffer before disclose pattern because ACS evaluates complete snapshots.

## Trust boundaries

The trusted computing base includes the app integration code, selected SDK, ACS core, manifest, Rego bundle, policy dispatcher, OPA sidecar, container images, and Kubernetes controls that protect mounted configuration. User input, model output, tool output, retrieved content, and final text remain untrusted until the relevant ACS intervention point allows them. Backend services still enforce their own authorization. ACS does not own credentials, egress, service account permissions, or data plane routing.

The mesh boundary protects pod to pod transport and identifies workloads. The ACS boundary protects model and tool semantics only when the host routes those semantics through the runtime. The OPA boundary receives canonical policy input selected by ACS and returns a verdict shaped object. If OPA is unreachable or returns invalid output, the dispatcher error path should produce a fail closed deny.

## Apply

```bash
kubectl apply -k deploy/kubernetes/acs-sidecar-reference
```

## Replace the placeholder image

```yaml
spec:
  template:
    spec:
      containers:
        - name: app
          image: registry.example.com/team/acs-mediated-app:v0.1.0
```

## Illustrative validation

```bash
bash deploy/kubernetes/acs-sidecar-reference/test.sh
```

The script checks rendered Kubernetes objects and sends health, allow, and deny probes through a local port forward. It assumes the replacement app exposes `/health` and `/chat`. It is a reference probe and not evidence that this repository has a tested cluster.
