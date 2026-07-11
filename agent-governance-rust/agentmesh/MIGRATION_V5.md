# Rust framework policy migration

`FrameworkGovernanceAdapter` now consumes native Agent Control Specification
objects. The removed local framework policy and pattern types are not
translated at runtime.

```rust
use agentmesh::{
    AgentControl, FrameworkGovernanceAdapter, FrameworkKind, Manifest,
};

let manifest = Manifest::from_path("manifest.yaml")?;
let control = AgentControl::from_manifest(manifest)?;
let adapter = FrameworkGovernanceAdapter::new(
    FrameworkKind::Tower,
    MyHook,
    control,
);
```

Move tool catalogs, intervention-point bindings, budgets, approval rules, and
content policies into the manifest. Keep framework-only drift and checkpoint
settings in `FrameworkHostConfig`.

Legacy-shaped YAML is rejected with `runtime_error:manifest_invalid`. The Rust
SDK does not guess at or partially translate removed fields.
