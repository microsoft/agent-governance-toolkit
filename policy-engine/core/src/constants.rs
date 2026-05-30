pub(crate) mod annotation {
    pub(crate) const FROM: &str = "from";
    pub(crate) const INPUT_FROM: &str = "input_from";
    pub(crate) const TYPE: &str = "type";
}

pub(crate) mod engine {
    pub(crate) const CEDAR: &str = "cedar";
    pub(crate) const CUSTOM: &str = "custom";
    pub(crate) const REGO: &str = "rego";
    pub(crate) const TEST: &str = "test";
}

/// Field names reserved for the `cedar` policy type, per AGT delta D3.1.
/// These are rejected when they appear on a `rego` policy's flattened
/// `adapter_config` so that mixed-language manifests are caught early.
pub(crate) mod cedar_field {
    pub(crate) const POLICY_SET: &str = "policy_set";
    pub(crate) const POLICY_PATH: &str = "policy_path";
    pub(crate) const ENTITIES_PATH: &str = "entities_path";
    pub(crate) const SCHEMA_PATH: &str = "schema_path";

    pub(crate) const ALL: [&str; 4] = [POLICY_SET, POLICY_PATH, ENTITIES_PATH, SCHEMA_PATH];
}

pub(crate) mod policy_input {
    pub(crate) const ANNOTATIONS: &str = "annotations";
    pub(crate) const INTERVENTION_POINT: &str = "intervention_point";
    pub(crate) const KIND: &str = "kind";
    pub(crate) const PATH: &str = "path";
    pub(crate) const SNAPSHOT: &str = "snapshot";
    pub(crate) const POLICY_TARGET: &str = "policy_target";
    pub(crate) const TOOL: &str = "tool";
    pub(crate) const VALUE: &str = "value";
}
