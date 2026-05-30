pub(crate) mod annotation {
    pub(crate) const FROM: &str = "from";
    pub(crate) const INPUT_FROM: &str = "input_from";
    pub(crate) const TYPE: &str = "type";
}

pub(crate) mod engine {
    pub(crate) const CUSTOM: &str = "custom";
    pub(crate) const REGO: &str = "rego";
    pub(crate) const TEST: &str = "test";
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
