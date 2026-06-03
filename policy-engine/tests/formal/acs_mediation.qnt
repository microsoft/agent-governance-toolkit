module acs_mediation {
  type MediationState = {
    phase: str,
    runtimeErrorReason: str,
    policyDecision: str,
    enforceMode: bool,
    effectsRequested: bool,
    effectsApplied: bool,
    approvalPathConfigured: bool,
    approvalOutcome: str,
    approvalRouted: bool,
    verdict: str,
    verdictCount: int,
    reason: str,
    explicitAllowDecision: bool,
  }

  var st: MediationState

  pure val Verdicts = Set("allow", "warn", "deny", "escalate")
  pure val PolicyDecisions = Set("allow", "warn", "deny", "escalate")
  pure val ApprovalOutcomes = Set("recognized", "missing", "failed", "unrecognized")
  pure val RuntimeErrorReasons = Set(
    "none",
    "runtime_error:manifest_invalid",
    "runtime_error:intervention_point_unknown",
    "runtime_error:path_missing",
    "runtime_error:path_type_mismatch",
    "runtime_error:tool_unknown",
    "runtime_error:annotation_failed",
    "runtime_error:annotation_timeout",
    "runtime_error:policy_invocation_failed",
    "runtime_error:policy_output_invalid",
    "runtime_error:effect_invalid",
    "runtime_error:effect_target_forbidden",
    "runtime_error:resource_limit_exceeded",
    "runtime_error:approval_action_mismatch",
  )

  pure def initial: MediationState = {
    phase: "ready",
    runtimeErrorReason: "none",
    policyDecision: "deny",
    enforceMode: true,
    effectsRequested: false,
    effectsApplied: false,
    approvalPathConfigured: false,
    approvalOutcome: "missing",
    approvalRouted: false,
    verdict: "deny",
    verdictCount: 0,
    reason: "not_mediated",
    explicitAllowDecision: false,
  }

  action init = st' = initial

  action runtimeError(reasonValue: str): bool = all {
    st.phase == "ready",
    st' = {
      phase: "terminal",
      runtimeErrorReason: reasonValue,
      policyDecision: "deny",
      enforceMode: true,
      effectsRequested: true,
      effectsApplied: false,
      approvalPathConfigured: false,
      approvalOutcome: "missing",
      approvalRouted: false,
      verdict: "deny",
      verdictCount: 1,
      reason: reasonValue,
      explicitAllowDecision: false,
    },
  }

  action policyAllowWithEffect = all {
    st.phase == "ready",
    st' = {
      phase: "terminal",
      runtimeErrorReason: "none",
      policyDecision: "allow",
      enforceMode: true,
      effectsRequested: true,
      effectsApplied: true,
      approvalPathConfigured: false,
      approvalOutcome: "missing",
      approvalRouted: false,
      verdict: "allow",
      verdictCount: 1,
      reason: "policy:allow",
      explicitAllowDecision: true,
    },
  }

  action policyAllowEvaluateOnly = all {
    st.phase == "ready",
    st' = {
      phase: "terminal",
      runtimeErrorReason: "none",
      policyDecision: "allow",
      enforceMode: false,
      effectsRequested: true,
      effectsApplied: false,
      approvalPathConfigured: false,
      approvalOutcome: "missing",
      approvalRouted: false,
      verdict: "allow",
      verdictCount: 1,
      reason: "policy:allow",
      explicitAllowDecision: true,
    },
  }

  action policyWarnWithEffect = all {
    st.phase == "ready",
    st' = {
      phase: "terminal",
      runtimeErrorReason: "none",
      policyDecision: "warn",
      enforceMode: true,
      effectsRequested: true,
      effectsApplied: true,
      approvalPathConfigured: false,
      approvalOutcome: "missing",
      approvalRouted: false,
      verdict: "warn",
      verdictCount: 1,
      reason: "policy:warn",
      explicitAllowDecision: false,
    },
  }

  action policyDenyEffectSuppressed = all {
    st.phase == "ready",
    st' = {
      phase: "terminal",
      runtimeErrorReason: "none",
      policyDecision: "deny",
      enforceMode: true,
      effectsRequested: true,
      effectsApplied: false,
      approvalPathConfigured: false,
      approvalOutcome: "missing",
      approvalRouted: false,
      verdict: "deny",
      verdictCount: 1,
      reason: "policy:deny",
      explicitAllowDecision: false,
    },
  }

  action policyEscalateRecognized = all {
    st.phase == "ready",
    st' = {
      phase: "terminal",
      runtimeErrorReason: "none",
      policyDecision: "escalate",
      enforceMode: true,
      effectsRequested: true,
      effectsApplied: false,
      approvalPathConfigured: true,
      approvalOutcome: "recognized",
      approvalRouted: true,
      verdict: "escalate",
      verdictCount: 1,
      reason: "policy:escalate",
      explicitAllowDecision: false,
    },
  }

  action policyEscalateNoPath = all {
    st.phase == "ready",
    st' = {
      phase: "terminal",
      runtimeErrorReason: "none",
      policyDecision: "escalate",
      enforceMode: true,
      effectsRequested: true,
      effectsApplied: false,
      approvalPathConfigured: false,
      approvalOutcome: "missing",
      approvalRouted: false,
      verdict: "deny",
      verdictCount: 1,
      reason: "runtime_error:path_missing",
      explicitAllowDecision: false,
    },
  }

  action policyEscalateFailedPath = all {
    st.phase == "ready",
    st' = {
      phase: "terminal",
      runtimeErrorReason: "none",
      policyDecision: "escalate",
      enforceMode: true,
      effectsRequested: true,
      effectsApplied: false,
      approvalPathConfigured: true,
      approvalOutcome: "failed",
      approvalRouted: true,
      verdict: "deny",
      verdictCount: 1,
      reason: "runtime_error:approval_action_mismatch",
      explicitAllowDecision: false,
    },
  }

  action policyEscalateUnrecognized = all {
    st.phase == "ready",
    st' = {
      phase: "terminal",
      runtimeErrorReason: "none",
      policyDecision: "escalate",
      enforceMode: true,
      effectsRequested: true,
      effectsApplied: false,
      approvalPathConfigured: true,
      approvalOutcome: "unrecognized",
      approvalRouted: true,
      verdict: "deny",
      verdictCount: 1,
      reason: "runtime_error:approval_action_mismatch",
      explicitAllowDecision: false,
    },
  }

  action terminalStutter = all {
    st.phase == "terminal",
    st' = st,
  }

  action step = any {
    runtimeError("runtime_error:manifest_invalid"),
    runtimeError("runtime_error:intervention_point_unknown"),
    runtimeError("runtime_error:path_missing"),
    runtimeError("runtime_error:path_type_mismatch"),
    runtimeError("runtime_error:tool_unknown"),
    runtimeError("runtime_error:annotation_failed"),
    runtimeError("runtime_error:annotation_timeout"),
    runtimeError("runtime_error:policy_invocation_failed"),
    runtimeError("runtime_error:policy_output_invalid"),
    runtimeError("runtime_error:effect_invalid"),
    runtimeError("runtime_error:effect_target_forbidden"),
    runtimeError("runtime_error:resource_limit_exceeded"),
    runtimeError("runtime_error:approval_action_mismatch"),
    policyAllowWithEffect,
    policyAllowEvaluateOnly,
    policyWarnWithEffect,
    policyDenyEffectSuppressed,
    policyEscalateRecognized,
    policyEscalateNoPath,
    policyEscalateFailedPath,
    policyEscalateUnrecognized,
    terminalStutter,
  }

  pure def RuntimeErrorsDeny =
    st.phase != "terminal" or st.runtimeErrorReason == "none" or st.verdict == "deny"

  pure def NoEffectsOnDenyOrEscalate =
    st.phase != "terminal" or not(st.verdict == "deny" or st.verdict == "escalate") or not(st.effectsApplied)

  pure def EffectsOnlyOnAllowOrWarn =
    st.phase != "terminal" or not(st.effectsApplied) or (st.verdict == "allow" or st.verdict == "warn")

  pure def EscalateWithoutValidApprovalDenies =
    st.phase != "terminal" or st.policyDecision != "escalate" or st.runtimeErrorReason != "none" or
      (st.approvalPathConfigured and st.approvalOutcome == "recognized") or st.verdict == "deny"

  pure def EscalateRequiresApprovalRouting =
    st.phase != "terminal" or st.verdict != "escalate" or
      (st.policyDecision == "escalate" and st.approvalPathConfigured and st.approvalOutcome == "recognized" and st.approvalRouted)

  pure def ExactlyOneVerdict =
    st.phase != "terminal" or (st.verdictCount == 1 and Verdicts.contains(st.verdict))

  pure def ExplicitAllowRequired =
    st.phase != "terminal" or st.verdict != "allow" or st.explicitAllowDecision
}
