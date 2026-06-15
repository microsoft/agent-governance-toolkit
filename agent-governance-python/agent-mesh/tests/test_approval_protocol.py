# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the action-bound approval protocol (ADR-0030, step 1 foundation)."""

from datetime import datetime, timedelta, timezone

import pytest

from agentmesh.governance.approval_protocol import (
    ActionBinding,
    ActionTarget,
    ApprovalChain,
    ApprovalCoordinator,
    ApprovalProtocolError,
    ApprovalStage,
    ApproverKind,
    EntryDecision,
    InMemoryApprovalStore,
    ReasonCode,
    canonicalize,
    sha256_jcs,
)


# --------------------------------------------------------------------------- #
# Test helpers
# --------------------------------------------------------------------------- #


class Clock:
    """Controllable monotonic clock for expiry tests."""

    def __init__(self, start: datetime | None = None) -> None:
        self.now = start or datetime(2026, 6, 11, 12, 0, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


ALICE = "did:web:example.com:users:alice"
BOB = "did:web:example.com:users:bob"


def make_binding(**overrides) -> ActionBinding:
    params = overrides.pop("parameters", {"statement": "UPDATE accounts SET status = ?", "values": ["closed", 42]})
    return ActionBinding(
        operation=overrides.pop("operation", "tool.invoke"),
        agent_id=overrides.pop("agent_id", "agent-123"),
        target=overrides.pop(
            "target", ActionTarget("sql_execute", "2", resource="prod-db")
        ),
        parameters=params,
        subject_id=overrides.pop("subject_id", "user-456"),
    )


def single_stage_chain() -> ApprovalChain:
    return ApprovalChain(
        chain_id="high-risk-tools",
        version="3",
        stages=(ApprovalStage(0, allowed_identities=frozenset({ALICE})),),
    )


def two_stage_chain() -> ApprovalChain:
    return ApprovalChain(
        chain_id="two-stage",
        version="1",
        stages=(
            ApprovalStage(0, allowed_identities=frozenset({ALICE})),
            ApprovalStage(1, allowed_roles=frozenset({"compliance"})),
        ),
    )


def make_coordinator(chain: ApprovalChain, clock: Clock | None = None) -> ApprovalCoordinator:
    return ApprovalCoordinator(
        InMemoryApprovalStore(), {chain.chain_id: chain}, clock=clock or Clock()
    )


# --------------------------------------------------------------------------- #
# JCS digest
# --------------------------------------------------------------------------- #


class TestJcsDigest:
    def test_key_order_independent(self):
        assert canonicalize({"b": 1, "a": 2}) == canonicalize({"a": 2, "b": 1})
        assert canonicalize({"b": 1, "a": 2}) == b'{"a":2,"b":1}'

    def test_no_insignificant_whitespace(self):
        assert canonicalize([1, {"x": "y"}]) == b'[1,{"x":"y"}]'

    def test_integer_valued_float_normalized(self):
        assert canonicalize(1.0) == canonicalize(1) == b"1"

    def test_non_ascii_kept_as_utf8(self):
        assert canonicalize("café") == '"café"'.encode("utf-8")

    def test_rejects_nan(self):
        with pytest.raises(ValueError):
            canonicalize(float("nan"))

    def test_rejects_non_json_type(self):
        with pytest.raises(TypeError):
            canonicalize({"k": object()})

    def test_sha256_prefix(self):
        digest = sha256_jcs({"a": 1})
        assert digest.startswith("sha256:")
        assert len(digest) == len("sha256:") + 64


# --------------------------------------------------------------------------- #
# Action binding
# --------------------------------------------------------------------------- #


class TestActionBinding:
    def test_digest_is_stable(self):
        assert make_binding().digest() == make_binding().digest()

    def test_digest_changes_with_parameters(self):
        a = make_binding(parameters={"values": [1]})
        b = make_binding(parameters={"values": [2]})
        assert a.digest() != b.digest()

    def test_digest_changes_with_target(self):
        a = make_binding(target=ActionTarget("sql_execute", "2", resource="prod-db"))
        b = make_binding(target=ActionTarget("sql_execute", "3", resource="prod-db"))
        assert a.digest() != b.digest()

    def test_digest_changes_with_subject(self):
        assert make_binding(subject_id="user-1").digest() != make_binding(
            subject_id="user-2"
        ).digest()


# --------------------------------------------------------------------------- #
# Happy path + one-time consumption
# --------------------------------------------------------------------------- #


class TestApprovalFlow:
    def test_single_stage_allow_releases_once(self):
        chain = single_stage_chain()
        coord = make_coordinator(chain)
        binding = make_binding()
        _, request = coord.open_request(
            binding,
            policy_rule_id="production-db-writes",
            policy_version="2026.06.11",
            chain_id=chain.chain_id,
            ttl_seconds=600,
        )

        coord.submit_entry(
            request.approval_request_id,
            stage_index=0,
            approver_kind=ApproverKind.HUMAN,
            approver_identity=ALICE,
            identity_assurance="oidc",
            decision=EntryDecision.ALLOW,
        )

        verdict = coord.validate_for_execution(
            request.approval_request_id,
            current_action_digest=binding.digest(),
            current_policy_version="2026.06.11",
            current_chain_version=chain.version,
        )
        assert verdict.allowed
        assert verdict.reason_code == ReasonCode.OK

        # One-time use: a second execution attempt is denied.
        again = coord.validate_for_execution(
            request.approval_request_id,
            current_action_digest=binding.digest(),
            current_policy_version="2026.06.11",
            current_chain_version=chain.version,
        )
        assert not again.allowed
        assert again.reason_code == ReasonCode.ALREADY_CONSUMED

    def test_pending_request_has_no_resolution(self):
        chain = single_stage_chain()
        coord = make_coordinator(chain)
        binding = make_binding()
        _, request = coord.open_request(
            binding,
            policy_rule_id="r",
            policy_version="v1",
            chain_id=chain.chain_id,
            ttl_seconds=600,
        )
        verdict = coord.validate_for_execution(
            request.approval_request_id,
            current_action_digest=binding.digest(),
            current_policy_version="v1",
            current_chain_version=chain.version,
        )
        assert not verdict.allowed
        assert verdict.reason_code == ReasonCode.NO_RESOLUTION

    def test_two_stages_both_required(self):
        chain = two_stage_chain()
        coord = make_coordinator(chain)
        binding = make_binding()
        _, request = coord.open_request(
            binding,
            policy_rule_id="r",
            policy_version="v1",
            chain_id=chain.chain_id,
            ttl_seconds=600,
        )
        # Stage 0 allowed: not yet terminal.
        coord.submit_entry(
            request.approval_request_id,
            stage_index=0,
            approver_kind=ApproverKind.HUMAN,
            approver_identity=ALICE,
            identity_assurance="oidc",
            decision=EntryDecision.ALLOW,
        )
        pending = coord.validate_for_execution(
            request.approval_request_id,
            current_action_digest=binding.digest(),
            current_policy_version="v1",
            current_chain_version=chain.version,
        )
        assert pending.reason_code == ReasonCode.NO_RESOLUTION

        # Stage 1 allowed by role: now terminal.
        coord.submit_entry(
            request.approval_request_id,
            stage_index=1,
            approver_kind=ApproverKind.SERVICE,
            approver_identity="svc:compliance-bot",
            identity_assurance="mtls",
            decision=EntryDecision.ALLOW,
            roles=["compliance"],
        )
        verdict = coord.validate_for_execution(
            request.approval_request_id,
            current_action_digest=binding.digest(),
            current_policy_version="v1",
            current_chain_version=chain.version,
        )
        assert verdict.allowed


# --------------------------------------------------------------------------- #
# Fail-closed behaviour
# --------------------------------------------------------------------------- #


class TestFailClosed:
    def _allow(self, coord, chain, binding):
        _, request = coord.open_request(
            binding,
            policy_rule_id="r",
            policy_version="v1",
            chain_id=chain.chain_id,
            ttl_seconds=600,
        )
        coord.submit_entry(
            request.approval_request_id,
            stage_index=0,
            approver_kind=ApproverKind.HUMAN,
            approver_identity=ALICE,
            identity_assurance="oidc",
            decision=EntryDecision.ALLOW,
        )
        return request

    def test_action_digest_mismatch_denies(self):
        chain = single_stage_chain()
        coord = make_coordinator(chain)
        request = self._allow(coord, chain, make_binding())
        verdict = coord.validate_for_execution(
            request.approval_request_id,
            current_action_digest=make_binding(parameters={"values": [999]}).digest(),
            current_policy_version="v1",
            current_chain_version=chain.version,
        )
        assert verdict.reason_code == ReasonCode.ACTION_DIGEST_MISMATCH

    def test_policy_version_mismatch_denies(self):
        chain = single_stage_chain()
        coord = make_coordinator(chain)
        binding = make_binding()
        request = self._allow(coord, chain, binding)
        verdict = coord.validate_for_execution(
            request.approval_request_id,
            current_action_digest=binding.digest(),
            current_policy_version="v2",
            current_chain_version=chain.version,
        )
        assert verdict.reason_code == ReasonCode.POLICY_VERSION_MISMATCH

    def test_chain_version_mismatch_denies(self):
        chain = single_stage_chain()
        coord = make_coordinator(chain)
        binding = make_binding()
        request = self._allow(coord, chain, binding)
        verdict = coord.validate_for_execution(
            request.approval_request_id,
            current_action_digest=binding.digest(),
            current_policy_version="v1",
            current_chain_version="999",
        )
        assert verdict.reason_code == ReasonCode.CHAIN_VERSION_MISMATCH

    def test_deny_entry_terminates_chain(self):
        chain = single_stage_chain()
        coord = make_coordinator(chain)
        binding = make_binding()
        _, request = coord.open_request(
            binding,
            policy_rule_id="r",
            policy_version="v1",
            chain_id=chain.chain_id,
            ttl_seconds=600,
        )
        coord.submit_entry(
            request.approval_request_id,
            stage_index=0,
            approver_kind=ApproverKind.HUMAN,
            approver_identity=ALICE,
            identity_assurance="oidc",
            decision=EntryDecision.DENY,
        )
        verdict = coord.validate_for_execution(
            request.approval_request_id,
            current_action_digest=binding.digest(),
            current_policy_version="v1",
            current_chain_version=chain.version,
        )
        assert verdict.reason_code == ReasonCode.NOT_TERMINAL_ALLOW

    def test_expiry_denies(self):
        chain = single_stage_chain()
        clock = Clock()
        coord = make_coordinator(chain, clock)
        binding = make_binding()
        _, request = coord.open_request(
            binding,
            policy_rule_id="r",
            policy_version="v1",
            chain_id=chain.chain_id,
            ttl_seconds=60,
        )
        clock.advance(61)
        verdict = coord.validate_for_execution(
            request.approval_request_id,
            current_action_digest=binding.digest(),
            current_policy_version="v1",
            current_chain_version=chain.version,
        )
        assert verdict.reason_code == ReasonCode.EXPIRED

    def test_submit_after_expiry_raises(self):
        chain = single_stage_chain()
        clock = Clock()
        coord = make_coordinator(chain, clock)
        _, request = coord.open_request(
            make_binding(),
            policy_rule_id="r",
            policy_version="v1",
            chain_id=chain.chain_id,
            ttl_seconds=60,
        )
        clock.advance(61)
        with pytest.raises(ApprovalProtocolError):
            coord.submit_entry(
                request.approval_request_id,
                stage_index=0,
                approver_kind=ApproverKind.HUMAN,
                approver_identity=ALICE,
                identity_assurance="oidc",
                decision=EntryDecision.ALLOW,
            )

    def test_unauthorized_identity_rejected(self):
        chain = single_stage_chain()
        coord = make_coordinator(chain)
        _, request = coord.open_request(
            make_binding(),
            policy_rule_id="r",
            policy_version="v1",
            chain_id=chain.chain_id,
            ttl_seconds=600,
        )
        with pytest.raises(ApprovalProtocolError):
            coord.submit_entry(
                request.approval_request_id,
                stage_index=0,
                approver_kind=ApproverKind.HUMAN,
                approver_identity=BOB,  # not permitted for stage 0
                identity_assurance="oidc",
                decision=EntryDecision.ALLOW,
            )

    def test_unknown_request_denies(self):
        coord = make_coordinator(single_stage_chain())
        verdict = coord.validate_for_execution(
            "ar_does_not_exist",
            current_action_digest="sha256:00",
            current_policy_version="v1",
            current_chain_version="3",
        )
        assert verdict.reason_code == ReasonCode.UNKNOWN_REQUEST


# --------------------------------------------------------------------------- #
# Tamper evidence + advisory entries + idempotency
# --------------------------------------------------------------------------- #


class TestChainIntegrity:
    def test_tampered_entry_detected(self):
        chain = single_stage_chain()
        store = InMemoryApprovalStore()
        coord = ApprovalCoordinator(store, {chain.chain_id: chain}, clock=Clock())
        binding = make_binding()
        _, request = coord.open_request(
            binding,
            policy_rule_id="r",
            policy_version="v1",
            chain_id=chain.chain_id,
            ttl_seconds=600,
        )
        coord.submit_entry(
            request.approval_request_id,
            stage_index=0,
            approver_kind=ApproverKind.HUMAN,
            approver_identity=ALICE,
            identity_assurance="oidc",
            decision=EntryDecision.ALLOW,
        )
        # Mutate a stored entry without recomputing its sealed digest.
        entry = store.get_entries(request.approval_request_id)[0]
        entry.approver_identity = BOB

        verdict = coord.validate_for_execution(
            request.approval_request_id,
            current_action_digest=binding.digest(),
            current_policy_version="v1",
            current_chain_version=chain.version,
        )
        assert verdict.reason_code == ReasonCode.CHAIN_TAMPERED

    def test_advisory_entry_does_not_satisfy_stage(self):
        chain = single_stage_chain()
        coord = make_coordinator(chain)
        binding = make_binding()
        _, request = coord.open_request(
            binding,
            policy_rule_id="r",
            policy_version="v1",
            chain_id=chain.chain_id,
            ttl_seconds=600,
        )
        # An LLM advisory "allow" must not resolve the request.
        coord.submit_entry(
            request.approval_request_id,
            stage_index=0,
            approver_kind=ApproverKind.LLM_ADVISORY,
            approver_identity="model:claude-opus-4-8",
            identity_assurance="none",
            decision=EntryDecision.ALLOW,
        )
        verdict = coord.validate_for_execution(
            request.approval_request_id,
            current_action_digest=binding.digest(),
            current_policy_version="v1",
            current_chain_version=chain.version,
        )
        assert verdict.reason_code == ReasonCode.NO_RESOLUTION

    def test_idempotent_resubmission_by_entry_id(self):
        chain = single_stage_chain()
        coord = make_coordinator(chain)
        _, request = coord.open_request(
            make_binding(),
            policy_rule_id="r",
            policy_version="v1",
            chain_id=chain.chain_id,
            ttl_seconds=600,
        )
        first = coord.submit_entry(
            request.approval_request_id,
            stage_index=0,
            approver_kind=ApproverKind.HUMAN,
            approver_identity=ALICE,
            identity_assurance="oidc",
            decision=EntryDecision.ALLOW,
            chain_entry_id="ace_fixed",
        )
        second = coord.submit_entry(
            request.approval_request_id,
            stage_index=0,
            approver_kind=ApproverKind.HUMAN,
            approver_identity=ALICE,
            identity_assurance="oidc",
            decision=EntryDecision.ALLOW,
            chain_entry_id="ace_fixed",
        )
        assert first is second
        assert len(coord.store.get_entries(request.approval_request_id)) == 1
