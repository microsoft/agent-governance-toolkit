# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the centralized exception hierarchy."""

import pytest

from agentmesh.exceptions import (
    AgentMeshError,
    DelegationError,
    GovernanceError,
    HandshakeError,
    IdentityError,
    StorageError,
    TrustError,
    TrustVerificationError,
    TrustViolationError,
)


class TestExceptionHierarchy:
    """Verify the exception class hierarchy is correct."""

    def test_base_exception_exists(self):
        assert issubclass(AgentMeshError, Exception)

    @pytest.mark.parametrize(
        "exc_cls",
        [
            IdentityError,
            TrustError,
            DelegationError,
            GovernanceError,
            StorageError,
        ],
    )
    def test_direct_subclasses_of_agentmesh_error(self, exc_cls):
        assert issubclass(exc_cls, AgentMeshError)
        assert exc_cls.__bases__ == (AgentMeshError,)

    @pytest.mark.parametrize(
        "exc_cls",
        [TrustVerificationError, TrustViolationError, HandshakeError],
    )
    def test_trust_subclasses(self, exc_cls):
        assert issubclass(exc_cls, TrustError)
        assert issubclass(exc_cls, AgentMeshError)
        assert exc_cls.__bases__ == (TrustError,)

    @pytest.mark.parametrize(
        "exc_cls",
        [
            AgentMeshError,
            IdentityError,
            TrustError,
            TrustVerificationError,
            TrustViolationError,
            DelegationError,
            GovernanceError,
            HandshakeError,
            StorageError,
        ],
    )
    def test_instance_of_agentmesh_error(self, exc_cls):
        err = exc_cls("test message")
        assert isinstance(err, AgentMeshError)
        assert isinstance(err, Exception)


class TestExceptionMessages:
    """Verify exception messages propagate correctly."""

    def test_message_propagation(self):
        err = TrustVerificationError("trust score too low")
        assert str(err) == "trust score too low"

    def test_catch_by_base_class(self):
        with pytest.raises(AgentMeshError):
            raise TrustViolationError("policy violated")

    def test_catch_by_trust_error(self):
        with pytest.raises(TrustError):
            raise TrustVerificationError("verification failed")

    def test_catch_by_trust_error_catches_handshake(self):
        with pytest.raises(TrustError):
            raise HandshakeError("handshake timeout")

    def test_does_not_catch_sibling(self):
        with pytest.raises(IdentityError):
            raise IdentityError("bad DID")
        # GovernanceError should NOT catch IdentityError
        with pytest.raises(IdentityError):
            try:
                raise IdentityError("bad DID")
            except GovernanceError:
                pytest.fail("GovernanceError should not catch IdentityError")


class TestBackwardCompatibility:
    """Verify that importing from integration modules still works."""

    def test_swarm_trust_violation_error(self):
        from agentmesh.integrations.swarm import TrustViolationError as SwarmError

        assert issubclass(SwarmError, TrustError)
        assert SwarmError is TrustViolationError

    def test_langgraph_trust_verification_error(self):
        from agentmesh.integrations.langgraph import (
            TrustVerificationError as LanggraphError,
        )

        assert issubclass(LanggraphError, TrustError)
        assert LanggraphError is TrustVerificationError

    def test_langflow_trust_verification_error(self):
        from agentmesh.integrations.langflow import (
            TrustVerificationError as LangflowError,
        )

        assert issubclass(LangflowError, TrustError)
        assert LangflowError is TrustVerificationError

    def test_flowise_trust_error(self):
        from agentmesh.integrations.flowise import FlowiseTrustError

        assert issubclass(FlowiseTrustError, TrustError)
        assert issubclass(FlowiseTrustError, AgentMeshError)

    def test_haystack_trust_error(self):
        from agentmesh.integrations.haystack import HaystackTrustError

        assert issubclass(HaystackTrustError, TrustError)
        assert issubclass(HaystackTrustError, AgentMeshError)

    def test_top_level_import(self):
        """Exceptions are importable from the agentmesh package."""
        from agentmesh import AgentMeshError as TopLevelError

        assert TopLevelError is AgentMeshError
