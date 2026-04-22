# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from agent_mcp_governance import (
    AuditEntry,
    GovernanceAuditLogger,
    GovernanceMiddleware,
    GovernancePolicy,
    PolicyEvaluator,
    TrustDecision,
    TrustRoot,
)


def test_exported_symbols_import() -> None:
    assert GovernanceMiddleware is not None
    assert PolicyEvaluator is not None
    assert GovernanceAuditLogger is not None
    assert AuditEntry is not None
    assert GovernancePolicy is not None
    assert TrustRoot is not None
    assert TrustDecision is not None
