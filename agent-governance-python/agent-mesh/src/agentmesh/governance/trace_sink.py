# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""TRACE v0.2 Trust Record emission for AGT sessions (ADR-0032).

Called at session close via GovernedCallable.close_session(). Uses the
agentrust-trace package for the TrustRecord model, Ed25519 signing, and
pre-write validation -- no local reimplementation of those primitives.

Phase 1 only: software-only, SLSA Level 0, no TEE attestation.
Phase 2 (hardware attestation) is cMCP's responsibility.
"""

from __future__ import annotations

import hashlib
import json
import re
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from .audit import AuditLog

_SUBJECT_RE = re.compile(r"^(spiffe://|did:)")


@dataclass
class TraceConfig:
    """Configuration for TRACE Trust Record emission.

    Add to GovernanceConfig.trace to enable session-close TRACE emission.
    The agent_id in GovernanceConfig must be a DID or SPIFFE URI -- TRACE
    records are skipped (with a warning) if it is a bare identifier like "*".

    Attributes:
        output_path: Directory (trailing /) or file path for the output JSON.
            Directories produce one file per session named
            ``trace-<iat>-<session_id>.json``.
        model_provider: Model provider string (e.g. "anthropic", "openai").
        model_id: Model identifier as used by the provider.
        model_version: Optional model version or snapshot string.
        build_provenance_slsa_level: SLSA Build Level. Use 0 for software-only.
        build_provenance_digest: SHA-256 digest of the agent container or
            binary (``sha256:<64 hex>``). Falls back to the Merkle root hash
            when not set -- valid but carries no SLSA attestation value.
        appraisal_verifier: URI identifying the verifier (can be self-hosted).
        data_class: Highest-sensitivity data class processed in the session.
    """

    output_path: str
    model_provider: str = "unknown"
    model_id: str = "unknown"
    model_version: Optional[str] = None
    build_provenance_slsa_level: int = 0
    build_provenance_digest: str = ""
    appraisal_verifier: str = "https://agt.local/verifier"
    data_class: str = "internal"


def session_to_trust_record(
    agent_did: str,
    audit_log: AuditLog,
    policy_bundle_hash: str,
    config: TraceConfig,
) -> dict[str, Any]:
    """Map an AGT session's AuditLog to an unsigned TRACE v0.2 Trust Record dict.

    Pass the returned dict to agentrust_trace.sign_record() before writing.
    """
    import time

    entries = audit_log._chain._entries
    iat = int(entries[-1].timestamp.timestamp()) if entries else int(time.time())

    # SHA-256 of the canonical JSON of all audit entries -- the tool transcript hash
    entries_canonical = json.dumps(
        [e.model_dump(mode="json") for e in entries],
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode()
    transcript_hash = "sha256:" + hashlib.sha256(entries_canonical).hexdigest()

    # Merkle root as the runtime measurement (software-only; no TEE measurement)
    merkle_root = audit_log._chain.get_root_hash() or ("0" * 64)
    measurement = "sha256:" + hashlib.sha256(merkle_root.encode()).hexdigest()

    bp_digest = config.build_provenance_digest or measurement

    record: dict[str, Any] = {
        "eat_profile": "tag:agentrust.io,2026:trace-v0.1",
        "iat": iat,
        "subject": agent_did,
        "model": {
            "provider": config.model_provider,
            "model_id": config.model_id,
        },
        "runtime": {
            "platform": "software-only",
            "measurement": measurement,
        },
        "policy": {
            "bundle_hash": policy_bundle_hash,
            "enforcement_mode": "enforce",
        },
        "data_class": config.data_class,
        "tool_transcript": {
            "hash": transcript_hash,
            "call_count": len(entries),
        },
        "build_provenance": {
            "slsa_level": config.build_provenance_slsa_level,
            "digest": bp_digest,
        },
        "appraisal": {
            "status": "affirming",
            "verifier": config.appraisal_verifier,
        },
        "transparency": "",
    }

    if config.model_version:
        record["model"]["version"] = config.model_version

    return record


class TRACEAuditSink:
    """Emit a TRACE v0.2 Trust Record at session close (ADR-0032).

    This is NOT an entry-level AuditSink. It is a session-level emitter:
    call emit() once after all governed calls complete to write a signed
    Trust Record JSON file for the session.

    Example::

        config = GovernanceConfig(
            policy="policy.yaml",
            agent_id="did:web:example.org/agent/payments",
            trace=TraceConfig(
                output_path="./trust-records/",
                model_provider="anthropic",
                model_id="claude-sonnet-4-6",
            ),
        )
        agent = govern(my_tool, config)
        agent(action="charge", resource="card")
        path = agent.close_session()  # writes trust-records/trace-<iat>-<sid>.json
    """

    def __init__(
        self,
        config: TraceConfig,
        agent_did: str,
        policy_bundle_hash: str,
    ) -> None:
        self._config = config
        self._agent_did = agent_did
        self._policy_bundle_hash = policy_bundle_hash

    def emit(self, audit_log: Optional[AuditLog]) -> Optional[str]:
        """Build, sign, validate, and write a TRACE Trust Record.

        Returns the path of the written file, or None if the audit log is
        empty, the agent_id is not a DID/SPIFFE URI, or audit_log is None.
        """
        if audit_log is None or not audit_log._chain._entries:
            return None

        if not _SUBJECT_RE.match(self._agent_did):
            warnings.warn(
                f"TRACE emission skipped: agent_id {self._agent_did!r} is not a "
                "SPIFFE URI or DID. Set GovernanceConfig.agent_id to a DID "
                "(e.g. 'did:web:example.org/agent/my-agent') to enable TRACE.",
                stacklevel=2,
            )
            return None

        try:
            from agentrust_trace import TrustRecord, sign_record, load_signing_key
        except ImportError as exc:
            raise RuntimeError(
                "agentrust-trace is required for TRACE emission. "
                "Install it with: pip install agentrust-trace>=0.2.0"
            ) from exc

        record = session_to_trust_record(
            self._agent_did,
            audit_log,
            self._policy_bundle_hash,
            self._config,
        )

        key = load_signing_key()
        signed = sign_record(record, key)
        TrustRecord.model_validate(signed)

        out = Path(self._config.output_path)
        if self._config.output_path.endswith("/") or (out.exists() and out.is_dir()):
            out.mkdir(parents=True, exist_ok=True)
            entries = audit_log._chain._entries
            session_id = (entries[0].session_id or "session")[:16]
            iat = signed["iat"]
            out = out / f"trace-{iat}-{session_id}.json"
        else:
            out.parent.mkdir(parents=True, exist_ok=True)

        out.write_text(
            json.dumps(signed, sort_keys=True, indent=2),
            encoding="utf-8",
        )
        return str(out)
