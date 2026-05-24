# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Credential vault, scoping, and injection for agent tool calls.

This module implements the runtime-governance side of credential offload as
described in issue #2481. The design goals are:

1. **Value boundary** — agents never receive resolved secret values. They
   reference credentials by opaque handle names; only the injector (running
   inside the trust boundary of AGT) ever sees the resolved value, and only
   long enough to render it into an outbound request.
2. **Authority boundary** — every resolution is gated by a per-agent
   credential profile that binds an *action capability* (not just an agent
   identity) to a specific credential handle. Cross-agent and cross-action
   credential access is denied by default.
3. **Policy-first** — placeholder substitution happens *after* policy
   evaluation. A prompt-injected tool argument cannot smuggle a credential
   reference into a parameter that the workflow policy never authorized.
4. **Deterministic deny** — denied resolutions emit the same opaque
   ``DenyReceipt`` regardless of whether the handle exists, is bound to a
   different agent, or is bound to a different action class. Existence of a
   credential outside an agent's scope is never disclosed.
5. **Untrusted server metadata** — only placeholders whose names appear in
   the caller-supplied ``allowed_handles`` set are eligible for substitution.
   Anything else in the payload — including values returned by MCP servers
   or model output — is left verbatim and recorded as a denied attempt.
6. **Rotation without rebinding** — credential values can be rotated in
   place; the handle name is stable so prompts, MCP descriptions, saved
   plans, and memory entries never need to change.

The vault supports optional encrypted-at-rest persistence via Fernet
(``cryptography``); if ``cryptography`` is not installed the vault operates
in-memory only and refuses to write a persistence file (failing closed
rather than writing plaintext secrets to disk).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Callable, Iterable, Mapping, MutableMapping

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

#: Regex matching the credential placeholder syntax ``{{cred:NAME}}``.
#: NAME may contain ``[A-Za-z0-9_.-]`` and must be 1..128 chars.
PLACEHOLDER_RE: re.Pattern[str] = re.compile(r"\{\{\s*cred:([A-Za-z0-9_.\-]{1,128})\s*\}\}")

#: Stable string returned in audit/deny records when an agent's request is
#: refused. The string is intentionally generic so it cannot be used to probe
#: vault contents.
DENY_REASON: str = "credential_denied"


class CredentialDecision(str, Enum):
    """Outcome of a credential resolution attempt."""

    ALLOW = "allow"
    DENY = "deny"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CredentialError(Exception):
    """Base error for credential vault operations."""


class VaultLocked(CredentialError):
    """Raised when an operation requires an unlocked vault."""


class EncryptionUnavailable(CredentialError):
    """Raised when persistence is requested but ``cryptography`` is missing."""


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CredentialRecord:
    """An internal credential entry. Never exposed to agents."""

    name: str
    value: str
    cred_type: str = "secret"
    version: int = 1
    created_at: float = field(default_factory=time.time)
    rotated_at: float | None = None

    def __post_init__(self) -> None:  # pragma: no cover - dataclass invariant
        if not self.name or not isinstance(self.name, str):
            raise ValueError("Credential name must be a non-empty string")
        if not isinstance(self.value, str):
            raise TypeError("Credential value must be a string")


@dataclass(frozen=True)
class CredentialHandle:
    """Opaque handle an agent may reference.

    Holding a ``CredentialHandle`` does **not** grant access to the underlying
    value. The handle is just a name; resolution requires the vault, the
    agent's DID, and an action capability binding.
    """

    name: str

    def placeholder(self) -> str:
        """Return the ``{{cred:NAME}}`` placeholder for this handle."""
        return f"{{{{cred:{self.name}}}}}"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"<CredentialHandle {self.name!r}>"


@dataclass(frozen=True)
class CredentialProfile:
    """Per-agent capability binding.

    A profile maps action capabilities (e.g. ``github:read_issues``,
    ``github:push_code``) to the credential handle name that may be used to
    fulfil that capability. Two capabilities that happen to share an
    underlying credential are still modelled as separate bindings so that
    revoking one does not implicitly revoke the other.

    Bindings are immutable; rotation operates on the vault entry, not the
    profile.
    """

    agent_did: str
    bindings: Mapping[str, str]

    def __post_init__(self) -> None:
        if not self.agent_did:
            raise ValueError("agent_did must be a non-empty string")
        # Freeze bindings into a tuple-backed mapping to avoid post-construction
        # mutation; we copy into a plain dict and re-wrap as MappingProxyType
        # to keep equality cheap while preventing in-place writes.
        from types import MappingProxyType

        object.__setattr__(self, "bindings", MappingProxyType(dict(self.bindings)))

    def capability_for(self, action_class: str) -> str | None:
        """Return the handle name bound to ``action_class``, or None."""
        return self.bindings.get(action_class)


@dataclass(frozen=True)
class VaultAuditEvent:
    """A single audit record.

    Records contain the agent identity, the handle name, the target service,
    the action class, the decision, and the policy version that was in force
    at decision time. They do **not** contain the resolved credential value,
    the raw request body, or the raw tool arguments.
    """

    timestamp: float
    agent_did: str
    handle_name: str
    target_service: str
    action_class: str
    decision: CredentialDecision
    policy_version: str
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "agent_did": self.agent_did,
            "handle_name": self.handle_name,
            "target_service": self.target_service,
            "action_class": self.action_class,
            "decision": self.decision.value,
            "policy_version": self.policy_version,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class DenyReceipt:
    """Deterministic deny output returned in place of a rendered payload.

    Identical for missing handles, out-of-scope handles, and policy denials so
    that agents cannot probe vault contents via tool-error retry paths.
    """

    reason: str = DENY_REASON
    action_class: str = ""
    target_service: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "reason": self.reason,
            "action_class": self.action_class,
            "target_service": self.target_service,
        }


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------


def _try_import_fernet() -> Any | None:
    try:
        from cryptography.fernet import Fernet

        return Fernet
    except Exception:  # pragma: no cover - exercised when cryptography missing
        return None


class CredentialVault:
    """Encrypted-at-rest credential store and scoped resolver.

    The vault is thread-safe for concurrent reads and writes via an internal
    lock. It exposes two distinct surfaces:

    * **Admin surface** (``put``, ``rotate``, ``delete``, ``list_handles``,
      ``register_profile``) — for operators provisioning credentials.
    * **Resolver surface** (``check_access``, ``_resolve_internal``) — for
      the injector. Agents are never expected to call these directly.

    Parameters
    ----------
    persist_path:
        Optional filesystem path for encrypted persistence. Requires
        ``cryptography`` to be installed; otherwise
        :class:`EncryptionUnavailable` is raised.
    encryption_key:
        Fernet key (URL-safe base64-encoded 32 bytes). Generate one with
        :func:`CredentialVault.generate_key`. Required when ``persist_path``
        is set.
    """

    def __init__(
        self,
        persist_path: str | os.PathLike[str] | None = None,
        encryption_key: bytes | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._records: dict[str, CredentialRecord] = {}
        self._profiles: dict[str, CredentialProfile] = {}
        self._audit: list[VaultAuditEvent] = []
        self._persist_path: str | None = str(persist_path) if persist_path else None
        self._fernet = None

        if self._persist_path is not None:
            Fernet = _try_import_fernet()
            if Fernet is None:
                raise EncryptionUnavailable(
                    "Persistent vault requires the 'cryptography' package. "
                    "Install with: pip install cryptography"
                )
            if not encryption_key:
                raise ValueError("encryption_key is required when persist_path is set")
            self._fernet = Fernet(encryption_key)
            if os.path.exists(self._persist_path):
                self._load_from_disk()

    # -- Key management -----------------------------------------------------

    @staticmethod
    def generate_key() -> bytes:
        """Generate a fresh Fernet encryption key (URL-safe base64, 32 bytes).

        Falls back to :func:`os.urandom` if ``cryptography`` is unavailable
        so callers can still mint a key for later use.
        """
        return base64.urlsafe_b64encode(os.urandom(32))

    # -- Admin surface ------------------------------------------------------

    def put(self, name: str, value: str, *, cred_type: str = "secret") -> CredentialHandle:
        """Store or replace a credential. Returns its opaque handle."""
        if not name or not re.fullmatch(r"[A-Za-z0-9_.\-]{1,128}", name):
            raise ValueError(
                "Credential name must match [A-Za-z0-9_.-]{1,128}"
            )
        with self._lock:
            existing = self._records.get(name)
            version = (existing.version + 1) if existing else 1
            record = CredentialRecord(
                name=name,
                value=value,
                cred_type=cred_type,
                version=version,
                created_at=existing.created_at if existing else time.time(),
                rotated_at=time.time() if existing else None,
            )
            self._records[name] = record
            self._flush()
        return CredentialHandle(name=name)

    def rotate(self, name: str, new_value: str) -> CredentialHandle:
        """Rotate the value of an existing credential.

        Handle name is preserved so callers, prompts, and saved plans do not
        need to be updated.
        """
        with self._lock:
            if name not in self._records:
                raise KeyError(name)
            old = self._records[name]
            self._records[name] = replace(
                old,
                value=new_value,
                version=old.version + 1,
                rotated_at=time.time(),
            )
            self._flush()
        return CredentialHandle(name=name)

    def delete(self, name: str) -> bool:
        """Remove a credential. Returns True if it existed."""
        with self._lock:
            present = self._records.pop(name, None) is not None
            if present:
                self._flush()
        return present

    def list_handles(self) -> list[str]:
        """Return all credential handle names (admin operation; not for agents)."""
        with self._lock:
            return sorted(self._records.keys())

    def get_metadata(self, name: str) -> dict[str, Any] | None:
        """Return non-secret metadata for a credential, or None."""
        with self._lock:
            rec = self._records.get(name)
            if rec is None:
                return None
            return {
                "name": rec.name,
                "cred_type": rec.cred_type,
                "version": rec.version,
                "created_at": rec.created_at,
                "rotated_at": rec.rotated_at,
            }

    def register_profile(self, profile: CredentialProfile) -> None:
        """Register or replace a per-agent capability profile."""
        with self._lock:
            self._profiles[profile.agent_did] = profile

    def revoke_profile(self, agent_did: str) -> bool:
        with self._lock:
            return self._profiles.pop(agent_did, None) is not None

    # -- Resolver surface ---------------------------------------------------

    def check_access(
        self,
        agent_did: str,
        handle_name: str,
        action_class: str,
    ) -> bool:
        """Return True iff ``agent_did`` may use ``handle_name`` for ``action_class``.

        This is a pure check; it does not audit. Use :meth:`_resolve_internal`
        (via :class:`CredentialInjector`) to perform an audited resolution.
        """
        with self._lock:
            profile = self._profiles.get(agent_did)
            if profile is None:
                return False
            bound = profile.capability_for(action_class)
            if bound is None or bound != handle_name:
                return False
            return handle_name in self._records

    def _resolve_internal(
        self,
        agent_did: str,
        handle_name: str,
        *,
        action_class: str,
        target_service: str,
        policy_version: str,
    ) -> tuple[str | None, VaultAuditEvent]:
        """Resolve a credential value and emit an audit event.

        Returns ``(value_or_None, audit_event)``. On deny, the value is None.
        Callers must ensure ``value`` never crosses the agent trust boundary.
        """
        with self._lock:
            allowed = self.check_access(agent_did, handle_name, action_class)
            if allowed:
                value = self._records[handle_name].value
                event = VaultAuditEvent(
                    timestamp=time.time(),
                    agent_did=agent_did,
                    handle_name=handle_name,
                    target_service=target_service,
                    action_class=action_class,
                    decision=CredentialDecision.ALLOW,
                    policy_version=policy_version,
                    reason="",
                )
                self._audit.append(event)
                return value, event
            event = VaultAuditEvent(
                timestamp=time.time(),
                agent_did=agent_did,
                handle_name=handle_name,
                target_service=target_service,
                action_class=action_class,
                decision=CredentialDecision.DENY,
                policy_version=policy_version,
                reason=DENY_REASON,
            )
            self._audit.append(event)
            return None, event

    # -- Audit access -------------------------------------------------------

    def audit_log(self) -> tuple[VaultAuditEvent, ...]:
        """Return an immutable snapshot of audit events."""
        with self._lock:
            return tuple(self._audit)

    def clear_audit(self) -> None:
        with self._lock:
            self._audit.clear()

    # -- Persistence --------------------------------------------------------

    def _flush(self) -> None:
        if self._persist_path is None or self._fernet is None:
            return
        payload = {
            "records": [
                {
                    "name": r.name,
                    "value": r.value,
                    "cred_type": r.cred_type,
                    "version": r.version,
                    "created_at": r.created_at,
                    "rotated_at": r.rotated_at,
                }
                for r in self._records.values()
            ]
        }
        blob = json.dumps(payload, sort_keys=True).encode("utf-8")
        token = self._fernet.encrypt(blob)
        # Atomic write
        tmp_path = self._persist_path + ".tmp"
        with open(tmp_path, "wb") as fh:
            fh.write(token)
        os.replace(tmp_path, self._persist_path)

    def _load_from_disk(self) -> None:
        assert self._persist_path is not None and self._fernet is not None
        with open(self._persist_path, "rb") as fh:
            token = fh.read()
        if not token:
            return
        blob = self._fernet.decrypt(token)
        payload = json.loads(blob.decode("utf-8"))
        for entry in payload.get("records", []):
            rec = CredentialRecord(
                name=entry["name"],
                value=entry["value"],
                cred_type=entry.get("cred_type", "secret"),
                version=int(entry.get("version", 1)),
                created_at=float(entry.get("created_at", time.time())),
                rotated_at=(
                    float(entry["rotated_at"])
                    if entry.get("rotated_at") is not None
                    else None
                ),
            )
            self._records[rec.name] = rec


# ---------------------------------------------------------------------------
# Injector
# ---------------------------------------------------------------------------


PolicyCheck = Callable[["InjectionContext"], "PolicyOutcome"]


@dataclass(frozen=True)
class InjectionContext:
    """Information presented to the workflow policy before resolution."""

    agent_did: str
    action_class: str
    target_service: str
    requested_handles: tuple[str, ...]
    policy_version: str


@dataclass(frozen=True)
class PolicyOutcome:
    """Result returned by a workflow policy callback."""

    allow: bool
    reason: str = ""


@dataclass(frozen=True)
class InjectionResult:
    """Outcome of an injection call."""

    allowed: bool
    payload: Any
    deny_receipt: DenyReceipt | None
    audit_events: tuple[VaultAuditEvent, ...]


class CredentialInjector:
    """Render ``{{cred:NAME}}`` placeholders into HTTP, MCP, and env payloads.

    The injector is the *only* component that ever holds resolved credential
    values, and it holds them only long enough to render an outbound payload.
    Resolved values are never returned to the caller in the
    ``audit_events``; only handle names appear there.

    Each ``inject_*`` method takes:

    * ``agent_did`` — the agent's decentralized identifier.
    * ``action_class`` — what the agent is trying to do (e.g.
      ``"github:read_issues"``). Profiles bind credential handles to these
      action classes, not to generic agent identities.
    * ``target_service`` — recorded in the audit log.
    * ``allowed_handles`` — the *workflow-policy* allowlist of handle names
      eligible for substitution on this call. Placeholders found in the
      payload whose names are not in this set are treated as injection and
      cause the entire call to be denied. This implements the
      "MCP/server metadata is untrusted" requirement.
    * ``policy_check`` — optional callback invoked *before* any resolution.
      If it returns ``allow=False`` no value is ever read from the vault.
    * ``policy_version`` — recorded in the audit log.

    On any deny, ``payload`` is replaced with a :class:`DenyReceipt` so the
    agent receives a deterministic, non-leaky tool result.
    """

    def __init__(self, vault: CredentialVault) -> None:
        self._vault = vault

    # -- Public entrypoints -------------------------------------------------

    def inject_headers(
        self,
        agent_did: str,
        headers: Mapping[str, str],
        *,
        action_class: str,
        target_service: str,
        allowed_handles: Iterable[str],
        policy_version: str = "v0",
        policy_check: PolicyCheck | None = None,
    ) -> InjectionResult:
        return self._inject(
            agent_did=agent_did,
            payload=dict(headers),
            action_class=action_class,
            target_service=target_service,
            allowed_handles=allowed_handles,
            policy_version=policy_version,
            policy_check=policy_check,
        )

    def inject_tool_args(
        self,
        agent_did: str,
        args: Any,
        *,
        action_class: str,
        target_service: str,
        allowed_handles: Iterable[str],
        policy_version: str = "v0",
        policy_check: PolicyCheck | None = None,
    ) -> InjectionResult:
        return self._inject(
            agent_did=agent_did,
            payload=args,
            action_class=action_class,
            target_service=target_service,
            allowed_handles=allowed_handles,
            policy_version=policy_version,
            policy_check=policy_check,
        )

    def inject_env(
        self,
        agent_did: str,
        env: Mapping[str, str],
        *,
        action_class: str,
        target_service: str,
        allowed_handles: Iterable[str],
        policy_version: str = "v0",
        policy_check: PolicyCheck | None = None,
    ) -> InjectionResult:
        return self._inject(
            agent_did=agent_did,
            payload=dict(env),
            action_class=action_class,
            target_service=target_service,
            allowed_handles=allowed_handles,
            policy_version=policy_version,
            policy_check=policy_check,
        )

    # -- Core implementation ------------------------------------------------

    def _inject(
        self,
        *,
        agent_did: str,
        payload: Any,
        action_class: str,
        target_service: str,
        allowed_handles: Iterable[str],
        policy_version: str,
        policy_check: PolicyCheck | None,
    ) -> InjectionResult:
        allowlist = frozenset(allowed_handles)
        requested = _collect_placeholders(payload)

        # 1. Reject any placeholder that wasn't pre-authorized by the workflow.
        #    This is the "MCP descriptions are untrusted" boundary: if a tool
        #    schema or model output managed to slip in a credential reference
        #    the workflow didn't pre-declare, the entire call is denied.
        outside_scope = [name for name in requested if name not in allowlist]
        if outside_scope:
            event = VaultAuditEvent(
                timestamp=time.time(),
                agent_did=agent_did,
                handle_name=outside_scope[0],
                target_service=target_service,
                action_class=action_class,
                decision=CredentialDecision.DENY,
                policy_version=policy_version,
                reason=DENY_REASON,
            )
            # Record the deny via the vault's audit log too, but without
            # disclosing whether the handle exists.
            with self._vault._lock:
                self._vault._audit.append(event)
            return InjectionResult(
                allowed=False,
                payload=DenyReceipt(
                    action_class=action_class, target_service=target_service
                ),
                deny_receipt=DenyReceipt(
                    action_class=action_class, target_service=target_service
                ),
                audit_events=(event,),
            )

        # 2. Run policy *before* reading any value from the vault.
        if policy_check is not None:
            ctx = InjectionContext(
                agent_did=agent_did,
                action_class=action_class,
                target_service=target_service,
                requested_handles=tuple(sorted(requested)),
                policy_version=policy_version,
            )
            outcome = policy_check(ctx)
            if not outcome.allow:
                event = VaultAuditEvent(
                    timestamp=time.time(),
                    agent_did=agent_did,
                    handle_name=next(iter(requested), ""),
                    target_service=target_service,
                    action_class=action_class,
                    decision=CredentialDecision.DENY,
                    policy_version=policy_version,
                    reason=DENY_REASON,
                )
                with self._vault._lock:
                    self._vault._audit.append(event)
                return InjectionResult(
                    allowed=False,
                    payload=DenyReceipt(
                        action_class=action_class, target_service=target_service
                    ),
                    deny_receipt=DenyReceipt(
                        action_class=action_class, target_service=target_service
                    ),
                    audit_events=(event,),
                )

        # 3. Resolve each requested handle. Any single deny aborts the whole
        #    call so partial-secret payloads never leave the trust boundary.
        resolved: dict[str, str] = {}
        events: list[VaultAuditEvent] = []
        for name in requested:
            value, ev = self._vault._resolve_internal(
                agent_did,
                name,
                action_class=action_class,
                target_service=target_service,
                policy_version=policy_version,
            )
            events.append(ev)
            if value is None:
                return InjectionResult(
                    allowed=False,
                    payload=DenyReceipt(
                        action_class=action_class, target_service=target_service
                    ),
                    deny_receipt=DenyReceipt(
                        action_class=action_class, target_service=target_service
                    ),
                    audit_events=tuple(events),
                )
            resolved[name] = value

        rendered = _substitute(payload, resolved)
        return InjectionResult(
            allowed=True,
            payload=rendered,
            deny_receipt=None,
            audit_events=tuple(events),
        )


# ---------------------------------------------------------------------------
# Placeholder helpers
# ---------------------------------------------------------------------------


def _collect_placeholders(payload: Any) -> set[str]:
    """Walk a nested structure and return the set of placeholder names found."""
    found: set[str] = set()
    _walk(payload, lambda s: found.update(PLACEHOLDER_RE.findall(s)))
    return found


def _substitute(payload: Any, resolved: Mapping[str, str]) -> Any:
    """Return a copy of ``payload`` with placeholders replaced by values.

    Only placeholder names present in ``resolved`` are substituted; any other
    placeholder is left verbatim (the caller is responsible for ensuring all
    placeholders were authorized first).
    """

    def _sub_str(s: str) -> str:
        def repl(match: re.Match[str]) -> str:
            name = match.group(1)
            return resolved.get(name, match.group(0))

        return PLACEHOLDER_RE.sub(repl, s)

    return _map_strings(payload, _sub_str)


def _walk(payload: Any, visit: Callable[[str], None]) -> None:
    if isinstance(payload, str):
        visit(payload)
    elif isinstance(payload, Mapping):
        for k, v in payload.items():
            if isinstance(k, str):
                visit(k)
            _walk(v, visit)
    elif isinstance(payload, (list, tuple)):
        for item in payload:
            _walk(item, visit)


def _map_strings(payload: Any, fn: Callable[[str], str]) -> Any:
    if isinstance(payload, str):
        return fn(payload)
    if isinstance(payload, MutableMapping):
        return {(fn(k) if isinstance(k, str) else k): _map_strings(v, fn) for k, v in payload.items()}
    if isinstance(payload, Mapping):
        return {(fn(k) if isinstance(k, str) else k): _map_strings(v, fn) for k, v in payload.items()}
    if isinstance(payload, list):
        return [_map_strings(v, fn) for v in payload]
    if isinstance(payload, tuple):
        return tuple(_map_strings(v, fn) for v in payload)
    return payload


# ---------------------------------------------------------------------------
# Audit-log integrity helper
# ---------------------------------------------------------------------------


def audit_digest(events: Iterable[VaultAuditEvent], *, key: bytes) -> str:
    """Return a stable HMAC-SHA256 digest of an audit-event sequence.

    Useful for downstream tamper-evidence checks. The digest covers handle
    names and decisions but never references resolved credential values
    (the vault never stores them in events).
    """
    h = hmac.new(key, digestmod=hashlib.sha256)
    for ev in events:
        h.update(json.dumps(ev.to_dict(), sort_keys=True).encode("utf-8"))
        h.update(b"\x1f")
    return h.hexdigest()


__all__ = [
    "PLACEHOLDER_RE",
    "DENY_REASON",
    "CredentialDecision",
    "CredentialError",
    "VaultLocked",
    "EncryptionUnavailable",
    "CredentialRecord",
    "CredentialHandle",
    "CredentialProfile",
    "VaultAuditEvent",
    "DenyReceipt",
    "CredentialVault",
    "InjectionContext",
    "PolicyOutcome",
    "InjectionResult",
    "CredentialInjector",
    "audit_digest",
]
