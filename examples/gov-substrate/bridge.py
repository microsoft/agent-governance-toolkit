"""AGT authorization followed by independently enforced substrate execution."""

# cspell:ignore ungranted

import asyncio
import copy
import hashlib
import json
import threading
import uuid
from dataclasses import dataclass

import httpx
from agent_control_specification import (
    AgentControl,
    AgentControlBlocked,
    ApprovalOutcome,
    ApprovalResolution,
    EnforcementMode,
    SnapshotBuilder,
)
from agentmesh.governance.audit import AuditLog
from hypervisor.security.kill_switch import KillReason, KillSwitch


def fingerprint(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    ).hexdigest()


TOOLS = (
    "write_file",
    "read_file",
    "fetch_url",
    "send_email",
    "blocked_email",
    "restricted_email",
    "approval_email",
    "start_worker",
)
MANIFEST = {
    "agent_control_specification_version": "0.4.0-alpha.1",
    "policies": {"boundary": {"type": "custom", "adapter": "execution_boundary"}},
    "intervention_points": {
        "pre_tool_call": {
            "policy_target": "$.tool_call.args",
            "tool_name_from": "$.tool_call.name",
            "policy": {"id": "boundary"},
        },
        "post_tool_call": {
            "policy_target": "$.tool_result",
            "tool_name_from": "$.tool_call.name",
            "policy": {"id": "boundary"},
        },
    },
    "tools": {name: {"type": "Tool", "id": name} for name in TOOLS},
}


class BoundaryPolicy:
    """Operator-owned deterministic policy dispatched by AGT's native engine."""

    def evaluate(self, invocation):
        policy_input = invocation["input"]
        tool = (policy_input.get("tool") or {}).get("name")
        if tool not in TOOLS:
            return {"decision": "deny", "reason": "unknown_tool"}
        if policy_input["intervention_point"] == "post_tool_call":
            return {"decision": "allow"}
        if tool == "blocked_email":
            return {"decision": "deny", "reason": "agt_permission_denied"}
        if tool == "approval_email":
            return {
                "decision": "deny",
                "reason": "human_approval_required",
                "approval": {"channel": "operator"},
            }
        return {"decision": "allow"}


def action_for(tool, arguments, call_id):
    if tool == "write_file":
        if set(arguments) != {"path", "content"}:
            raise ValueError("invalid file write")
        return {**arguments, "kind": "filesystem.write"}
    if tool == "read_file":
        if set(arguments) != {"path"}:
            raise ValueError("invalid file read")
        return {**arguments, "kind": "filesystem.read"}
    if tool == "fetch_url":
        if set(arguments) != {"url"}:
            raise ValueError("invalid network request")
        return {**arguments, "kind": "network.request"}
    if tool == "start_worker":
        if set(arguments) != {"input_ids"}:
            raise ValueError("invalid worker input")
        return {**arguments, "kind": "generation.prepare"}
    if tool in ("send_email", "blocked_email", "approval_email", "restricted_email"):
        return {
            "kind": "tool.invoke",
            "tool": "ungranted_email" if tool == "restricted_email" else "send_email",
            "arguments": arguments,
            "call_id": call_id,
        }
    raise ValueError("unknown tool")


@dataclass
class Prepared:
    tool: str
    arguments: dict
    action: dict
    token: str
    call_id: str
    evidence: dict


class TrustedBridge:
    def __init__(
        self,
        identity,
        session_id,
        substrate,
        operator,
        session_token,
        actor,
        mode=EnforcementMode.ENFORCE,
    ):
        if EnforcementMode(mode) is not EnforcementMode.ENFORCE:
            raise ValueError("this bridge requires strict AGT enforcement")
        self.identity, self.actor = identity, actor
        self.session_id, self.session_token = session_id, session_token
        self.substrate, self.operator = substrate, operator
        self.audit = AuditLog()
        self.builder = SnapshotBuilder(
            agent_id=str(identity.did), session_id=session_id
        )
        self.control = AgentControl.from_native(
            MANIFEST, policy_dispatcher=BoundaryPolicy()
        )
        self.pending = {}
        self.prepared = {}
        self.calls = set()
        self._lock = threading.Lock()
        self.kill_switch = KillSwitch(callback_timeout=45)
        self.kill_switch.register_agent(str(identity.did), self._terminate)
        self.last_shutdown = None
        self.workers = {}

    def _record(self, call_id, tool, arguments, result):
        self.audit.log(
            "execution_boundary",
            str(self.identity.did),
            tool,
            data={"call_id": call_id, "session_id": self.session_id, "result": result},
            arguments_hash=fingerprint(arguments),
            trace_id=call_id,
            outcome=result.get("outcome", result.get("decision", "unconfirmed")),
        )

    async def _approval(self, point, result):
        call_id = result.policy_input["snapshot"]["tool_call"]["id"]
        event = asyncio.Event()
        record = {
            "event": event,
            "identity": result.action_identity,
            "outcome": None,
            "loop": asyncio.get_running_loop(),
        }
        self.pending[call_id] = record
        try:
            await asyncio.wait_for(event.wait(), timeout=30)
            if record["outcome"] == "allow":
                return ApprovalResolution.allow(result.action_identity)
            return ApprovalResolution(
                ApprovalOutcome.DENY, action_identity=result.action_identity
            )
        finally:
            self.pending.pop(call_id, None)

    def resolve(self, call_id, action_identity, outcome):
        record = self.pending.get(call_id)
        if (
            record is None
            or action_identity != record["identity"]
            or outcome not in ("allow", "deny")
            or record["outcome"] is not None
        ):
            raise ValueError("approval does not match the pending action")
        record["outcome"] = outcome
        record["loop"].call_soon_threadsafe(record["event"].set)

    async def run(self, tool, arguments, call_id, prepare_only=False):
        arguments = copy.deepcopy(arguments)
        evidence = {
            "call_id": call_id,
            "agent_did": str(self.identity.did),
            "session_id": self.session_id,
            "agt": {"mode": "enforce", "execution_permitted": False},
        }
        if prepare_only and tool == "start_worker":
            return {
                "decision": "deny",
                "system": "bridge",
                "reason": "worker_requires_immediate_start",
            }
        with self._lock:
            if call_id in self.calls:
                result = {
                    "decision": "deny",
                    "system": "bridge",
                    "reason": "call_replayed",
                }
                self._record(call_id, tool, arguments, result)
                return result
            self.calls.add(call_id)

        async def execute(effective):
            evidence["agt"]["execution_permitted"] = True
            evidence["effective_arguments_sha256"] = fingerprint(effective)
            action = action_for(tool, effective, call_id)
            authorized = await asyncio.to_thread(
                self.substrate.request,
                "POST",
                "/authorizations",
                {"action": action},
                self.session_token,
            )
            evidence["authorization_event_id"] = authorized["event_id"]
            if authorized["decision"] != "allow":
                return {**authorized, "system": "gov-sub"}
            evidence["grant_sha256"] = hashlib.sha256(
                authorized["execution_token"].encode()
            ).hexdigest()
            if prepare_only:
                handle = uuid.uuid4().hex
                self.prepared[handle] = Prepared(
                    tool,
                    copy.deepcopy(effective),
                    action,
                    authorized["execution_token"],
                    call_id,
                    copy.deepcopy(evidence),
                )
                return {
                    "decision": "allow",
                    "outcome": "prepared",
                    "handle": handle,
                    "event_id": authorized["event_id"],
                }
            result = await asyncio.to_thread(
                self.substrate.request,
                "POST",
                "/executions",
                {"action": action, "execution_token": authorized["execution_token"]},
                self.session_token,
            )
            evidence["execution_event_id"] = result["event_id"]
            generation_token = result.pop("execution_token", None)
            if tool == "start_worker" and result["decision"] == "allow":
                started = await asyncio.to_thread(
                    self.substrate.request,
                    "POST",
                    "/workers/start",
                    {
                        "agent_did": str(self.identity.did),
                        "session_id": self.session_id,
                        "generation_id": result["generation_id"],
                        "execution_token": generation_token,
                    },
                    self.session_token,
                )
                self.workers[started["generation_id"]] = started["runtime_id"]
                result.update(started)
            return {**result, "system": "gov-sub"}

        try:
            result = await self.control.run_tool(
                tool,
                arguments,
                execute,
                tool_call_id=call_id,
                snapshot=self.builder,
                mode=EnforcementMode.ENFORCE,
                approval_resolver=self._approval,
            )
            value = result.value
            evidence["agt"].update(
                {
                    "policy_decision": result.pre_tool_call_result.verdict.decision.value,
                    "action_identity": result.pre_tool_call_result.action_identity,
                }
            )
            if prepare_only and value.get("outcome") == "prepared":
                self.prepared[value["handle"]].evidence = copy.deepcopy(evidence)
        except AgentControlBlocked as exc:
            evidence["agt"].update(
                {
                    "policy_decision": exc.result.verdict.decision.value,
                    "action_identity": exc.result.action_identity,
                }
            )
            value = {
                "decision": "deny",
                "system": "agt",
                "reason": exc.result.verdict.reason,
            }
        except httpx.TransportError:
            value = {
                "decision": "deny",
                "outcome": "unconfirmed",
                "system": "gov-sub",
                "reason": "substrate_unavailable",
            }
        except (TimeoutError, ValueError, httpx.HTTPError):
            value = {"decision": "deny", "system": "bridge", "reason": "unconfirmed"}
        value = {**value, "evidence": evidence}
        self._record(call_id, tool, arguments, value)
        return value

    async def dispatch(self, handle, arguments):
        prepared = self.prepared[handle]
        evidence = copy.deepcopy(prepared.evidence)
        evidence["authorization_agt"] = evidence["agt"]
        evidence["agt"] = {"mode": "enforce", "execution_permitted": False}
        if fingerprint(arguments) != fingerprint(prepared.arguments):
            result = {
                "decision": "deny",
                "system": "bridge",
                "reason": "action_changed",
            }
        else:

            async def execute(effective):
                evidence["agt"]["execution_permitted"] = True
                evidence["effective_arguments_sha256"] = fingerprint(effective)
                action = action_for(prepared.tool, effective, prepared.call_id)
                if fingerprint(action) != fingerprint(prepared.action):
                    raise ValueError("approved action changed")
                return await asyncio.to_thread(
                    self.substrate.request,
                    "POST",
                    "/executions",
                    {"action": action, "execution_token": prepared.token},
                    self.session_token,
                )

            try:
                governed = await self.control.run_tool(
                    prepared.tool,
                    copy.deepcopy(arguments),
                    execute,
                    tool_call_id=prepared.call_id,
                    snapshot=self.builder,
                    mode=EnforcementMode.ENFORCE,
                    approval_resolver=self._approval,
                )
                result = governed.value
                evidence["execution_event_id"] = result["event_id"]
                evidence["agt"].update(
                    {
                        "policy_decision": governed.pre_tool_call_result.verdict.decision.value,
                        "action_identity": governed.pre_tool_call_result.action_identity,
                    }
                )
            except AgentControlBlocked as exc:
                evidence["agt"].update(
                    {
                        "policy_decision": exc.result.verdict.decision.value,
                        "action_identity": exc.result.action_identity,
                    }
                )
                result = {
                    "decision": "deny",
                    "system": "agt",
                    "reason": exc.result.verdict.reason,
                }
            except httpx.TransportError:
                result = {
                    "decision": "deny",
                    "outcome": "unconfirmed",
                    "system": "gov-sub",
                    "reason": "substrate_unavailable",
                }
            except (TimeoutError, ValueError, httpx.HTTPError):
                result = {
                    "decision": "deny",
                    "system": "bridge",
                    "reason": "unconfirmed",
                }
        result = {**result, "evidence": evidence}
        self._record(prepared.call_id, prepared.tool, arguments, result)
        return result

    def _terminate(self):
        result = self.operator.request(
            "POST",
            "/stop",
            {
                "agent_did": str(self.identity.did),
                "session_id": self.session_id,
                "actor": self.actor,
            },
        )
        self.last_shutdown = result
        if (
            result.get("agent_did") != str(self.identity.did)
            or result.get("session_id") != self.session_id
            or result.get("shutdown_confirmed") is not True
            or not result.get("workers")
            or {
                item.get("generation_id"): item.get("runtime_id")
                for item in result["workers"]
            }
            != self.workers
            or any(
                not item.get("confirmed") or not item.get("runtime_id")
                for item in result["workers"]
            )
        ):
            raise RuntimeError("worker shutdown is unconfirmed")

    def shutdown(self):
        self.last_shutdown = None
        result = self.kill_switch.kill(
            str(self.identity.did), self.session_id, KillReason.MANUAL
        )
        return {
            "terminated": result.terminated,
            "agent_did": result.agent_did,
            "session_id": result.session_id,
            "receipt": self.last_shutdown,
        }
