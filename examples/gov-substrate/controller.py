"""Trusted AGT controller. Worker and operator applications use different sockets."""

import json
from pathlib import Path

from agentmesh.identity.agent_id import AgentIdentity
from bridge import TrustedBridge
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from transport import UnixClient, serve_roles


class ToolRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: str = Field(min_length=1, max_length=64)
    args: dict
    call_id: str = Field(min_length=1, max_length=128)


class Resolution(BaseModel):
    model_config = ConfigDict(extra="forbid")
    call_id: str
    action_identity: str
    outcome: str


class DispatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    handle: str
    args: dict


def applications(config):
    identity = AgentIdentity.model_validate(config["identity"])
    substrate = UnixClient("/substrate/api.sock", config["agent_token"])
    session = substrate.request("POST", "/sessions", {})
    bridge = TrustedBridge(
        identity,
        config["session_id"],
        substrate,
        UnixClient("/operator/stop.sock", config["control_token"], timeout=40),
        session["session_token"],
        config["actor"],
    )
    worker, admin = FastAPI(), FastAPI()

    @worker.post("/tools")
    async def tool(body: ToolRequest):
        return await bridge.run(body.tool, body.args, body.call_id)

    @admin.get("/health")
    def health():
        return {
            "ready": True,
            "identity": str(identity.did),
            "session_id": bridge.session_id,
            "native_policy": True,
        }

    @admin.get("/approvals")
    def approvals():
        return [
            {"call_id": key, "action_identity": value["identity"]}
            for key, value in list(bridge.pending.items())
        ]

    @admin.post("/approvals")
    def resolve(body: Resolution):
        try:
            bridge.resolve(body.call_id, body.action_identity, body.outcome)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"resolved": True}

    @admin.post("/prepare")
    async def prepare(body: ToolRequest):
        return await bridge.run(body.tool, body.args, body.call_id, prepare_only=True)

    @admin.post("/invoke")
    async def invoke(body: ToolRequest):
        return await bridge.run(body.tool, body.args, body.call_id)

    @admin.post("/dispatch")
    async def dispatch(body: DispatchRequest):
        try:
            return await bridge.dispatch(body.handle, body.args)
        except (KeyError, ValueError) as exc:
            raise HTTPException(409, "invalid prepared action") from exc

    @admin.post("/shutdown")
    def shutdown():
        result = bridge.shutdown()
        bridge.audit.log(
            "shutdown",
            str(identity.did),
            "emergency_stop",
            data=result,
            outcome="confirmed" if result["terminated"] else "unconfirmed",
        )
        return result

    @admin.get("/audit")
    def audit():
        return bridge.audit.export()

    return worker, admin


if __name__ == "__main__":
    configuration = json.loads(
        Path("/config/controller.json").read_text(encoding="utf-8")
    )
    worker_app, admin_app = applications(configuration)
    serve_roles(
        [
            (worker_app, "/bridge/tools.sock", 65534, 0o666),
            (admin_app, "/admin/controller.sock", 0, 0o600),
        ]
    )
