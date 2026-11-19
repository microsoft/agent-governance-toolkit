"""Separate substrate service and restricted, authenticated operator stop bridge."""

# cspell:ignore ungranted

import base64
import hashlib
import hmac
import json
import threading
import time
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from governance_substrate.docker_runtime_supervisor import DockerRuntimeSupervisor
from governance_substrate.substrate import Substrate, create_app
from governance_substrate.tool_adapter import SMTPSendEmailAdapter
from pydantic import BaseModel, ConfigDict
from transport import serve_roles


class WorkerStart(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_did: str
    session_id: str
    generation_id: str
    execution_token: str


class StopRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_did: str
    session_id: str
    actor: str


def applications(config):
    runtime = DockerRuntimeSupervisor(
        "/config/worker-compose.json", None, config["project"]
    )
    registry = {
        "actors": {config["actor"]: config["capabilities"]},
        "tokens": {config["agent_token"]: config["actor"]},
        "operator_token": config["operator_token"],
        "circuit_operator_token": config["circuit_token"],
    }
    smtp = SMTPSendEmailAdapter("127.0.0.1", 8025, "operator@example.test")
    substrate = Substrate(
        "/state/substrate.db",
        registry,
        workspace_root="/workspace",
        runtime_supervisor=runtime,
        tool_adapters={"send_email": smtp, "ungranted_email": smtp},
    )
    source = substrate.import_object(
        "public",
        "text/plain",
        base64.b64encode(b"sealed test input").decode(),
        [config["actor"]],
        "agt-integration",
    )
    app, operator = create_app(substrate), FastAPI()
    workers = {}

    def require(token, expected):
        if not hmac.compare_digest((token or "").removeprefix("Bearer "), expected):
            raise HTTPException(403, "unauthorized controller")

    @app.get("/integration/input")
    def input_object(authorization: str | None = Header(default=None)):
        require(authorization, config["agent_token"])
        return {"object_id": source["object_id"]}

    @app.post("/workers/start")
    def start(
        body: WorkerStart,
        authorization: str | None = Header(default=None),
        x_session_token: str | None = Header(default=None),
    ):
        require(authorization, config["agent_token"])
        if (
            body.agent_did != config["agent_did"]
            or body.session_id != config["session_id"]
        ):
            raise HTTPException(403, "worker binding mismatch")
        # Only a previously admitted generation belonging to this session can start.
        with substrate._db() as db:
            row = db.execute(
                "SELECT actor,status FROM generations WHERE id=?", (body.generation_id,)
            ).fetchone()
            session = db.execute(
                "SELECT id FROM sessions WHERE actor=? AND token_hash=? AND active=1",
                (
                    config["actor"],
                    hashlib.sha256((x_session_token or "").encode()).hexdigest(),
                ),
            ).fetchone()
            attached = db.execute(
                "SELECT session_id FROM generation_sessions WHERE generation_id=?",
                (body.generation_id,),
            ).fetchone()
        if (
            row is None
            or row["actor"] != config["actor"]
            or row["status"] != "prepared"
            or session is None
            or attached[0] != session["id"]
            or body.generation_id in workers
        ):
            raise HTTPException(403, "generation binding mismatch")
        claimed = substrate.claim_generation(body.generation_id, body.execution_token)
        if claimed["decision"] != "allow":
            raise HTTPException(403, "worker claim denied")
        sealed = json.dumps(claimed["inputs"])
        errors = []

        def execute_worker():
            try:
                runtime.run(body.generation_id, sealed)
            except RuntimeError as exc:
                errors.append(str(exc))

        thread = threading.Thread(target=execute_worker, daemon=True)
        workers[body.generation_id] = thread
        thread.start()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not errors:
            info = runtime._inspect("gov-substrate-" + body.generation_id)
            if info and info["State"]["Running"]:
                import subprocess

                ready = subprocess.run(
                    ["docker", "exec", info["Id"], "cat", "/tmp/ready"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                if (
                    ready.returncode == 0
                    and ready.stdout.strip()
                    == hashlib.sha256(sealed.encode()).hexdigest()
                ):
                    return {
                        "generation_id": body.generation_id,
                        "runtime_id": info["Id"],
                        "sealed_input_sha256": ready.stdout.strip(),
                        "ready": True,
                    }
            time.sleep(0.05)
        runtime.stop((body.generation_id,))
        raise HTTPException(503, "worker startup unconfirmed")

    @operator.post("/stop")
    def stop(body: StopRequest, authorization: str | None = Header(default=None)):
        require(authorization, config["control_token"])
        if (
            body.agent_did != config["agent_did"]
            or body.session_id != config["session_id"]
            or body.actor != config["actor"]
        ):
            raise HTTPException(403, "stop target mismatch")
        trip = substrate.set_circuit(
            config["circuit_token"],
            "actor",
            config["actor"],
            True,
            "AGT emergency shutdown",
        )
        events = substrate.audit()
        receipt = next(
            item for item in events if item["id"] == trip["receipt_event_id"]
        )
        return {
            "agent_did": body.agent_did,
            "session_id": body.session_id,
            "shutdown_confirmed": trip["shutdown_confirmed"],
            "workers": receipt["action"]["results"],
            "receipt": receipt,
        }

    return app, operator


if __name__ == "__main__":
    configuration = json.loads(
        Path("/config/substrate.json").read_text(encoding="utf-8")
    )
    api, stop_api = applications(configuration)
    serve_roles(
        [
            (api, "/substrate/api.sock", 0, 0o600),
            (stop_api, "/operator/stop.sock", 0, 0o600),
        ]
    )
