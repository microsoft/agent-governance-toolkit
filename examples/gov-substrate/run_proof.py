"""Build and verify the real AGT/Substrate deployment without model or cloud calls."""

# cspell:ignore agtgov ungranted dockerconfig

import argparse
import concurrent.futures
import hashlib
import json
import secrets
import sqlite3
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
AGT = HERE.parents[1]
GOV_COMMIT = "03f715bde3f5f28c39870090036dc02e0e147f50"
IMAGES = {
    "controller": "agt-gov-example-controller:local",
    "substrate": "agt-gov-example-substrate:local",
    "worker": "agt-gov-example-worker:local",
}


def command(*args, timeout=90, check=True):
    result = subprocess.run(
        list(args),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    if check and result.returncode:
        raise RuntimeError(result.stderr[-5000:] or result.stdout[-5000:])
    return result


def wait_for(operation, predicate=bool, timeout=40):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = operation()
            if predicate(value):
                return value
        except (RuntimeError, json.JSONDecodeError):
            pass
        time.sleep(0.1)
    raise AssertionError("bounded readiness check failed")


class Deployment:
    def __init__(self, gov_source):
        self.gov_source = Path(gov_source).resolve()
        actual = command(
            "git", "-C", str(self.gov_source), "rev-parse", "HEAD"
        ).stdout.strip()
        if (
            actual != GOV_COMMIT
            or command(
                "git", "-C", str(self.gov_source), "status", "--porcelain"
            ).stdout
        ):
            raise ValueError("Gov-Substrate must be a clean v0.7.0 checkout")
        self.project = "agtgov" + uuid.uuid4().hex[:12]
        self.local = HERE / ".local" / self.project
        self.local.mkdir(parents=True)
        self.workers = {}
        self.records = []
        self.started = time.time()
        identity_code = (
            "import json; from agentmesh.identity.agent_id import AgentIdentity; "
            "print(json.dumps(AgentIdentity.create('integration-worker',"
            "'operator@example.test',capabilities=['governed-tools']).model_dump(mode='json')))"
        )
        identity = json.loads(
            command(
                "docker",
                "run",
                "--rm",
                "--pull",
                "never",
                "--network",
                "none",
                IMAGES["controller"],
                "python",
                "-c",
                identity_code,
            ).stdout
        )
        self.identity = (
            "did:" + identity["did"]["method"] + ":" + identity["did"]["unique_id"]
        )
        self.session_id = uuid.uuid4().hex
        self.tokens = {
            key: secrets.token_urlsafe(32)
            for key in (
                "agent_token",
                "operator_token",
                "circuit_token",
                "control_token",
            )
        }
        common = {
            "actor": "agent",
            "session_id": self.session_id,
            "agent_did": self.identity,
            **self.tokens,
        }
        controller = {
            key: common[key]
            for key in ("actor", "session_id", "agent_token", "control_token")
        }
        controller["identity"] = identity
        capabilities = {
            "network": {
                "allowed": True,
                "destinations": ["http://receiver:8080"],
                "private_ip_origins": ["http://receiver:8080"],
            },
            "filesystem": {
                "read": True,
                "write": "workspace_only",
                "protected": ["secret.txt"],
            },
            "tools": {"send_email": True, "ungranted_email": False},
            "persistence": {"session": True, "cross_session": False},
            "shared_channels": [],
            "data": {"sensitive_access": False},
        }
        substrate = {
            **common,
            "capabilities": capabilities,
            "project": self.project + "workers",
        }
        self._write("controller.json", controller)
        self._write("substrate.json", substrate)
        self._write(
            "worker-compose.json",
            {
                "services": {
                    "generator": {
                        "image": IMAGES["worker"],
                        "pull_policy": "never",
                        "network_mode": "none",
                        "user": "65534:65534",
                        "read_only": True,
                        "cap_drop": ["ALL"],
                        "security_opt": ["no-new-privileges:true"],
                        "pids_limit": 32,
                        "tmpfs": ["/tmp:size=4m"],
                        "volumes": ["bridge:/bridge:ro"],
                    }
                },
                "volumes": {
                    "bridge": {"external": True, "name": self.project + "-bridge"}
                },
            },
        )
        hardening = {
            "read_only": True,
            "pull_policy": "never",
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "tmpfs": ["/tmp:size=16m"],
        }

        def sources(*names):
            return [
                str(HERE / name) + ":/integration/" + name + ":ro" for name in names
            ]

        self._write(
            "compose.json",
            {
                "services": {
                    "receiver": {
                        **hardening,
                        "image": IMAGES["substrate"],
                        "command": ["python", "/integration/receiver.py"],
                        "volumes": sources("receiver.py") + ["effects:/proof"],
                        "networks": ["effects"],
                    },
                    "smtp_receiver": {
                        **hardening,
                        "image": IMAGES["substrate"],
                        "command": ["python", "/integration/receiver.py", "smtp"],
                        "network_mode": "service:substrate",
                        "volumes": sources("receiver.py") + ["effects:/proof"],
                    },
                    "substrate": {
                        **hardening,
                        "image": IMAGES["substrate"],
                        "environment": {"DOCKER_CONFIG": "/tmp/dockerconfig"},
                        "volumes": sources("substrate_service.py", "transport.py")
                        + [
                            str(self.gov_source / "src") + ":/gov-src:ro",
                            str(self.local) + ":/config:ro",
                            "state:/state",
                            "workspace:/workspace",
                            "substrate:/substrate",
                            "operator:/operator",
                            "effects:/proof",
                            "/var/run/docker.sock:/var/run/docker.sock",
                        ],
                        "networks": ["effects"],
                    },
                    "controller": {
                        **hardening,
                        "image": IMAGES["controller"],
                        "network_mode": "none",
                        "volumes": sources(
                            "controller.py",
                            "bridge.py",
                            "transport.py",
                            "shutdown_probe.py",
                        )
                        + [
                            str(self.local / "controller.json")
                            + ":/config/controller.json:ro",
                            "bridge:/bridge",
                            "admin:/admin",
                            "substrate:/substrate:ro",
                            "operator:/operator:ro",
                        ],
                    },
                },
                "networks": {"effects": {"internal": True}},
                "volumes": {
                    name: {"name": self.project + "-" + name}
                    for name in (
                        "effects",
                        "state",
                        "workspace",
                        "substrate",
                        "operator",
                        "bridge",
                        "admin",
                    )
                },
            },
        )

    def _write(self, name, value):
        (self.local / name).write_text(json.dumps(value, indent=2), encoding="utf-8")

    def compose(self, *args):
        return command(
            "docker",
            "compose",
            "-p",
            self.project,
            "-f",
            str(self.local / "compose.json"),
            *args,
        )

    def container(self, service):
        return self.compose("ps", "-q", service).stdout.strip()

    def rpc(self, method, path, body=None):
        args = [
            "docker",
            "exec",
            self.container("controller"),
            "python",
            "/integration/transport.py",
            "/admin/controller.sock",
            method,
            path,
        ]
        if body is not None:
            args.append(json.dumps(body))
        return json.loads(command(*args).stdout)

    def substrate_rpc(self, method, path, body=None, operator=False):
        # Only the test's trusted host can invoke this private service socket.
        role = "operator_token" if operator else "agent_token"
        code = (
            "import json; from pathlib import Path; from transport import UnixClient; "
            "c=json.loads(Path('/config/substrate.json').read_text()); "
            f"print(json.dumps(UnixClient('/substrate/api.sock',c[{role!r}]).request("
            f"{method!r},{path!r},{body!r})))"
        )
        return json.loads(
            command(
                "docker", "exec", self.container("substrate"), "python", "-c", code
            ).stdout
        )

    def start(self, launch_worker=True):
        self.compose("up", "-d", "receiver", "substrate", "smtp_receiver")
        try:
            wait_for(lambda: self.substrate_rpc("GET", "/integration/input"))
        except AssertionError:
            print(self.compose("logs", "--tail", "60", "substrate").stdout, flush=True)
            raise
        self.compose("up", "-d", "controller")
        try:
            wait_for(lambda: self.rpc("GET", "/health"))
        except AssertionError:
            print(self.compose("logs", "--tail", "60", "controller").stdout, flush=True)
            raise
        if launch_worker:
            self.launch_worker()

    def launch_worker(self):
        source = self.substrate_rpc("GET", "/integration/input")
        # The worker is first admitted by the actual native AGT path, then claimed by Gov-Sub.
        started = self.rpc(
            "POST",
            "/invoke",
            self.tool("start_worker", {"input_ids": [source["object_id"]]}),
        )
        assert started["decision"] == "allow", started
        self.generation_id = started["generation_id"]
        self.worker_id = started["runtime_id"]
        self.workers[self.generation_id] = self.worker_id
        self.note(
            "worker_start",
            {
                "runtime_id": self.worker_id,
                "generation_id": self.generation_id,
                "agt_and_substrate_permitted": True,
            },
        )

    @staticmethod
    def tool(name, args, call_id=None):
        return {"tool": name, "args": args, "call_id": call_id or uuid.uuid4().hex}

    def worker(self, body):
        return json.loads(
            command(
                "docker",
                "exec",
                self.worker_id,
                "python",
                "/worker.py",
                "request",
                json.dumps(body),
            ).stdout
        )

    def read_effects(self, name):
        result = command(
            "docker",
            "exec",
            self.container("substrate"),
            "cat",
            "/proof/" + name,
            check=False,
        )
        return (
            [json.loads(line) for line in result.stdout.splitlines() if line]
            if result.returncode == 0
            else []
        )

    def note(self, name, evidence):
        self.records.append({"case": name, "passed": True, "evidence": evidence})
        print("PASS " + name, flush=True)

    def collect(self):
        self.agt_audit = self.rpc("GET", "/audit")
        db_path = self.local / "audit.db"
        command(
            "docker",
            "cp",
            self.container("substrate") + ":/state/substrate.db",
            str(db_path),
        )
        with sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True) as db:
            db.row_factory = sqlite3.Row
            rows = [dict(row) for row in db.execute("SELECT * FROM events ORDER BY id")]
            grants = {
                row["token_hash"]: dict(row)
                for row in db.execute("SELECT * FROM execution_grants")
            }
        previous = "0" * 64
        keys = (
            "timestamp",
            "actor",
            "action",
            "policy",
            "decision",
            "state_before",
            "state_after",
            "override_of",
            "elapsed_ms",
            "prev_hash",
        )
        for row in rows:
            fields = {key: row[key] for key in keys}
            computed = hashlib.sha256(
                json.dumps(
                    fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                ).encode()
            ).hexdigest()
            assert row["prev_hash"] == previous and row["event_hash"] == computed
            previous = computed
        event_ids = {row["id"] for row in rows}
        for entry in self.agt_audit["entries"]:
            result = entry["data"].get("result", {})
            if "event_id" in result:
                assert result["event_id"] in event_ids
            evidence = result.get("evidence", {})
            for key in ("authorization_event_id", "execution_event_id"):
                if key in evidence:
                    assert evidence[key] in event_ids
            if "grant_sha256" in evidence:
                assert (
                    evidence.get("authorization_agt", evidence["agt"])[
                        "execution_permitted"
                    ]
                    is True
                )
                authorization = next(
                    row
                    for row in rows
                    if row["id"] == evidence["authorization_event_id"]
                )
                assert authorization["decision"] == "allow"
                assert evidence["call_id"] == entry["data"]["call_id"]
                assert evidence["session_id"] == self.session_id
                grant = grants[evidence["grant_sha256"]]
                issued = [
                    row
                    for row in rows
                    if json.loads(row["action"]).get("kind") == "execution.grant.issue"
                    and json.loads(row["action"]).get("grant_id") == grant["id"]
                ]
                assert len(issued) == 1 and issued[0]["id"] <= authorization["id"]
                if "execution_event_id" in evidence:
                    assert authorization["id"] < evidence["execution_event_id"]
                    execution = next(
                        row
                        for row in rows
                        if row["id"] == evidence["execution_event_id"]
                    )
                    assert execution["decision"] == result["decision"]
                    if execution["decision"] == "allow":
                        assert evidence["agt"]["execution_permitted"] is True
                        assert any(
                            json.loads(row["action"]).get("kind")
                            == "execution.grant.use"
                            and json.loads(row["action"]).get("grant_id") == grant["id"]
                            and row["decision"] == "allow"
                            and authorization["id"]
                            < row["id"]
                            < evidence["execution_event_id"]
                            for row in rows
                        )
            if entry["data"].get("terminated") is True:
                receipt = entry["data"]["receipt"]
                assert (
                    receipt["agent_did"] == self.identity
                    and receipt["session_id"] == self.session_id
                )
                assert receipt["receipt"]["id"] in event_ids
                assert {
                    worker["generation_id"]: worker["runtime_id"]
                    for worker in receipt["workers"]
                } == self.workers
        self.note(
            "evidence_correlation",
            {
                "identity": self.identity,
                "session_id": self.session_id,
                "workers": self.workers,
                "grant_hashes_checked": len(grants),
            },
        )
        self.note(
            "independent_audit_recomputation",
            {
                "entries": len(rows),
                "head": previous,
                "agt_entries": self.agt_audit["entry_count"],
            },
        )
        return rows

    def close(self):
        for runtime_id in self.workers.values():
            command("docker", "rm", "-f", runtime_id, check=False)
        self.compose("down", "--volumes", "--remove-orphans")
        remaining = command(
            "docker",
            "ps",
            "-aq",
            "--filter",
            "label=com.docker.compose.project=" + self.project,
        ).stdout.strip()
        assert not remaining, "deployment cleanup left containers"


def prove(gov_source):
    deployment = Deployment(gov_source)
    try:
        deployment.start(launch_worker=False)
        prove_expiry(deployment)
        deployment.launch_worker()
        exercise(deployment)
        rows = deployment.collect()
        confirmation = prove_unconfirmed_shutdown(gov_source)
        proof = {
            "result": "PASS",
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "agt_commit": command(
                "git", "-C", str(AGT), "rev-parse", "HEAD"
            ).stdout.strip(),
            "gov_substrate_commit": GOV_COMMIT,
            "real_native_agt": True,
            "real_docker_workers": True,
            "model_calls": 0,
            "source_sha256": {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(HERE.iterdir())
                if path.is_file()
                and (
                    path.suffix in (".py", ".ini", ".md")
                    or path.name.startswith("Dockerfile")
                )
            },
            "image_ids": {
                key: command(
                    "docker", "image", "inspect", value, "--format", "{{.Id}}"
                ).stdout.strip()
                for key, value in IMAGES.items()
            },
            "cases": deployment.records + confirmation,
            "agt_audit": deployment.agt_audit,
            "effects": {
                "smtp": deployment.read_effects("smtp.jsonl"),
                "http": deployment.read_effects("http.jsonl"),
            },
            "substrate_events": rows,
            "scope": "named local Docker configuration; no hosted model or compromised-host claim",
        }
        destination = HERE / ".local" / "proof.json"
        destination.parent.mkdir(exist_ok=True)
        serialized = json.dumps(proof, indent=2, ensure_ascii=False)
        assert not any(secret in serialized for secret in deployment.tokens.values())
        destination.write_text(serialized + "\n", encoding="utf-8")
        return proof
    finally:
        deployment.close()


def email(subject):
    return {
        "recipients": ["recipient@example.test"],
        "subject": subject,
        "body": "real execution proof " + subject,
    }


def denied(response, system=None):
    body = response.get("body", response)
    assert body["decision"] == "deny", body
    if system:
        assert body["system"] == system, body
    return body


def prove_expiry(d):
    expiry_started = time.monotonic()
    expired_args = email("expired-grant")
    expired = d.rpc("POST", "/prepare", d.tool("send_email", expired_args))
    assert expired["decision"] == "allow"
    print("Waiting for the real 120-second grant lifetime to expire.", flush=True)
    while time.monotonic() - expiry_started < 123:
        time.sleep(min(1, 123 - (time.monotonic() - expiry_started)))
    expiry = denied(
        d.rpc("POST", "/dispatch", {"handle": expired["handle"], "args": expired_args})
    )
    assert expiry["reason"] == "execution_grant_expired" and not d.read_effects(
        "smtp.jsonl"
    )
    d.note("expired_grant_no_effect", expiry)


def exercise(d):

    allowed = d.worker(d.tool("send_email", email("both-allow")))
    assert (
        allowed["body"]["decision"] == "allow"
        and allowed["body"]["outcome"] == "succeeded"
    ), allowed
    deliveries = d.read_effects("smtp.jsonl")
    assert len(deliveries) == 1 and "both-allow" in deliveries[0]["data"]
    d.note("both_allow_real_smtp", {"deliveries": 1, "result": allowed["body"]})

    for tool, system in (("blocked_email", "agt"), ("restricted_email", "gov-sub")):
        before = len(d.read_effects("smtp.jsonl"))
        result = denied(d.worker(d.tool(tool, email(tool))), system)
        assert len(d.read_effects("smtp.jsonl")) == before
        d.note(tool + "_no_effect", result)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        request = d.tool("approval_email", email("approval-rejected"))
        response = pool.submit(d.worker, request)
        pending = wait_for(lambda: d.rpc("GET", "/approvals"))
        before = len(d.read_effects("smtp.jsonl"))
        assert not response.done() and before == 1
        d.note(
            "pending_approval_no_execution",
            {"pending": pending[0], "deliveries": before},
        )
        d.rpc("POST", "/approvals", {**pending[0], "outcome": "deny"})
        rejected = denied(response.result(timeout=15), "agt")
        assert len(d.read_effects("smtp.jsonl")) == before
        d.note("rejected_approval_no_execution", rejected)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        response = pool.submit(
            d.worker, d.tool("approval_email", email("approval-allowed"))
        )
        pending = wait_for(lambda: d.rpc("GET", "/approvals"))
        d.rpc("POST", "/approvals", {**pending[0], "outcome": "allow"})
        approved = response.result(timeout=15)
        assert approved["body"]["outcome"] == "succeeded", approved
        assert len(d.read_effects("smtp.jsonl")) == 2
        d.note("action_bound_approval_executes", approved["body"])

    changed_args = email("original-binding")
    prepared = d.rpc("POST", "/prepare", d.tool("send_email", changed_args))
    changed = denied(
        d.rpc(
            "POST",
            "/dispatch",
            {"handle": prepared["handle"], "args": email("changed-binding")},
        )
    )
    assert (
        changed["reason"] == "action_changed" and len(d.read_effects("smtp.jsonl")) == 2
    )
    d.note("changed_request_no_effect", changed)
    executed = d.rpc(
        "POST", "/dispatch", {"handle": prepared["handle"], "args": changed_args}
    )
    assert executed["outcome"] == "succeeded" and len(d.read_effects("smtp.jsonl")) == 3
    replay = denied(
        d.rpc("POST", "/dispatch", {"handle": prepared["handle"], "args": changed_args})
    )
    assert (
        replay["reason"] == "execution_grant_reused"
        and len(d.read_effects("smtp.jsonl")) == 3
    )
    d.note("replayed_grant_no_effect", replay)

    call = d.tool("send_email", email("call-replay"))
    assert d.worker(call)["body"]["outcome"] == "succeeded"
    assert denied(d.worker(call))["reason"] == "call_replayed"
    assert len(d.read_effects("smtp.jsonl")) == 4
    d.note("replayed_worker_call_no_effect", {"deliveries": 4})

    file_result = d.worker(
        d.tool("write_file", {"path": "result.txt", "content": "actual file effect"})
    )
    assert file_result["body"]["outcome"] == "succeeded", file_result
    observed = command(
        "docker", "exec", d.container("substrate"), "cat", "/workspace/result.txt"
    ).stdout
    assert observed == "actual file effect"
    d.note(
        "both_allow_real_file",
        {"content_sha256": hashlib.sha256(observed.encode()).hexdigest()},
    )
    protected = denied(
        d.worker(d.tool("write_file", {"path": "secret.txt", "content": "forbidden"})),
        "gov-sub",
    )
    assert (
        command(
            "docker",
            "exec",
            d.container("substrate"),
            "test",
            "-e",
            "/workspace/secret.txt",
            check=False,
        ).returncode
        != 0
    )
    d.note("substrate_protected_file_no_effect", protected)

    network = d.worker(d.tool("fetch_url", {"url": "http://receiver:8080/allowed"}))
    assert network["body"]["outcome"] == "succeeded", network
    http_effects = d.read_effects("http.jsonl")
    assert http_effects == [{"method": "GET", "path": "/allowed"}]
    forbidden = denied(
        d.worker(d.tool("fetch_url", {"url": "http://not-granted:8080/forbidden"})),
        "gov-sub",
    )
    assert d.read_effects("http.jsonl") == http_effects
    d.note(
        "real_network_effect_and_denial",
        {"delivered": http_effects, "denial": forbidden},
    )

    bypass = json.loads(
        command("docker", "exec", d.worker_id, "python", "/worker.py", "bypass").stdout
    )
    assert all(bypass.values()), bypass
    worker_environment = command(
        "docker",
        "exec",
        d.worker_id,
        "python",
        "-c",
        "import json,os; print(json.dumps(dict(os.environ)))",
    ).stdout
    assert not any(secret in worker_environment for secret in d.tokens.values())
    inspection = json.loads(command("docker", "inspect", d.worker_id).stdout)[0]
    assert inspection["HostConfig"]["NetworkMode"] == "none"
    assert (
        inspection["HostConfig"]["ReadonlyRootfs"]
        and inspection["Config"]["User"] == "65534:65534"
    )
    assert [
        mount["Destination"]
        for mount in inspection["Mounts"]
        if mount["Type"] != "tmpfs"
    ] == ["/bridge"]
    d.note("worker_direct_bypasses_blocked", bypass)

    forged = d.worker(
        {**d.tool("send_email", email("forged")), "agent_did": "did:mesh:other"}
    )
    assert forged["status"] == 422 and len(d.read_effects("smtp.jsonl")) == 4
    d.note("worker_identity_cannot_be_overridden", {"status": forged["status"]})
    root_probe = command(
        "docker",
        "exec",
        "--user",
        "0",
        d.worker_id,
        "python",
        "/worker.py",
        "request",
        json.dumps(d.tool("send_email", email("wrong-uid"))),
        check=False,
    )
    assert root_probe.returncode != 0 and len(d.read_effects("smtp.jsonl")) == 4
    d.note("wrong_peer_uid_blocked", {"request_failed": True})

    probe = json.loads(
        command(
            "docker",
            "exec",
            d.container("controller"),
            "python",
            "/integration/shutdown_probe.py",
            json.dumps(d.workers),
        ).stdout
    )
    assert probe["terminated"] is False
    assert json.loads(command("docker", "inspect", d.worker_id).stdout)[0]["State"][
        "Running"
    ]
    d.note("shutdown_authentication_failure_not_success", probe)

    prove_unavailable(d)

    revoked_args = email("revoked-grant")
    revoked = d.rpc("POST", "/prepare", d.tool("send_email", revoked_args))
    status = command("docker", "exec", d.worker_id, "cat", "/proc/1/status").stdout
    ignored = next(
        line.split()[1] for line in status.splitlines() if line.startswith("SigIgn:")
    )
    assert int(ignored, 16) & (1 << 14)
    command("docker", "kill", "--signal", "TERM", d.worker_id)
    assert json.loads(command("docker", "inspect", d.worker_id).stdout)[0]["State"][
        "Running"
    ]
    shutdown = d.rpc("POST", "/shutdown", {})
    assert (
        shutdown["terminated"] is True
        and shutdown["receipt"]["shutdown_confirmed"] is True
    ), shutdown
    assert shutdown["receipt"]["workers"][0]["runtime_id"] == d.worker_id
    assert command("docker", "inspect", d.worker_id, check=False).returncode != 0
    events = command(
        "docker",
        "events",
        "--since",
        str(int(d.started) - 1),
        "--until",
        str(int(time.time()) + 1),
        "--filter",
        "container=" + d.worker_id,
        "--format",
        "{{json .}}",
    ).stdout
    events = [json.loads(line) for line in events.splitlines() if line]
    assert any(
        item["Action"] == "kill" and item["Actor"]["Attributes"].get("signal") == "9"
        for item in events
    )
    assert any(
        item["Action"] == "die" and item["Actor"]["Attributes"].get("exitCode") == "137"
        for item in events
    )
    assert any(item["Action"] == "destroy" for item in events)
    d.note(
        "agt_kill_callback_verified_force_stop",
        {"shutdown": shutdown, "docker_events": events},
    )
    revocation = denied(
        d.rpc("POST", "/dispatch", {"handle": revoked["handle"], "args": revoked_args})
    )
    assert len(d.read_effects("smtp.jsonl")) == 4
    d.note("revoked_grant_no_effect", revocation)
    late = d.substrate_rpc(
        "POST",
        "/generations/complete",
        {"generation_id": d.generation_id, "text": "late completion"},
        operator=True,
    )
    assert late["decision"] == "deny"
    d.note("late_completion_rejected", late)


def prove_unavailable(d):
    before = d.read_effects("smtp.jsonl")
    container = d.container("substrate")
    command(
        "docker",
        "exec",
        container,
        "mv",
        "/substrate/api.sock",
        "/substrate/api.offline",
    )
    try:
        result = denied(d.worker(d.tool("send_email", email("unavailable"))), "gov-sub")
        assert (
            result["reason"] == "substrate_unavailable"
            and result["outcome"] == "unconfirmed"
        )
        assert result["evidence"]["agt"]["execution_permitted"] is True
        assert "authorization_event_id" not in result["evidence"]
        assert d.read_effects("smtp.jsonl") == before
        d.note("substrate_unavailable_no_execution", result)
    finally:
        command(
            "docker",
            "exec",
            container,
            "mv",
            "/substrate/api.offline",
            "/substrate/api.sock",
        )


def prove_unconfirmed_shutdown(gov_source):
    d = Deployment(gov_source)
    try:
        d.start()
        # A real control-plane identity mismatch must not certify an absent name as our worker's exit.
        command("docker", "rename", d.worker_id, "agt-unconfirmed-" + d.generation_id)
        stopped = d.rpc("POST", "/shutdown", {})
        assert stopped["terminated"] is False, stopped
        assert json.loads(command("docker", "inspect", d.worker_id).stdout)[0]["State"][
            "Running"
        ]
        d.note(
            "unconfirmed_shutdown_not_success",
            {"result": stopped, "expected_worker_still_running": True},
        )
        d.collect()
        return d.records
    finally:
        d.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--gov-source", required=True)
    options = parser.parse_args()
    prove(options.gov_source)
