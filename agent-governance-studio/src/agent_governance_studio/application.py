# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Secure ASGI composition around the canonical adapter, isolated from the listener."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import sys
import tempfile
import time
from collections import deque
from dataclasses import asdict
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from fastapi.routing import compile_path

from .config import Configuration, ConfigurationError
from .processes import ProcessTree, reap

logger = logging.getLogger(__name__)
REQUEST_HEADER = "x-agt-studio-request"
REQUEST_HEADER_VALUE = "1"
PRIVACY_HEADERS = {
    "cache-control": "no-store, private",
    "pragma": "no-cache",
    "expires": "0",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
}


class WorkerFailure(RuntimeError):
    """Worker diagnostics are identifiers, never exception messages or request data."""


class Workers:
    def __init__(self, config: Configuration) -> None:
        self.config = config
        self.active: dict[asyncio.Task, asyncio.subprocess.Process | None] = {}
        self.closing = False
        self.snapshot = tempfile.TemporaryDirectory(prefix="agt-studio-inventory-")
        self.policy_root = Path(self.snapshot.name) / "policies"
        self.policy_root.mkdir()
        self.started_at = time.monotonic()

    async def run(self, command: dict, timeout: float) -> dict:
        if self.closing:
            raise WorkerFailure("shutdown")
        task = asyncio.current_task()
        if task is None:
            raise RuntimeError("Worker requires an asyncio task.")
        self.active[task] = None
        process = tree = None
        try:
            with tempfile.TemporaryDirectory(prefix="agt-studio-") as scratch:
                env = {**os.environ, "TMP": scratch, "TEMP": scratch, "TMPDIR": scratch}
                process = await asyncio.create_subprocess_exec(
                    sys.executable, "-I", "-m", "agent_governance_studio.worker",
                    stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                    env=env, start_new_session=os.name != "nt",
                )
                self.active[task] = process
                try:
                    tree = ProcessTree(process.pid)
                    command = {
                        **command, "policy_dir": str(self.policy_root),
                        "source_root": str(self.config.policy_dir) if self.config.policy_dir else None,
                        "started_at": self.started_at, "limits": asdict(self.config.limits),
                    }

                    async def exchange():
                        if process.stdin is None or process.stdout is None:
                            raise WorkerFailure("protocol")
                        process.stdin.write(json.dumps(command).encode() + b"\n")
                        await process.stdin.drain()
                        process.stdin.close()
                        maximum = self.config.limits.response_bytes * 2 + 1024 * 1024
                        output = bytearray()
                        while chunk := await process.stdout.read(65536):
                            if len(output) + len(chunk) > maximum:
                                raise WorkerFailure("response-limit")
                            output.extend(chunk)
                        await process.wait()
                        if process.returncode != 0:
                            raise WorkerFailure("process")
                        try:
                            result = json.loads(output)
                        except (ValueError, UnicodeError):
                            raise WorkerFailure("protocol") from None
                        if not isinstance(result, dict):
                            raise WorkerFailure("protocol")
                        if "failure" in result:
                            raise WorkerFailure(result["failure"])
                        return result

                    return await asyncio.wait_for(exchange(), timeout)
                finally:
                    await reap(process, tree)
        finally:
            self.active.pop(task, None)

    async def close(self) -> None:
        self.closing = True
        tasks = tuple(self.active)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                self.config.limits.shutdown_seconds,
            )
        self.snapshot.cleanup()


class Sidecar:
    """Importable ASGI/lifecycle surface; no sockets or scanning at construction."""

    def __init__(self, config: Configuration) -> None:
        self.config = config
        self.workers = Workers(config)
        self.document: dict | None = None
        self.operations: list[tuple[str, object, dict]] = []
        self.read_only_operations: tuple[str, ...] = ()
        self.requests: deque[float] = deque()
        self.probes: deque[float] = deque()
        self.inflight = 0
        self.probes_inflight = 0

    async def start(self) -> None:
        try:
            result = await self.workers.run({"kind": "inspect"}, self.config.limits.startup_seconds)
            document = result["openapi"]
            operations = []
            for path, item in document["paths"].items():
                for method, operation in item.items():
                    if isinstance(operation, dict) and "operationId" in operation:
                        flags = operation["x-capability-flags"]
                        if (
                            set(flags) != {"runtime_mutating", "read_only_surface", "user_intent_required"}
                            or any(not isinstance(value, bool) for value in flags.values())
                            or flags["runtime_mutating"] == flags["read_only_surface"]
                        ):
                            raise ValueError("Invalid adapter capabilities.")
                        operations.append((method.upper(), compile_path(path)[0], operation))
            if len(operations) != 12 or len(result["read_only"]) != 11:
                raise ValueError("Incompatible Engine API baseline.")
            self.operations = operations
            self.read_only_operations = tuple(result["read_only"])
            self.document = document
        except (TimeoutError, WorkerFailure, OSError, KeyError, ValueError) as exc:
            reason = str(exc) if isinstance(exc, WorkerFailure) else type(exc).__name__
            logger.error("Studio startup rejected (%s)", reason)
            if isinstance(exc, WorkerFailure) and reason == "policy-root":
                message = "Policy root is unreadable or exceeds the documented finite file/size limits."
            else:
                message = (
                    "Studio backend initialization failed. Install matching core/compliance/native ACS "
                    "wheels and OPA; check the read-only policy root and startup limits."
                )
            raise ConfigurationError(message) from None

    def openapi(self) -> dict:
        if self.document is None:
            raise RuntimeError("Start the sidecar before requesting its metadata.")
        return self.document

    async def close(self) -> None:
        await self.workers.close()

    def _operation(self, method: str, path: str) -> dict | None:
        return next(
            (operation for verb, pattern, operation in self.operations if verb == method and pattern.fullmatch(path)),
            None,
        )

    def _allowed_origin(self, origin: str) -> bool:
        try:
            parsed = urlsplit(origin)
            return (
                parsed.scheme == "http" and parsed.hostname == self.config.host
                and (parsed.port or 80) == self.config.port
                and not parsed.username and not parsed.password
                and not parsed.path and not parsed.query and not parsed.fragment
                and origin in (
                    {self.config.origin, "http://127.0.0.1"} if self.config.port == 80 else {self.config.origin}
                )
            )
        except ValueError:
            return False

    def _gate(self, scope: dict) -> tuple[dict[str, str], tuple[int, str, str] | None]:
        headers: dict[str, str] = {}
        unique = {
            "host", "origin", "sec-fetch-site", REQUEST_HEADER, "content-type", "content-length",
            "access-control-request-method", "access-control-request-headers",
        }
        for name, value in scope["headers"]:
            key = name.decode("latin1").lower()
            if key in unique and key in headers:
                return headers, (403, "FORBIDDEN", "Ambiguous security headers are forbidden.")
            headers[key] = value.decode("latin1")
        if headers.get("host") != self.config.authority:
            return headers, (403, "FORBIDDEN", "Host must match the configured listener authority.")
        if any(key == "forwarded" or key.startswith("x-forwarded-") for key in headers):
            return headers, (403, "FORBIDDEN", "Proxy forwarding is not supported.")
        credential_headers = {"authorization", "proxy-authorization", "cookie", "x-api-key", "x-agt-studio-token"}
        if credential_headers & headers.keys() or any("token" in key.split("-") for key in headers) or any(
            key.casefold().replace("-", "_") in {"token", "access_token", "authorization", "api_key", "studio_token", "agt_studio_token"}
            for key, _ in parse_qsl(scope.get("query_string", b"").decode("latin1"))
        ):
            return headers, (401, "UNAUTHORIZED", "Supplied credentials are unsupported in this profile.")
        if "origin" in headers and not self._allowed_origin(headers["origin"]):
            return headers, (403, "FORBIDDEN", "Origin is not allowed.")
        if headers.get("sec-fetch-site", "none") not in {"none", "same-origin"}:
            return headers, (403, "FORBIDDEN", "Cross-site requests are forbidden.")
        if scope["method"] == "POST":
            if "origin" not in headers or headers.get(REQUEST_HEADER) != REQUEST_HEADER_VALUE:
                return headers, (403, "FORBIDDEN", "POST requires the allowed Origin and X-AGT-Studio-Request: 1.")
            if headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                return headers, (422, "VALIDATION_ERROR", "POST requires application/json.")
        if "content-encoding" in headers:
            return headers, (422, "VALIDATION_ERROR", "Encoded request bodies are unsupported.")
        return headers, None

    async def _respond(self, send, status: int, body: bytes, extra: dict | None = None) -> None:
        headers = {**PRIVACY_HEADERS, "content-type": "application/json", **(extra or {})}
        await send({"type": "http.response.start", "status": status, "headers": [
            (key.encode(), value.encode()) for key, value in headers.items()
        ]})
        await send({"type": "http.response.body", "body": body})

    async def _error(self, send, status: int, code: str, message: str) -> None:
        from agentmesh.engine_api.errors import ErrorEnvelope

        body = ErrorEnvelope(status=status, code=code, message=message).model_dump_json().encode()
        await self._respond(send, status, body, {"retry-after": "60"} if status == 429 else None)

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "lifespan":
            while True:
                event = await receive()
                if event["type"] == "lifespan.startup":
                    try:
                        if self.document is None:
                            await self.start()
                    except ConfigurationError as exc:
                        await send({"type": "lifespan.startup.failed", "message": str(exc)})
                        return
                    await send({"type": "lifespan.startup.complete"})
                elif event["type"] == "lifespan.shutdown":
                    await self.close()
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        elif scope["type"] != "http":
            await send({"type": "websocket.close", "code": 1008})
            return
        if self.document is None or self.workers.closing:
            await self._error(send, 503, "ENGINE_UNAVAILABLE", "Sidecar is not accepting requests.")
            return
        if len(scope.get("query_string", b"")) > 2048 or len(scope["path"]) > 1024:
            await self._error(send, 422, "VALIDATION_ERROR", "Request target exceeds its finite limit.")
            return
        headers, error = self._gate(scope)
        if error:
            await self._error(send, *error)
            return
        method, path = scope["method"], scope["path"]
        operation = self._operation(method, path)
        if method == "OPTIONS":
            requested_method = headers.get("access-control-request-method", "")
            requested_headers = {
                value.strip().lower()
                for value in headers.get("access-control-request-headers", "").split(",") if value.strip()
            }
            allowed = {"content-type", REQUEST_HEADER}
            if (
                "origin" not in headers or self._operation(requested_method, path) is None
                or not requested_headers <= allowed
                or (requested_method == "POST" and requested_headers != allowed)
            ):
                await self._error(send, 403, "FORBIDDEN", "Preflight does not match the supported request contract.")
                return
        elif operation is None and not (path == "/openapi.json" and method == "GET"):
            await self._error(send, 404, "POLICY_NOT_FOUND", "Not Found")
            return
        if operation and operation["x-capability-flags"]["runtime_mutating"]:
            await self._error(send, 403, "FORBIDDEN", "Policy saving is disabled in Studio.")
            return
        probe = bool(operation and operation["operationId"] in {"getHealth", "getVersions"})
        queue = self.probes if probe else self.requests
        maximum = self.config.limits.probes_per_minute if probe else self.config.limits.requests_per_minute
        now = time.monotonic()
        while queue and queue[0] <= now - 60:
            queue.popleft()
        if len(queue) >= maximum:
            await self._error(send, 429, "RATE_LIMITED", "Request rate limit exceeded.")
            return
        queue.append(now)
        if (self.probes_inflight >= 1 if probe else self.inflight >= self.config.limits.concurrent_requests):
            await self._error(send, 429, "RATE_LIMITED", "Concurrent request limit exceeded.")
            return
        if probe:
            self.probes_inflight += 1
        else:
            self.inflight += 1
        try:
            length = headers.get("content-length")
            if length is not None and (len(length) > 10 or not length.isascii() or not length.isdecimal()):
                await self._error(send, 422, "VALIDATION_ERROR", "Invalid Content-Length.")
                return
            if length is not None and int(length) > self.config.limits.body_bytes:
                await self._error(send, 413, "VALIDATION_ERROR", "Request body exceeds its finite byte limit.")
                return

            async def read_body():
                body = bytearray()
                while True:
                    event = await receive()
                    if event["type"] == "http.disconnect":
                        raise ConnectionError
                    chunk = event.get("body", b"")
                    if len(body) + len(chunk) > self.config.limits.body_bytes:
                        return None
                    body.extend(chunk)
                    if not event.get("more_body", False):
                        return bytes(body)

            try:
                body = await asyncio.wait_for(read_body(), self.config.limits.receive_seconds)
            except TimeoutError:
                await self._error(send, 408, "VALIDATION_ERROR", "Request body deadline exceeded.")
                return
            except ConnectionError:
                return
            if body is None:
                await self._error(send, 413, "VALIDATION_ERROR", "Request body exceeds its finite byte limit.")
                return
            if length is not None and int(length) != len(body):
                await self._error(send, 422, "VALIDATION_ERROR", "Content-Length does not match body size.")
                return
            if method == "OPTIONS":
                await self._respond(send, 204, b"", {
                    "access-control-allow-origin": headers["origin"],
                    "access-control-allow-methods": headers["access-control-request-method"],
                    "access-control-allow-headers": "Content-Type, X-AGT-Studio-Request",
                    "vary": "Origin",
                })
                return
            if path == "/openapi.json":
                await self._respond(send, 200, json.dumps(self.openapi()).encode())
                return
            worker_scope = {key: scope[key] for key in ("type", "method", "path", "root_path", "http_version", "scheme")}
            worker_scope.update(
                asgi={"version": "3.0"}, server=[self.config.host, self.config.port],
                client=[self.config.host, 0],
                query_string=base64.b64encode(scope.get("query_string", b"")).decode(),
                headers=[(key.decode("latin1"), value.decode("latin1")) for key, value in scope["headers"]],
            )
            try:
                work = asyncio.create_task(self.workers.run(
                    {"kind": "request", "scope": worker_scope, "body": base64.b64encode(body).decode()},
                    self.config.limits.execution_seconds,
                ))

                async def disconnected():
                    while True:
                        if (await receive())["type"] == "http.disconnect":
                            return
                        await asyncio.sleep(0)

                disconnect = asyncio.create_task(disconnected())
                try:
                    done, _ = await asyncio.wait({work, disconnect}, return_when=asyncio.FIRST_COMPLETED)
                    if disconnect in done:
                        return
                    result = work.result()
                finally:
                    disconnect.cancel()
                    if not work.done():
                        work.cancel()
                    await asyncio.gather(work, disconnect, return_exceptions=True)
                payload = base64.b64decode(result["body"], validate=True)
                await self._respond(send, result["status"], payload)
            except TimeoutError:
                logger.warning("Studio request rejected (execution deadline)")
                await self._error(send, 504, "ENGINE_UNAVAILABLE", "Computation deadline exceeded; owned work was terminated.")
            except (WorkerFailure, OSError, ValueError, KeyError) as exc:
                logger.warning("Studio request failed (%s)", type(exc).__name__)
                await self._error(send, 503, "ENGINE_UNAVAILABLE", "Backend request failed; check runtime and policy-root limits.")
            except asyncio.CancelledError:
                if not self.workers.closing:
                    raise
                await self._error(send, 503, "ENGINE_UNAVAILABLE", "Sidecar is shutting down.")
        finally:
            if probe:
                self.probes_inflight -= 1
            else:
                self.inflight -= 1


def create_sidecar(config: Configuration) -> Sidecar:
    return Sidecar(config)
