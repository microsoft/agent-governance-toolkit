from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping

from agent_control_specification import AgentControl, AgentControlBlocked, InterventionPoint

ROOT = Path(__file__).resolve().parents[4]
ENV_PATH = ROOT / ".env"
DEFAULT_MANIFEST = ROOT / "tests" / "fixtures" / "smoke" / "manifest.yaml"


def load_env() -> None:
    if not ENV_PATH.exists():
        return
    for raw in ENV_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def control() -> AgentControl:
    manifest = Path(os.environ.get("ACS_REALPKG_MANIFEST", str(DEFAULT_MANIFEST)))
    return AgentControl.from_path(str(manifest))


def require_azure() -> dict[str, str]:
    load_env()
    names = (
        "AZURE_OPENAI_ENDPOINT",
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_DEPLOYMENT",
        "AZURE_OPENAI_API_VERSION",
    )
    values = {name: os.environ.get(name, "") for name in names}
    missing = [name for name, value in values.items() if not value]
    if missing:
        raise RuntimeError(f"Missing Azure OpenAI environment variables: {', '.join(missing)}")
    return values


def assert_blocked(exc: BaseException, point: InterventionPoint) -> None:
    if not isinstance(exc, AgentControlBlocked):
        raise AssertionError(f"expected AgentControlBlocked, got {type(exc).__name__}") from exc
    if exc.intervention_point != point:
        raise AssertionError(f"expected {point.value}, got {exc.intervention_point.value}") from exc


async def call_asgi(app: Any, path: str, body: Mapping[str, Any]) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    raw = json.dumps(body).encode("utf-8")
    sent = False

    async def receive() -> dict[str, Any]:
        nonlocal sent
        if sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": raw, "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        messages.append(dict(message))

    await app(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(raw)).encode()),
            ],
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
            "scheme": "http",
        },
        receive,
        send,
    )
    return messages
