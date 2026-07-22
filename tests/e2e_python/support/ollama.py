# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Ollama chat adapter and model-output parsing."""

from __future__ import annotations

import ast
import json
import os
import re
import urllib.error
import urllib.request
from typing import Any

from .logging_config import log_model_event
from .models import ModelReply, ToolCall


class OllamaModel:
    """Call Ollama's native chat API and normalize its response."""

    def __init__(self) -> None:
        self.base_url = os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
        self.model = os.environ.get("AGT_E2E_MODEL", "llama3.1")
        self.attempts = int(os.environ.get("AGT_E2E_MODEL_ATTEMPTS", "3"))
        self.inputs: list[str] = []

    def complete(
        self,
        scenario_id: str,
        prompt: str,
        tools: list[dict[str, Any]],
    ) -> ModelReply:
        self.inputs.append(prompt)
        last_reply = ModelReply()
        for attempt in range(1, self.attempts + 1):
            payload: dict[str, Any] = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "options": {"temperature": 0},
            }
            if tools:
                payload["tools"] = tools
            log_model_event(
                "ollama.request",
                scenario_id,
                {"attempt": attempt, "url": f"{self.base_url}/api/chat", "payload": payload},
            )
            request = urllib.request.Request(
                f"{self.base_url}/api/chat",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            try:
                with urllib.request.urlopen(request, timeout=120) as response:
                    body = json.loads(response.read().decode("utf-8"))
            except (urllib.error.URLError, TimeoutError) as exc:
                raise RuntimeError(
                    f"Ollama is unavailable at {self.base_url}; start it and pull {self.model}"
                ) from exc
            log_model_event(
                "ollama.response",
                scenario_id,
                {"attempt": attempt, "body": body},
            )

            message = body.get("message", {})
            tool_calls = message.get("tool_calls") or []
            if tool_calls:
                function = tool_calls[0].get("function", {})
                arguments = function.get("arguments") or {}
                if isinstance(arguments, str):
                    arguments = json.loads(arguments)
                reply = ModelReply(
                    tool_call=ToolCall(str(function.get("name", "")), arguments)
                )
                log_model_event("ollama.normalized_response", scenario_id, _reply_for_log(reply))
                return reply
            last_reply = ModelReply(content=str(message.get("content", "")))
            if scenario_id == "filesystem":
                code = extract_python(last_reply.content)
                try:
                    tree = ast.parse(code)
                except SyntaxError:
                    continue
                if any(
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "open"
                    for node in ast.walk(tree)
                ):
                    log_model_event(
                        "ollama.normalized_response",
                        scenario_id,
                        _reply_for_log(last_reply),
                    )
                    return last_reply
        log_model_event(
            "ollama.normalized_response",
            scenario_id,
            _reply_for_log(last_reply),
        )
        return last_reply


def select_model() -> OllamaModel:
    return OllamaModel()


def extract_python(content: str) -> str:
    fenced = re.search(r"```(?:python)?\s*(.*?)```", content, re.DOTALL | re.IGNORECASE)
    if fenced:
        return fenced.group(1).strip()
    return content.strip()


def _reply_for_log(reply: ModelReply) -> dict[str, Any]:
    if reply.tool_call is not None:
        return {
            "tool_call": {
                "name": reply.tool_call.name,
                "arguments": reply.tool_call.arguments,
            }
        }
    return {"content": reply.content}
