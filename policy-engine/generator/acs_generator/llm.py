from __future__ import annotations

import json
import os
from typing import Protocol
from urllib import error, parse, request


class LanguageModel(Protocol):
    def complete(self, system: str, user: str) -> str: ...


class OpenAICompatibleLanguageModel:
    def __init__(
        self,
        *,
        api_base: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        api_version: str | None = None,
    ) -> None:
        self.api_base = (api_base or os.getenv("ACS_GENERATOR_API_BASE") or "https://api.openai.com/v1").rstrip("/")
        self.api_key = api_key or os.getenv("ACS_GENERATOR_API_KEY")
        self.model = model or os.getenv("ACS_GENERATOR_MODEL") or "gpt-4o-mini"
        self.api_version = api_version or os.getenv("ACS_GENERATOR_API_VERSION")
        self.is_azure = self.api_version is not None or _is_azure_api_base(self.api_base)

    def complete(self, system: str, user: str) -> str:
        if not self.api_key:
            raise RuntimeError("ACS_GENERATOR_API_KEY is required for the real provider")
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": 0,
            "response_format": {"type": "json_object"},
        }
        data = json.dumps(payload).encode("utf-8")
        url = f"{self.api_base}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.is_azure:
            if self.api_version:
                url += f"?api-version={self.api_version}"
            headers["api-key"] = self.api_key
        else:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = request.Request(
            url,
            data=data,
            headers=headers,
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=60) as response:
                body = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            raise RuntimeError(_http_error_detail(exc)) from exc
        return body["choices"][0]["message"]["content"]


def _is_azure_api_base(api_base: str) -> bool:
    hostname = parse.urlparse(api_base).hostname or ""
    normalized = hostname.lower().rstrip(".")
    return normalized == "azure.com" or normalized.endswith(".azure.com")


def _http_error_detail(exc: "error.HTTPError") -> str:
    # urllib surfaces only "HTTP Error 400: Bad Request"; the provider body
    # carries the actionable reason (e.g. Azure content_filter / jailbreak), so
    # decode and include it. Guardrail prose that reads like an injection
    # instruction trips the Azure jailbreak shield with a 400.
    base = f"LLM request failed with HTTP {exc.code}"
    try:
        payload = json.loads(exc.read().decode("utf-8"))
    except Exception:  # noqa: BLE001 - fall back to the bare status line
        return base
    err = payload.get("error", payload) if isinstance(payload, dict) else {}
    parts = [base]
    if isinstance(err, dict):
        if err.get("code"):
            parts.append(f"code={err['code']}")
        if err.get("message"):
            parts.append(str(err["message"]))
        inner = err.get("innererror") or {}
        cf = inner.get("content_filter_result") if isinstance(inner, dict) else None
        if isinstance(cf, dict):
            flagged = sorted(k for k, v in cf.items() if isinstance(v, dict) and (v.get("filtered") or v.get("detected")))
            if flagged:
                parts.append(f"content_filter={flagged}")
    return ". ".join(parts)


class FakeLanguageModel:
    def __init__(self, responses: list[str | dict]) -> None:
        if not responses:
            raise ValueError("FakeLanguageModel requires at least one response")
        self._responses = [json.dumps(item) if isinstance(item, dict) else item for item in responses]
        self.prompts: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.prompts.append((system, user))
        if len(self.prompts) <= len(self._responses):
            return self._responses[len(self.prompts) - 1]
        return self._responses[-1]
