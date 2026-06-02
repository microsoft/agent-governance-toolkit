from __future__ import annotations

import json
import os
from typing import Protocol
from urllib import parse, request


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
        with request.urlopen(req, timeout=60) as response:
            body = json.loads(response.read().decode("utf-8"))
        return body["choices"][0]["message"]["content"]


def _is_azure_api_base(api_base: str) -> bool:
    hostname = parse.urlparse(api_base).hostname or ""
    normalized = hostname.lower().rstrip(".")
    return normalized == "azure.com" or normalized.endswith(".azure.com")


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
