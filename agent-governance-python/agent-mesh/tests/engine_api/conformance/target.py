# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Reference and external Engine API targets for shared conformance assertions."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import yaml


@dataclass
class EngineTarget:
    """Transport plus metadata for one Engine API target."""

    client: Any
    openapi: dict[str, Any] | None
    metadata: dict[str, Any] | None
    external: bool
    origin: str
    allow_writes: bool = False

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        """Send an HTTP request through the configured target transport."""
        if (
            self.external
            and not self.allow_writes
            and method.upper() == "POST"
            and path in {"/api/v1/policy/save", "/api/v1/policy/reload"}
        ):
            raise PermissionError(
                "External write operations require AGT_ENGINE_API_ALLOW_WRITES=1"
            )
        return self.client.request(method, path, **kwargs)

    def close(self) -> None:
        """Close transports that own network resources."""
        close = getattr(self.client, "close", None)
        if close is not None:
            close()


def reference_target(app: Any) -> EngineTarget:
    """Build an in-process target without opening a TCP port."""
    from fastapi.testclient import TestClient

    client = TestClient(app)
    return EngineTarget(
        client=client,
        openapi=app.openapi(),
        metadata=None,
        external=False,
        origin="in-process",
    )


def _load_document(source: str) -> dict[str, Any]:
    parsed = urlparse(source)
    if parsed.scheme in {"http", "https"}:
        response = httpx.get(source, timeout=10.0)
        response.raise_for_status()
        document = response.json()
    else:
        with Path(source).open("r", encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
    if not isinstance(document, dict):
        raise ValueError(f"Engine metadata must be a JSON/YAML object: {source}")
    return document


def external_target_from_environment() -> EngineTarget:
    """Build an external target from explicit environment configuration.

    ``AGT_ENGINE_API_URL`` is the engine origin. The optional
    ``AGT_ENGINE_API_OPENAPI`` and ``AGT_ENGINE_API_METADATA`` values accept either a local
    JSON/YAML path or an HTTP URL. Metadata is required when the target does not expose
    ``/openapi.json``.
    """
    origin = os.environ["AGT_ENGINE_API_URL"].rstrip("/")
    client = httpx.Client(base_url=origin, timeout=10.0)
    openapi_source = os.getenv("AGT_ENGINE_API_OPENAPI", f"{origin}/openapi.json")
    openapi: dict[str, Any] | None = None
    try:
        openapi = _load_document(openapi_source)
    except (httpx.HTTPError, OSError, ValueError):
        metadata_source = os.getenv("AGT_ENGINE_API_METADATA")
        if not metadata_source:
            client.close()
            raise RuntimeError(
                "External target must expose /openapi.json or set AGT_ENGINE_API_METADATA"
            )
    metadata_source = os.getenv("AGT_ENGINE_API_METADATA")
    metadata = _load_document(metadata_source) if metadata_source else None
    return EngineTarget(
        client=client,
        openapi=openapi,
        metadata=metadata,
        external=True,
        origin=origin,
        allow_writes=os.getenv("AGT_ENGINE_API_ALLOW_WRITES") == "1",
    )


def metadata_to_openapi(metadata: dict[str, Any]) -> dict[str, Any]:
    """Normalize the documented operation metadata shape for identity checks.

    Metadata-only adapters cannot advertise response schemas, so the resulting document is
    intentionally suitable for route/flag checks only. HTTP payloads remain validated against
    the canonical contract by the shared assertions.
    """
    if isinstance(metadata.get("paths"), dict):
        return metadata
    operations = metadata.get("operations")
    if not isinstance(operations, list):
        raise ValueError("Engine metadata must contain either paths or an operations list")
    paths: dict[str, dict[str, Any]] = {}
    for item in operations:
        if not isinstance(item, dict):
            raise ValueError("Each engine metadata operation must be an object")
        method = item.get("method")
        path = item.get("path")
        operation_id = item.get("operationId")
        flags = item.get("x-capability-flags")
        if not all(isinstance(value, str) for value in (method, path, operation_id)):
            raise ValueError("Metadata operations require method, path, and operationId strings")
        if not isinstance(flags, dict):
            raise ValueError(f"Metadata operation {operation_id!r} lacks x-capability-flags")
        paths.setdefault(path, {})[method.lower()] = {
            "operationId": operation_id,
            "x-capability-flags": flags,
        }
    return {"openapi": "3.1.0", "paths": paths}
