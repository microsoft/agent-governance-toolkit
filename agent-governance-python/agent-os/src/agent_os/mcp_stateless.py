# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""MCP ``2026-07-28`` request-envelope helpers for governance gateways.

The ``2026-07-28`` MCP revision removed the ``initialize`` handshake and
protocol sessions. Every request now carries its protocol version, client
identity and client capabilities in ``params._meta``, and Streamable HTTP
mirrors selected body fields into headers (``MCP-Protocol-Version``,
``Mcp-Method``, ``Mcp-Name`` and ``Mcp-Param-{Name}`` from ``x-mcp-header``
schema annotations) so that intermediaries can route without parsing the
body. Server-to-client interactions are returned as ``input_required``
results (multi round-trip requests) instead of server-initiated requests.

A gateway that enforces policy on the body while other components route on
headers must reject any header/body disagreement, otherwise the policy and the
executed call can diverge. This module implements those checks without
depending on the native policy runtime so that proxies, the ``MCPGateway`` and
the ``mcp-scan`` CLI can share them.

Specification references:

* https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
* https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

#: Current (modern, stateless) MCP protocol revision.
PROTOCOL_VERSION_STATELESS = "2026-07-28"
#: Latest legacy (``initialize``-based) MCP protocol revision.
PROTOCOL_VERSION_LEGACY = "2025-11-25"
#: Protocol versions this module accepts by default, newest first.
DEFAULT_SUPPORTED_PROTOCOL_VERSIONS: tuple[str, ...] = (
    PROTOCOL_VERSION_STATELESS,
    PROTOCOL_VERSION_LEGACY,
)

META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"

HEADER_PROTOCOL_VERSION = "MCP-Protocol-Version"
HEADER_METHOD = "Mcp-Method"
HEADER_NAME = "Mcp-Name"
HEADER_PARAM_PREFIX = "Mcp-Param-"

#: JSON-RPC error code for header/body disagreement or malformed headers.
ERROR_HEADER_MISMATCH = -32020
#: JSON-RPC error code for an unsupported protocol version.
ERROR_UNSUPPORTED_PROTOCOL_VERSION = -32022

#: Methods whose ``Mcp-Name`` header mirrors ``params.name`` or ``params.uri``.
NAME_SOURCE_BY_METHOD: Mapping[str, str] = {
    "tools/call": "name",
    "prompts/get": "name",
    "resources/read": "uri",
}

#: Server-to-client request methods permitted inside ``inputRequests``.
INPUT_REQUEST_METHODS = frozenset({"elicitation/create", "sampling/createMessage", "roots/list"})

_B64_PREFIX = "=?base64?"
_B64_SUFFIX = "?="
_TCHAR = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_SAFE_HEADER_VALUE = re.compile(r"^[\x20-\x7e\t]*$")
_TRACEPARENT = re.compile(r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
_JS_SAFE_INTEGER = 2**53 - 1
_MAX_TRACESTATE = 512
_MAX_BAGGAGE = 8192


@dataclass(frozen=True)
class HeaderBinding:
    """A tool parameter that ``x-mcp-header`` mirrors into an HTTP header."""

    header: str
    path: tuple[str, ...]
    schema_type: str


@dataclass
class EnvelopeCheck:
    """Outcome of validating one MCP request envelope."""

    allowed: bool
    reason: str
    error_code: int | None = None
    protocol_version: str | None = None
    trace_context: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class InputRequest:
    """One server-to-client request carried in an ``input_required`` result."""

    key: str
    method: str
    params: Mapping[str, Any]


def _lower_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()}


def decode_header_value(value: str) -> str:
    """Decode an MCP header value, honouring the ``=?base64?…?=`` sentinel.

    Raises:
        ValueError: If the value has invalid characters or bad Base64.
    """
    if not _SAFE_HEADER_VALUE.match(value):
        raise ValueError("header value contains characters outside visible ASCII")
    if value.startswith(_B64_PREFIX) and value.endswith(_B64_SUFFIX) and len(value) >= len(_B64_PREFIX) + len(_B64_SUFFIX):
        encoded = value[len(_B64_PREFIX) : -len(_B64_SUFFIX)]
        try:
            return base64.b64decode(encoded, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise ValueError("invalid Base64 header value") from exc
    return value


def encode_header_value(value: str) -> str:
    """Encode a value for an MCP header, using Base64 only when required."""
    needs_encoding = (
        not value.isascii()
        or not _SAFE_HEADER_VALUE.match(value)
        or "\t" in value
        or value != value.strip()
        or (value.startswith(_B64_PREFIX) and value.endswith(_B64_SUFFIX))
    )
    if not needs_encoding:
        return value
    return f"{_B64_PREFIX}{base64.b64encode(value.encode('utf-8')).decode('ascii')}{_B64_SUFFIX}"


def request_meta(message: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return ``params._meta`` from a JSON-RPC request, or an empty mapping."""
    params = message.get("params")
    if isinstance(params, Mapping):
        meta = params.get("_meta")
        if isinstance(meta, Mapping):
            return meta
    return {}


def build_request_meta(
    client_info: Mapping[str, Any],
    client_capabilities: Mapping[str, Any] | None = None,
    *,
    protocol_version: str = PROTOCOL_VERSION_STATELESS,
) -> dict[str, Any]:
    """Build the per-request ``_meta`` a modern MCP client must send."""
    return {
        META_PROTOCOL_VERSION: protocol_version,
        META_CLIENT_INFO: dict(client_info),
        META_CLIENT_CAPABILITIES: dict(client_capabilities or {}),
    }


def mirrored_headers(message: Mapping[str, Any]) -> dict[str, str]:
    """Return the standard headers a client mirrors from a request body."""
    method = str(message.get("method", ""))
    headers = {HEADER_METHOD: method}
    version = request_meta(message).get(META_PROTOCOL_VERSION)
    if isinstance(version, str):
        headers[HEADER_PROTOCOL_VERSION] = version
    source = NAME_SOURCE_BY_METHOD.get(method)
    params = message.get("params")
    if source and isinstance(params, Mapping) and isinstance(params.get(source), str):
        headers[HEADER_NAME] = encode_header_value(params[source])
    return headers


def extract_trace_context(meta: Mapping[str, Any]) -> dict[str, str]:
    """Return validated W3C trace-context fields carried in ``_meta``.

    Invalid values are dropped rather than propagated into audit records.
    """
    context: dict[str, str] = {}
    traceparent = meta.get("traceparent")
    if isinstance(traceparent, str):
        match = _TRACEPARENT.match(traceparent)
        if match and match.group(1) != "ff" and set(match.group(2)) != {"0"} and set(match.group(3)) != {"0"}:
            context["traceparent"] = traceparent
    if "traceparent" not in context:
        return context
    tracestate = meta.get("tracestate")
    if isinstance(tracestate, str) and len(tracestate) <= _MAX_TRACESTATE and _SAFE_HEADER_VALUE.match(tracestate):
        context["tracestate"] = tracestate
    baggage = meta.get("baggage")
    if isinstance(baggage, str) and len(baggage) <= _MAX_BAGGAGE and _SAFE_HEADER_VALUE.match(baggage):
        context["baggage"] = baggage
    return context


def x_mcp_header_bindings(input_schema: Mapping[str, Any]) -> list[HeaderBinding]:
    """Return the ``x-mcp-header`` bindings declared by a tool ``inputSchema``.

    Raises:
        ValueError: If any annotation violates the specification constraints.
            Clients must exclude such tools from ``tools/list``.
    """
    bindings: list[HeaderBinding] = []
    seen: set[str] = set()

    def walk(node: Any, path: tuple[str, ...], reachable: bool) -> None:
        if isinstance(node, Mapping):
            if "x-mcp-header" in node:
                if not reachable or not path:
                    raise ValueError(f"x-mcp-header at {'/'.join(path) or '<root>'} is not statically reachable")
                header = node["x-mcp-header"]
                if not isinstance(header, str) or not header or not _TCHAR.match(header):
                    raise ValueError(f"x-mcp-header at {'/'.join(path)} is not a valid header token")
                if header.lower() in seen:
                    raise ValueError(f"x-mcp-header {header!r} is declared more than once")
                schema_type = node.get("type")
                if schema_type not in {"string", "integer", "boolean"}:
                    raise ValueError(f"x-mcp-header {header!r} must annotate a string, integer or boolean")
                seen.add(header.lower())
                bindings.append(HeaderBinding(header, path, schema_type))
            for key, child in node.items():
                if key == "properties" and isinstance(child, Mapping) and reachable:
                    for prop_name, prop_schema in child.items():
                        walk(prop_schema, (*path, str(prop_name)), True)
                elif key != "x-mcp-header":
                    walk(child, path, False)
        elif isinstance(node, list):
            for child in node:
                walk(child, path, False)

    walk(input_schema, (), True)
    return bindings


def _value_at(arguments: Any, path: tuple[str, ...]) -> Any:
    node = arguments
    for key in path:
        if not isinstance(node, Mapping) or key not in node:
            return None
        node = node[key]
    return node


def _header_matches(header_value: str, body_value: Any, schema_type: str) -> bool:
    if schema_type == "boolean":
        return isinstance(body_value, bool) and header_value == ("true" if body_value else "false")
    if schema_type == "integer":
        if isinstance(body_value, bool) or not isinstance(body_value, (int, float)):
            return False
        try:
            parsed = float(header_value)
        except ValueError:
            return False
        return float(body_value) == parsed and abs(parsed) <= _JS_SAFE_INTEGER
    return isinstance(body_value, str) and header_value == body_value


def _deny(reason: str, code: int, version: str | None, trace: dict[str, str]) -> EnvelopeCheck:
    return EnvelopeCheck(False, reason, code, version, trace)


def validate_request_envelope(
    message: Mapping[str, Any],
    headers: Mapping[str, str] | None = None,
    *,
    tool_input_schema: Mapping[str, Any] | None = None,
    supported_versions: tuple[str, ...] = DEFAULT_SUPPORTED_PROTOCOL_VERSIONS,
) -> EnvelopeCheck:
    """Validate a JSON-RPC request envelope against MCP ``2026-07-28`` rules.

    Pass ``headers=None`` for transports without HTTP headers (stdio); only
    the body ``_meta`` is then checked. With headers, the Streamable HTTP
    server-validation rules apply: required headers must be present, values
    must be header-safe, and every mirrored header must equal the body value
    after Base64 decoding. ``tool_input_schema`` enables ``Mcp-Param-*``
    validation for ``tools/call``.

    Legacy ``initialize``-era requests (no modern ``_meta`` and a legacy
    ``MCP-Protocol-Version`` header) are accepted when the version is listed
    in ``supported_versions``; any ``Mcp-Method``/``Mcp-Name`` headers they
    carry must still match the body so that header-based routing cannot
    diverge from what the gateway evaluates.
    """
    meta = request_meta(message)
    trace = extract_trace_context(meta)
    method = message.get("method")
    if not isinstance(method, str) or not method:
        return _deny("Request has no JSON-RPC method", ERROR_HEADER_MISMATCH, None, trace)

    body_version = meta.get(META_PROTOCOL_VERSION)
    if body_version is not None and not isinstance(body_version, str):
        return _deny("_meta protocolVersion is not a string", ERROR_HEADER_MISMATCH, None, trace)

    lowered = _lower_headers(headers) if headers is not None else None
    header_version = lowered.get(HEADER_PROTOCOL_VERSION.lower()) if lowered is not None else None

    if lowered is not None:
        for name, value in lowered.items():
            if name.startswith("mcp-") and not _SAFE_HEADER_VALUE.match(value):
                return _deny(f"Header {name} contains invalid characters", ERROR_HEADER_MISMATCH, body_version, trace)
        if header_version is None:
            return _deny("Missing MCP-Protocol-Version header", ERROR_HEADER_MISMATCH, body_version, trace)

    version = body_version or header_version
    if version is None:
        return _deny("Request does not declare an MCP protocol version", ERROR_UNSUPPORTED_PROTOCOL_VERSION, None, trace)
    if version not in supported_versions:
        return _deny(
            f"Unsupported MCP protocol version {version!r}; supported: {list(supported_versions)}",
            ERROR_UNSUPPORTED_PROTOCOL_VERSION,
            version,
            trace,
        )

    modern = body_version is not None
    if modern and not isinstance(meta.get(META_CLIENT_CAPABILITIES), Mapping):
        return _deny("_meta is missing clientCapabilities", ERROR_HEADER_MISMATCH, version, trace)
    if modern and not isinstance(meta.get(META_CLIENT_INFO), Mapping):
        return _deny("_meta is missing clientInfo", ERROR_HEADER_MISMATCH, version, trace)

    if lowered is None:
        return EnvelopeCheck(True, "Envelope valid", None, version, trace)

    if modern and header_version != body_version:
        return _deny(
            f"MCP-Protocol-Version header {header_version!r} does not match body {body_version!r}",
            ERROR_HEADER_MISMATCH,
            version,
            trace,
        )

    header_method = lowered.get(HEADER_METHOD.lower())
    if header_method is None and modern:
        return _deny("Missing Mcp-Method header", ERROR_HEADER_MISMATCH, version, trace)
    if header_method is not None and header_method != method:
        return _deny(
            f"Mcp-Method header {header_method!r} does not match body {method!r}",
            ERROR_HEADER_MISMATCH,
            version,
            trace,
        )

    params = message.get("params") if isinstance(message.get("params"), Mapping) else {}
    source = NAME_SOURCE_BY_METHOD.get(method)
    raw_name = lowered.get(HEADER_NAME.lower())
    if source is not None:
        body_name = params.get(source)
        if raw_name is None and modern:
            return _deny("Missing Mcp-Name header", ERROR_HEADER_MISMATCH, version, trace)
        if raw_name is not None:
            try:
                header_name = decode_header_value(raw_name)
            except ValueError as exc:
                return _deny(f"Mcp-Name header is malformed: {exc}", ERROR_HEADER_MISMATCH, version, trace)
            if header_name != body_name:
                return _deny("Mcp-Name header does not match the request body", ERROR_HEADER_MISMATCH, version, trace)
    elif raw_name is not None:
        return _deny(f"Mcp-Name header is not defined for {method}", ERROR_HEADER_MISMATCH, version, trace)

    if method == "tools/call" and tool_input_schema is not None:
        try:
            bindings = x_mcp_header_bindings(tool_input_schema)
        except ValueError as exc:
            return _deny(f"Tool inputSchema is invalid: {exc}", ERROR_HEADER_MISMATCH, version, trace)
        arguments = params.get("arguments") if isinstance(params.get("arguments"), Mapping) else {}
        for binding in bindings:
            header_key = f"{HEADER_PARAM_PREFIX}{binding.header}".lower()
            raw = lowered.get(header_key)
            body_value = _value_at(arguments, binding.path)
            if body_value is None:
                if raw is not None:
                    return _deny(
                        f"{HEADER_PARAM_PREFIX}{binding.header} header is set but the argument is absent",
                        ERROR_HEADER_MISMATCH,
                        version,
                        trace,
                    )
                continue
            if raw is None:
                return _deny(
                    f"Missing {HEADER_PARAM_PREFIX}{binding.header} header for a supplied argument",
                    ERROR_HEADER_MISMATCH,
                    version,
                    trace,
                )
            try:
                decoded = decode_header_value(raw)
            except ValueError as exc:
                return _deny(
                    f"{HEADER_PARAM_PREFIX}{binding.header} header is malformed: {exc}",
                    ERROR_HEADER_MISMATCH,
                    version,
                    trace,
                )
            if not _header_matches(decoded, body_value, binding.schema_type):
                return _deny(
                    f"{HEADER_PARAM_PREFIX}{binding.header} header does not match the request body",
                    ERROR_HEADER_MISMATCH,
                    version,
                    trace,
                )

    return EnvelopeCheck(True, "Envelope valid", None, version, trace)


def is_input_required(result: Any) -> bool:
    """Return True when a JSON-RPC result is an MRTR ``input_required`` result."""
    return isinstance(result, Mapping) and result.get("resultType") == "input_required"


def iter_input_requests(result: Mapping[str, Any]) -> Iterator[InputRequest]:
    """Yield validated input requests from an ``input_required`` result.

    Raises:
        ValueError: If the result is malformed or carries an unknown method.
    """
    if not is_input_required(result):
        raise ValueError("result is not an input_required result")
    requests = result.get("inputRequests")
    state = result.get("requestState")
    if requests is None and state is None:
        raise ValueError("input_required result has neither inputRequests nor requestState")
    if state is not None and not isinstance(state, str):
        raise ValueError("requestState must be a string")
    if requests is None:
        return
    if not isinstance(requests, Mapping):
        raise ValueError("inputRequests must be an object")
    for key, request in requests.items():
        if not isinstance(request, Mapping):
            raise ValueError(f"inputRequests[{key!r}] is not an object")
        method = request.get("method")
        if method not in INPUT_REQUEST_METHODS:
            raise ValueError(f"inputRequests[{key!r}] uses unsupported method {method!r}")
        params = request.get("params", {})
        if not isinstance(params, Mapping):
            raise ValueError(f"inputRequests[{key!r}].params is not an object")
        yield InputRequest(str(key), str(method), params)
