# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Output formatters for CLI commands."""

from __future__ import annotations

import json
from typing import Any


def format_output(data: Any, fmt: str) -> str:
    """Format data as table, json, or yaml."""
    if fmt == "json":
        return json.dumps(data, indent=2, default=str)
    if fmt == "yaml":
        return _to_yaml(data)
    # Default: table
    if isinstance(data, list):
        return _format_table(data)
    if isinstance(data, dict):
        return _format_dict(data)
    return str(data)


def _format_table(rows: list[dict[str, Any]]) -> str:
    """Render a list of dicts as an aligned text table."""
    if not rows:
        return "No results."
    keys = list(rows[0].keys())
    widths = {k: max(len(k), *(len(str(r.get(k, ""))) for r in rows)) for k in keys}
    header = "  ".join(k.upper().ljust(widths[k]) for k in keys)
    sep = "  ".join("-" * widths[k] for k in keys)
    lines = [header, sep]
    for row in rows:
        lines.append("  ".join(str(row.get(k, "")).ljust(widths[k]) for k in keys))
    return "\n".join(lines)


def _format_dict(d: dict[str, Any]) -> str:
    """Render a dict as key-value pairs."""
    if not d:
        return "No data."
    width = max(len(str(k)) for k in d)
    lines = []
    for k, v in d.items():
        if isinstance(v, list):
            lines.append(f"{str(k).ljust(width)}: ({len(v)} items)")
            for item in v:
                if isinstance(item, dict):
                    parts = ", ".join(f"{ik}={iv}" for ik, iv in item.items())
                    lines.append(f"  - {parts}")
                else:
                    lines.append(f"  - {item}")
        else:
            lines.append(f"{str(k).ljust(width)}: {v}")
    return "\n".join(lines)


def _to_yaml(data: Any, indent: int = 0) -> str:
    """Minimal YAML serializer (no external dependency)."""
    prefix = "  " * indent
    if isinstance(data, dict):
        if not data:
            return f"{prefix}{{}}"
        lines = []
        for k, v in data.items():
            if isinstance(v, (dict, list)):
                lines.append(f"{prefix}{k}:")
                lines.append(_to_yaml(v, indent + 1))
            else:
                lines.append(f"{prefix}{k}: {_yaml_scalar(v)}")
        return "\n".join(lines)
    if isinstance(data, list):
        if not data:
            return f"{prefix}[]"
        lines = []
        for item in data:
            if isinstance(item, dict):
                first = True
                for k, v in item.items():
                    tag = "- " if first else "  "
                    first = False
                    if isinstance(v, (dict, list)):
                        lines.append(f"{prefix}{tag}{k}:")
                        lines.append(_to_yaml(v, indent + 2))
                    else:
                        lines.append(f"{prefix}{tag}{k}: {_yaml_scalar(v)}")
            else:
                lines.append(f"{prefix}- {_yaml_scalar(item)}")
        return "\n".join(lines)
    return f"{prefix}{_yaml_scalar(data)}"


def _yaml_scalar(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)
