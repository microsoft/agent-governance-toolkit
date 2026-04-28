# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
SLO Template Loader — load pre-built SLO configs from YAML files.

Usage:
    from agent_sre.specs import load_slo_template, list_templates

    # List available templates
    templates = list_templates()
    # ['coding-agent', 'customer-support-agent', 'data-pipeline-agent', 'research-agent']

    # Load a template
    spec = load_slo_template("coding-agent")
    print(spec["name"])  # "coding-agent"
    print(spec["indicators"])  # list of indicator configs
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml  # type: ignore
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

# specs/ directory is at the repo root, not inside the package
_SPECS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "specs"


def _parse_value(val: str) -> Any:
    """Parse a YAML scalar value."""
    if not val:
        return ""
    if val in ("true", "True"):
        return True
    if val in ("false", "False"):
        return False
    try:
        if "." in val:
            return float(val)
        return int(val)
    except ValueError:
        return val


def _parse_yaml(content: str) -> dict[str, Any]:
    """Parse YAML content. Uses PyYAML if available, otherwise basic parser."""
    if _HAS_YAML:
        return yaml.safe_load(content)  # type: ignore
    return _minimal_yaml_parse(content)


def _minimal_yaml_parse(content: str) -> dict[str, Any]:
    """
    Minimal YAML parser for SLO template format.
    Handles: top-level keys, nested dicts, list-of-dicts, multiline strings.
    """
    result: dict[str, Any] = {}
    lines = content.split("\n")
    i = 0
    current_key = ""
    current_list: list[dict[str, Any]] | None = None
    current_item: dict[str, Any] | None = None

    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip()

        if not stripped or stripped.startswith("#"):
            i += 1
            continue

        indent = len(line) - len(line.lstrip())

        if indent == 0 and ":" in stripped:
            # Flush pending list
            if current_list is not None and current_key:
                if current_item:
                    current_list.append(current_item)
                    current_item = None
                result[current_key] = current_list
                current_list = None

            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip()
            current_key = key

            if val == ">":
                text_lines = []
                i += 1
                while i < len(lines):
                    nl = lines[i]
                    if nl.strip() and not nl.startswith(" "):
                        break
                    if nl.strip():
                        text_lines.append(nl.strip())
                    i += 1
                result[key] = " ".join(text_lines)
                continue
            elif val:
                result[key] = _parse_value(val)
            i += 1
            continue

        if indent >= 2 and stripped.lstrip().startswith("- "):
            if current_list is None:
                current_list = []
            if current_item:
                current_list.append(current_item)
            item_content = stripped.lstrip()[2:].strip()
            if ":" in item_content:
                k, _, v = item_content.partition(":")
                current_item = {k.strip(): _parse_value(v.strip())}
            else:
                current_item = {"value": _parse_value(item_content)}
            i += 1
            continue

        if indent >= 4 and ":" in stripped and current_item is not None:
            k, _, v = stripped.strip().partition(":")
            current_item[k.strip()] = _parse_value(v.strip())
            i += 1
            continue

        if indent == 2 and ":" in stripped and current_list is None:
            k, _, v = stripped.strip().partition(":")
            if current_key not in result or not isinstance(result.get(current_key), dict):
                result[current_key] = {}
            result[current_key][k.strip()] = _parse_value(v.strip())
            i += 1
            continue

        i += 1

    if current_list is not None and current_key:
        if current_item:
            current_list.append(current_item)
        result[current_key] = current_list

    return result


def list_templates(specs_dir: str | None = None) -> list[str]:
    """List available SLO template names."""
    d = Path(specs_dir) if specs_dir else _SPECS_DIR
    if not d.exists():
        return []
    return sorted(p.stem for p in d.glob("*.yaml"))


def load_slo_template(
    name: str,
    specs_dir: str | None = None,
) -> dict[str, Any]:
    """
    Load an SLO template by name.

    Args:
        name: Template name (e.g. "coding-agent")
        specs_dir: Optional custom specs directory path

    Returns:
        Dict with keys: name, description, labels, indicators, error_budget
    """
    d = Path(specs_dir) if specs_dir else _SPECS_DIR
    path = d / f"{name}.yaml"
    if not path.exists():
        available = list_templates(specs_dir)
        raise FileNotFoundError(
            f"Template '{name}' not found. Available: {available}"
        )
    content = path.read_text(encoding="utf-8")
    return _parse_yaml(content)


__all__ = ["list_templates", "load_slo_template"]
