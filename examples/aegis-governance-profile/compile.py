# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# cspell:words cedarpy pyyaml startswith stdlib
"""
AEGIS governance profile compiler.

Reads an AEGIS governance profile (YAML) and emits equivalent
Cedar and Rego policies suitable for AGT's external policy backends.

The profile schema describes governance intent in domain terms
(role, allowed/denied actions, resource scopes) and the compiler
translates that into idiomatic policy text in both target languages.
The two outputs implement the same authorization semantics; tests in
``tests/test_compilation.py`` verify that they agree on a fixed input
matrix.

Run as a script::

    python compile.py --profile profile-research-agent.yaml --output-dir build/

Outputs are deterministic — the same input profile produces byte-identical
Cedar and Rego files on every run, so the example fits cleanly into a
review-and-diff workflow.

Schema (AEGIS profile v1)::

    profile:
      id: <string>            # human-readable identifier
      version: <string>       # semantic version
      description: <string>   # short prose summary

    principal:
      role: <string>          # principal role this profile applies to

    capabilities:
      allowed_actions: [<snake_case_action>, ...]
      denied_actions:  [<snake_case_action>, ...]

    resource_scopes:
      allowed_patterns: [<prefix_glob>, ...]   # e.g. "public/*"
      denied_patterns:  [<prefix_glob>, ...]

Cedar emission::

    permit(
        principal,
        action in [Action::"<PascalCase>", ...],
        resource
    ) when {
        context.principal_role == "<role>" &&
        (context.resource_path like "<prefix>/*" || ...)
    };
    forbid(principal, action in [Action::"<PascalCase>", ...], resource);
    forbid(principal, action, resource)
        when { context.resource_path like "<denied_prefix>/*" || ... };

Rego emission::

    package agentos.aegis
    default allow = false
    allowed_actions := { "<snake_case>", ... }
    denied_actions  := { "<snake_case>", ... }
    allowed_resource_patterns := [ "<prefix>/", ... ]
    denied_resource_patterns  := [ "<prefix>/", ... ]
    allow { input.principal_role == "<role>"; allowed_actions[input.tool_name]; ... }

Calling convention (caller's evaluation context)::

    {
        "agent_id":       "<string>",   # consumed by AGT's CedarBackend wrapper
        "tool_name":      "<snake>",    # mapped to Action::"<PascalCase>" by AGT
        "resource":       "<string>",   # Cedar entity id; Rego full string
        "principal_role": "<string>",   # discriminator for role gating
        "resource_path":  "<string>",   # discriminator for scope matching
    }

The emitted policies target *production* Cedar and OPA engines
(``cedarpy`` / ``cedar`` CLI; ``opa`` CLI / OPA server). They use
features — Cedar ``when`` clauses with ``like`` patterns, Rego
``startswith`` — that AGT's built-in fallback evaluators do not parse.
See README for the recommended toolchain.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

__all__ = [
    "Profile",
    "ProfileMetadata",
    "Principal",
    "Capabilities",
    "ResourceScopes",
    "load_profile",
    "compile_to_cedar",
    "compile_to_rego",
    "snake_to_pascal",
]

PROFILE_SCHEMA_VERSION = "v1"


# ── Data model ────────────────────────────────────────────────


@dataclass(frozen=True)
class ProfileMetadata:
    profile_id: str
    version: str
    description: str


@dataclass(frozen=True)
class Principal:
    role: str


@dataclass(frozen=True)
class Capabilities:
    allowed_actions: tuple[str, ...]
    denied_actions: tuple[str, ...]


@dataclass(frozen=True)
class ResourceScopes:
    allowed_patterns: tuple[str, ...]
    denied_patterns: tuple[str, ...]


@dataclass(frozen=True)
class Profile:
    metadata: ProfileMetadata
    principal: Principal
    capabilities: Capabilities
    resource_scopes: ResourceScopes


# ── Loader / validator ────────────────────────────────────────


class ProfileError(ValueError):
    """Raised when a profile fails schema or semantic validation."""


def load_profile(path: Path) -> Profile:
    """Load and validate a profile from a YAML file.

    Raises ``ProfileError`` with a path-prefixed message on any
    schema violation, missing key, wrong type, or semantic conflict.
    """
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ProfileError(f"{path}: invalid YAML: {exc}") from exc

    if not isinstance(raw, dict):
        raise ProfileError(f"{path}: top-level must be a mapping")

    return _build_profile(raw, source=str(path))


def _build_profile(raw: dict[str, Any], *, source: str) -> Profile:
    metadata = _build_metadata(_require(raw, "profile", source, dict), source)
    principal = _build_principal(_require(raw, "principal", source, dict), source)
    capabilities = _build_capabilities(
        _require(raw, "capabilities", source, dict), source
    )
    resource_scopes = _build_resource_scopes(
        _require(raw, "resource_scopes", source, dict), source
    )

    overlap = set(capabilities.allowed_actions) & set(capabilities.denied_actions)
    if overlap:
        raise ProfileError(
            f"{source}: capabilities.allowed_actions and capabilities.denied_actions "
            f"overlap: {sorted(overlap)}"
        )

    pattern_overlap = set(resource_scopes.allowed_patterns) & set(
        resource_scopes.denied_patterns
    )
    if pattern_overlap:
        raise ProfileError(
            f"{source}: resource_scopes.allowed_patterns and "
            f"resource_scopes.denied_patterns overlap: {sorted(pattern_overlap)}"
        )

    return Profile(
        metadata=metadata,
        principal=principal,
        capabilities=capabilities,
        resource_scopes=resource_scopes,
    )


def _build_metadata(raw: dict[str, Any], source: str) -> ProfileMetadata:
    return ProfileMetadata(
        profile_id=_require_str(raw, "id", f"{source}:profile"),
        version=_require_str(raw, "version", f"{source}:profile"),
        description=_require_str(raw, "description", f"{source}:profile"),
    )


def _build_principal(raw: dict[str, Any], source: str) -> Principal:
    role = _require_str(raw, "role", f"{source}:principal")
    if not _is_snake_case(role):
        raise ProfileError(f"{source}:principal.role must be snake_case, got {role!r}")
    return Principal(role=role)


def _build_capabilities(raw: dict[str, Any], source: str) -> Capabilities:
    allowed = _require_action_list(raw, "allowed_actions", f"{source}:capabilities")
    denied = _require_action_list(raw, "denied_actions", f"{source}:capabilities")
    return Capabilities(allowed_actions=allowed, denied_actions=denied)


def _build_resource_scopes(raw: dict[str, Any], source: str) -> ResourceScopes:
    allowed = _require_pattern_list(
        raw, "allowed_patterns", f"{source}:resource_scopes"
    )
    denied = _require_pattern_list(raw, "denied_patterns", f"{source}:resource_scopes")
    return ResourceScopes(allowed_patterns=allowed, denied_patterns=denied)


# ── Validators ────────────────────────────────────────────────


def _require(raw: dict[str, Any], key: str, source: str, expected_type: type) -> Any:
    if key not in raw:
        raise ProfileError(f"{source}: missing required key {key!r}")
    value = raw[key]
    if not isinstance(value, expected_type):
        raise ProfileError(
            f"{source}: {key!r} must be {expected_type.__name__}, "
            f"got {type(value).__name__}"
        )
    return value


def _require_str(raw: dict[str, Any], key: str, source: str) -> str:
    value = _require(raw, key, source, str)
    if not value.strip():
        raise ProfileError(f"{source}: {key!r} must be non-empty")
    return str(value)


def _require_action_list(raw: dict[str, Any], key: str, source: str) -> tuple[str, ...]:
    items = _require(raw, key, source, list)
    if not items:
        raise ProfileError(f"{source}: {key!r} must be non-empty")
    out: list[str] = []
    for index, item in enumerate(items):
        if not isinstance(item, str):
            raise ProfileError(
                f"{source}: {key}[{index}] must be a string, got {type(item).__name__}"
            )
        if not _is_snake_case(item):
            raise ProfileError(
                f"{source}: {key}[{index}] must be snake_case, got {item!r}"
            )
        if item in out:
            raise ProfileError(f"{source}: {key} contains duplicate {item!r}")
        out.append(item)
    return tuple(out)


def _require_pattern_list(
    raw: dict[str, Any], key: str, source: str
) -> tuple[str, ...]:
    items = _require(raw, key, source, list)
    if not items:
        raise ProfileError(f"{source}: {key!r} must be non-empty")
    out: list[str] = []
    for index, item in enumerate(items):
        if not isinstance(item, str):
            raise ProfileError(
                f"{source}: {key}[{index}] must be a string, got {type(item).__name__}"
            )
        if not item.endswith("/*"):
            raise ProfileError(
                f"{source}: {key}[{index}] must end with '/*' "
                f"(prefix glob), got {item!r}"
            )
        if '"' in item or "\\" in item:
            raise ProfileError(
                f"{source}: {key}[{index}] must not contain backslash "
                f"or double quote, got {item!r}"
            )
        if item in out:
            raise ProfileError(f"{source}: {key} contains duplicate {item!r}")
        out.append(item)
    return tuple(out)


def _is_snake_case(value: str) -> bool:
    if not value:
        return False
    if not value[0].isalpha():
        return False
    return (
        all(c.islower() or c.isdigit() or c == "_" for c in value) and "__" not in value
    )


# ── Cedar emission ────────────────────────────────────────────


def snake_to_pascal(snake: str) -> str:
    """Convert ``snake_case`` to ``PascalCase``.

    Matches AGT's ``_tool_to_cedar_action`` mapping
    (``file_read`` -> ``FileRead``).
    """
    return "".join(part[:1].upper() + part[1:] for part in snake.split("_") if part)


def _cedar_action_list(actions: tuple[str, ...]) -> str:
    return ",\n        ".join(f'Action::"{snake_to_pascal(a)}"' for a in actions)


def _cedar_pattern_disjunction(
    patterns: tuple[str, ...], context_field: str, indent: int
) -> str:
    sep = " ||\n" + " " * indent
    return sep.join(f'context.{context_field} like "{p}"' for p in patterns)


def compile_to_cedar(profile: Profile) -> str:
    """Compile a profile to a Cedar policy string.

    The output is deterministic and ordered to match the source profile.
    """
    header = (
        f"// AEGIS Governance Profile: {profile.metadata.profile_id} "
        f"v{profile.metadata.version}\n"
        f"// Schema: AEGIS profile {PROFILE_SCHEMA_VERSION}\n"
        f"// {profile.metadata.description.strip()}\n"
        "//\n"
        "// Generated by aegis-governance-profile/compile.py — "
        "DO NOT EDIT BY HAND.\n"
        "// Re-run the compiler against the source YAML to regenerate.\n"
    )

    permit_block = (
        "// Permit allowed actions when principal role and resource scope match.\n"
        "permit(\n"
        "    principal,\n"
        "    action in [\n"
        f"        {_cedar_action_list(profile.capabilities.allowed_actions)}\n"
        "    ],\n"
        "    resource\n"
        ")\n"
        "when {\n"
        f'    context.principal_role == "{profile.principal.role}" &&\n'
        "    (\n"
        f"        {_cedar_pattern_disjunction(profile.resource_scopes.allowed_patterns, 'resource_path', 8)}\n"
        "    )\n"
        "};\n"
    )

    forbid_actions_block = (
        "// Forbid denied actions outright (forbid overrides permit).\n"
        "forbid(\n"
        "    principal,\n"
        "    action in [\n"
        f"        {_cedar_action_list(profile.capabilities.denied_actions)}\n"
        "    ],\n"
        "    resource\n"
        ");\n"
    )

    forbid_scopes_block = (
        "// Forbid any action on denied resource paths.\n"
        "forbid(\n"
        "    principal,\n"
        "    action,\n"
        "    resource\n"
        ")\n"
        "when {\n"
        f"    {_cedar_pattern_disjunction(profile.resource_scopes.denied_patterns, 'resource_path', 4)}\n"
        "};\n"
    )

    return "\n".join([header, permit_block, forbid_actions_block, forbid_scopes_block])


# ── Rego emission ─────────────────────────────────────────────


def _rego_set_literal(values: tuple[str, ...]) -> str:
    body = ",\n    ".join(f'"{v}"' for v in values)
    return "{\n    " + body + ",\n}"


def _rego_array_literal(values: tuple[str, ...]) -> str:
    body = ",\n    ".join(f'"{v}"' for v in values)
    return "[\n    " + body + ",\n]"


def _scope_prefix(pattern: str) -> str:
    # "public/*" -> "public/"
    return pattern[:-1]


def compile_to_rego(profile: Profile) -> str:
    """Compile a profile to a Rego policy string.

    Output is deterministic and ordered to match the source profile.
    """
    allowed_prefixes = tuple(
        _scope_prefix(p) for p in profile.resource_scopes.allowed_patterns
    )
    denied_prefixes = tuple(
        _scope_prefix(p) for p in profile.resource_scopes.denied_patterns
    )

    return (
        f"# AEGIS Governance Profile: {profile.metadata.profile_id} "
        f"v{profile.metadata.version}\n"
        f"# Schema: AEGIS profile {PROFILE_SCHEMA_VERSION}\n"
        f"# {profile.metadata.description.strip()}\n"
        "#\n"
        "# Generated by aegis-governance-profile/compile.py — "
        "DO NOT EDIT BY HAND.\n"
        "# Re-run the compiler against the source YAML to regenerate.\n"
        "\n"
        "package agentos.aegis\n"
        "\n"
        "import rego.v1\n"
        "\n"
        "default allow := false\n"
        "\n"
        f"allowed_actions := {_rego_set_literal(profile.capabilities.allowed_actions)}\n"
        "\n"
        f"denied_actions := {_rego_set_literal(profile.capabilities.denied_actions)}\n"
        "\n"
        f"allowed_resource_patterns := {_rego_array_literal(allowed_prefixes)}\n"
        "\n"
        f"denied_resource_patterns := {_rego_array_literal(denied_prefixes)}\n"
        "\n"
        "allow if {\n"
        f'    input.principal_role == "{profile.principal.role}"\n'
        "    allowed_actions[input.tool_name]\n"
        "    in_allowed_scope\n"
        "    not in_denied_action\n"
        "    not in_denied_scope\n"
        "}\n"
        "\n"
        "in_allowed_scope if {\n"
        "    some prefix in allowed_resource_patterns\n"
        "    startswith(input.resource_path, prefix)\n"
        "}\n"
        "\n"
        "in_denied_scope if {\n"
        "    some prefix in denied_resource_patterns\n"
        "    startswith(input.resource_path, prefix)\n"
        "}\n"
        "\n"
        "in_denied_action if {\n"
        "    denied_actions[input.tool_name]\n"
        "}\n"
    )


# ── CLI ───────────────────────────────────────────────────────


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Compile an AEGIS governance profile to Cedar and Rego.",
    )
    parser.add_argument(
        "--profile",
        type=Path,
        required=True,
        help="Path to the AEGIS governance profile YAML file.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("build"),
        help="Directory to write generated Cedar and Rego files (default: build/).",
    )
    parser.add_argument(
        "--cedar-name",
        type=str,
        default=None,
        help=("Filename for the generated Cedar policy (default: <profile-id>.cedar)."),
    )
    parser.add_argument(
        "--rego-name",
        type=str,
        default=None,
        help=("Filename for the generated Rego policy (default: <profile-id>.rego)."),
    )
    return parser.parse_args(argv)


def _default_output_name(profile: Profile, suffix: str) -> str:
    return f"{profile.metadata.profile_id}{suffix}"


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(list(sys.argv[1:] if argv is None else argv))

    try:
        profile = load_profile(args.profile)
    except ProfileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    cedar_text = compile_to_cedar(profile)
    rego_text = compile_to_rego(profile)

    args.output_dir.mkdir(parents=True, exist_ok=True)

    cedar_name = args.cedar_name or _default_output_name(profile, ".cedar")
    rego_name = args.rego_name or _default_output_name(profile, ".rego")
    cedar_path = args.output_dir / cedar_name
    rego_path = args.output_dir / rego_name

    cedar_path.write_text(cedar_text, encoding="utf-8")
    rego_path.write_text(rego_text, encoding="utf-8")

    print(
        f"[compile] {args.profile} -> {cedar_path} ({cedar_text.count(chr(10))} lines)"
    )
    print(f"[compile] {args.profile} -> {rego_path} ({rego_text.count(chr(10))} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
