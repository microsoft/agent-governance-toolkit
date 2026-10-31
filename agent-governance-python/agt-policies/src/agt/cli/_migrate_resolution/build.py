# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""End-to-end resolve_manifest, per AGT-RESOLUTION §2.

Glues discovery + scope filter + merge + Rego-bundle translation, and
returns a flat ACS manifest dict ready to pass to the engine.

The translation to Rego is intentionally minimal in this milestone:
the merged rule list is turned into a single Rego rule that scans for
the first matching rule (priority-sorted) and emits a verdict. M5
expands the translation to cover the full spec of AGT v4 conditions.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import sys
import tempfile
from pathlib import Path
from typing import Any

import yaml

from .._migrate_re2 import validate_re2
from .discover import discover_policies
from .errors import ResolutionError
from .merge import merge_documents, merge_top_level_section
from .scope import filter_by_scope

logger = logging.getLogger(__name__)

ACS_VERSION = "0.4.0-alpha.1"


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise ResolutionError.invalid_governance(
            f"failed to parse {path}: {exc}"
        ) from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise ResolutionError.invalid_governance(
            f"failed to read governance file {path} ({type(exc).__name__})"
        ) from exc
    except ValueError as exc:
        # PyYAML builds a decimal integer scalar with int(), which raises
        # ValueError (not a YAMLError) once the scalar has more digits than
        # sys.get_int_max_str_digits() allows.
        raise ResolutionError.invalid_governance(
            f"failed to parse {path}: {exc}"
        ) from exc
    except RecursionError as exc:
        # PyYAML composes nodes recursively, so a document nested a few
        # hundred levels deep overflows the interpreter stack before the
        # depth check below can see it.
        raise ResolutionError.invalid_governance(
            f"failed to parse {path}: the document is nested too deeply"
        ) from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ResolutionError.invalid_governance(
            f"governance file {path} must be a mapping at top level"
        )
    _check_document_values(path, data)
    return data


def _int_too_long(value: int) -> bool:
    """True when ``str(value)`` and ``json.dumps(value)`` raise ``ValueError``.

    CPython caps int-to-decimal conversion at ``sys.get_int_max_str_digits()``
    digits (4300 by default, 0 disables the cap). Parsing is not capped the
    same way: a hex scalar such as ``0x`` followed by 4,000 digits loads fine
    and only fails when it is written back as text.
    """
    limit = sys.get_int_max_str_digits()
    # Every decimal digit needs more than three bits, so an int of at most
    # 3 * limit bits has fewer than limit digits and needs no conversion.
    if not limit or value.bit_length() <= limit * 3:
        return False
    try:
        str(value)
    except ValueError:
        return True
    return False


# Governance documents are shallow: rules[i].condition.value[j] is four levels
# down. The cap keeps every later recursive step (_is_json_value, json.dumps,
# yaml.safe_dump) far from the interpreter's recursion limit.
_MAX_NESTING_DEPTH = 64


def _check_document_values(path: Path, document: dict[str, Any]) -> None:
    """Refuse a parsed governance document the migrator cannot write back.

    Runs once per file, before merge, validation and rendering, so every
    later step (rule labels built with ``str(name)``, ``json.dumps`` in the
    Rego renderer, ``yaml.safe_dump`` of the manifest) only sees values it
    can serialize. The walk is iterative so it cannot itself overflow the
    stack.

    Raises:
        ResolutionError: ``INVALID_GOVERNANCE`` for an int (value or mapping
            key) with more digits than ``sys.get_int_max_str_digits()``
            allows anywhere in the document; for a value that contains
            itself through a YAML anchor/alias cycle (``&v [*v]``), which
            every recursive step would turn into ``RecursionError``; and for
            nesting deeper than ``_MAX_NESTING_DEPTH`` levels, for the same
            reason. The message names the rule when the value sits under
            ``rules``.
    """
    limit = sys.get_int_max_str_digits()
    # Entries: (value, location, rule name or None, depth). A container is
    # pushed a second time with depth -1 as its exit marker, so ``ancestors``
    # holds exactly the containers on the current path: an alias that points
    # back to one of them is a cycle, while a shared acyclic alias is not.
    stack: list[tuple[Any, str, str | None, int]] = [(document, "document", None, 0)]
    ancestors: set[int] = set()
    # One anchored container can be aliased from many parents, and those
    # parents aliased again (ten aliases of ten aliases of ...), so walking
    # every path separately is exponential in the number of alias levels.
    # Remember the depth each container was walked at and skip it on a later
    # visit unless that visit is deeper, where the nesting cap could still
    # trip. Each (container, depth) pair is then walked at most once.
    walked_at_depth: dict[int, int] = {}
    while stack:
        value, where, rule_name, depth = stack.pop()
        if depth < 0:
            ancestors.discard(id(value))
            continue
        label = f"rule {rule_name!r} ({where})" if rule_name is not None else where
        if isinstance(value, bool) or value is None or isinstance(value, (str, float)):
            continue
        if isinstance(value, int):
            if _int_too_long(value):
                raise ResolutionError.invalid_governance(
                    f"{label} in {path} is an integer with more than {limit} "
                    "digits, which cannot be written to the manifest or Rego "
                    "bundle; use a shorter number"
                )
            continue
        if not isinstance(value, (list, dict)):
            continue
        if id(value) in ancestors:
            raise ResolutionError.invalid_governance(
                f"{label} in {path} is a YAML alias that points back to a value "
                "containing it (an anchor/alias cycle); a cyclic value cannot "
                "be written to the manifest or Rego bundle"
            )
        if depth >= _MAX_NESTING_DEPTH:
            raise ResolutionError.invalid_governance(
                f"{label} in {path} is nested more than {_MAX_NESTING_DEPTH} "
                "levels deep; flatten the document before migrating"
            )
        if walked_at_depth.get(id(value), -1) >= depth:
            continue
        walked_at_depth[id(value)] = depth
        ancestors.add(id(value))
        stack.append((value, where, rule_name, -1))
        if isinstance(value, list):
            for index, item in enumerate(value):
                name = rule_name
                if where == "rules" and isinstance(item, dict) and isinstance(item.get("name"), str):
                    name = item["name"]
                stack.append((item, f"{where}[{index}]", name, depth + 1))
            continue
        for key, item in value.items():
            if isinstance(key, int) and not isinstance(key, bool) and _int_too_long(key):
                raise ResolutionError.invalid_governance(
                    f"{label} in {path} has a mapping key that is an integer "
                    f"with more than {limit} digits, which cannot be written "
                    "to the manifest; use a shorter key"
                )
            key_text = key if isinstance(key, str) else f"<{type(key).__name__} key>"
            child = key_text if where == "document" else f"{where}.{key_text}"
            stack.append((item, child, rule_name, depth + 1))


def _apply_inheritance(documents: list[tuple[Path, dict[str, Any]]]) -> list[tuple[Path, dict[str, Any]]]:
    """Trim the chain at the first ``inherit: false`` document, per §2.2.

    Walks from most-specific (last) toward root.
    """
    for i in range(len(documents) - 1, -1, -1):
        if documents[i][1].get("inherit") is False:
            return documents[i:]
    return documents


def resolve_manifest(
    root: Path,
    action_path: Path,
    *,
    bundle_dir: Path | None = None,
) -> dict[str, Any]:
    """Resolve a governance chain into a flat ACS manifest.

    Args:
        root: Workspace root that bounds discovery.
        action_path: Path the agent action originates from.
        bundle_dir: Where to materialize the generated Rego bundle.
            Defaults to a unique temporary directory outside ``root``.

    Returns:
        A dict-shaped ACS manifest with ``extends: []`` and a
        ``policies.agt_legacy_rules`` entry pointing at the generated
        Rego bundle.

    Raises:
        ResolutionError: When discovery, parsing, or merging fails.
    """
    chain_paths = discover_policies(action_path, root)

    if not chain_paths:
        raise ResolutionError.invalid_governance(
            f"no governance.yaml found from {action_path} up to {root}; "
            "AGT v5 requires at least one governance file in the chain"
        )

    raw_docs: list[tuple[Path, dict[str, Any]]] = [
        (p, _load_yaml(p)) for p in chain_paths
    ]

    raw_docs = _apply_inheritance(raw_docs)

    scoped_docs: list[tuple[Path, dict[str, Any]]] = []
    for path, doc in raw_docs:
        scope_pattern = doc.get("scope")
        if filter_by_scope(path, scope_pattern, action_path, root):
            scoped_docs.append((path, doc))

    docs_only = [doc for _, doc in scoped_docs]

    merged_rules = merge_documents(docs_only)

    # Validate before materializing anything. Every guard below rejects the
    # chain, and creating the bundle first would leave an orphaned temp
    # directory behind on every rejected migration.
    _validate_rules(merged_rules)
    intervention_points = _collect_intervention_points(docs_only)
    if merged_rules and not _binds_legacy_rules(intervention_points):
        raise ResolutionError.invalid_governance(
            "governance rules must bind policy id 'agt_legacy_rules' at one or more intervention points"
        )
    # The engine rejects a manifest with no intervention points
    # ("at least one intervention point config is required"), so refuse here
    # rather than reporting a successful migration and writing a manifest that
    # cannot be loaded. A chain that binds nothing also governs nothing.
    if not intervention_points:
        raise ResolutionError.invalid_governance(
            "no intervention points were declared across the governance chain; "
            "add an 'intervention_points' block binding policy id "
            "'agt_legacy_rules' to at least one point (for example 'input') "
            "before migrating"
        )

    bundle_path = bundle_dir or Path(tempfile.mkdtemp(prefix="agt_resolved_bundle_"))
    rego_path = _materialize_rego_bundle(bundle_path, merged_rules)

    manifest: dict[str, Any] = {
        "agent_control_specification_version": ACS_VERSION,
        "metadata": {
            "name": "agt_resolved",
            "resolved_from": {
                "root": str(root),
                "action_path": str(action_path),
                "chain": [str(p) for p in chain_paths],
            },
        },
        "extends": [],
        "policies": {
            "agt_legacy_rules": {
                "type": "rego",
                "bundle": str(rego_path),
                "query": "data.agt.legacy.verdict",
            },
        },
        "intervention_points": intervention_points,
    }

    for section in ("tools", "annotators", "limits", "approval"):
        value = merge_top_level_section(section, docs_only)
        if value is not None:
            manifest[section] = value

    return manifest


_SUPPORTED_OPERATORS = frozenset(
    {
        "eq",
        "ne",
        "gt",
        "gte",
        "lt",
        "lte",
        "in",
        "not_in",
        "exists",
        "contains",
        "startswith",
        "endswith",
        "matches",
        "regex",
    }
)
_LIST_OPERATORS = frozenset({"in", "not_in"})
_STRING_OPERATORS = frozenset({"contains", "startswith", "endswith", "matches", "regex"})
_REGEX_OPERATORS = frozenset({"matches", "regex"})
_COMPOUND_KEYS = ("and", "or", "not")


def _is_json_value(value: Any) -> bool:
    """True when ``json.dumps`` writes *value* exactly, with no coercion.

    YAML yields Python types JSON has no spelling for (``date``,
    ``datetime``, ``bytes`` from ``!!binary``, ``set``), ``.nan``/``.inf``
    floats that JSON writes as literals Rego does not parse, and integers past
    the interpreter's digit cap that ``json.dumps`` refuses to convert.
    """
    if value is None or isinstance(value, (str, bool)):
        return True
    if isinstance(value, int):
        # json.dumps raises ValueError, not TypeError, past the digit cap.
        return not _int_too_long(value)
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        return all(_is_json_value(item) for item in value)
    if isinstance(value, dict):
        return all(
            isinstance(key, str) and _is_json_value(item) for key, item in value.items()
        )
    return False


def _validate_rules(rules: list[dict[str, Any]]) -> None:
    """Refuse any merged rule the Rego renderer cannot translate exactly.

    ``_render_rego`` keeps an always-matching fail-closed deny as its last
    line of defence, but reaching it turns every lower-priority rule into
    dead code with only a log warning. A migration tool must refuse such a
    chain instead, naming the rule and the construct.

    Raises:
        ResolutionError: ``INVALID_GOVERNANCE`` for a missing or non-mapping
            condition, a compound ``and``/``or``/``not`` condition (the
            renderer emits one scalar predicate per rule), an invalid field
            path, an operator outside the supported set, a value of the
            wrong shape for the operator, a regex that is not valid Go RE2
            (or cannot be validated), or a value JSON cannot write exactly.
    """
    for rule in rules:
        label = f"rule {str(rule.get('name'))!r}"
        condition = rule.get("condition")
        if not isinstance(condition, dict) or not condition:
            raise ResolutionError.invalid_governance(
                f"{label} has no condition mapping; every migrated rule needs "
                "a condition with field, operator and value"
            )
        for key in _COMPOUND_KEYS:
            if key in condition:
                raise ResolutionError.invalid_governance(
                    f"{label} uses a compound {key!r} condition, which the "
                    "generated Rego does not express; split it into separate "
                    "rules before migrating"
                )
        field = condition.get("field")
        if not isinstance(field, str) or not field or _rego_field_accessor(field) is None:
            raise ResolutionError.invalid_governance(
                f"{label} has an invalid field path; use a non-empty "
                "dot-separated path of identifiers"
            )
        operator = condition.get("operator")
        if not isinstance(operator, str) or operator.lower() not in _SUPPORTED_OPERATORS:
            shown = repr(operator) if isinstance(operator, str) else type(operator).__name__
            raise ResolutionError.invalid_governance(
                f"{label} uses an unsupported operator ({shown})"
            )
        operator = operator.lower()
        value = condition.get("value")
        if operator in _LIST_OPERATORS and not isinstance(value, list):
            raise ResolutionError.invalid_governance(
                f"{label}: operator {operator!r} requires a list value, "
                f"got {type(value).__name__}"
            )
        if operator in _STRING_OPERATORS and not isinstance(value, str):
            raise ResolutionError.invalid_governance(
                f"{label}: operator {operator!r} requires a string value, "
                f"got {type(value).__name__}"
            )
        if operator in _REGEX_OPERATORS:
            try:
                validate_re2(value, require_opa=True)
            except ValueError as exc:
                raise ResolutionError.invalid_governance(
                    f"{label} has a regex pattern that was rejected or could "
                    f"not be validated against Go RE2: {exc}"
                ) from exc
        if not _is_json_value(value):
            raise ResolutionError.invalid_governance(
                f"{label} has a condition value of type {type(value).__name__} "
                "that cannot be written to Rego exactly; use strings, finite "
                "numbers, booleans, null, or lists of those"
            )


def _binds_legacy_rules(intervention_points: dict[str, Any]) -> bool:
    for config in intervention_points.values():
        if not isinstance(config, dict):
            continue
        policy = config.get("policy")
        if isinstance(policy, dict) and policy.get("id") == "agt_legacy_rules":
            return True
    return False


def _collect_intervention_points(documents: list[dict[str, Any]]) -> dict[str, Any]:
    """Last-writer-wins union of intervention_points across documents.

    AGT-RESOLUTION does not introduce custom merge logic for
    intervention point bindings; the most-specific document wins.
    Annotations within a binding ARE unioned per upstream ACS §2.2.
    """
    merged: dict[str, Any] = {}
    for doc in documents:
        for ip, config in (doc.get("intervention_points") or {}).items():
            if ip in merged and isinstance(merged[ip], dict) and isinstance(config, dict):
                base = dict(merged[ip])
                base_annotations = dict(base.get("annotations") or {})
                base_annotations.update(config.get("annotations") or {})
                base.update(config)
                if base_annotations:
                    base["annotations"] = base_annotations
                merged[ip] = base
            else:
                merged[ip] = config
    return merged


def _materialize_rego_bundle(bundle_root: Path, rules: list[dict[str, Any]]) -> Path:
    """Write a generated Rego file to disk and return the bundle path.

    The generated rule package is ``agt.legacy`` and exposes a single
    ``verdict`` rule that scans the priority-sorted rules in order and
    returns the first matching verdict shape. Per AGT-RESOLUTION §2.5
    the AGT host points the engine at this bundle, not at inline rego.
    """
    # Hash the exact bytes written, including on Windows where write_text
    # would otherwise translate line endings after the digest was computed.
    try:
        body = _render_rego(rules).encode("utf-8")
    except (TypeError, ValueError) as exc:
        # _validate_rules and _check_document_values refuse these earlier;
        # this keeps a render-time failure from escaping as a traceback and
        # runs before any directory is created, so nothing is left behind.
        raise ResolutionError.invalid_governance(
            f"generated Rego could not be rendered ({type(exc).__name__}); "
            "a rule carries a value that cannot be written as text"
        ) from exc
    digest = hashlib.sha256(body).hexdigest().encode("ascii")
    try:
        bundle_root = bundle_root.resolve()
        policy_dir = bundle_root / "policy"
        if policy_dir.exists() or policy_dir.is_symlink():
            raise ResolutionError.invalid_governance(
                "migration policy output already exists; refusing to overwrite"
            )
        bundle_root.mkdir(parents=True, exist_ok=True)
        # Publish both files with one same-filesystem directory rename. The
        # private staging directory is cleaned if either write or rename fails.
        with tempfile.TemporaryDirectory(prefix=".agt-policy-", dir=bundle_root) as staging:
            staged_policy = Path(staging) / "policy"
            staged_policy.mkdir()
            (staged_policy / "agt_legacy.rego").write_bytes(body)
            (staged_policy / "agt_legacy.rego.sha256").write_bytes(digest)
            staged_policy.rename(policy_dir)
        return policy_dir
    except OSError as exc:
        raise ResolutionError.invalid_governance(
            f"could not publish generated policy bundle at {bundle_root / 'policy'} "
            f"({type(exc).__name__})"
        ) from exc


def _render_rego(rules: list[dict[str, Any]]) -> str:
    """Render a Rego module emitting an AGT verdict from rule conditions.

    Each rule becomes one ``verdict`` branch keyed on its index. Field
    paths are inlined per-rule to avoid Rego recursion limits.
    """
    header = (
        "# Copyright (c) Microsoft Corporation.\n"
        "# Licensed under the MIT License.\n"
        "# AUTO-GENERATED by agt.cli._migrate_resolution.build._render_rego\n"
        "# Source rules are merged from the host-side governance chain.\n"
        "package agt.legacy\n"
        "import rego.v1\n\n"
        "default verdict := {\"decision\": \"allow\"}\n\n"
    )

    branches: list[str] = []
    matchers: list[str] = []
    unsupported_drops: list[str] = []

    for idx, rule in enumerate(rules):
        cond = rule.get("condition") or {}
        field = str(cond.get("field", ""))
        operator = str(cond.get("operator", "")).lower()
        value = cond.get("value")
        name = str(rule.get("name", f"rule_{idx}"))
        action = str(rule.get("action", "allow")).lower()
        message = str(rule.get("message", ""))

        accessor = _rego_field_accessor(field)
        op_clause = _rego_op_clause(operator, accessor, value, action=action) if accessor is not None else None
        if op_clause is None:
            # Unsupported operators or invalid field paths MUST fail
            # closed. Render an always-matching deny rule so evaluation
            # never silently falls through to default-allow. The merge
            # layer should ideally catch this at validation, but this is
            # the last line of defense.
            if accessor is None:
                invalid_detail = f"invalid field {field!r}"
            elif operator in {"matches", "regex"}:
                # The operator is supported; the clause was dropped because
                # the pattern was rejected or no authoritative RE2 validator
                # was present (validate_re2(require_opa=True)).
                invalid_detail = (
                    f"a regex pattern for operator {operator!r} that was "
                    f"rejected or could not be validated "
                    f"(ensure Go RE2 compatibility and install OPA or google-re2)"
                )
            elif operator in _SUPPORTED_OPERATORS:
                invalid_detail = (
                    f"a value that cannot be translated for operator {operator!r}"
                )
            else:
                invalid_detail = f"unsupported operator {operator!r}"
            unsupported_drops.append(name)
            matchers.append(
                f"_match_{idx} if {{\n"
                f"    true\n"
                f"}}"
            )
            branches.append(
                f"verdict := {{\"decision\": \"deny\", "
                f"\"reason\": \"runtime_error:manifest_invalid\", "
                f"\"message\": {json.dumps(f'rule {name!r} has {invalid_detail}; fail-closed deny')}}} if {{\n"
                f"    _match_{idx}\n"
                f"    _snapshot_valid\n"
                + "".join(f"    not _match_{j}\n" for j in range(idx))
                + "}"
            )
            continue

        matchers.append(
            f"_match_{idx} if {{\n"
            f"{op_clause}\n"
            f"}}"
        )
        previous_negations = "".join(
            f"    not _match_{j}\n" for j in range(idx)
        )
        verdict_dict = (
            "{"
            f"\"decision\": {json.dumps(action)}, "
            f"\"reason\": {json.dumps(name)}, "
            f"\"message\": {json.dumps(message)}"
            "}"
        )
        branches.append(
            f"verdict := {verdict_dict} if {{\n"
            f"    _match_{idx}\n"
            f"    _snapshot_valid\n"
            f"{previous_negations}"
            f"}}"
        )

    if unsupported_drops:
        import logging
        logging.getLogger(__name__).warning(
            "agt.cli._migrate_resolution: %d invalid rule(s) now fail-closed: %s",
            len(unsupported_drops),
            unsupported_drops,
        )

    # Fail-closed snapshot guard (issue #3517): when input.snapshot is absent,
    # null, or not an object, every field accessor is undefined, no _match_i
    # fires, and evaluation would fall through to the default-allow verdict, so a
    # caller that omits or mistypes the snapshot root would be allowed on a
    # deny-side policy. Snapshot validity is expressed with a defaulted helper: a
    # bare `not is_object(input.snapshot)` does not hold when the reference is
    # undefined (an inline negation over a builtin with an undefined operand is
    # itself undefined), so the absent-snapshot case would leak through to
    # default-allow. `default _snapshot_valid := false` makes the undefined case
    # explicit. Every rule branch above is gated on `_snapshot_valid` so the
    # guard is mutually exclusive with them: a rule branch (including the
    # always-matching fail-closed deny for an unsupported operator) and the guard
    # can never both hold, or OPA would raise a complete-rule conflict on
    # `verdict`.
    matchers.insert(
        0,
        "default _snapshot_valid := false\n\n"
        "_snapshot_valid if {\n    is_object(input.snapshot)\n}",
    )
    branches.insert(
        0,
        "verdict := {\"decision\": \"deny\", "
        "\"reason\": \"runtime_error:snapshot_invalid\", "
        "\"message\": \"input.snapshot is absent, null, or not an object; "
        "fail-closed deny\"} if {\n"
        "    not _snapshot_valid\n"
        "}",
    )

    return header + "\n\n".join(matchers) + ("\n\n" if matchers else "") + "\n\n".join(branches) + "\n"


def _rego_field_accessor(field: str) -> str | None:
    """Build an inline Rego accessor for a dot-separated snapshot field.

    Args:
        field: dotted path such as ``tool_call.args.amount_usd`` or
            ``envelope.budgets.tool_call_count``.

    Returns:
        Rego source using OPA's array-path ``object.get`` so that a
        missing segment at *any* depth (leaf or intermediate) resolves
        to the ``null`` sentinel rather than ``undefined``. This is
        critical for fail-closed semantics: an undefined binding makes a
        ``_match_i`` rule silently not fire, falling through to
        ``default verdict := allow``. With the array-path form OPA
        returns ``null`` whenever any segment is absent, which the
        polarity-aware ``_rego_op_clause`` can then test explicitly.
    """
    parts = [p for p in field.split(".") if p]
    if not parts:
        return "input.snapshot"
    # Validate every segment before embedding; reject anything that is
    # not a plain identifier to prevent Rego injection from policy authors.
    for part in parts:
        if not part.replace("_", "").isalnum():
            return None
    return f"object.get(input.snapshot, {json.dumps(parts)}, null)"


def _rego_op_clause(operator: str, accessor: str, value: Any, action: str = "allow") -> str | None:
    """Render the body of a ``_match[i]`` rule for a given operator.

    The ``action`` parameter controls polarity for negative operators
    (``ne``, ``not_in``). An absent field (null sentinel from the
    array-path accessor) is genuinely "not equal to" a pinned value and
    genuinely "not in" an allowlist, so a ``deny`` rule with a negative
    operator MUST fire when the field is absent. The ``_v != null``
    guard is therefore dropped for deny rules using these operators.

    Keeping the guard for ``allow`` rules is equally important: an allow
    rule that fires on a missing field is itself fail-open and can
    preempt a later deny in the first-match-wins chain.

    Args:
        operator: Comparison operator string (``"eq"``, ``"ne"``,
            ``"gt"``, ``"lt"``, ``"gte"``, ``"lte"``, ``"in"``,
            ``"not_in"``, ``"exists"``, ``"contains"``,
            ``"startswith"``, ``"endswith"``, ``"matches"``/``"regex"``).
        accessor: Rego expression for the field value, produced by
            ``_rego_field_accessor``.
        value: The comparison value from the rule condition.
        action: The rule action string, passed through from the rule as-is.
            Only ``"deny"`` drops the ``_v != null`` guard for ``ne`` and
            ``not_in``; every other action value (``"allow"``, ``"warn"``,
            etc.) keeps the guard. All other operators are unaffected.

    Returns:
        Indented Rego body lines for a ``_match_i`` rule, or ``None``
        for unsupported operators. The caller emits a fail-closed deny
        in place of any rule that returns ``None``.
    """
    try:
        # allow_nan=False: NaN/Infinity are not Rego literals, and a YAML date
        # or !!binary value is not JSON. Both would otherwise either raise a
        # bare TypeError here or write a bundle OPA cannot parse. The caller
        # treats None as "cannot translate" and emits a fail-closed deny;
        # _validate_rules refuses such a rule before rendering is reached.
        literal = json.dumps(value, allow_nan=False)
    except (TypeError, ValueError):
        return None
    indent = "    "
    if operator == "eq":
        if value is None and action != "deny":
            # allow/warn ``eq null`` must NOT fire on an ABSENT field. The
            # array-path accessor returns the null default for both an absent
            # field and a genuinely present null, collapsing the two, so a
            # bare ``== null`` is fail-open (it can preempt a lower-priority
            # deny in the first-match chain). Rebuild the accessor with an
            # object sentinel default so an absent field yields a non-null
            # object; ``== null`` is then true only for a present null. deny
            # keeps the null default so an absent field still fires (fail closed).
            sentinel_accessor = accessor
            if accessor.endswith(", null)"):
                sentinel_accessor = (
                    accessor[: -len(", null)")]
                    + f", {json.dumps({'__agt_absent__': True})})"
                )
            return f"{indent}{sentinel_accessor} == {literal}"
        return f"{indent}{accessor} == {literal}"
    if operator == "ne":
        if action == "deny":
            # Drop the null guard: absent field != pinned value, so deny must fire.
            return f"{indent}_v := {accessor}\n{indent}_v != {literal}"
        return f"{indent}_v := {accessor}\n{indent}_v != null\n{indent}_v != {literal}"
    if operator == "gt":
        return f"{indent}_v := {accessor}\n{indent}_v != null\n{indent}_v > {literal}"
    if operator == "lt":
        return f"{indent}_v := {accessor}\n{indent}_v != null\n{indent}_v < {literal}"
    if operator == "gte":
        return f"{indent}_v := {accessor}\n{indent}_v != null\n{indent}_v >= {literal}"
    if operator == "lte":
        return f"{indent}_v := {accessor}\n{indent}_v != null\n{indent}_v <= {literal}"
    if operator == "in":
        if not isinstance(value, list):
            return None
        return f"{indent}_v := {accessor}\n{indent}_v != null\n{indent}_v in {literal}"
    if operator == "not_in":
        if not isinstance(value, list):
            return None
        if action == "deny":
            # Drop the null guard: absent field is not in the allowlist, so deny must fire.
            return f"{indent}_v := {accessor}\n{indent}not _v in {literal}"
        return f"{indent}_v := {accessor}\n{indent}_v != null\n{indent}not _v in {literal}"
    if operator == "exists":
        return f"{indent}{accessor} != null"
    if operator == "contains":
        if not isinstance(value, str):
            return None
        return (
            f"{indent}_v := {accessor}\n"
            f"{indent}_v != null\n"
            f"{indent}is_string(_v)\n"
            f"{indent}contains(_v, {literal})"
        )
    if operator == "startswith":
        if not isinstance(value, str):
            return None
        return (
            f"{indent}_v := {accessor}\n"
            f"{indent}_v != null\n"
            f"{indent}is_string(_v)\n"
            f"{indent}startswith(_v, {literal})"
        )
    if operator == "endswith":
        if not isinstance(value, str):
            return None
        return (
            f"{indent}_v := {accessor}\n"
            f"{indent}_v != null\n"
            f"{indent}is_string(_v)\n"
            f"{indent}endswith(_v, {literal})"
        )
    if operator in {"matches", "regex"}:
        # Validate the pattern at build time with require_opa=True, so an
        # authoritative Go RE2 engine (OPA on PATH or the google-re2 binding)
        # must be present. Without require_opa the check would silently fall
        # to the non-authoritative Python tier, which can accept a pattern Go
        # RE2 rejects; that pattern then makes regex.match raise at eval time,
        # leaving a silently dead deny (fail open). A rejected or non-string
        # pattern returns None so the caller emits a fail-closed always-
        # matching deny instead.
        if not isinstance(value, str):
            return None
        try:
            validate_re2(value, require_opa=True)
        except ValueError:
            return None
        return (
            f"{indent}_v := {accessor}\n"
            f"{indent}_v != null\n"
            f"{indent}is_string(_v)\n"
            f"{indent}regex.match({literal}, _v)"
        )
    return None
