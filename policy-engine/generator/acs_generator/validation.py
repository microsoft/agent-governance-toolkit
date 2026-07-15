from __future__ import annotations

import json
import re
import warnings
from collections.abc import Mapping
from importlib import resources
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from .vocabulary import (
    DECISIONS,
    DEPRECATED_INPUT_REFS,
    POLICY_INPUT_ANNOTATIONS_KEY,
    POLICY_INPUT_POINT_KEY,
)

OPA_TIMEOUT_SECONDS = 10
SCHEMA_PACKAGE = "acs_generator.schema"
SCHEMA_NAME = "manifest.schema.json"
APPROVAL_SCHEMA_NAME = "approval.schema.json"
VALIDATION_DIR_NAME = ".acs_generator_validation"
OPA_OUTPUT_LIMIT = 4096
# Core transform-path grammar (see rego_builder._TRANSFORM_PATH_RE): dotted object
# keys and numeric list indices only; the core rejects string bracket keys.
_TRANSFORM_PATH_RE = re.compile(r"^\$policy_target(\.[A-Za-z_][A-Za-z0-9_]*|\[[0-9]+\])*$")


@dataclass
class ValidationResult:
    warnings: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ValidationDiagnostic:
    component: str
    code: str
    message: str
    source: str
    path: str | None = None
    line: int | None = None
    column: int | None = None
    snippet: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "code": self.code,
            "message": self.message,
            "source": self.source,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
        }


@dataclass(frozen=True)
class ArtifactValidationResult:
    diagnostics: tuple[ValidationDiagnostic, ...] = ()

    @property
    def valid(self) -> bool:
        return not self.diagnostics

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "diagnostics": [diagnostic.to_dict() for diagnostic in self.diagnostics],
        }


class ValidationError(RuntimeError):
    pass


def validate_acs_artifacts(
    manifest: str,
    rego: str | Mapping[str, str],
    *,
    opa_path: str | None = None,
) -> ArtifactValidationResult:
    """Validate an ACS manifest string and one or more Rego module strings.

    The check is intentionally suitable for an API boundary. It returns
    structured diagnostics instead of raising for invalid artifacts. Manifest
    validation uses the packaged canonical schema. Rego validation uses the OPA
    compiler so syntax and cross-module compile failures are reported together.
    """

    diagnostics: list[ValidationDiagnostic] = []
    parsed_manifest, manifest_diagnostic = _parse_manifest_string(manifest)
    if manifest_diagnostic is not None:
        diagnostics.append(manifest_diagnostic)
    elif parsed_manifest is not None:
        diagnostics.extend(_manifest_schema_diagnostics(parsed_manifest))

    rego_modules, input_diagnostics = _normalize_rego_modules(rego)
    diagnostics.extend(input_diagnostics)
    if rego_modules:
        executable = opa_path or shutil.which("opa")
        if executable is None:
            diagnostics.append(
                ValidationDiagnostic(
                    component="rego",
                    code="opa_unavailable",
                    message="OPA is required to validate Rego. Install opa on PATH or pass opa_path.",
                    source="opa",
                )
            )
        else:
            diagnostics.extend(_validate_rego_modules(executable, rego_modules))

    return ArtifactValidationResult(tuple(diagnostics))


def _parse_manifest_string(
    manifest: str,
) -> tuple[dict[str, Any] | None, ValidationDiagnostic | None]:
    if not isinstance(manifest, str):
        return None, ValidationDiagnostic(
            component="manifest",
            code="manifest_input_invalid",
            message="Manifest input must be a YAML or JSON string.",
            source="manifest",
        )
    try:
        parsed = yaml.safe_load(manifest)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        message = getattr(exc, "problem", None) or str(exc)
        return None, ValidationDiagnostic(
            component="manifest",
            code="manifest_parse_error",
            message=message,
            source="manifest",
            line=mark.line + 1 if mark is not None else None,
            column=mark.column + 1 if mark is not None else None,
        )
    if not isinstance(parsed, dict):
        return None, ValidationDiagnostic(
            component="manifest",
            code="manifest_root_invalid",
            message="Manifest must decode to a YAML or JSON object.",
            source="manifest",
            path="$",
        )
    return parsed, None


def _load_packaged_schema(name: str) -> dict[str, Any]:
    with resources.files(SCHEMA_PACKAGE).joinpath(name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _manifest_validator() -> jsonschema.Draft202012Validator:
    schema = _load_packaged_schema(SCHEMA_NAME)
    approval_schema = _load_packaged_schema(APPROVAL_SCHEMA_NAME)
    try:
        from referencing import Registry, Resource

        registry = Registry().with_resource(
            approval_schema["$id"],
            Resource.from_contents(approval_schema),
        )
        return jsonschema.Draft202012Validator(schema, registry=registry)
    except (ImportError, TypeError):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            resolver = jsonschema.RefResolver.from_schema(
                schema,
                store={approval_schema["$id"]: approval_schema},
            )
        return jsonschema.Draft202012Validator(schema, resolver=resolver)


def _manifest_schema_diagnostics(manifest: dict[str, Any]) -> list[ValidationDiagnostic]:
    errors = sorted(
        _manifest_validator().iter_errors(manifest),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    return [
        ValidationDiagnostic(
            component="manifest",
            code="manifest_schema_error",
            message=error.message,
            source="manifest",
            path=_json_path(error.absolute_path),
        )
        for error in errors
    ]


def _json_path(parts: Any) -> str:
    path = "$"
    for part in parts:
        if isinstance(part, int):
            path += f"[{part}]"
        elif isinstance(part, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", part):
            path += f".{part}"
        else:
            path += f"[{json.dumps(part)}]"
    return path


def _normalize_rego_modules(
    rego: str | Mapping[str, str],
) -> tuple[list[tuple[str, str]], list[ValidationDiagnostic]]:
    if isinstance(rego, str):
        items: list[tuple[Any, Any]] = [("policy.rego", rego)]
    elif isinstance(rego, Mapping):
        items = list(rego.items())
    else:
        return [], [
            ValidationDiagnostic(
                component="rego",
                code="rego_input_invalid",
                message="Rego input must be a string or a mapping of source names to strings.",
                source="rego",
            )
        ]

    modules: list[tuple[str, str]] = []
    diagnostics: list[ValidationDiagnostic] = []
    for index, (source, contents) in enumerate(items):
        if not isinstance(source, str) or not source.strip():
            diagnostics.append(
                ValidationDiagnostic(
                    component="rego",
                    code="rego_source_invalid",
                    message="Each Rego module must have a non-empty string source name.",
                    source=f"rego[{index}]",
                )
            )
            continue
        if not isinstance(contents, str):
            diagnostics.append(
                ValidationDiagnostic(
                    component="rego",
                    code="rego_input_invalid",
                    message="Each Rego module value must be a string.",
                    source=source,
                )
            )
            continue
        if not contents.strip():
            diagnostics.append(
                ValidationDiagnostic(
                    component="rego",
                    code="rego_empty",
                    message="Rego module must not be empty.",
                    source=source,
                )
            )
            continue
        modules.append((source, contents))
    return modules, diagnostics


def _validate_rego_modules(
    opa: str,
    modules: list[tuple[str, str]],
) -> list[ValidationDiagnostic]:
    with tempfile.TemporaryDirectory(prefix="acs-validation-") as tmp:
        root = Path(tmp)
        paths: list[Path] = []
        source_by_file: dict[str, str] = {}
        try:
            for index, (source, contents) in enumerate(modules):
                path = root / f"module-{index:04d}.rego"
                path.write_text(contents, encoding="utf-8")
                paths.append(path)
                source_by_file[str(path)] = source
                source_by_file[str(path.resolve())] = source
                source_by_file[path.name] = source
        except OSError as exc:
            return [
                ValidationDiagnostic(
                    component="rego",
                    code="rego_staging_error",
                    message=f"Could not stage Rego modules for OPA validation. {exc}",
                    source="rego",
                )
            ]

        try:
            completed = subprocess.run(
                [opa, "check", "--format=json", *(str(path) for path in paths)],
                check=False,
                capture_output=True,
                text=True,
                timeout=OPA_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return [
                ValidationDiagnostic(
                    component="rego",
                    code="opa_timeout",
                    message=f"OPA validation exceeded {OPA_TIMEOUT_SECONDS} seconds.",
                    source="opa",
                )
            ]
        except OSError as exc:
            return [
                ValidationDiagnostic(
                    component="rego",
                    code="opa_execution_error",
                    message=f"OPA could not be executed. {exc}",
                    source="opa",
                )
            ]

        if completed.returncode == 0:
            return []
        return _opa_check_diagnostics(completed, source_by_file)


def _opa_check_diagnostics(
    completed: subprocess.CompletedProcess[str],
    source_by_file: dict[str, str],
) -> list[ValidationDiagnostic]:
    payload: dict[str, Any] | None = None
    for candidate in (completed.stderr.strip(), completed.stdout.strip()):
        if not candidate:
            continue
        try:
            decoded = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(decoded, dict):
            payload = decoded
            break

    errors = payload.get("errors") if payload is not None else None
    if isinstance(errors, list) and errors:
        diagnostics: list[ValidationDiagnostic] = []
        for error in errors:
            if not isinstance(error, dict):
                continue
            location = error.get("location")
            location = location if isinstance(location, dict) else {}
            details = error.get("details")
            details = details if isinstance(details, dict) else {}
            file_name = location.get("file")
            source = _rego_source_label(file_name, source_by_file)
            diagnostics.append(
                ValidationDiagnostic(
                    component="rego",
                    code=str(error.get("code") or "rego_validation_error"),
                    message=_replace_opa_paths(
                        str(error.get("message") or "OPA rejected the Rego module."),
                        source_by_file,
                    ),
                    source=source,
                    line=location.get("row") if isinstance(location.get("row"), int) else None,
                    column=location.get("col") if isinstance(location.get("col"), int) else None,
                    snippet=details.get("line") if isinstance(details.get("line"), str) else None,
                )
            )
        if diagnostics:
            return diagnostics

    detail = completed.stderr.strip() or completed.stdout.strip()
    detail = _replace_opa_paths(detail, source_by_file)
    if len(detail) > OPA_OUTPUT_LIMIT:
        detail = detail[:OPA_OUTPUT_LIMIT] + "..."
    return [
        ValidationDiagnostic(
            component="rego",
            code="opa_validation_error",
            message=detail or f"OPA exited with status {completed.returncode} without diagnostics.",
            source="opa",
        )
    ]


def _rego_source_label(file_name: Any, source_by_file: dict[str, str]) -> str:
    if not isinstance(file_name, str):
        return "rego"
    return (
        source_by_file.get(file_name)
        or source_by_file.get(str(Path(file_name).resolve()))
        or source_by_file.get(Path(file_name).name)
        or Path(file_name).name
    )


def _replace_opa_paths(value: str, source_by_file: dict[str, str]) -> str:
    replaced = value
    for path, source in sorted(source_by_file.items(), key=lambda item: len(item[0]), reverse=True):
        replaced = replaced.replace(path, source)
    return replaced


class _NoopAnnotator:
    def dispatch(self, annotator_name: str, annotator_config: dict[str, Any], preliminary_policy_input: dict[str, Any]) -> dict[str, Any]:
        return {}


class _NoopPolicy:
    def evaluate(self, invocation: dict[str, Any]) -> dict[str, Any]:
        return {"decision": "allow"}


def validate_artifacts(
    manifest: dict[str, Any],
    manifest_yaml: str,
    rego: str,
    slug: str,
    out_dir: Path,
    *,
    strict: bool = False,
    regex_patterns: tuple[str, ...] = (),
) -> ValidationResult:
    warnings: list[str] = []
    _validate_schema(manifest)
    _validate_core(manifest_yaml)
    _reject_deprecated_refs(rego)
    _reject_legacy_effects(rego)
    opa = shutil.which("opa")
    if opa is None:
        message = "opa not found on PATH; skipped Rego syntax and eval validation"
        if strict:
            raise ValidationError(message)
        warnings.append(message)
        return ValidationResult(warnings)
    _validate_opa(opa, rego, slug, manifest, out_dir)
    _validate_regex_patterns(opa, rego, regex_patterns)
    return ValidationResult(warnings)


# Regex patterns used in the generated Rego are validated against RE2. Every pattern
# that statically reaches a `regex.<fn>(...)` call is extracted by parsing the Rego to
# its AST (`opa parse --format json`) and resolving each call's pattern argument
# through the rule body's bindings. Working on the parser's AST (rather than scanning
# the Rego text) means parentheses, comments, dot-vs-bracket access, inline-vs-named
# collections, and `some`/`every` iteration are already normalized, so the extractor
# is both simpler and free of text-scanning blind spots. A pattern COMPUTED at runtime
# (concat/sprintf, function return, input-derived, comprehension result) is out of
# scope: it is never emitted by the generator and evaluates to undefined at runtime
# rather than silently matching.
# Index of the regex-pattern argument for each builtin. template_match's arg 0 is a
# template whose embedded regexes are handled separately. globs_match takes globs
# (not RE2 regexes) so it has no pattern to validate.
_PATTERN_ARG_INDEX = {
    "match": 0,
    "split": 0,
    "find_n": 0,
    "find_all_string_submatch_n": 0,
    "find_all_string_submatch": 0,
    "replace": 1,
}

# Recursion guard for cyclic variable bindings (x := y; y := x) and deep chains.
_RESOLVE_MAX_DEPTH = 32
# AST term types whose value is a single literal scalar (usable as an object key).
_SCALAR_TYPES = ("string", "number", "boolean", "null")


def _parse_rego_ast(opa: str, rego: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "policy.rego"
        path.write_text(rego, encoding="utf-8")
        completed = _run_opa([opa, "parse", str(path), "--format", "json"])
    return json.loads(completed.stdout)


def _ref_name(term: Any) -> str | None:
    # Dotted name of a ref term whose parts are all vars/strings (assign, eq,
    # regex.match, internal.member_2, ...); None for any other shape.
    if not isinstance(term, dict) or term.get("type") != "ref":
        return None
    names: list[str] = []
    for part in term.get("value", []):
        if isinstance(part, dict) and part.get("type") in ("var", "string"):
            names.append(str(part.get("value")))
        else:
            return None
    return ".".join(names)


def _stmt_op_args(stmt: Any) -> tuple[str | None, list]:
    # (operator name, argument terms) for a body statement, which is either a term
    # list (infix call like assign/eq/regex.match) or a call term (some membership).
    if isinstance(stmt, list):
        return (_ref_name(stmt[0]), stmt[1:]) if stmt else (None, [])
    if isinstance(stmt, dict) and stmt.get("type") == "call":
        value = stmt.get("value", [])
        return (_ref_name(value[0]), value[1:]) if value else (None, [])
    return None, []


def _value_terms(term: Any, assigns: dict[str, list], seen: frozenset[str] = frozenset(), depth: int = 0) -> list[dict]:
    # The concrete terms (scalar literals and collection literals) that `term` can take,
    # following variable bindings AND ref (member/index/membership) access. This is the
    # single resolution core; pattern and collection resolution are filters over it.
    if depth > _RESOLVE_MAX_DEPTH or not isinstance(term, dict):
        return []
    kind = term.get("type")
    if kind in _SCALAR_TYPES or kind in ("array", "set", "object"):
        return [term]
    if kind == "var":
        name = term["value"]
        if name in seen:
            return []
        nxt = seen | {name}
        out: list[dict] = []
        for bound in assigns.get(name, []):
            out += _value_terms(bound, assigns, nxt, depth + 1)
        return out
    if kind == "ref":
        parts = term.get("value", [])
        if not parts:
            return []
        return _selected_terms(parts[0], parts[1:], assigns, seen, depth + 1)
    return []


def _resolve_pattern_term(term: Any, assigns: dict[str, list], seen: frozenset[str] = frozenset(), depth: int = 0) -> list[str]:
    # Every string literal a regex-argument term can statically take.
    return [t.get("value", "") for t in _value_terms(term, assigns, seen, depth) if t.get("type") == "string"]


def _concrete_collections(term: Any, assigns: dict[str, list], seen: frozenset[str]) -> list[dict]:
    # The array/set/object literal terms a term can be (following vars and refs).
    return [t for t in _value_terms(term, assigns, seen, 0) if t.get("type") in ("array", "set", "object")]


def _collection_member_terms(term: Any, assigns: dict[str, list], seen: frozenset[str]) -> tuple[list, list]:
    # (element/value terms, key terms) for every collection `term` resolves to.
    elements: list = []
    keys: list = []
    for coll in _concrete_collections(term, assigns, seen):
        if coll["type"] in ("array", "set"):
            elements += list(coll.get("value", []))
        elif coll["type"] == "object":
            for pair in coll.get("value", []):
                if len(pair) >= 2:
                    keys.append(pair[0])
                    elements.append(pair[1])
    return elements, keys


def _resolve_selector_keys(selector: Any, assigns: dict[str, list], seen: frozenset[str]) -> list[dict] | None:
    # The concrete scalar selector terms a selector can take, or None when it cannot be
    # statically pinned (the caller then ranges over the whole collection). A selector
    # VARIABLE bound to a literal (k := "key"; m[k]) resolves precisely, so an unused
    # member with an invalid-looking value does not falsely reject the policy.
    if not isinstance(selector, dict):
        return None
    kind = selector.get("type")
    if kind in _SCALAR_TYPES:
        return [selector]
    if kind == "var":
        name = selector["value"]
        if name in seen or name not in assigns:
            return None
        nxt = seen | {name}
        out: list[dict] = []
        for bound in assigns[name]:
            sub = _resolve_selector_keys(bound, assigns, nxt)
            if sub is None:
                return None
            out += sub
        return out or None
    return None


def _selected_terms(base: Any, selectors: list, assigns: dict[str, list], seen: frozenset[str], depth: int) -> list[dict]:
    # The terms reached by base[selector0][selector1]... A numeric array index or a
    # scalar object key (literal, or a variable bound to one) selects exactly the
    # matching element/member; a set lookup selects the element equal to the selector;
    # an unpinned selector ranges over all. Selected children are resolved through
    # `_value_terms`, so nested collections (e.g. `groups.g[p]`) resolve transitively.
    if depth > _RESOLVE_MAX_DEPTH:
        return []
    if not selectors:
        return _value_terms(base, assigns, seen, depth)
    selector, rest = selectors[0], selectors[1:]
    base_seen = seen | {base["value"]} if isinstance(base, dict) and base.get("type") == "var" else seen
    keys = _resolve_selector_keys(selector, assigns, frozenset())
    wanted = {(key.get("type"), key.get("value")) for key in keys} if keys is not None else None
    chosen: list = []
    for coll in _value_terms(base, assigns, seen, depth):
        kind = coll.get("type")
        if kind == "array":
            elements = list(coll.get("value", []))
            if wanted is None:
                chosen += elements
                continue
            for key in keys:
                if key.get("type") != "number":
                    continue
                try:
                    index = int(key["value"])
                except (TypeError, ValueError):
                    continue
                if -len(elements) <= index < len(elements):
                    chosen.append(elements[index])
        elif kind == "set":
            # A set lookup `s[k]` yields k itself when k is a member, so the element
            # equal to the selector is chosen (an unpinned selector ranges over all).
            elements = list(coll.get("value", []))
            if wanted is None:
                chosen += elements
                continue
            for element in elements:
                if (element.get("type"), element.get("value")) in wanted:
                    chosen.append(element)
        elif kind == "object":
            if wanted is None:
                chosen += [pair[1] for pair in coll.get("value", []) if len(pair) >= 2]
                continue
            for pair in coll.get("value", []):
                if len(pair) >= 2 and (pair[0].get("type"), pair[0].get("value")) in wanted:
                    chosen.append(pair[1])
    out: list[dict] = []
    for child in chosen:
        out += _selected_terms(child, rest, assigns, base_seen, depth + 1) if rest else _value_terms(child, assigns, base_seen, depth + 1)
    return out


def _bind(assigns: dict[str, list], var_term: Any, terms: list) -> bool:
    # Record candidate value terms for a variable; returns whether anything was added.
    if not (isinstance(var_term, dict) and var_term.get("type") == "var"):
        return False
    bucket = assigns.setdefault(var_term["value"], [])
    seen_repr = {json.dumps(t, sort_keys=True) for t in bucket}
    changed = False
    for term in terms:
        rep = json.dumps(term, sort_keys=True)
        if rep not in seen_repr:
            bucket.append(term)
            seen_repr.add(rep)
            changed = True
    return changed


def _template_patterns(args: list, assigns: dict[str, list]) -> list[str]:
    # regex.template_match(template, value, start_delim, end_delim): the embedded
    # regexes live between the two delimiters.
    if len(args) < 4:
        return []
    patterns: list[str] = []
    for template in _resolve_pattern_term(args[0], assigns):
        for start in _resolve_pattern_term(args[2], assigns):
            for end in _resolve_pattern_term(args[3], assigns):
                if not (start and end):
                    continue
                pos = 0
                while True:
                    a = template.find(start, pos)
                    if a < 0:
                        break
                    b = template.find(end, a + len(start))
                    if b < 0:
                        break
                    patterns.append(template[a + len(start):b])
                    pos = b + len(end)
    return patterns


def _regex_call_patterns(fn: str, args: list, assigns: dict[str, list]) -> list[str]:
    if fn == "template_match":
        return _template_patterns(args, assigns)
    index = _PATTERN_ARG_INDEX.get(fn)
    if index is None or index >= len(args):
        return []
    return _resolve_pattern_term(args[index], assigns)


_COMPREHENSION_TYPES = ("arraycomprehension", "setcomprehension", "objectcomprehension")


def _nested_regex_calls(node: Any, calls: list[tuple[str, list]]) -> None:
    # Find `regex.<fn>(...)` call TERMS anywhere in an expression (e.g. a regex call on
    # an assignment's right-hand side), without descending into a nested-scope construct
    # (every body, comprehension body), each of which is resolved separately with its
    # own bindings. A comprehension's `value` dict carries the `body` key that stops the
    # descent; `every` bodies are handled via the caller's every_blocks.
    if isinstance(node, list):
        for item in node:
            _nested_regex_calls(item, calls)
    elif isinstance(node, dict):
        if "body" in node:
            return
        if node.get("type") == "call":
            value = node.get("value", [])
            name = _ref_name(value[0]) if value else None
            if name and name.startswith("regex."):
                calls.append((name.split(".", 1)[1], value[1:]))
        for sub in node.values():
            _nested_regex_calls(sub, calls)


def _comprehension_scopes(node: Any, scopes: list[dict]) -> None:
    # Collect the `value` dict ({term | key+value, body}) of every array/set/object
    # comprehension reachable in an expression, WITHOUT descending into a comprehension
    # or `every` body (those are recursed separately with their own scope). A
    # comprehension iterates/binds via the `some`/assignments inside its body, so it
    # inherits the enclosing scope; its head term(s) are evaluated in that same scope.
    if isinstance(node, list):
        for item in node:
            _comprehension_scopes(item, scopes)
    elif isinstance(node, dict):
        if node.get("type") in _COMPREHENSION_TYPES:
            value = node.get("value")
            if isinstance(value, dict):
                scopes.append(value)
            return
        if "domain" in node:  # an `every` term: its body is handled by every_blocks
            return
        for sub in node.values():
            _comprehension_scopes(sub, scopes)


def _membership_binding_terms(base: Any, assigns: dict[str, list]) -> list:
    # The terms a variable iterates over in a bare membership ref `coll[x]`: set
    # ELEMENTS or object KEYS (both can be string patterns). Array `a[i]` binds i to a
    # numeric index, not a pattern, so arrays contribute nothing here.
    out: list = []
    for coll in _concrete_collections(base, assigns, frozenset()):
        if coll["type"] == "set":
            out += list(coll.get("value", []))
        elif coll["type"] == "object":
            out += [pair[0] for pair in coll.get("value", []) if len(pair) >= 2]
    return out


def _collect_body_patterns(body: list, inherited: dict[str, list], patterns: list[str], head_terms: tuple = ()) -> None:
    assigns: dict[str, list] = {name: list(terms) for name, terms in inherited.items()}
    statements: list = []
    every_blocks: list[dict] = []
    membership_refs: list[dict] = []
    for expr in body:
        terms = expr.get("terms")
        if isinstance(terms, list):
            statements.append(terms)
        elif isinstance(terms, dict):
            if "domain" in terms:
                every_blocks.append(terms)
            elif "symbols" in terms:
                statements.extend(terms["symbols"])
            elif terms.get("type") == "call":
                statements.append(terms)
            elif terms.get("type") == "ref":
                membership_refs.append(terms)
    # Direct assignments first so iteration sources can resolve their collections.
    for stmt in statements:
        op, args = _stmt_op_args(stmt)
        if op in ("assign", "eq") and len(args) >= 2:
            _bind(assigns, args[0], [args[1]])
            if op == "eq":
                _bind(assigns, args[1], [args[0]])
    # `some` membership and bare-ref membership (`coll[x]`) bindings, to a fixed point.
    for _ in range(_RESOLVE_MAX_DEPTH):
        changed = False
        for stmt in statements:
            op, args = _stmt_op_args(stmt)
            if op == "internal.member_2" and len(args) >= 2:
                elements, _keys = _collection_member_terms(args[1], assigns, frozenset())
                changed |= _bind(assigns, args[0], elements)
            elif op == "internal.member_3" and len(args) >= 3:
                elements, keys = _collection_member_terms(args[2], assigns, frozenset())
                changed |= _bind(assigns, args[1], elements)
                changed |= _bind(assigns, args[0], keys)
        for ref in membership_refs:
            value = ref.get("value", [])
            last = value[-1] if value else None
            if len(value) >= 2 and isinstance(last, dict) and last.get("type") == "var":
                # `coll[x]` / `base.sel[x]`: the collection is the ref up to the last
                # selector; bind x to its set elements / object keys.
                coll_term = value[0] if len(value) == 2 else {"type": "ref", "value": value[:-1]}
                changed |= _bind(assigns, last, _membership_binding_terms(coll_term, assigns))
        if not changed:
            break
    # Equality narrowing: a non-negated `p == "lit"` (or `p = "lit"`) constrains p to
    # that literal for the whole (conjunctive) body, so an iteration-bound p that is
    # later pinned by equality should validate only the pinned literal — not every
    # member of the collection it ranged over. This is sound (the constraint must hold
    # for the rule to fire) and removes a false positive without risking a fail-open.
    eq_literals: dict[str, list] = {}
    for expr in body:
        if expr.get("negated"):
            continue
        terms = expr.get("terms")
        if not (isinstance(terms, list) and len(terms) == 3 and _ref_name(terms[0]) in ("equal", "eq")):
            continue
        # var == <fully static scalar>. The right side is resolved with the same
        # exact-or-None logic as a selector key (`_resolve_selector_keys` returns None
        # if any reachable value is dynamic), so a var pinned to a literal narrows but a
        # var that could also be input-derived does NOT — preserving fail-open safety.
        left, right = terms[1], terms[2]
        if isinstance(left, dict) and left.get("type") == "var":
            pinned = _resolve_selector_keys(right, assigns, frozenset())
            if pinned:
                eq_literals.setdefault(left["value"], []).extend(pinned)
        if isinstance(right, dict) and right.get("type") == "var":
            pinned = _resolve_selector_keys(left, assigns, frozenset())
            if pinned:
                eq_literals.setdefault(right["value"], []).extend(pinned)
    for name, literals in eq_literals.items():
        assigns[name] = list(literals)
    # Regex calls: top-level infix statements, calls nested in any expression, calls in
    # the comprehension head term(s) this body produces, and calls in an `every` domain.
    calls: list[tuple[str, list]] = []
    for stmt in statements:
        op, args = _stmt_op_args(stmt)
        if op and op.startswith("regex."):
            calls.append((op.split(".", 1)[1], args))
    for expr in body:
        _nested_regex_calls(expr.get("terms"), calls)
    for head in head_terms:
        _nested_regex_calls(head, calls)
    for block in every_blocks:
        _nested_regex_calls(block.get("domain"), calls)
    for fn, args in calls:
        patterns.extend(_regex_call_patterns(fn, args, assigns))
    # `every [k,] v in coll { body }`: bind the value (and object key) in the sub-scope.
    for block in every_blocks:
        sub = {name: list(terms) for name, terms in assigns.items()}
        elements, keys = _collection_member_terms(block.get("domain"), assigns, frozenset())
        _bind(sub, block.get("value"), elements)
        if block.get("key"):
            _bind(sub, block.get("key"), keys)
        _collect_body_patterns(block.get("body", []), sub, patterns)
    # Comprehensions (`[head | body]`) inherit the outer scope, add their own
    # `some`/assignment bindings, and may use regexes in the head term(s) too.
    comprehension_scopes: list[dict] = []
    for expr in body:
        _comprehension_scopes(expr.get("terms"), comprehension_scopes)
    for head in head_terms:  # a comprehension nested inside this scope's head term(s)
        _comprehension_scopes(head, comprehension_scopes)
    for scope in comprehension_scopes:
        heads = tuple(scope[key] for key in ("term", "key", "value") if isinstance(scope.get(key), dict))
        _collect_body_patterns(scope.get("body", []), assigns, patterns, head_terms=heads)


def _rule_bodies(rule: Any):
    # Yield each rule body, following `else` chains (each is its own variable scope).
    if isinstance(rule, dict):
        if isinstance(rule.get("body"), list):
            yield rule["body"]
        if rule.get("else"):
            yield from _rule_bodies(rule["else"])


def _regex_literals_in_rego(opa: str, rego: str) -> list[str]:
    try:
        ast = _parse_rego_ast(opa, rego)
    except (ValidationError, json.JSONDecodeError):
        # Syntax is validated by _validate_opa before this runs; if AST parsing is
        # somehow unavailable, extract nothing (the plan's known redact patterns are
        # still validated by the caller).
        return []
    patterns: list[str] = []
    for rule in ast.get("rules", []):
        for body in _rule_bodies(rule):
            _collect_body_patterns(body, {}, patterns)
    return patterns


def _validate_regex_patterns(opa: str, rego: str, regex_patterns: tuple[str, ...]) -> None:
    # OPA evaluates regex.match/regex.replace with RE2, whose language is a strict
    # subset of Python's re. A pattern using lookaround/backreferences compiles in
    # Python but is rejected by RE2, where it returns undefined at runtime so the
    # rule silently falls through to allow. Validate every regex pattern the policy
    # uses against RE2 itself: both redact effect patterns AND regex literals that
    # appear in rule conditions (which never pass through effect validation).
    candidates = list(dict.fromkeys([*regex_patterns, *_regex_literals_in_rego(opa, rego)]))
    for pattern in candidates:
        completed = _run_opa([opa, "eval", "--format", "json", f"regex.is_valid({json.dumps(pattern)})"])
        try:
            value = json.loads(completed.stdout)["result"][0]["expressions"][0]["value"]
        except (KeyError, IndexError, json.JSONDecodeError) as exc:
            raise ValidationError(f"could not validate regex {pattern!r} against RE2") from exc
        if value is not True:
            raise ValidationError(
                f"regex pattern {pattern!r} is not a valid RE2 regex (OPA uses RE2; "
                "avoid lookahead/lookbehind/backreferences)"
            )


def _validate_schema(manifest: dict[str, Any]) -> None:
    try:
        _manifest_validator().validate(manifest)
    except jsonschema.ValidationError as exc:
        path = ".".join(str(part) for part in exc.absolute_path) or "<root>"
        raise ValidationError(f"manifest schema validation failed at {path}: {exc.message}") from exc


def _validate_core(manifest_yaml: str) -> None:
    try:
        from agent_control_specification import NativeRuntimeClient

        NativeRuntimeClient(manifest_yaml, _NoopAnnotator(), _NoopPolicy())
    except Exception as exc:  # noqa: BLE001 - preserve core diagnostics verbatim.
        raise ValidationError(f"core semantic validation failed: {exc}") from exc


def _validate_opa(opa: str, rego: str, slug: str, manifest: dict[str, Any], out_dir: Path) -> None:
    scratch = out_dir / VALIDATION_DIR_NAME
    if scratch.exists():
        shutil.rmtree(scratch)
    policy_dir = scratch / "policy"
    input_dir = scratch / "input"
    policy_dir.mkdir(parents=True)
    input_dir.mkdir(parents=True)
    rego_path = policy_dir / f"{slug}.rego"
    rego_path.write_text(rego, encoding="utf-8")
    try:
        _run_opa([opa, "parse", str(rego_path)])
        for point_name, config in manifest["intervention_points"].items():
            policy_input = _synthetic_input(point_name, config)
            input_path = input_dir / f"{point_name}.json"
            input_path.write_text(json.dumps(policy_input), encoding="utf-8")
            query = config["policy"]["query"]
            completed = _run_opa([opa, "eval", "--format", "json", "-d", str(policy_dir), "-i", str(input_path), query])
            verdict = _extract_single_object(completed.stdout, query)
            _validate_verdict(verdict, query)
    finally:
        if scratch.exists():
            shutil.rmtree(scratch)


def _run_opa(args: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(args, check=True, capture_output=True, text=True, timeout=OPA_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        raise ValidationError(f"opa timed out running {' '.join(args[1:])}") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip()
        raise ValidationError(f"opa validation failed running {' '.join(args[1:])}: {detail}") from exc


def _reject_deprecated_refs(rego: str) -> None:
    for ref in DEPRECATED_INPUT_REFS:
        if ref in rego:
            raise ValidationError(
                f"generated Rego references deprecated policy input key '{ref}'; "
                f"use input.{POLICY_INPUT_POINT_KEY} and input.{POLICY_INPUT_ANNOTATIONS_KEY}"
            )


def _reject_legacy_effects(rego: str) -> None:
    # OPA eval only exercises the default (allow) path because synthetic inputs
    # do not fire rules, so a deny/warn rule carrying the removed ``effects``
    # array would slip past eval and only fail at runtime
    # (runtime_error:policy_output_invalid). Statically reject the dead member.
    if re.search(r'"effects"\s*:', rego):
        raise ValidationError(
            "generated Rego emits a removed verdict 'effects' array; AGT D1 replaced it "
            "with a single 'transform' object on a transform decision rooted at $policy_target"
        )


def _synthetic_input(point_name: str, config: dict[str, Any]) -> dict[str, Any]:
    tool = {"id": "", "name": ""} if point_name in {"pre_tool_call", "post_tool_call"} else None
    return {
        POLICY_INPUT_POINT_KEY: point_name,
        "snapshot": {},
        POLICY_INPUT_ANNOTATIONS_KEY: {},
        "policy_target": {
            "kind": config.get("policy_target_kind", ""),
            "path": config["policy_target"],
            "value": {},
        },
        "tool": tool,
    }


def _extract_single_object(stdout: str, query: str) -> dict[str, Any]:
    try:
        payload = json.loads(stdout)
        expressions = payload["result"][0]["expressions"]
    except (KeyError, IndexError, json.JSONDecodeError) as exc:
        raise ValidationError(f"opa eval for {query} returned no result") from exc
    if len(expressions) != 1 or not isinstance(expressions[0].get("value"), dict):
        raise ValidationError(f"opa eval for {query} must resolve to exactly one object")
    return expressions[0]["value"]


def _validate_verdict(verdict: dict[str, Any], query: str) -> None:
    decision = verdict.get("decision")
    if decision not in DECISIONS:
        raise ValidationError(f"opa eval for {query} returned unsupported decision: {decision}")
    # AGT D1 removed the verdict ``effects`` array in favor of a single
    # ``transform`` object rooted at ``$policy_target``. The core rejects any
    # verdict carrying ``effects`` with runtime_error:policy_output_invalid, so
    # reject it here too instead of validating the dead shape.
    if "effects" in verdict:
        raise ValidationError(
            f"opa eval for {query} returned a removed 'effects' member; "
            "use a 'transform' verdict (decision == transform) per AGT D1.1"
        )
    transform = verdict.get("transform")
    if decision == "transform":
        if not isinstance(transform, dict):
            raise ValidationError(f"opa eval for {query} transform verdict missing 'transform' object")
        path = transform.get("path")
        if not isinstance(path, str) or not _TRANSFORM_PATH_RE.match(path):
            raise ValidationError(f"opa eval for {query} transform.path must be a well-formed $policy_target path: {path!r}")
        if "value" not in transform:
            raise ValidationError(f"opa eval for {query} transform verdict missing 'transform.value'")
    elif transform is not None:
        raise ValidationError(f"opa eval for {query} carries 'transform' on a non-transform decision: {decision}")


def dump_manifest_yaml(manifest: dict[str, Any]) -> str:
    return yaml.safe_dump(manifest, sort_keys=False)
