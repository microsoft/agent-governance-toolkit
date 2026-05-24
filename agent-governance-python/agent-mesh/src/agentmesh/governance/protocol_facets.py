# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Protocol-aware facet extraction for policy evaluation.

Populates sql.* and k8s.* fields in the evaluation context so YAML rules
can reference wire-level semantics like sql.verb or k8s.namespace.

To add support for a new protocol, register an extractor on default_registry:

    from agentmesh.governance.protocol_facets import default_registry

    def extract_redis_facets(redis_ctx):
        cmd = (redis_ctx.get("command") or "").upper()
        return {"verb": cmd, "key": redis_ctx.get("key", "")}

    default_registry.register("redis", extract_redis_facets)
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable

logger = logging.getLogger(__name__)


class FacetRegistry:
    """Holds protocol facet extractors keyed by context field name.

    Each extractor receives the sub-dict at its registered key and returns
    fields to merge back in. Errors inside an extractor are caught and
    logged so a broken parser never blocks policy evaluation.
    """

    def __init__(self) -> None:
        self._extractors: list[tuple[str, Callable[[dict[str, Any]], dict[str, Any]]]] = []

    def register(
        self,
        context_key: str,
        extractor: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> None:
        """Register extractor for sub-dicts stored at context_key."""
        self._extractors.append((context_key, extractor))

    def extract(self, context: dict[str, Any]) -> dict[str, Any]:
        """Run all registered extractors against context in place."""
        for key, extractor in self._extractors:
            sub = context.get(key)
            if not isinstance(sub, dict):
                continue
            try:
                facets = extractor(sub)
                sub.update(facets)
            except Exception:
                logger.exception("Facet extraction failed for context key '%s'", key)
        return context


# SQL verb lookup keyed by sqlglot AST class name (lowercased)
_SQL_VERB_MAP: dict[str, str] = {
    "select": "SELECT",
    "insert": "INSERT",
    "update": "UPDATE",
    "delete": "DELETE",
    "drop": "DROP",
    "truncate": "TRUNCATE",
    "alter": "ALTER",
    "create": "CREATE",
    "grant": "GRANT",
    "revoke": "REVOKE",
    "merge": "MERGE",
    "call": "CALL",
    "execute": "EXECUTE",
    "explain": "EXPLAIN",
    "with": "WITH",
}


def _extract_sql_facets(sql_ctx: dict[str, Any]) -> dict[str, Any]:
    """Parse sql_ctx["query"] and return verb, target, tables and functions.

    Uses sqlglot for AST level parsing. Falls back to UNKNOWN if sqlglot
    is not installed or parsing fails.
    """
    query: str = sql_ctx.get("query", "")
    if not query or not query.strip():
        return {"verb": "", "target": "", "tables": "", "functions": ""}

    try:
        import sqlglot
        from sqlglot import exp

        try:
            statements = sqlglot.parse(query)
        except Exception:
            logger.warning("SQL parsing failed, defaulting to UNKNOWN verb")
            return {"verb": "UNKNOWN", "target": "", "tables": "", "functions": ""}

        if not statements or statements[0] is None:
            return {"verb": "UNKNOWN", "target": "", "tables": "", "functions": ""}

        stmt = statements[0]

        verb = "UNKNOWN"
        if isinstance(stmt, exp.Select):
            verb = "SELECT"
        elif isinstance(stmt, exp.Insert):
            verb = "INSERT"
        elif isinstance(stmt, exp.Update):
            verb = "UPDATE"
        elif isinstance(stmt, exp.Delete):
            verb = "DELETE"
        elif isinstance(stmt, exp.Drop):
            verb = "DROP"
        elif isinstance(stmt, exp.Create):
            verb = "CREATE"
        elif isinstance(stmt, exp.AlterTable):
            verb = "ALTER"
        elif isinstance(stmt, exp.Grant):
            verb = "GRANT"
        elif isinstance(stmt, exp.Merge):
            verb = "MERGE"
        elif isinstance(stmt, exp.Command):
            cmd = (stmt.this or "").upper()
            verb = _SQL_VERB_MAP.get(cmd.lower(), cmd) if cmd else "UNKNOWN"
        else:
            class_name = type(stmt).__name__.upper()
            verb = _SQL_VERB_MAP.get(class_name.lower(), class_name)

        tables = [t.name for t in stmt.find_all(exp.Table) if t.name]
        functions = [f.name.upper() for f in stmt.find_all(exp.Func) if f.name]

        # target is the first (primary) table the statement operates on
        target = tables[0] if tables else ""

        return {
            "verb": verb,
            "target": target,
            "tables": ",".join(tables),
            "functions": ",".join(functions),
        }

    except ImportError:
        logger.warning(
            "sqlglot is not installed so SQL facets are unavailable. "
            "Run: pip install sqlglot"
        )
        return {"verb": "UNKNOWN", "target": "", "tables": "", "functions": ""}


# Maps HTTP method to a Kubernetes verb when the URL targets a named object
_METHOD_TO_VERB_NAMED: dict[str, str] = {
    "GET": "get",
    "DELETE": "delete",
    "PUT": "update",
    "PATCH": "patch",
    "POST": "create",
    "HEAD": "get",
}

# Maps HTTP method to a Kubernetes verb when the URL targets a collection
_METHOD_TO_VERB_COLLECTION: dict[str, str] = {
    "GET": "list",
    "POST": "create",
    "DELETE": "deletecollection",
    "PUT": "update",
    "PATCH": "patch",
    "HEAD": "list",
}

# Path patterns ordered most specific first; captured groups named by the
# tuple that follows each compiled regex
_K8S_PATH_PATTERNS: list[tuple[re.Pattern[str], tuple[str, ...]]] = [
    (
        re.compile(r"^/api/[^/]+/namespaces/([^/]+)/([^/]+)/([^/]+)/([^/]+)/?$"),
        ("namespace", "resource", "name", "subresource"),
    ),
    (
        re.compile(r"^/apis/[^/]+/[^/]+/namespaces/([^/]+)/([^/]+)/([^/]+)/([^/]+)/?$"),
        ("namespace", "resource", "name", "subresource"),
    ),
    (
        re.compile(r"^/api/[^/]+/namespaces/([^/]+)/([^/]+)/([^/]+)/?$"),
        ("namespace", "resource", "name"),
    ),
    (
        re.compile(r"^/apis/[^/]+/[^/]+/namespaces/([^/]+)/([^/]+)/([^/]+)/?$"),
        ("namespace", "resource", "name"),
    ),
    (
        re.compile(r"^/api/[^/]+/namespaces/([^/]+)/([^/]+)/?$"),
        ("namespace", "resource"),
    ),
    (
        re.compile(r"^/apis/[^/]+/[^/]+/namespaces/([^/]+)/([^/]+)/?$"),
        ("namespace", "resource"),
    ),
    (
        re.compile(r"^/api/[^/]+/([^/]+)/([^/]+)/?$"),
        ("resource", "name"),
    ),
    (
        re.compile(r"^/apis/[^/]+/[^/]+/([^/]+)/([^/]+)/?$"),
        ("resource", "name"),
    ),
    (
        re.compile(r"^/api/[^/]+/([^/]+)/?$"),
        ("resource",),
    ),
    (
        re.compile(r"^/apis/[^/]+/[^/]+/([^/]+)/?$"),
        ("resource",),
    ),
]


def _extract_k8s_facets(k8s_ctx: dict[str, Any]) -> dict[str, Any]:
    """Parse a Kubernetes API request into policy-evaluable fields.

    Reads k8s_ctx["method"] and k8s_ctx["path"] and returns verb, resource,
    namespace, name and subresource.
    """
    method: str = (k8s_ctx.get("method") or "").upper()
    path: str = k8s_ctx.get("path") or ""

    result: dict[str, str] = {
        "verb": "",
        "resource": "",
        "namespace": "",
        "name": "",
        "subresource": "",
    }

    if not path:
        return result

    matched_groups: dict[str, str] = {}
    for pattern, group_names in _K8S_PATH_PATTERNS:
        m = pattern.match(path)
        if m:
            matched_groups = dict(zip(group_names, m.groups()))
            break

    result["resource"] = matched_groups.get("resource", "")
    result["namespace"] = matched_groups.get("namespace", "")
    result["name"] = matched_groups.get("name", "")
    result["subresource"] = matched_groups.get("subresource", "")

    has_name = bool(result["name"])
    if method:
        if has_name:
            result["verb"] = _METHOD_TO_VERB_NAMED.get(method, method.lower())
        else:
            result["verb"] = _METHOD_TO_VERB_COLLECTION.get(method, method.lower())

    return result


# Module-level registry pre-loaded with SQL and Kubernetes parsers.
# Import this and call register() to add support for new protocols.
default_registry = FacetRegistry()
default_registry.register("sql", _extract_sql_facets)
default_registry.register("k8s", _extract_k8s_facets)


def extract_protocol_facets(
    context: dict[str, Any],
    registry: FacetRegistry | None = None,
) -> dict[str, Any]:
    """Enrich a policy evaluation context with wire-protocol facets.

    Uses the supplied registry or default_registry if none is given.
    Modifies context in place and returns it.
    """
    return (registry or default_registry).extract(context)
