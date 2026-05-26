// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
/**
 * Protocol-aware facet extraction for policy evaluation.
 *
 * Populates `sql.*` and `k8s.*` fields in the evaluation context so policy
 * rules can reference wire-level semantics (e.g. `sql.verb`, `k8s.namespace`)
 * instead of only HTTP metadata.
 *
 * This is the TypeScript port of `protocol_facets.py` and mirrors its public
 * contract: `FacetRegistry`, `defaultRegistry`, and `extractProtocolFacets`.
 *
 * To add support for a new protocol, register an extractor on
 * `defaultRegistry`:
 *
 * ```ts
 * import { defaultRegistry } from '@microsoft/agent-governance-sdk';
 *
 * defaultRegistry.register('redis', (redisCtx) => ({
 *   verb: String(redisCtx.command ?? '').toUpperCase(),
 *   key: String(redisCtx.key ?? ''),
 * }));
 * ```
 */

export type FacetExtractor = (sub: Record<string, unknown>) => Record<string, unknown>;

/**
 * Holds protocol facet extractors keyed by context field name.
 *
 * Each extractor receives the sub-object stored at its registered key and
 * returns fields to merge back into that sub-object. Errors thrown inside an
 * extractor are caught and logged so a broken parser can never block policy
 * evaluation (fail-open for extraction, fail-closed for policy).
 */
export class FacetRegistry {
  private readonly extractors: Array<{ key: string; extractor: FacetExtractor }> = [];

  /** Register an extractor for sub-objects stored at `contextKey`. */
  register(contextKey: string, extractor: FacetExtractor): void {
    this.extractors.push({ key: contextKey, extractor });
  }

  /** Run all registered extractors against `context` in place. */
  extract(context: Record<string, unknown>): Record<string, unknown> {
    for (const { key, extractor } of this.extractors) {
      const sub = context[key];
      if (!isPlainObject(sub)) continue;
      try {
        const facets = extractor(sub);
        if (facets && typeof facets === 'object') {
          Object.assign(sub, facets);
        }
      } catch (err) {
        // Never block evaluation if an extractor throws.
        // eslint-disable-next-line no-console
        console.warn(
          `[protocol-facets] extractor for '${key}' threw: ${
            err instanceof Error ? err.message : String(err)
          }`,
        );
      }
    }
    return context;
  }

  /** Number of registered extractors (useful for tests). */
  get size(): number {
    return this.extractors.length;
  }

  /** Remove all extractors. Primarily for tests. */
  clear(): void {
    this.extractors.length = 0;
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// ── SQL facets ──────────────────────────────────────────────────────────────

/**
 * Canonical set of SQL verbs we surface to policies. Anything not in this set
 * is reported as `UNKNOWN` (fail-closed).
 */
const SQL_KNOWN_VERBS: ReadonlySet<string> = new Set([
  'SELECT',
  'INSERT',
  'UPDATE',
  'DELETE',
  'DROP',
  'TRUNCATE',
  'ALTER',
  'CREATE',
  'GRANT',
  'REVOKE',
  'MERGE',
  'CALL',
  'EXECUTE',
  'EXPLAIN',
  'WITH',
  'REPLACE',
  'RENAME',
  'COMMENT',
]);

interface SqlFacets extends Record<string, unknown> {
  verb: string;
  target: string;
  tables: string;
  functions: string;
}

const EMPTY_SQL_FACETS: SqlFacets = { verb: '', target: '', tables: '', functions: '' };
const UNKNOWN_SQL_FACETS: SqlFacets = {
  verb: 'UNKNOWN',
  target: '',
  tables: '',
  functions: '',
};

/**
 * Best-effort regex tokenizer used when no AST parser is available.
 *
 * This intentionally avoids pulling in a heavy SQL grammar dependency. It is
 * accurate enough for the wire-protocol policy use case (verb + first table)
 * and matches the Python implementation's exposed fields. For complex SQL
 * (CTEs, subqueries, dialect-specific syntax) callers should register their
 * own extractor backed by a full parser such as `node-sql-parser`.
 */
function regexExtractSql(rawQuery: string): SqlFacets {
  const query = stripSqlComments(rawQuery).trim();
  if (!query) return { ...EMPTY_SQL_FACETS };

  // First non-whitespace word is the verb.
  const verbMatch = query.match(/^\s*([A-Za-z]+)/);
  if (!verbMatch) return { ...UNKNOWN_SQL_FACETS };
  const verbRaw = verbMatch[1].toUpperCase();
  const verb = SQL_KNOWN_VERBS.has(verbRaw) ? verbRaw : 'UNKNOWN';

  const tables = extractTables(query, verb);
  const functions = extractFunctions(query);
  const target = tables[0] ?? '';

  return {
    verb,
    target,
    tables: tables.join(','),
    functions: functions.join(','),
  };
}

function stripSqlComments(sql: string): string {
  // Strip /* ... */ and -- line comments. Keep semantics simple.
  return sql
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/--[^\n\r]*/g, ' ');
}

const IDENT_PART = '(?:[A-Za-z_][A-Za-z0-9_]*|"[^"]+"|`[^`]+`|\\[[^\\]]+\\])';
const IDENT = `(${IDENT_PART}(?:\\.${IDENT_PART})*)`;

function extractTables(query: string, verb: string): string[] {
  const found: string[] = [];
  const patterns: RegExp[] = [];

  // Generic clauses across most verbs.
  patterns.push(new RegExp(`\\bFROM\\s+${IDENT}`, 'gi'));
  patterns.push(new RegExp(`\\bJOIN\\s+${IDENT}`, 'gi'));
  patterns.push(new RegExp(`\\bINTO\\s+${IDENT}`, 'gi'));
  patterns.push(new RegExp(`\\bUPDATE\\s+${IDENT}`, 'gi'));

  // Verb-specific patterns for DDL/DCL where the target follows the verb directly.
  if (
    verb === 'DROP' ||
    verb === 'TRUNCATE' ||
    verb === 'ALTER' ||
    verb === 'CREATE' ||
    verb === 'RENAME'
  ) {
    // e.g. DROP TABLE foo, ALTER TABLE foo, CREATE INDEX ... ON foo
    patterns.push(
      new RegExp(
        `\\b${verb}\\s+(?:TABLE|VIEW|INDEX|SEQUENCE|SCHEMA|DATABASE|TRIGGER|FUNCTION|PROCEDURE)?\\s*(?:IF\\s+(?:NOT\\s+)?EXISTS\\s+)?${IDENT}`,
        'gi',
      ),
    );
    patterns.push(new RegExp(`\\bON\\s+${IDENT}`, 'gi'));
  }

  if (verb === 'GRANT' || verb === 'REVOKE') {
    // GRANT/REVOKE ... ON <object> TO/FROM <principal>
    patterns.push(new RegExp(`\\bON\\s+(?:TABLE\\s+)?${IDENT}`, 'gi'));
  }

  const seen = new Set<string>();
  for (const re of patterns) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(query)) !== null) {
      const ident = normalizeIdent(m[1]);
      if (ident && !seen.has(ident)) {
        seen.add(ident);
        found.push(ident);
      }
    }
  }

  return found;
}

const FUNC_RE = /\b([A-Za-z_][A-Za-z0-9_]*)\s*\(/g;

// Reserved words that look like function calls syntactically but aren't.
const FUNC_DENYLIST: ReadonlySet<string> = new Set([
  'VALUES',
  'IN',
  'EXISTS',
  'ANY',
  'ALL',
  'SOME',
  'CAST',
  'CASE',
  'IF',
  'DISTINCT',
  'ON',
  'USING',
  'WHEN',
  'THEN',
  'ELSE',
  'AND',
  'OR',
  'NOT',
]);

function extractFunctions(query: string): string[] {
  const found: string[] = [];
  const seen = new Set<string>();
  let m: RegExpExecArray | null;
  while ((m = FUNC_RE.exec(query)) !== null) {
    const name = m[1].toUpperCase();
    if (FUNC_DENYLIST.has(name)) continue;
    if (!seen.has(name)) {
      seen.add(name);
      found.push(name);
    }
  }
  return found;
}

function normalizeIdent(ident: string): string {
  // Split into parts on dots that are outside any quote/bracket pair, then
  // take the last segment and strip surrounding quotes/brackets. Matches
  // Python sqlglot's `Table.name` (unqualified name).
  const s = ident.trim();
  const parts: string[] = [];
  let depth: '' | '"' | '`' | ']' = '';
  let buf = '';
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (depth === '') {
      if (ch === '"') {
        depth = '"';
        buf += ch;
      } else if (ch === '`') {
        depth = '`';
        buf += ch;
      } else if (ch === '[') {
        depth = ']';
        buf += ch;
      } else if (ch === '.') {
        parts.push(buf);
        buf = '';
      } else {
        buf += ch;
      }
    } else {
      buf += ch;
      if (
        (depth === '"' && ch === '"') ||
        (depth === '`' && ch === '`') ||
        (depth === ']' && ch === ']')
      ) {
        depth = '';
      }
    }
  }
  parts.push(buf);
  let last = parts[parts.length - 1].trim();
  if (
    (last.startsWith('"') && last.endsWith('"')) ||
    (last.startsWith('`') && last.endsWith('`'))
  ) {
    last = last.slice(1, -1);
  } else if (last.startsWith('[') && last.endsWith(']')) {
    last = last.slice(1, -1);
  }
  return last;
}

/**
 * Public SQL facet extractor. Reads `sqlCtx.query` and returns
 * `{ verb, target, tables, functions }`.
 *
 * Empty/missing query → all-empty fields.
 * Unrecognized verb → `verb: 'UNKNOWN'`, other fields empty.
 */
export function extractSqlFacets(sqlCtx: Record<string, unknown>): SqlFacets {
  const raw = sqlCtx.query;
  if (typeof raw !== 'string' || raw.trim() === '') {
    return { ...EMPTY_SQL_FACETS };
  }
  try {
    return regexExtractSql(raw);
  } catch {
    return { ...UNKNOWN_SQL_FACETS };
  }
}

// ── Kubernetes facets ───────────────────────────────────────────────────────

const METHOD_TO_VERB_NAMED: Readonly<Record<string, string>> = {
  GET: 'get',
  DELETE: 'delete',
  PUT: 'update',
  PATCH: 'patch',
  POST: 'create',
  HEAD: 'get',
};

const METHOD_TO_VERB_COLLECTION: Readonly<Record<string, string>> = {
  GET: 'list',
  POST: 'create',
  DELETE: 'deletecollection',
  PUT: 'update',
  PATCH: 'patch',
  HEAD: 'list',
};

interface K8sPattern {
  re: RegExp;
  groups: ReadonlyArray<'namespace' | 'resource' | 'name' | 'subresource'>;
}

// Ordered most specific first. Matches Python's _K8S_PATH_PATTERNS.
const K8S_PATH_PATTERNS: ReadonlyArray<K8sPattern> = [
  {
    re: /^\/api\/[^/]+\/namespaces\/([^/]+)\/([^/]+)\/([^/]+)\/([^/]+)\/?$/,
    groups: ['namespace', 'resource', 'name', 'subresource'],
  },
  {
    re: /^\/apis\/[^/]+\/[^/]+\/namespaces\/([^/]+)\/([^/]+)\/([^/]+)\/([^/]+)\/?$/,
    groups: ['namespace', 'resource', 'name', 'subresource'],
  },
  {
    re: /^\/api\/[^/]+\/namespaces\/([^/]+)\/([^/]+)\/([^/]+)\/?$/,
    groups: ['namespace', 'resource', 'name'],
  },
  {
    re: /^\/apis\/[^/]+\/[^/]+\/namespaces\/([^/]+)\/([^/]+)\/([^/]+)\/?$/,
    groups: ['namespace', 'resource', 'name'],
  },
  {
    re: /^\/api\/[^/]+\/namespaces\/([^/]+)\/([^/]+)\/?$/,
    groups: ['namespace', 'resource'],
  },
  {
    re: /^\/apis\/[^/]+\/[^/]+\/namespaces\/([^/]+)\/([^/]+)\/?$/,
    groups: ['namespace', 'resource'],
  },
  {
    re: /^\/api\/[^/]+\/([^/]+)\/([^/]+)\/?$/,
    groups: ['resource', 'name'],
  },
  {
    re: /^\/apis\/[^/]+\/[^/]+\/([^/]+)\/([^/]+)\/?$/,
    groups: ['resource', 'name'],
  },
  {
    re: /^\/api\/[^/]+\/([^/]+)\/?$/,
    groups: ['resource'],
  },
  {
    re: /^\/apis\/[^/]+\/[^/]+\/([^/]+)\/?$/,
    groups: ['resource'],
  },
];

interface K8sFacets extends Record<string, unknown> {
  verb: string;
  resource: string;
  namespace: string;
  name: string;
  subresource: string;
}

const EMPTY_K8S_FACETS: K8sFacets = {
  verb: '',
  resource: '',
  namespace: '',
  name: '',
  subresource: '',
};

/**
 * Public Kubernetes facet extractor. Reads `k8sCtx.method` and `k8sCtx.path`
 * and returns `{ verb, resource, namespace, name, subresource }`.
 */
export function extractK8sFacets(k8sCtx: Record<string, unknown>): K8sFacets {
  const methodRaw = k8sCtx.method;
  const pathRaw = k8sCtx.path;
  const method = typeof methodRaw === 'string' ? methodRaw.toUpperCase() : '';
  const path = typeof pathRaw === 'string' ? pathRaw : '';

  const result: K8sFacets = { ...EMPTY_K8S_FACETS };
  if (!path) return result;

  let matched: Partial<Record<'namespace' | 'resource' | 'name' | 'subresource', string>> = {};
  for (const { re, groups } of K8S_PATH_PATTERNS) {
    const m = path.match(re);
    if (m) {
      const captured: Partial<Record<string, string>> = {};
      groups.forEach((g, i) => {
        captured[g] = m[i + 1];
      });
      matched = captured;
      break;
    }
  }

  result.resource = matched.resource ?? '';
  result.namespace = matched.namespace ?? '';
  result.name = matched.name ?? '';
  result.subresource = matched.subresource ?? '';

  const hasName = result.name !== '';
  if (method) {
    const table = hasName ? METHOD_TO_VERB_NAMED : METHOD_TO_VERB_COLLECTION;
    result.verb = table[method] ?? method.toLowerCase();
  }

  return result;
}

// ── Default registry & top-level API ───────────────────────────────────────

/**
 * Module-level registry pre-loaded with SQL and Kubernetes extractors.
 * Import it to add support for new protocols via `register()`.
 */
export const defaultRegistry = new FacetRegistry();
defaultRegistry.register('sql', extractSqlFacets);
defaultRegistry.register('k8s', extractK8sFacets);

/**
 * Enrich a policy evaluation context with wire-protocol facets.
 *
 * Uses the supplied registry, or `defaultRegistry` if none is given.
 * Mutates `context` in place and returns it for chaining.
 */
export function extractProtocolFacets(
  context: Record<string, unknown>,
  registry: FacetRegistry = defaultRegistry,
): Record<string, unknown> {
  return registry.extract(context);
}
