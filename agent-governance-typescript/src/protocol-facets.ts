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

  /**
   * Run all registered extractors against `context`. Mutates the top-level
   * `context` map (replacing the slot for each registered key with a fresh
   * merged copy) but does NOT mutate the caller's nested sub-objects, so
   * passing the same sub-object alias into multiple evaluations is safe.
   */
  extract(context: Record<string, unknown>): Record<string, unknown> {
    for (const { key, extractor } of this.extractors) {
      const sub = context[key];
      if (!isPlainObject(sub)) continue;
      try {
        // Hand the extractor a defensive copy so a buggy implementation
        // cannot mutate the caller's input through the argument.
        const facets = extractor({ ...sub });
        if (facets && typeof facets === 'object') {
          // Replace the slot with a merged copy rather than mutating
          // `sub` in place, so the caller's original sub-object (which
          // may be aliased elsewhere) is left untouched.
          context[key] = { ...sub, ...facets };
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
  const stripped = stripSqlComments(rawQuery).trim();
  if (!stripped) return { ...EMPTY_SQL_FACETS };

  // Multi-statement guard: fail closed if the input contains more than one
  // meaningful statement (ignoring trailing semicolons and empties). A single
  // attacker-supplied query like `SELECT 1; DROP TABLE x` must not be
  // classified as `SELECT`.
  const statements = splitSqlStatements(stripped);
  if (statements.length > 1) {
    return { ...UNKNOWN_SQL_FACETS };
  }
  const query = statements[0] ?? stripped;

  // First non-whitespace word is the surface verb.
  const verbMatch = query.match(/^\s*([A-Za-z]+)/);
  if (!verbMatch) return { ...UNKNOWN_SQL_FACETS };
  const surfaceVerb = verbMatch[1].toUpperCase();

  // CTE handling: `WITH ... <verb> ...` should be classified by the underlying
  // DML verb, not by the `WITH` keyword. Matches Python sqlglot which exposes
  // the inner statement type for `WITH` queries.
  let verb: string;
  if (surfaceVerb === 'WITH') {
    verb = detectCteInnerVerb(query);
  } else {
    verb = SQL_KNOWN_VERBS.has(surfaceVerb) ? surfaceVerb : 'UNKNOWN';
  }

  const tables = extractTables(query, verb);
  const functions = extractFunctions(query);
  const target = pickTarget(query, verb, tables);

  return {
    verb,
    target,
    tables: tables.join(','),
    functions: functions.join(','),
  };
}

/**
 * Split SQL on top-level semicolons (semicolons outside of quoted strings).
 * Trailing empty/whitespace segments are dropped.
 */
function splitSqlStatements(sql: string): string[] {
  const out: string[] = [];
  let buf = '';
  let quote: '' | "'" | '"' | '`' = '';
  for (let i = 0; i < sql.length; i++) {
    const ch = sql[i];
    if (quote) {
      buf += ch;
      if (ch === quote) {
        // Handle SQL doubled-quote escape ('' or "")
        if (sql[i + 1] === quote) {
          buf += sql[++i];
        } else {
          quote = '';
        }
      }
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') {
      quote = ch as '"' | "'" | '`';
      buf += ch;
      continue;
    }
    if (ch === ';') {
      const t = buf.trim();
      if (t) out.push(t);
      buf = '';
      continue;
    }
    buf += ch;
  }
  const tail = buf.trim();
  if (tail) out.push(tail);
  return out;
}

/**
 * For a CTE-prefixed query (`WITH ... AS (...) <verb> ...`), find the first
 * DML keyword that appears at top-level paren depth (i.e. not inside a CTE
 * body or subquery). Falls back to SELECT because every CTE must terminate
 * in one of SELECT/INSERT/UPDATE/DELETE/MERGE.
 */
function detectCteInnerVerb(query: string): string {
  const candidates = new Set(['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'MERGE']);
  let depth = 0;
  let quote: '' | "'" | '"' | '`' = '';
  let token = '';
  let sawFirstWord = false;
  for (let i = 0; i <= query.length; i++) {
    const ch = i < query.length ? query[i] : ' ';
    if (quote) {
      if (ch === quote) {
        if (query[i + 1] === quote) {
          i++;
        } else {
          quote = '';
        }
      }
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') {
      quote = ch as '"' | "'" | '`';
      continue;
    }
    if (ch === '(') {
      depth++;
      token = '';
      continue;
    }
    if (ch === ')') {
      depth = Math.max(0, depth - 1);
      token = '';
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      token += ch;
      continue;
    }
    if (token) {
      if (depth === 0) {
        const up = token.toUpperCase();
        // Skip the leading WITH itself.
        if (!sawFirstWord && up === 'WITH') {
          sawFirstWord = true;
        } else if (candidates.has(up)) {
          return up;
        }
      }
      token = '';
    }
  }
  return 'SELECT';
}

/**
 * Verb-aware target picker so `INSERT INTO target SELECT ... FROM src` and
 * `UPDATE target SET ... FROM src` resolve `sql.target` to the written object,
 * not the read-from one.
 */
function pickTarget(query: string, verb: string, tables: string[]): string {
  let m: RegExpMatchArray | null = null;
  switch (verb) {
    case 'INSERT':
    case 'MERGE':
      m = query.match(new RegExp(`\\bINTO\\s+${IDENT}`, 'i'));
      break;
    case 'UPDATE':
      m = query.match(new RegExp(`\\bUPDATE\\s+${IDENT}`, 'i'));
      break;
    case 'DELETE':
      m = query.match(new RegExp(`\\bDELETE\\s+FROM\\s+${IDENT}`, 'i'));
      if (!m) m = query.match(new RegExp(`\\bFROM\\s+${IDENT}`, 'i'));
      break;
    case 'DROP':
    case 'TRUNCATE':
    case 'ALTER':
    case 'CREATE':
    case 'RENAME':
      m = query.match(
        new RegExp(
          `\\b${verb}\\s+(?:TABLE|VIEW|INDEX|SEQUENCE|SCHEMA|DATABASE|TRIGGER|FUNCTION|PROCEDURE)?\\s*(?:IF\\s+(?:NOT\\s+)?EXISTS\\s+)?${IDENT}`,
          'i',
        ),
      );
      break;
    case 'GRANT':
    case 'REVOKE':
      m = query.match(new RegExp(`\\bON\\s+(?:TABLE\\s+)?${IDENT}`, 'i'));
      break;
    default:
      // SELECT, WITH-as-SELECT, etc.: first FROM target.
      m = query.match(new RegExp(`\\bFROM\\s+${IDENT}`, 'i'));
      break;
  }
  if (m && m[1]) {
    return normalizeIdent(m[1]);
  }
  return tables[0] ?? '';
}

/**
 * Strip `/* ... *\/` and `-- ...` SQL comments in a quote-aware way.
 *
 * A naive regex strip would corrupt inputs like `SELECT '--'; DROP TABLE x`
 * (the `--` inside the string literal would be treated as a line comment
 * and the trailing `DROP` would be silently consumed) and, in the case of
 * the block-comment pattern, is susceptible to polynomial backtracking on
 * adversarial input (a CodeQL warning). This single-pass walker respects
 * single, double and backtick quoting (with SQL doubled-quote escapes)
 * before recognising comment markers.
 */
function stripSqlComments(sql: string): string {
  let out = '';
  let quote: '' | "'" | '"' | '`' = '';
  let i = 0;
  while (i < sql.length) {
    const c = sql[i];
    if (quote) {
      out += c;
      if (c === quote) {
        if (sql[i + 1] === quote) {
          // Escaped doubled quote
          out += sql[i + 1];
          i += 2;
          continue;
        }
        quote = '';
      }
      i++;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') {
      quote = c as "'" | '"' | '`';
      out += c;
      i++;
      continue;
    }
    if (c === '-' && sql[i + 1] === '-') {
      i += 2;
      while (i < sql.length && sql[i] !== '\n' && sql[i] !== '\r') i++;
      out += ' ';
      continue;
    }
    if (c === '/' && sql[i + 1] === '*') {
      i += 2;
      while (i + 1 < sql.length && !(sql[i] === '*' && sql[i + 1] === '/')) i++;
      if (i + 1 < sql.length) i += 2;
      out += ' ';
      continue;
    }
    out += c;
    i++;
  }
  return out;
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
  // Use matchAll on a fresh per-call regex so the module-scoped /g state
  // can never leak between calls (this is otherwise a common foot-gun).
  const re = /\b([A-Za-z_][A-Za-z0-9_]*)\s*\(/g;
  const found: string[] = [];
  const seen = new Set<string>();
  for (const m of query.matchAll(re)) {
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
  isWatch: boolean;
}

// Ordered most specific first. Matches Python's _K8S_PATH_PATTERNS, plus
// explicit `watch` and proxy-tail handling (namespaced and cluster-scoped).
const K8S_PATH_PATTERNS: ReadonlyArray<K8sPattern> = [
  // Watch — namespaced collection
  {
    re: /^\/api\/[^/]+\/watch\/namespaces\/([^/]+)\/([^/]+)\/?$/,
    groups: ['namespace', 'resource'],
    isWatch: true,
  },
  {
    re: /^\/apis\/[^/]+\/[^/]+\/watch\/namespaces\/([^/]+)\/([^/]+)\/?$/,
    groups: ['namespace', 'resource'],
    isWatch: true,
  },
  // Watch — namespaced named object
  {
    re: /^\/api\/[^/]+\/watch\/namespaces\/([^/]+)\/([^/]+)\/([^/]+)\/?$/,
    groups: ['namespace', 'resource', 'name'],
    isWatch: true,
  },
  {
    re: /^\/apis\/[^/]+\/[^/]+\/watch\/namespaces\/([^/]+)\/([^/]+)\/([^/]+)\/?$/,
    groups: ['namespace', 'resource', 'name'],
    isWatch: true,
  },
  // Watch — cluster-scoped
  { re: /^\/api\/[^/]+\/watch\/([^/]+)\/?$/, groups: ['resource'], isWatch: true },
  { re: /^\/apis\/[^/]+\/[^/]+\/watch\/([^/]+)\/?$/, groups: ['resource'], isWatch: true },
  // Proxy tail (namespaced): pods/<name>/proxy/<...> → subresource = proxy
  {
    re: /^\/api\/[^/]+\/namespaces\/([^/]+)\/([^/]+)\/([^/]+)\/(proxy)(?:\/.*)?$/,
    groups: ['namespace', 'resource', 'name', 'subresource'],
    isWatch: false,
  },
  {
    re: /^\/apis\/[^/]+\/[^/]+\/namespaces\/([^/]+)\/([^/]+)\/([^/]+)\/(proxy)(?:\/.*)?$/,
    groups: ['namespace', 'resource', 'name', 'subresource'],
    isWatch: false,
  },
  // Generic namespaced — most specific first
  {
    re: /^\/api\/[^/]+\/namespaces\/([^/]+)\/([^/]+)\/([^/]+)\/([^/]+)\/?$/,
    groups: ['namespace', 'resource', 'name', 'subresource'],
    isWatch: false,
  },
  {
    re: /^\/apis\/[^/]+\/[^/]+\/namespaces\/([^/]+)\/([^/]+)\/([^/]+)\/([^/]+)\/?$/,
    groups: ['namespace', 'resource', 'name', 'subresource'],
    isWatch: false,
  },
  {
    re: /^\/api\/[^/]+\/namespaces\/([^/]+)\/([^/]+)\/([^/]+)\/?$/,
    groups: ['namespace', 'resource', 'name'],
    isWatch: false,
  },
  {
    re: /^\/apis\/[^/]+\/[^/]+\/namespaces\/([^/]+)\/([^/]+)\/([^/]+)\/?$/,
    groups: ['namespace', 'resource', 'name'],
    isWatch: false,
  },
  {
    re: /^\/api\/[^/]+\/namespaces\/([^/]+)\/([^/]+)\/?$/,
    groups: ['namespace', 'resource'],
    isWatch: false,
  },
  {
    re: /^\/apis\/[^/]+\/[^/]+\/namespaces\/([^/]+)\/([^/]+)\/?$/,
    groups: ['namespace', 'resource'],
    isWatch: false,
  },
  // Cluster-scoped (resource, name, subresource): e.g. /api/v1/nodes/n1/status
  {
    re: /^\/api\/[^/]+\/([^/]+)\/([^/]+)\/([^/]+)\/?$/,
    groups: ['resource', 'name', 'subresource'],
    isWatch: false,
  },
  {
    re: /^\/apis\/[^/]+\/[^/]+\/([^/]+)\/([^/]+)\/([^/]+)\/?$/,
    groups: ['resource', 'name', 'subresource'],
    isWatch: false,
  },
  // Cluster-scoped proxy tail
  {
    re: /^\/api\/[^/]+\/([^/]+)\/([^/]+)\/(proxy)(?:\/.*)?$/,
    groups: ['resource', 'name', 'subresource'],
    isWatch: false,
  },
  {
    re: /^\/apis\/[^/]+\/[^/]+\/([^/]+)\/([^/]+)\/(proxy)(?:\/.*)?$/,
    groups: ['resource', 'name', 'subresource'],
    isWatch: false,
  },
  { re: /^\/api\/[^/]+\/([^/]+)\/([^/]+)\/?$/, groups: ['resource', 'name'], isWatch: false },
  {
    re: /^\/apis\/[^/]+\/[^/]+\/([^/]+)\/([^/]+)\/?$/,
    groups: ['resource', 'name'],
    isWatch: false,
  },
  { re: /^\/api\/[^/]+\/([^/]+)\/?$/, groups: ['resource'], isWatch: false },
  { re: /^\/apis\/[^/]+\/[^/]+\/([^/]+)\/?$/, groups: ['resource'], isWatch: false },
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
  const rawPath = typeof pathRaw === 'string' ? pathRaw : '';

  const result: K8sFacets = { ...EMPTY_K8S_FACETS };
  if (!rawPath) return result;

  // Strip query/fragment before pattern matching so resources or namespaces
  // whose names contain "watch" cannot spoof the verb signal, and so
  // ?watch=true can be detected independently of path.
  let pathOnly = rawPath;
  let query = '';
  const qIdx = pathOnly.indexOf('?');
  if (qIdx >= 0) {
    query = pathOnly.slice(qIdx + 1);
    pathOnly = pathOnly.slice(0, qIdx);
  }
  const hIdx = pathOnly.indexOf('#');
  if (hIdx >= 0) pathOnly = pathOnly.slice(0, hIdx);

  let matched: Partial<Record<'namespace' | 'resource' | 'name' | 'subresource', string>> = {};
  let matchedIsWatch = false;
  for (const { re, groups, isWatch } of K8S_PATH_PATTERNS) {
    const m = pathOnly.match(re);
    if (m) {
      const captured: Partial<Record<string, string>> = {};
      groups.forEach((g, i) => {
        captured[g] = m[i + 1];
      });
      matched = captured;
      matchedIsWatch = isWatch;
      break;
    }
  }

  result.resource = matched.resource ?? '';
  result.namespace = matched.namespace ?? '';
  result.name = matched.name ?? '';
  result.subresource = matched.subresource ?? '';

  // Honor ?watch=true as an alternate watch signal.
  let queryIsWatch = false;
  if (query) {
    for (const kv of query.split('&')) {
      const eq = kv.indexOf('=');
      if (eq < 0) continue;
      if (kv.slice(0, eq) === 'watch') {
        const v = kv.slice(eq + 1);
        if (v === 'true' || v === '1' || v === 'True') {
          queryIsWatch = true;
          break;
        }
      }
    }
  }

  // `watch` is a read-only verb. Only emit it for GET/HEAD or empty
  // method, so a write method with ?watch=true cannot be silently
  // classified as a benign watch.
  const methodAllowsWatch = method === '' || method === 'GET' || method === 'HEAD';
  const isWatch = (matchedIsWatch || queryIsWatch) && methodAllowsWatch;
  const hasName = result.name !== '';
  if (isWatch) {
    result.verb = 'watch';
  } else if (method) {
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
