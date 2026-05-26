// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import {
  FacetRegistry,
  defaultRegistry,
  extractProtocolFacets,
  extractSqlFacets,
  extractK8sFacets,
} from '../src/protocol-facets';
import { PolicyEngine } from '../src/policy';
import { ConflictResolutionStrategy } from '../src/types';

describe('FacetRegistry', () => {
  it('registers and runs a custom extractor in place', () => {
    const registry = new FacetRegistry();
    registry.register('redis', (ctx) => ({
      verb: String(ctx.command ?? '').toUpperCase(),
      key: String(ctx.key ?? ''),
    }));

    const context = { redis: { command: 'flushall', key: '' } };
    const result = registry.extract(context);

    expect(result).toBe(context); // mutates in place
    expect(context.redis).toMatchObject({
      command: 'flushall',
      verb: 'FLUSHALL',
      key: '',
    });
  });

  it('skips missing or non-object sub-contexts safely', () => {
    const registry = new FacetRegistry();
    registry.register('sql', () => ({ verb: 'SELECT' }));

    const a = registry.extract({});
    expect(a).toEqual({});

    const b = registry.extract({ sql: 'not an object' });
    expect(b).toEqual({ sql: 'not an object' });

    const c = registry.extract({ sql: null });
    expect(c).toEqual({ sql: null });

    const d = registry.extract({ sql: [1, 2, 3] });
    expect(d).toEqual({ sql: [1, 2, 3] });
  });

  it('swallows and logs extractor errors without blocking other extractors', () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    const registry = new FacetRegistry();
    registry.register('a', () => {
      throw new Error('boom');
    });
    registry.register('b', () => ({ ok: true }));

    const ctx = { a: { x: 1 }, b: { y: 2 } };
    registry.extract(ctx);

    expect((ctx.a as Record<string, unknown>).x).toBe(1); // untouched
    expect((ctx.b as Record<string, unknown>).ok).toBe(true);
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });

  it('default registry has sql and k8s pre-registered', () => {
    expect(defaultRegistry.size).toBeGreaterThanOrEqual(2);
  });
});

describe('extractSqlFacets', () => {
  it('returns empty fields for missing or blank queries', () => {
    expect(extractSqlFacets({})).toEqual({
      verb: '',
      target: '',
      tables: '',
      functions: '',
    });
    expect(extractSqlFacets({ query: '' })).toEqual({
      verb: '',
      target: '',
      tables: '',
      functions: '',
    });
    expect(extractSqlFacets({ query: '   ' })).toEqual({
      verb: '',
      target: '',
      tables: '',
      functions: '',
    });
  });

  it.each([
    ['SELECT * FROM users', 'SELECT', 'users'],
    ['select id from users', 'SELECT', 'users'],
    ['INSERT INTO orders (id) VALUES (1)', 'INSERT', 'orders'],
    ['UPDATE accounts SET balance = 0 WHERE id = 1', 'UPDATE', 'accounts'],
    ['DELETE FROM sessions WHERE expired = true', 'DELETE', 'sessions'],
    ['DROP TABLE production', 'DROP', 'production'],
    ['DROP TABLE IF EXISTS staging.payments', 'DROP', 'payments'],
    ['TRUNCATE TABLE audit_log', 'TRUNCATE', 'audit_log'],
    ['ALTER TABLE users ADD COLUMN age INT', 'ALTER', 'users'],
    ['CREATE TABLE foo (id INT)', 'CREATE', 'foo'],
    ['GRANT SELECT ON users TO bob', 'GRANT', 'users'],
    ['MERGE INTO dst USING src ON dst.id = src.id', 'MERGE', 'dst'],
  ])('parses verb+target for %s', (query, verb, target) => {
    const f = extractSqlFacets({ query });
    expect(f.verb).toBe(verb);
    expect(f.target).toBe(target);
    expect(f.tables.split(',')).toContain(target);
  });

  it('returns UNKNOWN verb for non-SQL or garbage input', () => {
    const f = extractSqlFacets({ query: 'WAT IS THIS' });
    expect(f.verb).toBe('UNKNOWN');
  });

  it('extracts multiple tables and joins them comma-separated', () => {
    const f = extractSqlFacets({
      query: 'SELECT * FROM orders JOIN users ON orders.user_id = users.id',
    });
    expect(f.verb).toBe('SELECT');
    expect(f.target).toBe('orders');
    expect(f.tables.split(',').sort()).toEqual(['orders', 'users']);
  });

  it('extracts function names uppercased and dedupes them', () => {
    const f = extractSqlFacets({
      query: "SELECT COUNT(id), Count(name), NOW() FROM users",
    });
    expect(f.functions.split(',')).toEqual(expect.arrayContaining(['COUNT', 'NOW']));
    // dedup
    expect(f.functions.split(',').filter((x) => x === 'COUNT').length).toBe(1);
  });

  it('does not classify SQL reserved tokens (VALUES, CAST, CASE) as functions', () => {
    const f = extractSqlFacets({
      query: "INSERT INTO t VALUES (CAST('1' AS INT))",
    });
    expect(f.functions.split(',').filter(Boolean)).not.toContain('VALUES');
    expect(f.functions.split(',').filter(Boolean)).not.toContain('CAST');
  });

  it('strips line and block comments before parsing', () => {
    const f = extractSqlFacets({
      query: "/* hello */ -- comment\n SELECT id FROM users -- trailing",
    });
    expect(f.verb).toBe('SELECT');
    expect(f.target).toBe('users');
  });

  it('strips schema qualifiers and quoting to match Python sqlglot table.name', () => {
    const f = extractSqlFacets({ query: 'SELECT * FROM "public"."users"' });
    expect(f.tables.split(',')).toContain('users');

    const g = extractSqlFacets({ query: 'SELECT * FROM `db`.`orders`' });
    expect(g.tables.split(',')).toContain('orders');

    const h = extractSqlFacets({ query: 'SELECT * FROM [dbo].[items]' });
    expect(h.tables.split(',')).toContain('items');
  });

  // ── Multi-statement / CTE / target-aware regression cases ────────────────

  it('fails closed to UNKNOWN for multi-statement input', () => {
    const f = extractSqlFacets({
      query: 'SELECT 1; DROP TABLE production',
    });
    expect(f.verb).toBe('UNKNOWN');
    expect(f.target).toBe('');
  });

  it('ignores trailing semicolons (still single statement)', () => {
    const f = extractSqlFacets({ query: 'SELECT * FROM users;' });
    expect(f.verb).toBe('SELECT');
    expect(f.target).toBe('users');
  });

  it('does not treat semicolons inside string literals as statement boundaries', () => {
    const f = extractSqlFacets({
      query: "SELECT * FROM users WHERE name = 'a;b'",
    });
    expect(f.verb).toBe('SELECT');
  });

  it('classifies a CTE-wrapped DELETE as DELETE, not WITH', () => {
    const f = extractSqlFacets({
      query: 'WITH stale AS (SELECT id FROM users WHERE inactive) DELETE FROM users WHERE id IN (SELECT id FROM stale)',
    });
    expect(f.verb).toBe('DELETE');
  });

  it('classifies a CTE-wrapped INSERT as INSERT', () => {
    const f = extractSqlFacets({
      query: 'WITH new_rows AS (SELECT 1 AS id) INSERT INTO audit (id) SELECT id FROM new_rows',
    });
    expect(f.verb).toBe('INSERT');
  });

  it('classifies a plain CTE+SELECT as SELECT', () => {
    const f = extractSqlFacets({
      query: 'WITH x AS (SELECT 1) SELECT * FROM x',
    });
    expect(f.verb).toBe('SELECT');
  });

  it('INSERT INTO target SELECT FROM src → target is written object', () => {
    const f = extractSqlFacets({
      query: 'INSERT INTO protected SELECT * FROM source',
    });
    expect(f.verb).toBe('INSERT');
    expect(f.target).toBe('protected');
    expect(f.tables.split(',').sort()).toEqual(['protected', 'source']);
  });

  it('UPDATE target FROM src → target is written object', () => {
    const f = extractSqlFacets({
      query: 'UPDATE protected SET val = src.val FROM source AS src WHERE protected.id = src.id',
    });
    expect(f.verb).toBe('UPDATE');
    expect(f.target).toBe('protected');
  });

  it('DELETE FROM target → target is the deleted-from table', () => {
    const f = extractSqlFacets({
      query: 'DELETE FROM protected WHERE id IN (SELECT id FROM staging)',
    });
    expect(f.verb).toBe('DELETE');
    expect(f.target).toBe('protected');
  });

  it('exposes sql.target to policy rules and denies on target match', () => {
    const engine = new PolicyEngine(undefined, ConflictResolutionStrategy.DenyOverrides);
    engine.loadYaml(`
apiVersion: governance.toolkit/v1
name: sql-target-guard
scope: global
default_action: allow
rules:
  - name: deny-writes-to-protected
    condition: "sql.target == 'protected'"
    ruleAction: deny
    priority: 100
`);
    const decision = engine.evaluatePolicy('did:example:agent1', {
      sql: { query: 'INSERT INTO protected SELECT * FROM staging' },
    });
    expect(decision.allowed).toBe(false);
    expect(decision.matchedRule).toBe('deny-writes-to-protected');
  });
});

describe('extractK8sFacets', () => {
  it('returns all-empty fields for missing path', () => {
    expect(extractK8sFacets({})).toEqual({
      verb: '',
      resource: '',
      namespace: '',
      name: '',
      subresource: '',
    });
  });

  it('parses cluster-scoped list (GET /api/v1/nodes)', () => {
    const f = extractK8sFacets({ method: 'GET', path: '/api/v1/nodes' });
    expect(f).toEqual({
      verb: 'list',
      resource: 'nodes',
      namespace: '',
      name: '',
      subresource: '',
    });
  });

  it('parses namespaced collection list', () => {
    const f = extractK8sFacets({
      method: 'GET',
      path: '/api/v1/namespaces/prod/pods',
    });
    expect(f).toMatchObject({
      verb: 'list',
      resource: 'pods',
      namespace: 'prod',
      name: '',
    });
  });

  it('parses namespaced named-object get', () => {
    const f = extractK8sFacets({
      method: 'GET',
      path: '/api/v1/namespaces/prod/pods/mypod',
    });
    expect(f).toMatchObject({
      verb: 'get',
      resource: 'pods',
      namespace: 'prod',
      name: 'mypod',
      subresource: '',
    });
  });

  it('parses subresource (pods/exec) under named object', () => {
    const f = extractK8sFacets({
      method: 'POST',
      path: '/api/v1/namespaces/prod/pods/mypod/exec',
    });
    expect(f).toMatchObject({
      resource: 'pods',
      namespace: 'prod',
      name: 'mypod',
      subresource: 'exec',
      verb: 'create',
    });
  });

  it('maps DELETE on a collection to deletecollection', () => {
    const f = extractK8sFacets({
      method: 'DELETE',
      path: '/api/v1/namespaces/prod/pods',
    });
    expect(f.verb).toBe('deletecollection');
  });

  it('maps DELETE on a named object to delete', () => {
    const f = extractK8sFacets({
      method: 'DELETE',
      path: '/api/v1/namespaces/prod/pods/p1',
    });
    expect(f.verb).toBe('delete');
  });

  it('handles non-core /apis group paths', () => {
    const f = extractK8sFacets({
      method: 'GET',
      path: '/apis/apps/v1/namespaces/prod/deployments/web',
    });
    expect(f).toMatchObject({
      verb: 'get',
      resource: 'deployments',
      namespace: 'prod',
      name: 'web',
    });
  });

  it('tolerates trailing slash', () => {
    const f = extractK8sFacets({
      method: 'GET',
      path: '/api/v1/namespaces/prod/pods/',
    });
    expect(f.resource).toBe('pods');
    expect(f.namespace).toBe('prod');
  });

  it('lowercases unknown HTTP methods', () => {
    const f = extractK8sFacets({
      method: 'OPTIONS',
      path: '/api/v1/namespaces/prod/pods',
    });
    expect(f.verb).toBe('options');
  });

  it('returns no verb if method is missing', () => {
    const f = extractK8sFacets({ path: '/api/v1/namespaces/prod/pods' });
    expect(f.verb).toBe('');
    expect(f.resource).toBe('pods');
  });

  // ── Watch / proxy / subresource regressions ──────────────────────────────

  it('parses cluster-scoped watch path → verb=watch', () => {
    const f = extractK8sFacets({
      method: 'GET',
      path: '/api/v1/watch/pods',
    });
    expect(f.verb).toBe('watch');
    expect(f.resource).toBe('pods');
    expect(f.namespace).toBe('');
  });

  it('parses namespaced watch collection path → verb=watch', () => {
    const f = extractK8sFacets({
      method: 'GET',
      path: '/api/v1/watch/namespaces/prod/pods',
    });
    expect(f.verb).toBe('watch');
    expect(f.namespace).toBe('prod');
    expect(f.resource).toBe('pods');
  });

  it('parses namespaced watch named path → verb=watch', () => {
    const f = extractK8sFacets({
      method: 'GET',
      path: '/api/v1/watch/namespaces/prod/pods/web',
    });
    expect(f.verb).toBe('watch');
    expect(f.name).toBe('web');
  });

  it('parses pod proxy tail → subresource=proxy', () => {
    const f = extractK8sFacets({
      method: 'GET',
      path: '/api/v1/namespaces/prod/pods/web/proxy/healthz',
    });
    expect(f.subresource).toBe('proxy');
    expect(f.resource).toBe('pods');
    expect(f.name).toBe('web');
    expect(f.namespace).toBe('prod');
  });

  it('parses pod log subresource', () => {
    const f = extractK8sFacets({
      method: 'GET',
      path: '/api/v1/namespaces/prod/pods/web/log',
    });
    expect(f.subresource).toBe('log');
    expect(f.resource).toBe('pods');
    expect(f.name).toBe('web');
  });

  it('parses status subresource for non-core /apis path', () => {
    const f = extractK8sFacets({
      method: 'PATCH',
      path: '/apis/apps/v1/namespaces/prod/deployments/web/status',
    });
    expect(f.subresource).toBe('status');
    expect(f.verb).toBe('patch');
  });
});

describe('extractProtocolFacets (default registry)', () => {
  it('merges sql.* fields into context.sql', () => {
    const ctx: Record<string, unknown> = {
      sql: { query: 'DROP TABLE production' },
    };
    extractProtocolFacets(ctx);
    expect(ctx.sql).toMatchObject({
      verb: 'DROP',
      target: 'production',
    });
  });

  it('merges k8s.* fields into context.k8s', () => {
    const ctx: Record<string, unknown> = {
      k8s: { method: 'DELETE', path: '/api/v1/namespaces/prod/pods/p1' },
    };
    extractProtocolFacets(ctx);
    expect(ctx.k8s).toMatchObject({
      verb: 'delete',
      namespace: 'prod',
      resource: 'pods',
      name: 'p1',
    });
  });

  it('is idempotent (running twice yields the same result)', () => {
    const ctx: Record<string, unknown> = {
      sql: { query: 'SELECT 1 FROM dual' },
    };
    extractProtocolFacets(ctx);
    const snapshot = JSON.parse(JSON.stringify(ctx));
    extractProtocolFacets(ctx);
    expect(ctx).toEqual(snapshot);
  });
});

// ── Integration: PolicyEngine.evaluatePolicy enriches context ──────────────

describe('PolicyEngine integration with protocol facets', () => {
  function loadPolicy(engine: PolicyEngine, yamlContent: string) {
    return engine.loadYaml(yamlContent);
  }

  it('denies destructive SQL via sql.verb rule', () => {
    const engine = new PolicyEngine(undefined, ConflictResolutionStrategy.DenyOverrides);
    loadPolicy(
      engine,
      `
apiVersion: governance.toolkit/v1
name: sql-guard
scope: global
default_action: allow
rules:
  - name: deny-destructive-sql
    condition: "sql.verb in ['DROP', 'TRUNCATE', 'DELETE']"
    ruleAction: deny
    priority: 100
`,
    );
    const decision = engine.evaluatePolicy('did:example:agent1', {
      sql: { query: 'DROP TABLE production' },
    });
    expect(decision.allowed).toBe(false);
    expect(decision.action).toBe('deny');
    expect(decision.matchedRule).toBe('deny-destructive-sql');
  });

  it('allows read-only SELECT via sql.verb rule', () => {
    const engine = new PolicyEngine(undefined, ConflictResolutionStrategy.DenyOverrides);
    loadPolicy(
      engine,
      `
apiVersion: governance.toolkit/v1
name: sql-guard
scope: global
default_action: deny
rules:
  - name: allow-select
    condition: "sql.verb == 'SELECT'"
    ruleAction: allow
    priority: 5
  - name: deny-destructive
    condition: "sql.verb in ['DROP', 'TRUNCATE', 'DELETE']"
    ruleAction: deny
    priority: 100
`,
    );
    const decision = engine.evaluatePolicy('did:example:agent1', {
      sql: { query: 'SELECT * FROM users' },
    });
    expect(decision.allowed).toBe(true);
    expect(decision.matchedRule).toBe('allow-select');
  });

  it('denies pod exec via k8s.subresource', () => {
    const engine = new PolicyEngine(undefined, ConflictResolutionStrategy.DenyOverrides);
    loadPolicy(
      engine,
      `
apiVersion: governance.toolkit/v1
name: k8s-guard
scope: global
default_action: allow
rules:
  - name: deny-exec
    condition: "k8s.subresource == 'exec'"
    ruleAction: deny
    priority: 100
`,
    );
    const decision = engine.evaluatePolicy('did:example:agent1', {
      k8s: { method: 'POST', path: '/api/v1/namespaces/prod/pods/web/exec' },
    });
    expect(decision.allowed).toBe(false);
    expect(decision.matchedRule).toBe('deny-exec');
  });

  it('denies writes targeting production namespace', () => {
    const engine = new PolicyEngine(undefined, ConflictResolutionStrategy.DenyOverrides);
    loadPolicy(
      engine,
      `
apiVersion: governance.toolkit/v1
name: k8s-guard
scope: global
default_action: allow
rules:
  - name: deny-production
    condition: "k8s.namespace == 'production'"
    ruleAction: deny
    priority: 110
`,
    );
    const decision = engine.evaluatePolicy('did:example:agent1', {
      k8s: { method: 'DELETE', path: '/api/v1/namespaces/production/pods/web' },
    });
    expect(decision.allowed).toBe(false);
  });

  it('does not fail when no sql/k8s context is present', () => {
    const engine = new PolicyEngine(undefined, ConflictResolutionStrategy.DenyOverrides);
    loadPolicy(
      engine,
      `
apiVersion: governance.toolkit/v1
name: simple
scope: global
default_action: allow
rules: []
`,
    );
    const decision = engine.evaluatePolicy('did:example:agent1', {});
    expect(decision.allowed).toBe(true);
  });

  it('does not mutate the caller-provided context or sub-object', () => {
    const engine = new PolicyEngine(undefined, ConflictResolutionStrategy.DenyOverrides);
    loadPolicy(
      engine,
      `
apiVersion: governance.toolkit/v1
name: noop
scope: global
default_action: allow
rules: []
`,
    );
    const sub = { query: 'SELECT 1' };
    const ctx: Record<string, unknown> = { sql: sub };
    engine.evaluatePolicy('did:example:agent1', ctx);

    // Caller's sub-object must not be mutated (no facets injected).
    expect(Object.keys(sub).sort()).toEqual(['query']);
    // Caller's outer dict must keep its original sub-object reference.
    expect(ctx.sql).toBe(sub);
  });
});

describe('regression: ReDoS / quote-aware comment stripping', () => {
  it('double-dash inside string literal does not hide injection', () => {
    // Naive `--[^\n]*` regex stripping would eat from `--';` through
    // to end-of-line and silently downgrade this to a single SELECT.
    const f = extractSqlFacets({
      query: "SELECT '--'; DROP TABLE production",
    });
    expect(f.verb).toBe('UNKNOWN');
  });

  it('block-comment marker inside string literal is preserved', () => {
    const f = extractSqlFacets({
      query: "SELECT '/* not a comment */' FROM users",
    });
    expect(f.verb).toBe('SELECT');
    expect(f.target).toBe('users');
  });
});

describe('K8s: query-string / fragment / cluster subresources / watch gating', () => {
  it('strips query string before path matching', () => {
    const f = extractK8sFacets({
      method: 'GET',
      path: '/api/v1/namespaces/prod/pods?fieldManager=test',
    });
    expect(f.resource).toBe('pods');
    expect(f.namespace).toBe('prod');
    expect(f.verb).toBe('list');
  });

  it('?watch=true on GET signals watch verb', () => {
    expect(
      extractK8sFacets({
        method: 'GET',
        path: '/api/v1/namespaces/prod/pods?watch=true',
      }).verb,
    ).toBe('watch');
  });

  it('?watch=true on POST must NOT yield watch (read-only verb)', () => {
    expect(
      extractK8sFacets({
        method: 'POST',
        path: '/api/v1/namespaces/prod/pods?watch=true',
      }).verb,
    ).not.toBe('watch');
  });

  it('namespace named "watch-test" does not spoof verb=watch', () => {
    const f = extractK8sFacets({
      method: 'GET',
      path: '/api/v1/namespaces/watch-test/pods',
    });
    expect(f.verb).toBe('list');
    expect(f.namespace).toBe('watch-test');
  });

  it('# fragment is stripped', () => {
    expect(
      extractK8sFacets({
        method: 'GET',
        path: '/api/v1/namespaces/prod/pods#anchor',
      }).resource,
    ).toBe('pods');
  });

  it('cluster-scoped subresource: /api/v1/nodes/n1/status', () => {
    const f = extractK8sFacets({
      method: 'PATCH',
      path: '/api/v1/nodes/node1/status',
    });
    expect(f.resource).toBe('nodes');
    expect(f.name).toBe('node1');
    expect(f.subresource).toBe('status');
  });

  it('cluster-scoped proxy tail', () => {
    const f = extractK8sFacets({
      method: 'GET',
      path: '/api/v1/nodes/node1/proxy/metrics',
    });
    expect(f.resource).toBe('nodes');
    expect(f.subresource).toBe('proxy');
  });
});
