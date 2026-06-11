// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { promises as fs } from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {
  CredentialInjector,
  CredentialProfile,
  CredentialVault,
  DENY_REASON,
  DenyReceipt,
  InjectionContext,
  PLACEHOLDER_RE,
  PolicyOutcome,
  VaultAuditEvent,
  auditDigest,
} from '../src/credential-vault';

describe('CredentialVault — admin surface', () => {
  let vault: CredentialVault;
  beforeEach(async () => {
    vault = new CredentialVault();
    await vault.put('github_pat', 'ghp_real_secret_value_xyz', 'bearer_token');
    await vault.put('db_password', 'p@ss-w0rd!', 'password');
  });

  it('put returns a handle and stable placeholder', async () => {
    const h = await vault.put('k1', 'v1');
    expect(h.name).toBe('k1');
    expect(h.placeholder()).toBe('{{cred:k1}}');
  });

  it('rejects bad names', async () => {
    await expect(vault.put('', 'v')).rejects.toThrow();
    await expect(vault.put('bad name', 'v')).rejects.toThrow();
    await expect(vault.put('a'.repeat(200), 'v')).rejects.toThrow();
  });

  it('listHandles never returns values', async () => {
    const names = await vault.listHandles();
    expect(names).toEqual(['db_password', 'github_pat']);
    for (const n of names) {
      const meta = await vault.getMetadata(n);
      expect(meta).not.toBeNull();
      expect(JSON.stringify(meta)).not.toContain('ghp_real');
    }
  });

  it('rotate preserves handle name and bumps version', async () => {
    const before = await vault.getMetadata('github_pat');
    expect(before!.version).toBe(1);
    const h = await vault.rotate('github_pat', 'ghp_new');
    const after = await vault.getMetadata('github_pat');
    expect(h.name).toBe('github_pat');
    expect(after!.version).toBe(2);
    expect(after!.rotatedAt).not.toBeNull();
  });

  it('rotate unknown throws', async () => {
    await expect(vault.rotate('nope', 'x')).rejects.toThrow();
  });

  it('delete returns presence flag', async () => {
    const first = await vault.delete('db_password');
    const second = await vault.delete('db_password');
    expect(first).toBe(true);
    expect(second).toBe(false);
  });
});

describe('Scoping', () => {
  let vault: CredentialVault;
  beforeEach(async () => {
    vault = new CredentialVault();
    await vault.put('github_pat', 'GHP-VALUE');
    await vault.put('db_password', 'DB-VALUE');
    vault.registerProfile(
      new CredentialProfile('did:web:agent-ci', {
        'github:read_issues': 'github_pat',
        'github:push_code': 'github_pat',
      }),
    );
    vault.registerProfile(
      new CredentialProfile('did:web:agent-analytics', { 'db:query': 'db_password' }),
    );
  });

  it('allows bound action', () => {
    expect(vault.checkAccess('did:web:agent-ci', 'github_pat', 'github:read_issues')).toBe(true);
  });

  it('denies unknown agent', () => {
    expect(vault.checkAccess('did:web:rogue', 'github_pat', 'github:read_issues')).toBe(false);
  });

  it('denies unbound action', () => {
    expect(vault.checkAccess('did:web:agent-ci', 'db_password', 'db:query')).toBe(false);
  });

  it('denies cross-action reuse (action-class scoping, not just agent)', () => {
    expect(vault.checkAccess('did:web:agent-analytics', 'db_password', 'db:admin')).toBe(false);
  });

  it('profile bindings are isolated from caller mutation', () => {
    const bindings: Record<string, string> = { a: 'h' };
    const p = new CredentialProfile('did:web:x', bindings);
    bindings.a = 'other';
    expect(p.capabilityFor('a')).toBe('h');
  });
});

describe('Injection', () => {
  let vault: CredentialVault;
  let injector: CredentialInjector;
  beforeEach(async () => {
    vault = new CredentialVault();
    await vault.put('github_pat', 'GHP-RESOLVED-VALUE');
    await vault.put('db_password', 'DBP-VALUE');
    vault.registerProfile(
      new CredentialProfile('did:web:agent-ci', {
        'github:read_issues': 'github_pat',
        'github:push_code': 'github_pat',
      }),
    );
    vault.registerProfile(
      new CredentialProfile('did:web:agent-analytics', { 'db:query': 'db_password' }),
    );
    injector = new CredentialInjector(vault);
  });

  it('renders headers on the happy path', async () => {
    const r = await injector.injectHeaders(
      'did:web:agent-ci',
      { Authorization: 'Bearer {{cred:github_pat}}', Accept: 'application/json' },
      {
        actionClass: 'github:read_issues',
        targetService: 'api.github.com',
        allowedHandles: ['github_pat'],
        policyVersion: 'v1',
      },
    );
    expect(r.allowed).toBe(true);
    expect((r.payload as Record<string, string>).Authorization).toBe('Bearer GHP-RESOLVED-VALUE');
    expect(r.denyReceipt).toBeNull();
    expect(r.auditEvents).toHaveLength(1);
    expect(r.auditEvents[0].decision).toBe('allow');
  });

  it('renders nested tool args without mutating the original', async () => {
    const args = {
      repo: 'octo/hello',
      secrets: ['{{cred:github_pat}}', 'literal'],
      nested: { token: '{{cred:github_pat}}' },
    };
    const r = await injector.injectToolArgs('did:web:agent-ci', args, {
      actionClass: 'github:push_code',
      targetService: 'api.github.com',
      allowedHandles: ['github_pat'],
    });
    expect(r.allowed).toBe(true);
    const out = r.payload as typeof args;
    expect(out.secrets[0]).toBe('GHP-RESOLVED-VALUE');
    expect(out.nested.token).toBe('GHP-RESOLVED-VALUE');
    expect(args.secrets[0]).toBe('{{cred:github_pat}}');
  });

  it('renders env vars', async () => {
    const r = await injector.injectEnv(
      'did:web:agent-ci',
      { PATH: '/usr/bin', GITHUB_TOKEN: '{{cred:github_pat}}' },
      { actionClass: 'github:read_issues', targetService: 'subprocess', allowedHandles: ['github_pat'] },
    );
    expect(r.allowed).toBe(true);
    expect((r.payload as Record<string, string>).GITHUB_TOKEN).toBe('GHP-RESOLVED-VALUE');
  });

  it('denies a whole call when an unauthorized placeholder appears (MCP untrusted)', async () => {
    const r = await injector.injectToolArgs(
      'did:web:agent-analytics',
      { sql: 'SELECT 1', auth: '{{cred:github_pat}}' },
      { actionClass: 'db:query', targetService: 'pg', allowedHandles: ['db_password'] },
    );
    expect(r.allowed).toBe(false);
    expect(r.payload).toBeInstanceOf(DenyReceipt);
    expect((r.payload as DenyReceipt).reason).toBe(DENY_REASON);
  });

  it('returns identical deny for missing vs out-of-scope handle', async () => {
    const missing = await injector.injectHeaders(
      'did:web:agent-ci',
      { X: '{{cred:does_not_exist}}' },
      {
        actionClass: 'github:read_issues',
        targetService: 'svc',
        allowedHandles: ['does_not_exist'],
      },
    );
    const outOfScope = await injector.injectHeaders(
      'did:web:agent-ci',
      { X: '{{cred:db_password}}' },
      {
        actionClass: 'github:read_issues',
        targetService: 'svc',
        allowedHandles: ['db_password'],
      },
    );
    expect(missing.allowed).toBe(false);
    expect(outOfScope.allowed).toBe(false);
    expect(missing.denyReceipt!.equals(outOfScope.denyReceipt!)).toBe(true);
  });

  it('runs policyCheck before any vault read', async () => {
    const seen: InjectionContext[] = [];
    const policy = (ctx: InjectionContext): PolicyOutcome => {
      seen.push(ctx);
      return { allow: false, reason: 'workflow denied' };
    };
    const r = await injector.injectHeaders(
      'did:web:agent-ci',
      { Authorization: 'Bearer {{cred:github_pat}}' },
      {
        actionClass: 'github:push_code',
        targetService: 'api.github.com',
        allowedHandles: ['github_pat'],
        policyCheck: policy,
        policyVersion: 'v7',
      },
    );
    expect(r.allowed).toBe(false);
    expect(seen[0].requestedHandles).toEqual(['github_pat']);
    expect(seen[0].policyVersion).toBe('v7');
  });

  it('produces the same deny across headers/args/env surfaces', async () => {
    const opts = {
      actionClass: 'db:query',
      targetService: 'svc',
      allowedHandles: ['github_pat'],
    };
    const h = await injector.injectHeaders(
      'did:web:agent-analytics',
      { Authorization: '{{cred:github_pat}}' },
      opts,
    );
    const a = await injector.injectToolArgs(
      'did:web:agent-analytics',
      { x: '{{cred:github_pat}}' },
      opts,
    );
    const e = await injector.injectEnv(
      'did:web:agent-analytics',
      { TOKEN: '{{cred:github_pat}}' },
      opts,
    );
    for (const r of [h, a, e]) {
      expect(r.allowed).toBe(false);
      expect(r.denyReceipt!.reason).toBe(DENY_REASON);
    }
  });

  it('passes through payloads with no placeholders', async () => {
    const r = await injector.injectHeaders(
      'did:web:agent-ci',
      { Accept: 'application/json' },
      { actionClass: 'github:read_issues', targetService: 'svc', allowedHandles: [] },
    );
    expect(r.allowed).toBe(true);
    expect(r.payload).toEqual({ Accept: 'application/json' });
  });
});

describe('Audit log', () => {
  let vault: CredentialVault;
  let injector: CredentialInjector;
  beforeEach(async () => {
    vault = new CredentialVault();
    await vault.put('github_pat', 'GHP-RESOLVED-VALUE');
    vault.registerProfile(
      new CredentialProfile('did:web:agent-ci', { 'github:read_issues': 'github_pat' }),
    );
    injector = new CredentialInjector(vault);
  });

  it('records allow events without leaking the value', async () => {
    await injector.injectHeaders(
      'did:web:agent-ci',
      { Authorization: 'Bearer {{cred:github_pat}}' },
      {
        actionClass: 'github:read_issues',
        targetService: 'api.github.com',
        allowedHandles: ['github_pat'],
        policyVersion: 'v1',
      },
    );
    const events = vault.auditLog();
    expect(events).toHaveLength(1);
    expect(events[0].decision).toBe('allow');
    expect(events[0].handleName).toBe('github_pat');
    expect(events[0].policyVersion).toBe('v1');
    expect(JSON.stringify(events)).not.toContain('GHP-RESOLVED-VALUE');
  });

  it('records deny events for unauthorized agents', async () => {
    await injector.injectHeaders(
      'did:web:rogue',
      { Authorization: 'Bearer {{cred:github_pat}}' },
      {
        actionClass: 'github:read_issues',
        targetService: 'api.github.com',
        allowedHandles: ['github_pat'],
      },
    );
    const events = vault.auditLog();
    expect(events.some((e: VaultAuditEvent) => e.decision === 'deny')).toBe(true);
  });

  it('auditDigest is stable and key-dependent', async () => {
    await injector.injectHeaders(
      'did:web:agent-ci',
      { Authorization: 'Bearer {{cred:github_pat}}' },
      {
        actionClass: 'github:read_issues',
        targetService: 'api.github.com',
        allowedHandles: ['github_pat'],
      },
    );
    const events = vault.auditLog();
    const k1 = new TextEncoder().encode('k');
    const k2 = new TextEncoder().encode('other');
    expect(auditDigest(events, k1)).toBe(auditDigest(events, k1));
    expect(auditDigest(events, k1)).not.toBe(auditDigest(events, k2));
  });
});

describe('Rotation', () => {
  it('does not require prompt changes', async () => {
    const vault = new CredentialVault();
    await vault.put('github_pat', 'GHP-V1');
    vault.registerProfile(
      new CredentialProfile('did:web:agent-ci', { 'github:read_issues': 'github_pat' }),
    );
    const injector = new CredentialInjector(vault);
    const saved = { Authorization: 'Bearer {{cred:github_pat}}' };

    const before = await injector.injectHeaders('did:web:agent-ci', saved, {
      actionClass: 'github:read_issues',
      targetService: 'svc',
      allowedHandles: ['github_pat'],
    });
    expect((before.payload as Record<string, string>).Authorization).toBe('Bearer GHP-V1');

    await vault.rotate('github_pat', 'GHP-V2');

    const after = await injector.injectHeaders('did:web:agent-ci', saved, {
      actionClass: 'github:read_issues',
      targetService: 'svc',
      allowedHandles: ['github_pat'],
    });
    expect((after.payload as Record<string, string>).Authorization).toBe('Bearer GHP-V2');
    expect(saved.Authorization).toBe('Bearer {{cred:github_pat}}');
  });
});

describe('Encrypted persistence', () => {
  it('round-trips via AES-256-GCM, distinctive plaintext not on disk', async () => { // gitleaks:allow
    const key = CredentialVault.generateKey();
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vault-'));
    const file = path.join(tmpDir, 'vault.bin');
    const secret = 'distinctive rotated fixture not a real key'; // gitleaks:allow

    const v1 = new CredentialVault({ persistPath: file, encryptionKey: key });
    await v1.put('k', 'original');
    await v1.rotate('k', secret);

    const blob = await fs.readFile(file);
    expect(blob.includes(Buffer.from(secret))).toBe(false);
    expect(blob.includes(Buffer.from('"value"'))).toBe(false);

    const v2 = new CredentialVault({ persistPath: file, encryptionKey: key });
    const names = await v2.listHandles();
    expect(names).toEqual(['k']);
    const meta = await v2.getMetadata('k');
    expect(meta!.version).toBe(2);
  });

  it('refuses persistence without a key', () => {
    expect(
      () => new CredentialVault({ persistPath: '/tmp/x.bin' }),
    ).toThrow();
  });

  it('refuses persistence with wrong-length key', () => {
    expect(
      () => new CredentialVault({ persistPath: '/tmp/x.bin', encryptionKey: new Uint8Array(16) }),
    ).toThrow();
  });
});

describe('Placeholder regex', () => {
  it('matches expected forms', () => {
    const find = (s: string): string[] => {
      const out: string[] = [];
      PLACEHOLDER_RE.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = PLACEHOLDER_RE.exec(s)) !== null) out.push(m[1]);
      return out;
    };
    expect(find('{{cred:abc}}')).toEqual(['abc']);
    expect(find('{{ cred:a.b-c_1 }}')).toEqual(['a.b-c_1']);
    expect(find('Bearer {{cred:x}} and {{cred:y}}')).toEqual(['x', 'y']);
    expect(find('{{cred:has space}}')).toEqual([]);
    expect(find('{{cred:bad/slash}}')).toEqual([]);
  });
});
