// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { ShadowDiscovery } from '../src/discovery';

describe('ShadowDiscovery', () => {
  const tempDirs: string[] = [];

  afterEach(() => {
    while (tempDirs.length > 0) {
      rmSync(tempDirs.pop() as string, { recursive: true, force: true });
    }
  });

  it('discovers config, container, and source-backed agents and reconciles shadows', () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'agt-discovery-'));
    tempDirs.push(tempDir);

    mkdirSync(join(tempDir, 'services'));
    mkdirSync(join(tempDir, 'apps'));

    const registeredConfigPath = join(tempDir, 'services', 'agentmesh.yaml');
    writeFileSync(registeredConfigPath, 'name: governed-agent\n');
    writeFileSync(join(tempDir, 'services', 'mcp-config.json'), '{"server":"catalog"}');
    writeFileSync(join(tempDir, 'docker-compose.yml'), 'services:\n  worker:\n    image: langchain-runtime\n');
    writeFileSync(join(tempDir, 'apps', 'assistant.ts'), 'const framework = "autogen";\n');

    const discovery = new ShadowDiscovery();
    const result = discovery.scan({
      paths: [tempDir],
      registry: [{ configPath: registeredConfigPath, owner: 'governance-team' }],
    });

    expect(result.agentCount).toBeGreaterThanOrEqual(4);
    expect(result.errors).toEqual([]);

    const registered = result.agents.find((agent) => agent.tags.configFile === 'services/agentmesh.yaml');
    expect(registered?.status).toBe('registered');
    expect(registered?.owner).toBe('governance-team');

    const shadows = result.shadowAgents;
    expect(shadows.length).toBeGreaterThanOrEqual(3);
    expect(shadows.every((entry) => entry.agent.status === 'shadow')).toBe(true);
    expect(shadows.some((entry) => entry.agent.agentType === 'mcp-server')).toBe(true);
    expect(shadows.some((entry) => entry.recommendedActions.some((action) => action.includes('MCP security scanner')))).toBe(true);
    expect(shadows.some((entry) => entry.risk.score >= 40)).toBe(true);
  });

  it('skips symlinked entries during walkDirectory', () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'agt-discovery-symlink-'));
    tempDirs.push(tempDir);

    // Real config so we know the scanner CAN find files in this tree.
    writeFileSync(join(tempDir, 'agentmesh.yaml'), 'name: real-agent\n');

    // Out-of-tree directory containing a config file that should NEVER
    // be reached by the scan rooted at `tempDir`.
    const outOfTree = mkdtempSync(join(tmpdir(), 'agt-discovery-outside-'));
    tempDirs.push(outOfTree);
    writeFileSync(join(outOfTree, 'mcp-config.json'), '{"server":"smuggled"}');

    // Symlink inside the scan root that points at the out-of-tree dir.
    // On Windows this requires either dev-mode or admin; skip when the
    // symlink call throws (e.g. EPERM in restricted CI sandboxes).
    try {
      symlinkSync(outOfTree, join(tempDir, 'sneaky-link'), 'dir');
    } catch {
      return;
    }

    // A symlinked CONFIG file too — the more common attack: a file with a
    // governed-looking name that targets sensitive content out-of-tree.
    try {
      symlinkSync(join(outOfTree, 'mcp-config.json'), join(tempDir, 'mcp-config.json'));
    } catch {
      return;
    }

    const discovery = new ShadowDiscovery();
    const result = discovery.scan({ paths: [tempDir] });

    // The real in-tree config is discovered.
    expect(result.agents.some((agent) => agent.tags.configFile === 'agentmesh.yaml')).toBe(true);

    // Neither the symlinked directory nor the symlinked file produces an agent.
    expect(result.agents.some((agent) => agent.tags.configFile?.startsWith('sneaky-link/'))).toBe(false);
    expect(result.agents.some((agent) => agent.tags.configFile === 'mcp-config.json')).toBe(false);
  });

  it('respects max depth and skip directories', () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'agt-discovery-depth-'));
    tempDirs.push(tempDir);

    mkdirSync(join(tempDir, 'node_modules'));
    mkdirSync(join(tempDir, 'deep'));
    mkdirSync(join(tempDir, 'deep', 'nested'));

    writeFileSync(join(tempDir, 'node_modules', 'mcp-config.json'), '{"ignored":true}');
    writeFileSync(join(tempDir, 'deep', 'nested', 'agentmesh.yaml'), 'name: too-deep\n');

    const discovery = new ShadowDiscovery();
    const result = discovery.scan({
      paths: [tempDir],
      maxDepth: 1,
    });

    expect(result.agentCount).toBe(0);
  });
});
