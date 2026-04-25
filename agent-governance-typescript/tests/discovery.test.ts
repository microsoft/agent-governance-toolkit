// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'fs';
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
