// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { readFileSync } from 'node:fs';
import { beforeEach, describe, expect, test } from 'vitest';
import { version as viteVersion } from 'vite';
import manifest from '../package.json';
import { TemplateLibrary } from '../src/services/template-library.js';

describe('Vitest toolchain', () => {
  test('installs the exact runner and coverage versions requested by the manifest', () => {
    const runner: { version: string } = JSON.parse(readFileSync(
      new URL('../node_modules/vitest/package.json', import.meta.url), 'utf-8',
    ));
    const coverage: { version: string; peerDependencies: { vitest: string } } = JSON.parse(
      readFileSync(
        new URL('../node_modules/@vitest/coverage-v8/package.json', import.meta.url), 'utf-8',
      ),
    );

    expect(runner.version).toBe(manifest.devDependencies.vitest);
    expect(coverage.version).toBe(manifest.devDependencies['@vitest/coverage-v8']);
    expect(coverage.version).toBe(runner.version);
    expect(coverage.peerDependencies.vitest).toBe(runner.version);
  });

  test('installs Vite as an explicit development dependency', () => {
    expect(manifest.devDependencies).toHaveProperty('vite', viteVersion);
  });
});

describe('TemplateLibrary under Vitest', () => {
  let library: TemplateLibrary;

  beforeEach(() => {
    library = new TemplateLibrary();
  });

  test('loads the built-in agent and policy templates', () => {
    expect(library.listAgentTemplates()).toHaveLength(10);
    expect(library.listPolicyTemplates()).toHaveLength(6);
    expect(library.getAgentTemplate('email-assistant')).toMatchObject({
      category: 'communication',
      config: { approvalRequired: true },
    });
    expect(library.getPolicyTemplate('gdpr-compliance')).toMatchObject({
      framework: 'GDPR',
      policy: { enabled: true },
    });
  });

  test('filters agents by category and tags together', () => {
    expect(library.listAgentTemplates({
      category: 'data', tags: ['scraping'],
    }).map(template => template.id)).toEqual(['web-scraper']);
  });

  test.each(['EMAIL ASSISTANT', 'MONITORS', 'email'])(
    'searches agent names, descriptions and tags: %s', search => {
      expect(library.listAgentTemplates({ search }).map(template => template.id))
        .toContain('email-assistant');
    },
  );

  test('does not filter agents for an empty tag list', () => {
    expect(library.listAgentTemplates({ tags: [] })).toEqual(library.listAgentTemplates());
  });

  test('filters policies by category and framework together', () => {
    expect(library.listPolicyTemplates({
      category: 'compliance', framework: 'GDPR',
    }).map(template => template.id)).toEqual(['gdpr-compliance']);
  });

  test.each(['GDPR DATA PROTECTION', 'Regulation', 'privacy'])(
    'searches policy names, descriptions and tags: %s', search => {
      expect(library.listPolicyTemplates({ search }).map(template => template.id))
        .toContain('gdpr-compliance');
    },
  );

  test('returns no templates for unknown IDs or filters', () => {
    expect(library.getAgentTemplate('unknown')).toBeUndefined();
    expect(library.getPolicyTemplate('unknown')).toBeUndefined();
    expect(library.listAgentTemplates({ category: 'unknown' })).toEqual([]);
    expect(library.listAgentTemplates({ search: 'unknown' })).toEqual([]);
    expect(library.listAgentTemplates({ tags: ['unknown'] })).toEqual([]);
    expect(library.listPolicyTemplates({ category: 'unknown' })).toEqual([]);
    expect(library.listPolicyTemplates({ framework: 'unknown' })).toEqual([]);
    expect(library.listPolicyTemplates({ search: 'unknown' })).toEqual([]);
  });

  test('lists unique categories and only named compliance frameworks', () => {
    const categories = library.getCategories();
    expect(categories.agents).toEqual([...new Set(
      library.listAgentTemplates().map(template => template.category),
    )]);
    expect(categories.policies).toEqual([...new Set(
      library.listPolicyTemplates().map(template => template.category),
    )]);
    expect(library.getFrameworks()).toEqual(['GDPR', 'SOC2', 'HIPAA', 'PCI_DSS']);
  });

  test('suggests matching templates without changing the stored template lists', () => {
    const suggestions = library.suggestTemplates('GDPR privacy email communication automation');

    expect(suggestions.agents.length).toBeGreaterThan(0);
    expect(suggestions.agents.length).toBeLessThanOrEqual(3);
    expect(suggestions.agents.map(template => template.id)).toContain('email-assistant');
    expect(suggestions.policies[0].id).toBe('gdpr-compliance');
    expect(suggestions.policies.length).toBeLessThanOrEqual(3);
    expect(library.listAgentTemplates()).toHaveLength(10);
    expect(library.listPolicyTemplates()).toHaveLength(6);
  });

  test('returns no suggestions when no keywords match', () => {
    expect(library.suggestTemplates('')).toEqual({ agents: [], policies: [] });
  });
});
