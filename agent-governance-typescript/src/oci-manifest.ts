// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { createHash } from 'crypto';
import type {
  AgentIdentityJSON,
  AICard,
  AICardCapabilities,
  AICardSkill,
  OciDescriptor,
  OciManifest,
  OciPackageResult,
  PolicyRule,
} from './types';

const AI_CARD_MEDIA_TYPE = 'application/vnd.ai-card.agent.v1+json';
const POLICY_MEDIA_TYPE = 'application/vnd.agt.policy.v1+json';
const OCI_MANIFEST_MEDIA_TYPE = 'application/vnd.oci.image.manifest.v2+json';
const OCI_CONFIG_MEDIA_TYPE = 'application/vnd.oci.image.config.v1+json';

/**
 * Converts AGT agent manifests to/from OCI manifest format with AI Card
 * compatibility. Enables registry-based discovery and verification of
 * agent metadata.
 */
export class OciManifestAdapter {
  /**
   * Convert an AGT agent identity to an AI Card.
   */
  identityToAICard(identity: AgentIdentityJSON, extra?: Partial<AICard>): AICard {
    const card: AICard = {
      name: identity.name ?? identity.did,
      version: '1.0.0',
      description: identity.description,
      author: identity.organization ?? identity.sponsor,
      capabilities: this.capabilitiesToAICard(identity.capabilities),
      metadata: {
        did: identity.did,
        status: identity.status ?? 'active',
        createdAt: identity.createdAt,
        expiresAt: identity.expiresAt,
        parentDid: identity.parentDid,
        delegationDepth: identity.delegationDepth,
      },
      ...extra,
    };

    return card;
  }

  /**
   * Convert an AI Card back to an AGT agent identity.
   */
  aiCardToIdentity(card: AICard, publicKey: string): AgentIdentityJSON {
    const metadata = (card.metadata ?? {}) as Record<string, unknown>;
    return {
      did: (metadata.did as string) ?? `did:agent:${card.name}`,
      publicKey,
      capabilities: this.aiCardToCapabilities(card.capabilities),
      name: card.name,
      description: card.description,
      organization: card.author,
      status: (metadata.status as AgentIdentityJSON['status']) ?? 'active',
      createdAt: metadata.createdAt as string | undefined,
      expiresAt: metadata.expiresAt as string | undefined,
      parentDid: metadata.parentDid as string | undefined,
      delegationDepth: metadata.delegationDepth as number | undefined,
    };
  }

  /**
   * Package an agent identity and optional policy rules into an OCI manifest.
   */
  package(
    identity: AgentIdentityJSON,
    policyRules?: PolicyRule[],
    extra?: Partial<AICard>,
  ): OciPackageResult {
    const aiCard = this.identityToAICard(identity, extra);
    const aiCardJson = JSON.stringify(aiCard, null, 2);
    const aiCardDescriptor = this.createDescriptor(aiCardJson, AI_CARD_MEDIA_TYPE, {
      'org.opencontainers.image.title': 'ai-card.json',
    });

    const layers: Array<{ descriptor: OciDescriptor; content: string }> = [
      { descriptor: aiCardDescriptor, content: aiCardJson },
    ];

    if (policyRules && policyRules.length > 0) {
      const policyJson = JSON.stringify({ rules: policyRules }, null, 2);
      const policyDescriptor = this.createDescriptor(policyJson, POLICY_MEDIA_TYPE, {
        'org.opencontainers.image.title': 'policy.json',
      });
      layers.push({ descriptor: policyDescriptor, content: policyJson });
    }

    const configContent = JSON.stringify({
      created: new Date().toISOString(),
      author: identity.organization ?? identity.sponsor ?? 'unknown',
      agent: { did: identity.did, name: identity.name },
    });
    const configDescriptor = this.createDescriptor(configContent, OCI_CONFIG_MEDIA_TYPE);

    const manifest: OciManifest = {
      schemaVersion: 2,
      mediaType: OCI_MANIFEST_MEDIA_TYPE,
      config: configDescriptor,
      layers: layers.map((l) => l.descriptor),
      annotations: {
        'org.opencontainers.image.title': identity.name ?? identity.did,
        'org.opencontainers.image.description': identity.description ?? '',
        'org.opencontainers.image.vendor': identity.organization ?? '',
        'dev.ai-card.version': aiCard.version,
        'dev.agt.did': identity.did,
      },
    };

    return { manifest, aiCard, configBlob: configContent, layers };
  }

  /**
   * Extract an AI Card from an OCI manifest's layers.
   */
  unpackAICard(layers: Array<{ descriptor: OciDescriptor; content: string }>): AICard | null {
    const aiCardLayer = layers.find((l) => l.descriptor.mediaType === AI_CARD_MEDIA_TYPE);
    if (!aiCardLayer) return null;

    try {
      return JSON.parse(aiCardLayer.content) as AICard;
    } catch {
      return null;
    }
  }

  /**
   * Extract policy rules from an OCI manifest's layers.
   */
  unpackPolicies(layers: Array<{ descriptor: OciDescriptor; content: string }>): PolicyRule[] {
    const policyLayer = layers.find((l) => l.descriptor.mediaType === POLICY_MEDIA_TYPE);
    if (!policyLayer) return [];

    try {
      const parsed = JSON.parse(policyLayer.content) as { rules: PolicyRule[] };
      return parsed.rules ?? [];
    } catch {
      return [];
    }
  }

  /**
   * Verify the integrity of an OCI manifest by checking layer digests.
   */
  verifyManifest(
    manifest: OciManifest,
    layers: Array<{ descriptor: OciDescriptor; content: string }>,
    configContent?: string,
  ): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (manifest.schemaVersion !== 2) {
      errors.push(`Unsupported schema version: ${manifest.schemaVersion}`);
    }

    // Verify config digest
    if (configContent) {
      const expectedDigest = this.sha256Digest(configContent);
      if (manifest.config.digest !== expectedDigest) {
        errors.push(`Config digest mismatch: expected ${expectedDigest}, got ${manifest.config.digest}`);
      }
    }

    // Verify layer digests
    for (const layer of layers) {
      const expectedDigest = this.sha256Digest(layer.content);
      if (layer.descriptor.digest !== expectedDigest) {
        errors.push(
          `Layer digest mismatch for ${layer.descriptor.annotations?.['org.opencontainers.image.title'] ?? 'unknown'}: expected ${expectedDigest}, got ${layer.descriptor.digest}`,
        );
      }

      const expectedSize = Buffer.byteLength(layer.content, 'utf-8');
      if (layer.descriptor.size !== expectedSize) {
        errors.push(
          `Layer size mismatch: expected ${expectedSize}, got ${layer.descriptor.size}`,
        );
      }
    }

    return { valid: errors.length === 0, errors };
  }

  // ── Internal helpers ──

  private createDescriptor(
    content: string,
    mediaType: string,
    annotations?: Record<string, string>,
  ): OciDescriptor {
    return {
      mediaType,
      digest: this.sha256Digest(content),
      size: Buffer.byteLength(content, 'utf-8'),
      annotations,
    };
  }

  private sha256Digest(content: string): string {
    const hash = createHash('sha256').update(content, 'utf-8').digest('hex');
    return `sha256:${hash}`;
  }

  private capabilitiesToAICard(capabilities: string[]): AICardCapabilities {
    return {
      domains: capabilities,
      input_modes: ['text'],
      output_modes: ['text', 'json'],
    };
  }

  private aiCardToCapabilities(capabilities?: AICardCapabilities): string[] {
    if (!capabilities) return [];
    return capabilities.domains ?? [];
  }
}
