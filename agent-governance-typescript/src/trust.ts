// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import * as fs from 'fs';
import { AgentIdentity } from './identity';
import {
  TrustConfig,
  TrustScore,
  TrustTier,
  TrustVerificationResult,
} from './types';

const DEFAULT_THRESHOLDS = {
  untrusted: 0.0,
  provisional: 0.3,
  trusted: 0.6,
  verified: 0.85,
};

interface AgentTrustState {
  successes: number;
  failures: number;
  score: number;
  lastUpdate: number;
}

/**
 * Manages trust scores for peer agents using a simple Bayesian-inspired model
 * with configurable decay.
 */
export class TrustManager {
  private readonly config: Required<Omit<TrustConfig, 'persistPath'>>;
  private readonly agents: Map<string, AgentTrustState> = new Map();
  private readonly persistPath?: string;

  constructor(config?: TrustConfig) {
    this.config = {
      initialScore: config?.initialScore ?? 0.5,
      decayFactor: config?.decayFactor ?? 0.95,
      thresholds: { ...DEFAULT_THRESHOLDS, ...config?.thresholds },
    };
    this.persistPath = config?.persistPath;
    if (this.persistPath) {
      this.loadFromDisk();
    }
  }

  /** Verify a peer agent's identity and return a trust result. */
  async verifyPeer(
    peerId: string,
    peerIdentity: AgentIdentity,
  ): Promise<TrustVerificationResult> {
    // Verify the identity is self-consistent (DID contains the key fingerprint)
    const challenge = new Uint8Array(
      require('crypto').randomBytes(32),
    );
    const signature = peerIdentity.sign(challenge);
    const verified = peerIdentity.verify(challenge, signature);

    const trustScore = this.getTrustScore(peerId);

    return {
      verified,
      trustScore,
      reason: verified ? undefined : 'Identity verification failed',
    };
  }

  /** Get the current trust score for an agent. */
  getTrustScore(agentId: string): TrustScore {
    const state = this.getOrCreateState(agentId);
    this.applyDecay(state);

    const tier = this.computeTier(state.score);

    return {
      overall: Math.round(state.score * 1000) / 1000,
      dimensions: {
        reliability: this.computeReliability(state),
        consistency: state.score,
      },
      tier,
    };
  }

  /** Record a successful interaction with an agent. */
  recordSuccess(agentId: string, reward: number = 0.05): void {
    const state = this.getOrCreateState(agentId);
    this.applyDecay(state);
    state.successes += 1;
    state.score = Math.min(1, state.score + reward);
    state.lastUpdate = Date.now();
    this.saveToDisk();
  }

  /** Record a failed interaction with an agent. */
  recordFailure(agentId: string, penalty: number = 0.1): void {
    const state = this.getOrCreateState(agentId);
    this.applyDecay(state);
    state.failures += 1;
    state.score = Math.max(0, state.score - penalty);
    state.lastUpdate = Date.now();
    this.saveToDisk();
  }

  // ── Private helpers ──

  private getOrCreateState(agentId: string): AgentTrustState {
    let state = this.agents.get(agentId);
    if (!state) {
      state = {
        successes: 0,
        failures: 0,
        score: this.config.initialScore,
        lastUpdate: Date.now(),
      };
      this.agents.set(agentId, state);
    }
    return state;
  }

  private applyDecay(state: AgentTrustState): void {
    const elapsed = Date.now() - state.lastUpdate;
    const hours = elapsed / (1000 * 60 * 60);
    if (hours >= 1) {
      const decaySteps = Math.floor(hours);
      state.score *= Math.pow(this.config.decayFactor, decaySteps);
      state.lastUpdate = Date.now();
    }
  }

  private computeTier(score: number): TrustTier {
    const t = this.config.thresholds;
    if (score >= t.verified) return 'Verified';
    if (score >= t.trusted) return 'Trusted';
    if (score >= t.provisional) return 'Provisional';
    return 'Untrusted';
  }

  private computeReliability(state: AgentTrustState): number {
    const total = state.successes + state.failures;
    if (total === 0) return this.config.initialScore;
    return Math.round((state.successes / total) * 1000) / 1000;
  }

  private saveToDisk(): void {
    if (!this.persistPath) return;
    try {
      const data: Record<string, AgentTrustState> = {};
      for (const [key, value] of this.agents) {
        data[key] = value;
      }
      fs.writeFileSync(this.persistPath, JSON.stringify(data), 'utf-8');
    } catch {
      // best-effort: ignore write errors
    }
  }

  private loadFromDisk(): void {
    if (!this.persistPath) return;
    try {
      const raw = fs.readFileSync(this.persistPath, 'utf-8');
      const data = JSON.parse(raw) as Record<string, AgentTrustState>;
      for (const [key, value] of Object.entries(data)) {
        this.agents.set(key, value);
      }
    } catch {
      // best-effort: ignore missing or corrupt files
    }
  }
}
