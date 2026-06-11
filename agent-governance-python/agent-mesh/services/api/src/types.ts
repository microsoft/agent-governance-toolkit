// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
export interface AgentRecord {
  did: string;
  name: string;
  sponsor_email: string;
  capabilities: string[];
  public_key: string;
  private_key: string;
  api_key: string;
  status: "active" | "suspended" | "revoked";
  trust_score: TrustScore;
  registered_at: string;
  last_seen: string;
}

export interface TrustScore {
  total: number;
  dimensions: TrustDimensions;
  tier: "Untrusted" | "Basic" | "Verified" | "Trusted" | "Highly Trusted";
  history: TrustEvent[];
}

export interface TrustDimensions {
  policy_compliance: number;
  interaction_success: number;
  verification_depth: number;
  community_vouching: number;
  uptime_reliability: number;
}

export interface TrustEvent {
  timestamp: string;
  event: string;
  score_delta: number;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  action: string;
  agent_did: string;
  details: Record<string, unknown>;
  previous_hash: string;
  hash: string;
}

export interface RegisterRequest {
  name: string;
  sponsor_email: string;
  capabilities: string[];
}

export interface RegisterResponse {
  agent_did: string;
  api_key: string;
  public_key: string;
  verification_url: string;
}

export interface VerifyResponse {
  registered: boolean;
  trust_score: number;
  sponsor: string;
  status: string;
  capabilities: string[];
}

export interface HandshakeRequest {
  agent_did: string;
  challenge: string;
  capabilities_requested: string[];
}

export interface HandshakeResponse {
  verified: boolean;
  trust_score: number;
  capabilities_granted: string[];
  signature: string;
  // Server-supplied components of the signed envelope so callers can
  // verify ``signature`` against ``${signing_domain}\n${agent_did}\n${server_nonce}\n${server_timestamp}\n${challenge_digest}``.
  signing_domain: string;
  agent_did: string;
  server_nonce: string;
  server_timestamp: string;
  challenge_digest: string;
}

export interface ScoreResponse {
  total: number;
  dimensions: TrustDimensions;
  tier: string;
  history: TrustEvent[];
}
