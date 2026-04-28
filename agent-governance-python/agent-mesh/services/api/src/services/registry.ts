// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { AgentRecord, RegisterRequest } from "../types";
import { generateKeyPair, generateDid, generateApiKey } from "./identity";
import { createInitialTrustScore } from "./trust";
import { appendAuditEntry } from "./audit";

/** In-memory agent registry keyed by DID. */
const agents = new Map<string, AgentRecord>();

/** API key -> DID index for fast lookup. */
const apiKeyIndex = new Map<string, string>();

export function registerAgent(req: RegisterRequest): AgentRecord {
  const did = generateDid();
  const keys = generateKeyPair();
  const apiKey = generateApiKey();

  const record: AgentRecord = {
    did,
    name: req.name,
    sponsor_email: req.sponsor_email,
    capabilities: req.capabilities,
    public_key: keys.publicKey,
    private_key: keys.privateKey,
    api_key: apiKey,
    status: "active",
    trust_score: createInitialTrustScore(),
    registered_at: new Date().toISOString(),
    last_seen: new Date().toISOString(),
  };

  agents.set(did, record);
  apiKeyIndex.set(apiKey, did);

  appendAuditEntry("agent_registered", did, {
    name: req.name,
    sponsor_email: req.sponsor_email,
    capabilities: req.capabilities,
  });

  return record;
}

export function getAgent(did: string): AgentRecord | undefined {
  return agents.get(did);
}

export function getAgentByApiKey(apiKey: string): AgentRecord | undefined {
  const did = apiKeyIndex.get(apiKey);
  return did ? agents.get(did) : undefined;
}

export function isValidApiKey(apiKey: string): boolean {
  return apiKeyIndex.has(apiKey);
}

export function updateLastSeen(did: string): void {
  const agent = agents.get(did);
  if (agent) {
    agent.last_seen = new Date().toISOString();
  }
}

/** Reset registry (for testing). */
export function resetRegistry(): void {
  agents.clear();
  apiKeyIndex.clear();
}
