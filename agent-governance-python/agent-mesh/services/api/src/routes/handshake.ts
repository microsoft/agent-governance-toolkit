// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { Router, Request, Response } from "express";
import { getAgent } from "../services/registry";
import { sign } from "../services/identity";
import { evaluateHandshake } from "../services/trust";
import { appendAuditEntry } from "../services/audit";
import { HandshakeRequest, HandshakeResponse } from "../types";

const router = Router();

router.post("/handshake", (req: Request, res: Response) => {
  const { agent_did, challenge, capabilities_requested } =
    req.body as Partial<HandshakeRequest>;

  if (!agent_did || typeof agent_did !== "string") {
    res.status(400).json({ error: "agent_did is required" });
    return;
  }
  if (!challenge || typeof challenge !== "string") {
    res.status(400).json({ error: "challenge is required" });
    return;
  }
  if (!Array.isArray(capabilities_requested)) {
    res.status(400).json({ error: "capabilities_requested must be an array" });
    return;
  }

  const agent = getAgent(agent_did);
  if (!agent) {
    res.status(404).json({ error: "Agent not found", verified: false });
    return;
  }

  if (agent.status !== "active") {
    res.status(403).json({ error: "Agent is not active", verified: false });
    return;
  }

  const granted = evaluateHandshake(
    agent.capabilities,
    capabilities_requested,
    agent.trust_score,
  );

  // Sign the challenge with the agent's private key
  const signature = sign(challenge, agent.private_key);

  appendAuditEntry("handshake", agent_did, {
    challenge,
    capabilities_requested,
    capabilities_granted: granted,
  });

  const response: HandshakeResponse = {
    verified: true,
    trust_score: agent.trust_score.total,
    capabilities_granted: granted,
    signature,
  };

  res.json(response);
});

export default router;
