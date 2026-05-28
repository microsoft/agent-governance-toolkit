// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { Request, Response, NextFunction } from "express";
import { getAgentByApiKey, isValidApiKey } from "../services/registry";
import { AgentRecord } from "../types";

/**
 * Augment Express ``Request`` with the authenticated agent so downstream
 * handlers do not need to re-look-up by API key. Anything that relies on
 * ``req.agent`` MUST also be protected by ``requireApiKey``.
 */
declare module "express-serve-static-core" {
  interface Request {
    agent?: AgentRecord;
  }
}

/** Require a valid API key in the `x-api-key` header for write endpoints. */
export function requireApiKey(req: Request, res: Response, next: NextFunction): void {
  const apiKey = req.header("x-api-key");

  if (!apiKey) {
    res.status(401).json({ error: "Missing x-api-key header" });
    return;
  }

  if (!isValidApiKey(apiKey)) {
    res.status(403).json({ error: "Invalid API key" });
    return;
  }

  // Bind the authenticated agent to the request so handlers cannot be
  // tricked into operating on a DID supplied by an untrusted caller —
  // the API key, not the request body, determines whose identity is in
  // use. This closes the handshake-signing-oracle issue where any API
  // key holder could request signatures for any DID.
  const agent = getAgentByApiKey(apiKey);
  if (!agent) {
    res.status(403).json({ error: "Invalid API key" });
    return;
  }
  if (agent.status !== "active") {
    res.status(403).json({ error: "Agent is not active" });
    return;
  }
  req.agent = agent;

  next();
}

