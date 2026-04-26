// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { Router, Request, Response } from "express";
import { registerAgent } from "../services/registry";
import { RegisterRequest, RegisterResponse } from "../types";

const router = Router();

router.post("/register", (req: Request, res: Response) => {
  const { name, sponsor_email, capabilities } = req.body as Partial<RegisterRequest>;

  if (!name || typeof name !== "string") {
    res.status(400).json({ error: "name is required and must be a string" });
    return;
  }
  if (!sponsor_email || typeof sponsor_email !== "string") {
    res.status(400).json({ error: "sponsor_email is required and must be a string" });
    return;
  }
  if (!Array.isArray(capabilities)) {
    res.status(400).json({ error: "capabilities is required and must be an array" });
    return;
  }

  const agent = registerAgent({ name, sponsor_email, capabilities });

  const response: RegisterResponse = {
    agent_did: agent.did,
    api_key: agent.api_key,
    public_key: agent.public_key,
    verification_url: `/api/verify/${agent.did}`,
  };

  res.status(201).json(response);
});

export default router;
