// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { Router, Request, Response } from "express";
import { getAgent, updateLastSeen } from "../services/registry";
import { VerifyResponse } from "../types";

const router = Router();

router.get("/verify/:agentDid", (req: Request, res: Response) => {
  const { agentDid } = req.params;
  const agent = getAgent(agentDid);

  if (!agent) {
    const response: VerifyResponse = {
      registered: false,
      trust_score: 0,
      sponsor: "",
      status: "unknown",
      capabilities: [],
    };
    res.status(404).json(response);
    return;
  }

  updateLastSeen(agentDid);

  const response: VerifyResponse = {
    registered: true,
    trust_score: agent.trust_score.total,
    sponsor: agent.sponsor_email,
    status: agent.status,
    capabilities: agent.capabilities,
  };

  res.json(response);
});

export default router;
