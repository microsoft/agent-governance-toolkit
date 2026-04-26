// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { Router, Request, Response } from "express";
import { getAgent } from "../services/registry";
import { ScoreResponse } from "../types";

const router = Router();

router.get("/score/:agentDid", (req: Request, res: Response) => {
  const { agentDid } = req.params;
  const agent = getAgent(agentDid);

  if (!agent) {
    res.status(404).json({ error: "Agent not found" });
    return;
  }

  const response: ScoreResponse = {
    total: agent.trust_score.total,
    dimensions: agent.trust_score.dimensions,
    tier: agent.trust_score.tier,
    history: agent.trust_score.history,
  };

  res.json(response);
});

export default router;
