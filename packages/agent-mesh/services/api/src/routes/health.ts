// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { Router, Request, Response } from "express";

const router = Router();

router.get("/health", (_req: Request, res: Response) => {
  res.json({
    status: "ok",
    service: "agentmesh-api",
    version: "0.1.0",
    timestamp: new Date().toISOString(),
  });
});

export default router;
