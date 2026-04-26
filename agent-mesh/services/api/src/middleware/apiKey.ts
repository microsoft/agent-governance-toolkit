// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { Request, Response, NextFunction } from "express";
import { isValidApiKey } from "../services/registry";

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

  next();
}
