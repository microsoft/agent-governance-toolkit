// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import express from "express";
import { rateLimit } from "./middleware/rateLimit";
import { requireApiKey } from "./middleware/apiKey";
import healthRouter from "./routes/health";
import registerRouter from "./routes/register";
import verifyRouter from "./routes/verify";
import handshakeRouter from "./routes/handshake";
import scoreRouter from "./routes/score";

const app = express();
const PORT = process.env.PORT ?? 3000;

app.use(express.json());
app.use(rateLimit);

// Public read endpoints
app.use("/api", healthRouter);
app.use("/api", verifyRouter);
app.use("/api", scoreRouter);

// Write endpoints require API key
app.use("/api", requireApiKey, registerRouter);
app.use("/api", requireApiKey, handshakeRouter);

app.listen(PORT, () => {
  console.log(`AgentMesh API listening on port ${PORT}`);
});

export default app;
