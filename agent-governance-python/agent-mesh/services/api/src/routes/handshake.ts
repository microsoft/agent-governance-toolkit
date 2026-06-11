// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import * as crypto from "crypto";
import { Router, Request, Response } from "express";
import { sign } from "../services/identity";
import { evaluateHandshake } from "../services/trust";
import { appendAuditEntry } from "../services/audit";
import { HandshakeRequest, HandshakeResponse } from "../types";

const router = Router();

// Domain separator: any signature this server emits is prefixed with this
// fixed string so a handshake signature can never be replayed as a
// signature over a different protocol message (e.g. a wire-protocol frame
// or a delegation token).
const HANDSHAKE_SIGNING_DOMAIN = "agentmesh-handshake-v1";

// Length cap on the client-supplied challenge nonce. The server only uses
// it inside a structured, hashed payload, but bounding the size prevents
// resource-exhaustion via very large bodies and keeps audit entries small.
const MAX_CHALLENGE_LENGTH = 256;

router.post("/handshake", (req: Request, res: Response) => {
  // The authenticated agent is bound to the API key by ``requireApiKey``
  // middleware. We deliberately ignore any ``agent_did`` in the request
  // body: accepting it would let any API key holder request signatures
  // for any other agent's DID — a textbook signing oracle.
  const agent = req.agent;
  if (!agent) {
    res.status(401).json({ error: "Authentication required" });
    return;
  }

  const { challenge, capabilities_requested } =
    req.body as Partial<HandshakeRequest>;

  if (!challenge || typeof challenge !== "string") {
    res.status(400).json({ error: "challenge is required" });
    return;
  }
  if (challenge.length > MAX_CHALLENGE_LENGTH) {
    res.status(400).json({
      error: `challenge must be <= ${MAX_CHALLENGE_LENGTH} characters`,
    });
    return;
  }
  if (!Array.isArray(capabilities_requested)) {
    res.status(400).json({ error: "capabilities_requested must be an array" });
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

  // Build a domain-separated, server-bound signing payload. We sign a
  // structured envelope rather than the raw client-supplied challenge,
  // and include EVERY field a relying party will act on (DID, granted
  // capabilities, advertised trust score, the challenge digest, and a
  // server-chosen nonce/timestamp). Without binding the grant + score
  // into the signed bytes a MITM could rewrite the response (e.g.
  // adding 'admin' to capabilities_granted) while the signature still
  // verified.
  const serverNonce = crypto.randomBytes(16).toString("hex");
  const serverTimestamp = new Date().toISOString();
  const challengeDigest = crypto
    .createHash("sha256")
    .update(challenge, "utf8")
    .digest("hex");

  // Canonical form for capability list: trim, sort, join with ','. This
  // guarantees the verifier reconstructs an identical byte sequence
  // regardless of the order the client cares about.
  const capabilitiesCanonical = [...granted]
    .map((c) => String(c))
    .sort()
    .join(",");
  const trustScoreCanonical = String(agent.trust_score.total);

  const signingPayload = [
    HANDSHAKE_SIGNING_DOMAIN,
    agent.did,
    serverNonce,
    serverTimestamp,
    challengeDigest,
    capabilitiesCanonical,
    trustScoreCanonical,
  ].join("\n");

  const signature = sign(signingPayload, agent.private_key);

  appendAuditEntry("handshake", agent.did, {
    challenge_digest: challengeDigest,
    capabilities_requested,
    capabilities_granted: granted,
    server_nonce: serverNonce,
    server_timestamp: serverTimestamp,
  });

  const response: HandshakeResponse = {
    verified: true,
    trust_score: agent.trust_score.total,
    capabilities_granted: granted,
    signature,
    // Echo the server-supplied envelope so the client can reconstruct
    // and verify the exact bytes that were signed.
    signing_domain: HANDSHAKE_SIGNING_DOMAIN,
    agent_did: agent.did,
    server_nonce: serverNonce,
    server_timestamp: serverTimestamp,
    challenge_digest: challengeDigest,
  };

  res.json(response);
});

export default router;

