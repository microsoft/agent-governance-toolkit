// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
import { once } from "events";
import type { AddressInfo } from "net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createServer } from "../src/server";

const ORIGINAL_HOST_OVERRIDE = process.env.COPILOT_GOVERNANCE_HOST;

async function listenForAddress(host?: string): Promise<AddressInfo> {
  const serverWrapper = createServer({ port: 0, host });
  const listening = once(serverWrapper.server, "listening");
  serverWrapper.listen();
  await listening;

  const address = serverWrapper.server.address();
  if (!address || typeof address === "string") {
    throw new Error("Expected the HTTP server to expose a TCP address");
  }

  await new Promise<void>((resolve, reject) => {
    serverWrapper.server.close((error?: Error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });

  return address;
}

describe("createServer", () => {
  beforeEach(() => {
    delete process.env.COPILOT_GOVERNANCE_HOST;
    vi.spyOn(console, "log").mockImplementation(() => undefined);
  });

  afterEach(() => {
    if (ORIGINAL_HOST_OVERRIDE === undefined) {
      delete process.env.COPILOT_GOVERNANCE_HOST;
    } else {
      process.env.COPILOT_GOVERNANCE_HOST = ORIGINAL_HOST_OVERRIDE;
    }
    vi.restoreAllMocks();
  });

  it("defaults to loopback for local development", async () => {
    const address = await listenForAddress();
    expect(address.address).toBe("127.0.0.1");
  });

  it("uses the environment override when provided", async () => {
    process.env.COPILOT_GOVERNANCE_HOST = "0.0.0.0";
    const address = await listenForAddress();
    expect(address.address).toBe("0.0.0.0");
  });

  it("prefers an explicit host option over the environment override", async () => {
    process.env.COPILOT_GOVERNANCE_HOST = "0.0.0.0";
    const address = await listenForAddress("127.0.0.1");
    expect(address.address).toBe("127.0.0.1");
  });
});
