// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

beforeEach(() => {
  vi.resetModules();
  const root = document.createElement("div");
  root.id = "root";
  document.body.replaceChildren(root);
});

describe("browser bootstrap", () => {
  it("mounts the app in the document root", async () => {
    await import("./main");

    expect(await screen.findByRole("heading", { name: "AGT Studio" })).toBeTruthy();
  });

  it("fails clearly when the document root is missing", async () => {
    document.body.replaceChildren();

    await expect(import("./main")).rejects.toThrow("AGT Studio root element is missing");
  });
});
