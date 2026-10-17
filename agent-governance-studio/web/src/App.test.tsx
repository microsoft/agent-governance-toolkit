// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { App } from "./App";

afterEach(cleanup);

describe("AGT Studio entry", () => {
  it("renders an accessible application heading", () => {
    render(<App />);

    const heading = screen.getByRole("heading", { level: 1, name: "AGT Studio" });
    expect(screen.getByRole("main").contains(heading)).toBe(true);
  });

  it("identifies the Agent Governance Toolkit", () => {
    render(<App />);

    expect(screen.getByText("Agent Governance Toolkit")).toBeTruthy();
  });
});
