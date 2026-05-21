// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  applyPolicy,
  diagnoseInstall,
  installPackage,
  resolveGeminiHome,
  showPolicy,
  uninstallPackage,
  validatePolicy,
} from "../lib/cli.mjs";

function createPolicyFixture(overrides = {}) {
  return {
    schemaVersion: 1,
    version: 1,
    mode: "enforce",
    denyOnPolicyError: true,
    minimumPromptDefenseGrade: "B",
    toolPolicies: {
      allowedTools: ["read_file", "glob", "grep_search", "mcp_agt_global_policy_agt_policy_status"],
      blockedTools: [],
      defaultEffect: "review",
      reviewTools: ["run_shell_command", "write_file", "replace"],
    },
    directResourcePolicies: {
      pathRules: [
        {
          id: "credential-read",
          effect: "deny",
          operation: "read",
          pathPatterns: [{ source: "(^|/)\\.env$", flags: "i" }],
        },
      ],
      urlRules: [
        {
          id: "metadata-endpoints",
          effect: "deny",
          urlPatterns: [{ source: "169\\.254\\.169\\.254|metadata\\.google\\.internal", flags: "i" }],
        },
      ],
    },
    scanOutputTools: ["run_shell_command"],
    poisoningPatterns: [],
    ...overrides,
  };
}

async function seedPackageFixture(packageRoot, version = "3.6.0") {
  await mkdir(join(packageRoot, "assets", "extensions", "agt-global-policy", "commands", "agt"), {
    recursive: true,
  });
  await mkdir(join(packageRoot, "assets", "extensions", "agt-global-policy", "hooks"), {
    recursive: true,
  });
  await mkdir(join(packageRoot, "assets", "extensions", "agt-global-policy", "mcp"), {
    recursive: true,
  });
  await mkdir(join(packageRoot, "assets", "extensions", "agt-global-policy", "config"), {
    recursive: true,
  });
  await mkdir(join(packageRoot, "node_modules", "@microsoft", "agent-governance-sdk", "dist"), {
    recursive: true,
  });
  await mkdir(join(packageRoot, "node_modules", "@modelcontextprotocol", "sdk"), {
    recursive: true,
  });

  await writeFile(
    join(packageRoot, "package.json"),
    `${JSON.stringify(
      {
        name: "@microsoft/agent-governance-gemini-cli",
        version,
        dependencies: {
          "@microsoft/agent-governance-sdk": version,
          "@modelcontextprotocol/sdk": "1.24.3",
        },
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
  await writeFile(
    join(packageRoot, "package-lock.json"),
    `${JSON.stringify(
      {
        name: "@microsoft/agent-governance-gemini-cli",
        version,
        lockfileVersion: 3,
        requires: true,
        packages: {
          "": {
            name: "@microsoft/agent-governance-gemini-cli",
            version,
            dependencies: {
              "@microsoft/agent-governance-sdk": version,
              "@modelcontextprotocol/sdk": "1.24.3",
            },
          },
          "node_modules/@microsoft/agent-governance-sdk": {
            version,
            integrity: "sha512-test-sdk",
          },
          "node_modules/@modelcontextprotocol/sdk": {
            version: "1.24.3",
            integrity: "sha512-test-mcp",
          },
        },
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
  await writeFile(
    join(packageRoot, "assets", "extensions", "agt-global-policy", "gemini-extension.json"),
    `${JSON.stringify({ name: "agt-global-policy", version }, null, 2)}\n`,
    "utf8",
  );
  await writeFile(
    join(packageRoot, "assets", "extensions", "agt-global-policy", "GEMINI.md"),
    "# AGT Gemini\n",
    "utf8",
  );
  await writeFile(
    join(packageRoot, "assets", "extensions", "agt-global-policy", "package.json"),
    `${JSON.stringify({ private: true, type: "module" }, null, 2)}\n`,
    "utf8",
  );
  await writeFile(
    join(packageRoot, "assets", "extensions", "agt-global-policy", "hooks", "hooks.json"),
    `${JSON.stringify({ BeforeTool: [] }, null, 2)}\n`,
    "utf8",
  );
  await writeFile(
    join(packageRoot, "assets", "extensions", "agt-global-policy", "mcp", "server.mjs"),
    "export const ready = true;\n",
    "utf8",
  );
  await writeFile(
    join(packageRoot, "assets", "extensions", "agt-global-policy", "commands", "agt", "status.toml"),
    "prompt = \"status\"\n",
    "utf8",
  );
  await writeFile(
    join(packageRoot, "assets", "extensions", "agt-global-policy", "commands", "agt", "check.toml"),
    "prompt = \"check {{args}}\"\n",
    "utf8",
  );
  await writeFile(
    join(packageRoot, "assets", "extensions", "agt-global-policy", "config", "default-policy.json"),
    `${JSON.stringify(createPolicyFixture(), null, 2)}\n`,
    "utf8",
  );
  await writeFile(
    join(
      packageRoot,
      "node_modules",
      "@microsoft",
      "agent-governance-sdk",
      "package.json",
    ),
    `${JSON.stringify(
      {
        name: "@microsoft/agent-governance-sdk",
        version,
        dependencies: {},
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
  await writeFile(
    join(packageRoot, "node_modules", "@microsoft", "agent-governance-sdk", "dist", "index.js"),
    "export const version = '3.6.0';\n",
    "utf8",
  );
  await writeFile(
    join(packageRoot, "node_modules", "@modelcontextprotocol", "sdk", "package.json"),
    `${JSON.stringify({ name: "@modelcontextprotocol/sdk", version: "1.24.3", dependencies: {} }, null, 2)}\n`,
    "utf8",
  );
}

test("installPackage vendors the Gemini extension and uninstallPackage removes managed state", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-gemini-package-"));
  const packageRoot = join(root, "package");
  const geminiHome = join(root, ".gemini");

  await mkdir(geminiHome, { recursive: true });
  await seedPackageFixture(packageRoot);

  const installResult = await installPackage({ geminiHome, packageRoot });
  const doctorReport = await diagnoseInstall({ geminiHome, packageRoot });

  assert.equal(installResult.settings.hookEnablement, "inspect in Gemini CLI (/hooks panel)");
  assert.equal(doctorReport.ok, true);
  assert.equal(doctorReport.managedInstall, true);
  assert.equal(doctorReport.geminiManifestPresent, true);
  assert.equal(doctorReport.hookConfigPresent, true);
  assert.equal(doctorReport.mcpServerPresent, true);
  assert.equal(doctorReport.vendoredRuntimeChecks["AGT SDK"], true);
  assert.equal(doctorReport.vendoredRuntimeChecks["MCP SDK"], true);
  assert.equal(
    JSON.parse(await readFile(join(geminiHome, "agt", "policy.json"), "utf8")).schemaVersion,
    1,
  );
  assert.match(
    await readFile(join(geminiHome, "extensions", "agt-global-policy", ".env"), "utf8"),
    /AGT_GEMINI_POLICY_PATH/,
  );

  const uninstallResult = await uninstallPackage({
    geminiHome,
    packageRoot,
    removePolicy: true,
  });

  assert.equal(uninstallResult.extensionRemoved, true);
  assert.equal(uninstallResult.policyRemoved, true);

  await rm(root, { recursive: true, force: true });
});

test("diagnoseInstall reports stale managed installs and installPackage refreshes the policy when forced", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-gemini-update-"));
  const packageRoot = join(root, "package");
  const geminiHome = join(root, ".gemini");

  await mkdir(geminiHome, { recursive: true });
  await seedPackageFixture(packageRoot, "3.6.1");

  await installPackage({ geminiHome, packageRoot });
  await writeFile(
    join(geminiHome, "extensions", "agt-global-policy", ".agt-install-manifest.json"),
    `${JSON.stringify(
      {
        extensionName: "agt-global-policy",
        installedAt: new Date().toISOString(),
        installedBy: "@microsoft/agent-governance-gemini-cli",
        installedByVersion: "3.6.0",
        policyPath: join(geminiHome, "agt", "policy.json"),
        policySeededByInstaller: true,
        schemaVersion: 1,
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
  await writeFile(
    join(geminiHome, "agt", "policy.json"),
    `${JSON.stringify(createPolicyFixture({ version: 9 }), null, 2)}\n`,
    "utf8",
  );

  const report = await diagnoseInstall({ geminiHome, packageRoot });
  assert.equal(report.ok, true);
  assert.match(report.warnings.join("\n"), /agt-gemini update/);
  await writeFile(
    join(geminiHome, "extensions", "agt-global-policy", ".env"),
    "AGT_GEMINI_POLICY_PATH=\"D:\\\\custom-policy.json\"\nCUSTOM_FLAG=true\n",
    "utf8",
  );

  await installPackage({
    forcePolicy: true,
    geminiHome,
    packageRoot,
  });

  const refreshedPolicy = JSON.parse(await readFile(join(geminiHome, "agt", "policy.json"), "utf8"));
  assert.equal(refreshedPolicy.version, 1);
  assert.match(
    await readFile(join(geminiHome, "extensions", "agt-global-policy", ".env"), "utf8"),
    /CUSTOM_FLAG=true/,
  );

  await rm(root, { recursive: true, force: true });
});

test("installPackage refuses to overwrite an unmanaged install unless explicitly requested", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-gemini-unmanaged-"));
  const packageRoot = join(root, "package");
  const geminiHome = join(root, ".gemini");

  await mkdir(join(geminiHome, "extensions", "agt-global-policy"), { recursive: true });
  await seedPackageFixture(packageRoot);

  await assert.rejects(
    () => installPackage({ geminiHome, packageRoot }),
    /not marked as an AGT-managed install/,
  );

  const result = await installPackage({
    geminiHome,
    packageRoot,
    replaceUnmanaged: true,
  });
  assert.equal(result.replacedUnmanaged, true);

  await rm(root, { recursive: true, force: true });
});

test("applyPolicy, validatePolicy, and showPolicy operate on the Gemini policy path", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-gemini-policy-"));
  const packageRoot = join(root, "package");
  const geminiHome = join(root, ".gemini");
  const customPolicyPath = join(root, "custom-policy.json");

  await mkdir(geminiHome, { recursive: true });
  await seedPackageFixture(packageRoot);
  await writeFile(customPolicyPath, `${JSON.stringify(createPolicyFixture({ version: 3 }), null, 2)}\n`, "utf8");

  const validation = await validatePolicy({
    file: customPolicyPath,
    geminiHome,
    packageRoot,
  });
  assert.equal(validation.schemaVersion, 1);

  const applyResult = await applyPolicy({
    file: customPolicyPath,
    geminiHome,
    packageRoot,
  });
  assert.equal(applyResult.policyPath, join(geminiHome, "agt", "policy.json"));

  const showResult = await showPolicy({ geminiHome, packageRoot });
  assert.equal(showResult.source, "user");
  assert.equal(showResult.policy.version, 3);

  await rm(root, { recursive: true, force: true });
});

test("installPackage fails clearly when vendored runtime dependencies are missing", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-gemini-missing-sdk-"));
  const packageRoot = join(root, "package");
  const geminiHome = join(root, ".gemini");

  await mkdir(geminiHome, { recursive: true });
  await seedPackageFixture(packageRoot);
  await rm(join(packageRoot, "node_modules", "@microsoft", "agent-governance-sdk"), {
    recursive: true,
    force: true,
  });

  await assert.rejects(
    () => installPackage({ geminiHome, packageRoot }),
    /Missing runtime dependency @microsoft\/agent-governance-sdk/,
  );

  await rm(root, { recursive: true, force: true });
});

test("installPackage fails when installed runtime dependencies drift from package-lock metadata", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-gemini-lock-drift-"));
  const packageRoot = join(root, "package");
  const geminiHome = join(root, ".gemini");

  await mkdir(geminiHome, { recursive: true });
  await seedPackageFixture(packageRoot);
  await writeFile(
    join(packageRoot, "node_modules", "@modelcontextprotocol", "sdk", "package.json"),
    `${JSON.stringify({ name: "@modelcontextprotocol/sdk", version: "1.29.1", dependencies: {} }, null, 2)}\n`,
    "utf8",
  );

  await assert.rejects(
    () => installPackage({ geminiHome, packageRoot }),
    /does not match package-lock\.json/,
  );

  await rm(root, { recursive: true, force: true });
});

test("resolveGeminiHome honors GEMINI_CLI_HOME as the parent of .gemini", () => {
  const originalGeminiCliHome = process.env.GEMINI_CLI_HOME;
  const originalGeminiHome = process.env.GEMINI_HOME;
  process.env.GEMINI_CLI_HOME = "C:\\Users\\Example\\GeminiRoot";
  delete process.env.GEMINI_HOME;

  try {
    assert.equal(
      resolveGeminiHome(),
      join("C:\\Users\\Example\\GeminiRoot", ".gemini"),
    );
  } finally {
    if (originalGeminiCliHome === undefined) {
      delete process.env.GEMINI_CLI_HOME;
    } else {
      process.env.GEMINI_CLI_HOME = originalGeminiCliHome;
    }
    if (originalGeminiHome === undefined) {
      delete process.env.GEMINI_HOME;
    } else {
      process.env.GEMINI_HOME = originalGeminiHome;
    }
  }
});
