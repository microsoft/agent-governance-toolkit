// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import {
  applyPolicy,
  diagnoseInstall,
  installPackage,
  resolveAntigravityHome,
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

async function seedPackageFixture(packageRoot, version = "3.3.0") {
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
  await writeFile(
    join(packageRoot, "package.json"),
    `${JSON.stringify(
      {
        name: "@microsoft/agent-governance-antigravity-cli",
        version,
        dependencies: {
          "@microsoft/agent-governance-sdk": version,
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
        name: "@microsoft/agent-governance-antigravity-cli",
        version,
        lockfileVersion: 3,
        requires: true,
        packages: {
          "": {
            name: "@microsoft/agent-governance-antigravity-cli",
            version,
            dependencies: {
              "@microsoft/agent-governance-sdk": version,
            },
          },
          "node_modules/@microsoft/agent-governance-sdk": {
            version,
            integrity: "sha512-test-sdk",
          },
        },
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
  await writeFile(
    join(packageRoot, "assets", "extensions", "agt-global-policy", "antigravity-extension.json"),
    `${JSON.stringify({ name: "agt-global-policy", version }, null, 2)}\n`,
    "utf8",
  );
  await writeFile(
    join(packageRoot, "assets", "extensions", "agt-global-policy", "ANTIGRAVITY.md"),
    "# AGT Antigravity\n",
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
    "export const version = '3.3.0';\n",
    "utf8",
  );
}

test("installPackage vendors the Antigravity extension and uninstallPackage removes managed state", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-antigravity-package-"));
  const packageRoot = join(root, "package");
  const antigravityHome = join(root, ".antigravity");

  await mkdir(antigravityHome, { recursive: true });
  await seedPackageFixture(packageRoot);

  const installResult = await installPackage({ antigravityHome, packageRoot });
  const doctorReport = await diagnoseInstall({ antigravityHome, packageRoot });

  assert.equal(installResult.settings.hookEnablement, "inspect in Antigravity CLI (/hooks panel)");
  assert.equal(doctorReport.ok, true);
  assert.equal(doctorReport.managedInstall, true);
  assert.equal(doctorReport.antigravityManifestPresent, true);
  assert.equal(doctorReport.hookConfigPresent, true);
  assert.equal(doctorReport.mcpServerPresent, true);
  assert.equal(doctorReport.vendoredRuntimeChecks["AGT SDK"], true);
  assert.equal(
    JSON.parse(await readFile(join(antigravityHome, "agt", "policy.json"), "utf8")).schemaVersion,
    1,
  );
  assert.match(
    await readFile(join(antigravityHome, "extensions", "agt-global-policy", ".env"), "utf8"),
    /AGT_ANTIGRAVITY_POLICY_PATH/,
  );

  const uninstallResult = await uninstallPackage({
    antigravityHome,
    packageRoot,
    removePolicy: true,
  });

  assert.equal(uninstallResult.extensionRemoved, true);
  assert.equal(uninstallResult.policyRemoved, true);

  await rm(root, { recursive: true, force: true });
});

test("diagnoseInstall reports stale managed installs and installPackage refreshes the policy when forced", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-antigravity-update-"));
  const packageRoot = join(root, "package");
  const antigravityHome = join(root, ".antigravity");

  await mkdir(antigravityHome, { recursive: true });
  await seedPackageFixture(packageRoot, "3.3.1");

  await installPackage({ antigravityHome, packageRoot });
  await writeFile(
    join(antigravityHome, "extensions", "agt-global-policy", ".agt-install-manifest.json"),
    `${JSON.stringify(
      {
        extensionName: "agt-global-policy",
        installedAt: new Date().toISOString(),
        installedBy: "@microsoft/agent-governance-antigravity-cli",
        installedByVersion: "3.3.0",
        policyPath: join(antigravityHome, "agt", "policy.json"),
        policySeededByInstaller: true,
        schemaVersion: 1,
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
  await writeFile(
    join(antigravityHome, "agt", "policy.json"),
    `${JSON.stringify(createPolicyFixture({ version: 9 }), null, 2)}\n`,
    "utf8",
  );

  const report = await diagnoseInstall({ antigravityHome, packageRoot });
  assert.equal(report.ok, true);
  assert.match(report.warnings.join("\n"), /agt-antigravity update/);
  await writeFile(
    join(antigravityHome, "extensions", "agt-global-policy", ".env"),
    "AGT_ANTIGRAVITY_POLICY_PATH=\"D:\\\\custom-policy.json\"\nCUSTOM_FLAG=true\n",
    "utf8",
  );

  await installPackage({
    forcePolicy: true,
    antigravityHome,
    packageRoot,
  });

  const refreshedPolicy = JSON.parse(await readFile(join(antigravityHome, "agt", "policy.json"), "utf8"));
  assert.equal(refreshedPolicy.version, 1);
  assert.match(
    await readFile(join(antigravityHome, "extensions", "agt-global-policy", ".env"), "utf8"),
    /CUSTOM_FLAG=true/,
  );

  await rm(root, { recursive: true, force: true });
});

test("installPackage refuses to overwrite an unmanaged install unless explicitly requested", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-antigravity-unmanaged-"));
  const packageRoot = join(root, "package");
  const antigravityHome = join(root, ".antigravity");

  await mkdir(join(antigravityHome, "extensions", "agt-global-policy"), { recursive: true });
  await seedPackageFixture(packageRoot);

  await assert.rejects(
    () => installPackage({ antigravityHome, packageRoot }),
    /not marked as an AGT-managed install/,
  );

  const result = await installPackage({
    antigravityHome,
    packageRoot,
    replaceUnmanaged: true,
  });
  assert.equal(result.replacedUnmanaged, true);

  await rm(root, { recursive: true, force: true });
});

test("applyPolicy, validatePolicy, and showPolicy operate on the Antigravity policy path", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-antigravity-policy-"));
  const packageRoot = join(root, "package");
  const antigravityHome = join(root, ".antigravity");
  const customPolicyPath = join(root, "custom-policy.json");

  await mkdir(antigravityHome, { recursive: true });
  await seedPackageFixture(packageRoot);
  await writeFile(customPolicyPath, `${JSON.stringify(createPolicyFixture({ version: 3 }), null, 2)}\n`, "utf8");

  const validation = await validatePolicy({
    file: customPolicyPath,
    antigravityHome,
    packageRoot,
  });
  assert.equal(validation.schemaVersion, 1);

  const applyResult = await applyPolicy({
    file: customPolicyPath,
    antigravityHome,
    packageRoot,
  });
  assert.equal(applyResult.policyPath, join(antigravityHome, "agt", "policy.json"));

  const showResult = await showPolicy({ antigravityHome, packageRoot });
  assert.equal(showResult.source, "user");
  assert.equal(showResult.policy.version, 3);

  await rm(root, { recursive: true, force: true });
});

test("installPackage fails clearly when vendored runtime dependencies are missing", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-antigravity-missing-sdk-"));
  const packageRoot = join(root, "package");
  const antigravityHome = join(root, ".antigravity");

  await mkdir(antigravityHome, { recursive: true });
  await seedPackageFixture(packageRoot);
  await rm(join(packageRoot, "node_modules", "@microsoft", "agent-governance-sdk"), {
    recursive: true,
    force: true,
  });

  await assert.rejects(
    () => installPackage({ antigravityHome, packageRoot }),
    /Missing runtime dependency @microsoft\/agent-governance-sdk/,
  );

  await rm(root, { recursive: true, force: true });
});

test("installPackage fails when installed runtime dependencies drift from package-lock metadata", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-antigravity-lock-drift-"));
  const packageRoot = join(root, "package");
  const antigravityHome = join(root, ".antigravity");

  await mkdir(antigravityHome, { recursive: true });
  await seedPackageFixture(packageRoot);
  await writeFile(
    join(packageRoot, "node_modules", "@microsoft", "agent-governance-sdk", "package.json"),
    `${JSON.stringify({ name: "@microsoft/agent-governance-sdk", version: "9.9.9", dependencies: {} }, null, 2)}\n`,
    "utf8",
  );

  await assert.rejects(
    () => installPackage({ antigravityHome, packageRoot }),
    /does not match package-lock\.json/,
  );

  await rm(root, { recursive: true, force: true });
});

test("resolveAntigravityHome honors ANTIGRAVITY_CLI_HOME as the parent of .antigravity", () => {
  const originalAntigravityCliHome = process.env.ANTIGRAVITY_CLI_HOME;
  const originalAntigravityHome = process.env.ANTIGRAVITY_HOME;
  const configuredCliHome = process.platform === "win32"
    ? "C:\\Users\\Example\\AntigravityRoot"
    : "/tmp/antigravity-cli-home";
  process.env.ANTIGRAVITY_CLI_HOME = configuredCliHome;
  delete process.env.ANTIGRAVITY_HOME;

  try {
    assert.equal(
      resolveAntigravityHome(),
      join(resolve(configuredCliHome), ".antigravity"),
    );
  } finally {
    if (originalAntigravityCliHome === undefined) {
      delete process.env.ANTIGRAVITY_CLI_HOME;
    } else {
      process.env.ANTIGRAVITY_CLI_HOME = originalAntigravityCliHome;
    }
    if (originalAntigravityHome === undefined) {
      delete process.env.ANTIGRAVITY_HOME;
    } else {
      process.env.ANTIGRAVITY_HOME = originalAntigravityHome;
    }
  }
});
