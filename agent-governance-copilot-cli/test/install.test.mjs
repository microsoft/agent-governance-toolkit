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
      allowedTools: ["view", "glob", "rg", "agt_policy_status", "agt_policy_check_text"],
      blockedTools: [],
      defaultEffect: "review",
      reviewTools: ["powershell", "bash"],
    },
    directResourcePolicies: {
      pathRules: [
        {
          id: "secret-read",
          effect: "deny",
          operation: "read",
          pathPatterns: [{ source: "(^|/)\\.env$", flags: "i" }],
        },
      ],
      urlRules: [
        {
          id: "metadata-endpoints",
          effect: "deny",
          urlPatterns: [{ source: "169\\.254\\.169\\.254|100\\.100\\.100\\.200|metadata\\.google\\.internal", flags: "i" }],
        },
      ],
    },
    scanOutputTools: ["powershell", "bash", "read_powershell", "list_powershell"],
    poisoningPatterns: [],
    ...overrides,
  };
}

test("installPackage vendors the extension and uninstallPackage removes managed state", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-copilot-package-"));
  const packageRoot = join(root, "package");
  const copilotHome = join(root, ".copilot");

  await mkdir(copilotHome, { recursive: true });
  await mkdir(join(packageRoot, "assets", "extensions", "agt-global-policy", "config"), {
    recursive: true,
  });
  await mkdir(join(packageRoot, "node_modules", "@microsoft", "agent-governance-sdk", "dist"), {
    recursive: true,
  });
  await mkdir(join(packageRoot, "node_modules", "js-yaml"), { recursive: true });

  await writeFile(
    join(packageRoot, "package.json"),
    `${JSON.stringify(
      {
        name: "@microsoft/agent-governance-copilot-cli",
        version: "3.6.0",
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
  await writeFile(
    join(packageRoot, "assets", "extensions", "agt-global-policy", "extension.mjs"),
    "await import('./main.mjs');\n",
    "utf8",
  );
  await writeFile(
    join(packageRoot, "assets", "extensions", "agt-global-policy", "main.mjs"),
    "export const ready = true;\n",
    "utf8",
  );
  await writeFile(
    join(packageRoot, "assets", "extensions", "agt-global-policy", "package.json"),
    `${JSON.stringify({ private: true, type: "module" }, null, 2)}\n`,
    "utf8",
  );
  await writeFile(
    join(packageRoot, "assets", "extensions", "agt-global-policy", "config", "default-policy.json"),
    `${JSON.stringify({ schemaVersion: 1, version: 1, mode: "enforce" }, null, 2)}\n`,
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
        version: "3.6.0",
        dependencies: {
          "js-yaml": "4.1.1",
        },
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
    join(packageRoot, "node_modules", "js-yaml", "package.json"),
    `${JSON.stringify({ name: "js-yaml", version: "4.1.1", dependencies: {} }, null, 2)}\n`,
    "utf8",
  );
  await writeFile(join(packageRoot, "node_modules", "js-yaml", "index.js"), "export {};\n", "utf8");
  await writeFile(
    join(copilotHome, "settings.json"),
    `${JSON.stringify(
      {
        experimental: true,
        experimental_flags: ["EXTENSIONS"],
      },
      null,
      2,
    )}\n`,
    "utf8",
  );

  const installResult = await installPackage({ copilotHome, packageRoot });
  const doctorReport = await diagnoseInstall({ copilotHome, packageRoot });

  assert.equal(installResult.settings.enabled, true);
  assert.equal(doctorReport.ok, true);
  assert.equal(doctorReport.vendoredSdkPresent, true);
  assert.equal(doctorReport.managedInstall, true);
  assert.equal(doctorReport.policySchemaVersion, 1);
  assert.equal(
    JSON.parse(await readFile(join(copilotHome, "agt", "policy.json"), "utf8")).schemaVersion,
    1,
  );

  const uninstallResult = await uninstallPackage({
    copilotHome,
    packageRoot,
    removePolicy: true,
  });

  assert.equal(uninstallResult.extensionRemoved, true);
  assert.equal(uninstallResult.policyRemoved, true);

  await rm(root, { recursive: true, force: true });
});

test("diagnoseInstall reports stale managed installs and installPackage refreshes the policy when forced", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-copilot-update-"));
  const packageRoot = join(root, "package");
  const copilotHome = join(root, ".copilot");

  await mkdir(copilotHome, { recursive: true });
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
        name: "@microsoft/agent-governance-copilot-cli",
        version: "3.6.1",
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
  await writeFile(
    join(packageRoot, "assets", "extensions", "agt-global-policy", "extension.mjs"),
    "await import('./main.mjs');\n",
    "utf8",
  );
  await writeFile(
    join(packageRoot, "assets", "extensions", "agt-global-policy", "main.mjs"),
    "export const ready = true;\n",
    "utf8",
  );
  await writeFile(
    join(packageRoot, "assets", "extensions", "agt-global-policy", "package.json"),
    `${JSON.stringify({ private: true, type: "module" }, null, 2)}\n`,
    "utf8",
  );
  await writeFile(
    join(packageRoot, "assets", "extensions", "agt-global-policy", "config", "default-policy.json"),
    `${JSON.stringify({ schemaVersion: 1, version: 2, mode: "enforce" }, null, 2)}\n`,
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
        version: "3.6.1",
        dependencies: {},
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
  await writeFile(
    join(packageRoot, "node_modules", "@microsoft", "agent-governance-sdk", "dist", "index.js"),
    "export const version = '3.6.1';\n",
    "utf8",
  );

  await installPackage({ copilotHome, packageRoot });
  await writeFile(
    join(copilotHome, "extensions", "agt-global-policy", ".agt-install-manifest.json"),
    `${JSON.stringify(
      {
        extensionName: "agt-global-policy",
        installedAt: new Date().toISOString(),
        installedBy: "@microsoft/agent-governance-copilot-cli",
        installedByVersion: "3.6.0",
        policyPath: join(copilotHome, "agt", "policy.json"),
        policySeededByInstaller: true,
        schemaVersion: 1,
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
  await writeFile(
    join(copilotHome, "agt", "policy.json"),
    `${JSON.stringify({ schemaVersion: 1, version: 99, mode: "advisory" }, null, 2)}\n`,
    "utf8",
  );

  const staleReport = await diagnoseInstall({ copilotHome, packageRoot });
  assert.equal(staleReport.currentPackageVersion, "3.6.1");
  assert.equal(staleReport.installedByVersion, "3.6.0");
  assert.ok(staleReport.warnings.some((warning) => warning.includes("agt-copilot update")));

  await installPackage({ copilotHome, forcePolicy: true, packageRoot });

  const refreshedPolicy = JSON.parse(await readFile(join(copilotHome, "agt", "policy.json"), "utf8"));
  const refreshedReport = await diagnoseInstall({ copilotHome, packageRoot });
  assert.equal(refreshedPolicy.version, 2);
  assert.equal(refreshedReport.installedByVersion, "3.6.1");

  await rm(root, { recursive: true, force: true });
});

test("installPackage can replace an unmanaged install when explicitly requested", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-copilot-replace-"));
  const packageRoot = join(root, "package");
  const copilotHome = join(root, ".copilot");
  const extensionRoot = join(copilotHome, "extensions", "agt-global-policy");

  await mkdir(join(extensionRoot, "legacy"), { recursive: true });
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
        name: "@microsoft/agent-governance-copilot-cli",
        version: "3.6.1",
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
  await writeFile(join(extensionRoot, "legacy", "marker.txt"), "old install\n", "utf8");
  await writeFile(
    join(packageRoot, "assets", "extensions", "agt-global-policy", "extension.mjs"),
    "await import('./main.mjs');\n",
    "utf8",
  );
  await writeFile(
    join(packageRoot, "assets", "extensions", "agt-global-policy", "main.mjs"),
    "export const ready = true;\n",
    "utf8",
  );
  await writeFile(
    join(packageRoot, "assets", "extensions", "agt-global-policy", "package.json"),
    `${JSON.stringify({ private: true, type: "module" }, null, 2)}\n`,
    "utf8",
  );
  await writeFile(
    join(packageRoot, "assets", "extensions", "agt-global-policy", "config", "default-policy.json"),
    `${JSON.stringify({ schemaVersion: 1, version: 3, mode: "enforce" }, null, 2)}\n`,
    "utf8",
  );
  await writeFile(
    join(packageRoot, "node_modules", "@microsoft", "agent-governance-sdk", "package.json"),
    `${JSON.stringify(
      {
        name: "@microsoft/agent-governance-sdk",
        version: "3.6.1",
        dependencies: {},
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
  await writeFile(
    join(packageRoot, "node_modules", "@microsoft", "agent-governance-sdk", "dist", "index.js"),
    "export const version = '3.6.1';\n",
    "utf8",
  );

  await assert.rejects(
    installPackage({ copilotHome, packageRoot }),
    /--replace-unmanaged/,
  );

  const result = await installPackage({
    copilotHome,
    packageRoot,
    replaceUnmanaged: true,
  });
  assert.equal(result.replacedUnmanaged, true);
  assert.equal(JSON.parse(await readFile(join(extensionRoot, ".agt-install-manifest.json"), "utf8")).installedByVersion, "3.6.1");

  await rm(root, { recursive: true, force: true });
});

test("policy commands can apply, validate, show, and resolve bundled profiles", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-copilot-policy-"));
  const packageRoot = join(root, "package");
  const copilotHome = join(root, ".copilot");
  const profileRoot = join(packageRoot, "assets", "extensions", "agt-global-policy", "config", "profiles");

  await mkdir(profileRoot, { recursive: true });
  await writeFile(
    join(packageRoot, "package.json"),
    `${JSON.stringify(
      {
        name: "@microsoft/agent-governance-copilot-cli",
        version: "3.6.1",
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
  await writeFile(
    join(packageRoot, "assets", "extensions", "agt-global-policy", "config", "default-policy.json"),
    `${JSON.stringify(createPolicyFixture({ profile: "strict" }), null, 2)}\n`,
    "utf8",
  );
  await writeFile(
    join(profileRoot, "balanced.json"),
    `${JSON.stringify(createPolicyFixture({ profile: "balanced", version: 2 }), null, 2)}\n`,
    "utf8",
  );
  await writeFile(
    join(profileRoot, "advisory.json"),
    `${JSON.stringify(
      createPolicyFixture({
        profile: "advisory",
        version: 3,
        mode: "advisory",
        toolPolicies: {
          allowedTools: ["view", "glob", "rg", "agt_policy_status", "agt_policy_check_text"],
          blockedTools: [],
          defaultEffect: "review",
          reviewTools: ["powershell", "bash"],
        },
      }),
      null,
      2,
    )}\n`,
    "utf8",
  );
  await writeFile(
    join(root, "custom-policy.json"),
    `${JSON.stringify(createPolicyFixture({ profile: "custom", version: 4 }), null, 2)}\n`,
    "utf8",
  );

  const appliedProfile = await applyPolicy({
    copilotHome,
    packageRoot,
    profile: "balanced",
  });
  assert.equal(appliedProfile.schemaVersion, 1);
  assert.equal(
    JSON.parse(await readFile(join(copilotHome, "agt", "policy.json"), "utf8")).profile,
    "balanced",
  );

  const validatedCurrent = await validatePolicy({
    copilotHome,
    packageRoot,
  });
  assert.equal(validatedCurrent.schemaVersion, 1);
  assert.equal(validatedCurrent.sourcePath, join(copilotHome, "agt", "policy.json"));

  const appliedFile = await applyPolicy({
    copilotHome,
    file: join(root, "custom-policy.json"),
    packageRoot,
  });
  assert.equal(appliedFile.schemaVersion, 1);
  assert.equal(
    JSON.parse(await readFile(join(copilotHome, "agt", "policy.json"), "utf8")).profile,
    "custom",
  );

  const shown = await showPolicy({ copilotHome, packageRoot });
  assert.equal(shown.source, "user");
  assert.equal(shown.policy.profile, "custom");

  const validatedProfile = await validatePolicy({
    copilotHome,
    packageRoot,
    profile: "advisory",
  });
  assert.equal(validatedProfile.sourcePath, join(profileRoot, "advisory.json"));

  await rm(root, { recursive: true, force: true });
});

test("policy commands reject weakened custom policies but still allow bundled advisory", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-copilot-policy-baseline-"));
  const packageRoot = join(root, "package");
  const profileRoot = join(packageRoot, "assets", "extensions", "agt-global-policy", "config", "profiles");

  await mkdir(profileRoot, { recursive: true });
  await writeFile(
    join(packageRoot, "package.json"),
    `${JSON.stringify({ name: "@microsoft/agent-governance-copilot-cli", version: "3.6.1" }, null, 2)}\n`,
    "utf8",
  );
  await writeFile(
    join(profileRoot, "advisory.json"),
    `${JSON.stringify(
      createPolicyFixture({
        profile: "advisory",
        version: 3,
        mode: "advisory",
      }),
      null,
      2,
    )}\n`,
    "utf8",
  );
  await writeFile(
    join(root, "weakened-policy.json"),
    `${JSON.stringify(
      createPolicyFixture({
        toolPolicies: {
          allowedTools: ["view"],
          blockedTools: [],
          defaultEffect: "allow",
          reviewTools: [],
        },
        scanOutputTools: ["powershell"],
      }),
      null,
      2,
    )}\n`,
    "utf8",
  );

  const bundled = await validatePolicy({ packageRoot, profile: "advisory" });
  assert.equal(bundled.schemaVersion, 1);

  await applyPolicy({
    copilotHome: join(root, ".copilot"),
    packageRoot,
    profile: "advisory",
  });
  const validatedInstalledAdvisory = await validatePolicy({
    copilotHome: join(root, ".copilot"),
    packageRoot,
  });
  assert.equal(validatedInstalledAdvisory.schemaVersion, 1);

  await assert.rejects(
    validatePolicy({
      file: join(root, "weakened-policy.json"),
      packageRoot,
    }),
    /Custom policies must keep toolPolicies\.defaultEffect set to review|Policies must scan read_powershell output/,
  );

  await rm(root, { recursive: true, force: true });
});

test("policy commands reject invalid profile and conflicting sources", async () => {
  const root = await mkdtemp(join(tmpdir(), "agt-copilot-policy-errors-"));
  const packageRoot = join(root, "package");
  const copilotHome = join(root, ".copilot");
  const profileRoot = join(packageRoot, "assets", "extensions", "agt-global-policy", "config", "profiles");

  await mkdir(profileRoot, { recursive: true });
  await writeFile(
    join(packageRoot, "package.json"),
    `${JSON.stringify(
      {
        name: "@microsoft/agent-governance-copilot-cli",
        version: "3.6.1",
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
  await writeFile(
    join(root, "custom-policy.json"),
    `${JSON.stringify({ schemaVersion: 1, version: 4, mode: "enforce", profile: "custom" }, null, 2)}\n`,
    "utf8",
  );

  await assert.rejects(
    validatePolicy({
      copilotHome,
      packageRoot,
      profile: "..\\..\\secrets",
    }),
    /Invalid policy profile/,
  );

  await assert.rejects(
    validatePolicy({
      copilotHome,
      file: join(root, "custom-policy.json"),
      packageRoot,
      profile: "balanced",
    }),
    /Specify either --file or --profile, not both/,
  );

  await assert.rejects(
    validatePolicy({
      copilotHome,
      packageRoot,
      profile: "missing",
    }),
    /Unknown policy profile/,
  );

  await rm(root, { recursive: true, force: true });
});
