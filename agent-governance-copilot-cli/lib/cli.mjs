// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

import { existsSync } from "node:fs";
import {
  cp,
  mkdtemp,
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";

const PACKAGE_NAME = "@microsoft/agent-governance-copilot-cli";
const EXTENSION_NAME = "agt-global-policy";
const INSTALL_MANIFEST_NAME = ".agt-install-manifest.json";
const SUPPORTED_POLICY_SCHEMA_VERSION = 1;
const VENDORED_SDK_ENTRY_RELATIVE_PATH = join(
  "vendor",
  "agent-governance-sdk",
  "node_modules",
  "@microsoft",
  "agent-governance-sdk",
  "dist",
  "index.js",
);

export async function runCli(argv = [], io = console) {
  try {
    const parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        "copilot-home": { type: "string" },
        file: { type: "string" },
        "force-policy": { type: "boolean" },
        help: { type: "boolean", short: "h" },
        json: { type: "boolean" },
        profile: { type: "string" },
        "remove-policy": { type: "boolean" },
        "replace-unmanaged": { type: "boolean" },
        version: { type: "boolean", short: "v" },
      },
    });

    const command = (parsed.positionals[0] ?? "help").toLowerCase();
    const copilotHome = resolveCopilotHome(parsed.values["copilot-home"]);

    if (parsed.values.version) {
      const metadata = await readPackageMetadata();
      io.log(`${metadata.name} ${metadata.version}`);
      return 0;
    }

    if (parsed.values.help || command === "help") {
      io.log(getHelpText());
      return 0;
    }

    if (command === "install" || command === "update") {
      const result = await installPackage({
        copilotHome,
        forcePolicy: parsed.values["force-policy"] ?? false,
        replaceUnmanaged: parsed.values["replace-unmanaged"] ?? false,
      });
      const verb = command === "update" ? "Updated" : "Installed";
      io.log(`${verb} ${PACKAGE_NAME} at ${result.extensionPath}`);
      if (result.replacedUnmanaged) {
        io.log("Replaced an unmanaged agt-global-policy install because --replace-unmanaged was specified.");
      }
      io.log(`Policy file: ${result.policyPath}`);
      if (!result.settings.enabled) {
        io.log(
          "Copilot CLI extensions are not enabled yet. Add experimental=true and experimental_flags=[\"EXTENSIONS\"] to your Copilot settings, then run /clear.",
        );
      }
      io.log(
        `If a custom policy becomes invalid, remove ${result.policyPath} or point AGT_COPILOT_POLICY_PATH at a valid replacement.`,
      );
      io.log("Reload Copilot CLI with /clear and inspect with /agt status.");
      return 0;
    }

    if (command === "policy") {
      const subcommand = (parsed.positionals[1] ?? "help").toLowerCase();
      const packageRoot = getPackageRoot();

      if (subcommand === "apply") {
        const result = await applyPolicy({
          copilotHome,
          file: parsed.values.file,
          packageRoot,
          profile: parsed.values.profile,
        });
        io.log(`Applied policy to ${result.policyPath}`);
        io.log(`Source: ${result.sourcePath}`);
        io.log(`Schema version: ${result.schemaVersion}`);
        io.log("Reload Copilot CLI with /clear or /agt reload to pick up the new policy.");
        return 0;
      }

      if (subcommand === "validate") {
        const result = await validatePolicy({
          copilotHome,
          file: parsed.values.file,
          packageRoot,
          profile: parsed.values.profile,
        });
        io.log(`Valid policy: ${result.sourcePath}`);
        io.log(`Schema version: ${result.schemaVersion}`);
        return 0;
      }

      if (subcommand === "path") {
        io.log(getPackagePaths({ copilotHome, packageRoot }).policyPath);
        return 0;
      }

      if (subcommand === "show") {
        const result = await showPolicy({
          copilotHome,
          packageRoot,
        });
        io.log(`Policy source: ${result.source}`);
        io.log(`Policy path: ${result.sourcePath}`);
        io.log(JSON.stringify(result.policy, null, 2));
        return 0;
      }

      io.log(getPolicyHelpText());
      return subcommand === "help" ? 0 : 1;
    }

    if (command === "uninstall") {
      const result = await uninstallPackage({
        copilotHome,
        removePolicy: parsed.values["remove-policy"] ?? false,
      });
      if (!result.extensionRemoved) {
        io.log(`No managed ${EXTENSION_NAME} install was found at ${result.extensionPath}.`);
        return 0;
      }
      io.log(`Removed ${result.extensionPath}`);
      if (result.policyRemoved) {
        io.log(`Removed managed policy file ${result.policyPath}`);
      } else if (parsed.values["remove-policy"]) {
        io.log(`Preserved existing policy file ${result.policyPath}`);
      }
      return 0;
    }

    if (command === "doctor") {
      const report = await diagnoseInstall({ copilotHome });
      if (parsed.values.json) {
        io.log(JSON.stringify(report, null, 2));
      } else {
        io.log(formatDoctorReport(report));
      }
      return report.ok ? 0 : 1;
    }

    io.error(`Unknown command: ${command}\n`);
    io.error(getHelpText());
    return 1;
  } catch (error) {
    io.error(error instanceof Error ? error.message : String(error));
    return 1;
  }
}

export async function installPackage({
  copilotHome = resolveCopilotHome(),
  forcePolicy = false,
  packageRoot = getPackageRoot(),
  replaceUnmanaged = false,
} = {}) {
  const metadata = await readPackageMetadata(packageRoot);
  const paths = getPackagePaths({ copilotHome, packageRoot });
  const settings = await getCopilotSettingsStatus(paths.settingsCandidates);
  const existingManifest = await readInstallManifest(paths.manifestPath);
  const extensionExists = existsSync(paths.extensionPath);
  const shouldSeedPolicy = !existsSync(paths.policyPath);

  const replacingUnmanaged = extensionExists && !existingManifest;
  if (replacingUnmanaged && !replaceUnmanaged) {
    throw new Error(
      `Refusing to overwrite ${paths.extensionPath} because it is not marked as an AGT-managed install. Re-run with --replace-unmanaged if you want this installer to take ownership of that extension path.`,
    );
  }

  await mkdir(paths.extensionsRoot, { recursive: true });
  await mkdir(paths.policyRoot, { recursive: true });

  if (forcePolicy || shouldSeedPolicy) {
    await cp(paths.sourcePolicyPath, paths.policyPath, { force: true });
  }

  const stageRoot = await mkdtemp(join(paths.extensionsRoot, `${EXTENSION_NAME}.stage-`));
  const stagedExtensionPath = join(stageRoot, EXTENSION_NAME);
  const backupPath = join(
    paths.extensionsRoot,
    `${EXTENSION_NAME}.backup-${Date.now()}-${process.pid}`,
  );

  let renamedExisting = false;
  try {
    await cp(paths.sourceExtensionPath, stagedExtensionPath, { recursive: true, force: true });
    await vendorSdkDependencyTree({
      destinationExtensionPath: stagedExtensionPath,
      packageRoot,
    });
    await writeInstallManifest(join(stagedExtensionPath, INSTALL_MANIFEST_NAME), {
      extensionName: EXTENSION_NAME,
      installedAt: new Date().toISOString(),
      installedBy: metadata.name,
      installedByVersion: metadata.version,
      policyPath: paths.policyPath,
      policySeededByInstaller: shouldSeedPolicy,
      schemaVersion: 1,
    });

    if (extensionExists) {
      await rename(paths.extensionPath, backupPath);
      renamedExisting = true;
    }

    await rename(stagedExtensionPath, paths.extensionPath);

    if (renamedExisting) {
      await rm(backupPath, { recursive: true, force: true }).catch(() => undefined);
    }
  } catch (error) {
    if (renamedExisting && !existsSync(paths.extensionPath) && existsSync(backupPath)) {
      await rename(backupPath, paths.extensionPath).catch(() => undefined);
    }
    if (existsSync(stageRoot)) {
      await rm(stageRoot, { recursive: true, force: true }).catch(() => undefined);
    }
    throw error;
  }

  await rm(stageRoot, { recursive: true, force: true }).catch(() => undefined);

  return {
    extensionPath: paths.extensionPath,
    manifestPath: paths.manifestPath,
    policyPath: paths.policyPath,
    replacedUnmanaged: replacingUnmanaged,
    settings,
  };
}

export async function uninstallPackage({
  copilotHome = resolveCopilotHome(),
  packageRoot = getPackageRoot(),
  removePolicy = false,
} = {}) {
  const paths = getPackagePaths({ copilotHome, packageRoot });
  const manifest = await readInstallManifest(paths.manifestPath);

  if (!existsSync(paths.extensionPath)) {
    return {
      extensionPath: paths.extensionPath,
      extensionRemoved: false,
      policyPath: paths.policyPath,
      policyRemoved: false,
    };
  }

  if (!manifest) {
    throw new Error(
      `Refusing to remove ${paths.extensionPath} because it is not marked as an AGT-managed install.`,
    );
  }

  await rm(paths.extensionPath, { recursive: true, force: true });

  let policyRemoved = false;
  if (removePolicy && manifest.policySeededByInstaller && existsSync(paths.policyPath)) {
    await rm(paths.policyPath, { force: true });
    policyRemoved = true;
  }

  return {
    extensionPath: paths.extensionPath,
    extensionRemoved: true,
    policyPath: paths.policyPath,
    policyRemoved,
  };
}

export async function diagnoseInstall({
  copilotHome = resolveCopilotHome(),
  packageRoot = getPackageRoot(),
} = {}) {
  const paths = getPackagePaths({ copilotHome, packageRoot });
  const metadata = await readPackageMetadata(packageRoot);
  const settings = await getCopilotSettingsStatus(paths.settingsCandidates);
  const manifest = await readInstallManifest(paths.manifestPath);

  const report = {
    ok: true,
    copilotHome,
    extensionInstalled: existsSync(paths.extensionPath),
    extensionPath: paths.extensionPath,
    currentPackageVersion: metadata.version ?? null,
    managedInstall: Boolean(manifest),
    manifestPath: paths.manifestPath,
    installedBy: manifest?.installedBy ?? null,
    installedByVersion: manifest?.installedByVersion ?? null,
    policyPath: paths.policyPath,
    policySchemaVersion: null,
    policyValid: false,
    policySource: existsSync(paths.policyPath) ? "user" : "bundled-default",
    settings,
    vendoredSdkEntryPath: join(paths.extensionPath, VENDORED_SDK_ENTRY_RELATIVE_PATH),
    vendoredSdkPresent: existsSync(join(paths.extensionPath, VENDORED_SDK_ENTRY_RELATIVE_PATH)),
    warnings: [],
    errors: [],
  };

  if (!report.extensionInstalled) {
    report.ok = false;
    report.errors.push("Extension is not installed.");
  }
  if (report.extensionInstalled && !report.managedInstall) {
    report.ok = false;
    report.errors.push("Extension exists but is not marked as an AGT-managed install.");
  }
  if (report.extensionInstalled && !report.vendoredSdkPresent) {
    report.ok = false;
    report.errors.push("Vendored AGT SDK is missing from the installed extension.");
  }
  if (
    report.extensionInstalled &&
    report.installedByVersion &&
    report.currentPackageVersion &&
    report.installedByVersion !== report.currentPackageVersion
  ) {
    report.warnings.push(
      `Installed extension version ${report.installedByVersion} differs from package version ${report.currentPackageVersion}. Run agt-copilot update to refresh the managed install.`,
    );
  }

  if (existsSync(paths.policyPath)) {
    try {
      const policy = await readJsonFile(paths.policyPath);
      report.policySchemaVersion = normalizePolicySchemaVersion(policy?.schemaVersion);
      report.policyValid = true;
    } catch (error) {
      report.warnings.push(
        `User policy could not be parsed or validated: ${error.message} Remove the file or set AGT_COPILOT_POLICY_PATH to a valid policy.`,
      );
    }
  } else {
    report.policyValid = true;
    report.policySchemaVersion = SUPPORTED_POLICY_SCHEMA_VERSION;
    report.warnings.push("User policy file is missing; the installed extension will use its bundled default policy.");
  }

  const bundledDefaultPath = join(paths.extensionPath, "config", "default-policy.json");
  if (!existsSync(bundledDefaultPath) && report.extensionInstalled) {
    report.ok = false;
    report.errors.push("Bundled default policy is missing from the installed extension.");
  }

  if (!settings.enabled) {
    report.warnings.push("Copilot CLI extensions do not appear to be enabled in settings.json or config.json.");
  }

  return report;
}

export function resolveCopilotHome(override) {
  return resolve(override ?? process.env.COPILOT_HOME ?? join(homedir(), ".copilot"));
}

function getPackageRoot() {
  return resolve(dirname(fileURLToPath(import.meta.url)), "..");
}

function getPackagePaths({ copilotHome, packageRoot }) {
  return {
    copilotHome,
    extensionPath: join(copilotHome, "extensions", EXTENSION_NAME),
    extensionsRoot: join(copilotHome, "extensions"),
    manifestPath: join(copilotHome, "extensions", EXTENSION_NAME, INSTALL_MANIFEST_NAME),
    policyPath: join(copilotHome, "agt", "policy.json"),
    policyRoot: join(copilotHome, "agt"),
    settingsCandidates: [join(copilotHome, "settings.json"), join(copilotHome, "config.json")],
    sourceExtensionPath: join(packageRoot, "assets", "extensions", EXTENSION_NAME),
    sourcePolicyPath: join(
      packageRoot,
      "assets",
      "extensions",
      EXTENSION_NAME,
      "config",
      "default-policy.json",
    ),
    sourceProfilesRoot: join(
      packageRoot,
      "assets",
      "extensions",
      EXTENSION_NAME,
      "config",
      "profiles",
    ),
  };
}

async function readPackageMetadata(packageRoot = getPackageRoot()) {
  return readJsonFile(join(packageRoot, "package.json"));
}

export async function applyPolicy({
  copilotHome = resolveCopilotHome(),
  file,
  packageRoot = getPackageRoot(),
  profile,
} = {}) {
  const paths = getPackagePaths({ copilotHome, packageRoot });
  const sourcePath = resolvePolicySourcePath({ file, paths, profile });
  const { schemaVersion } = await validatePolicyFile(sourcePath, { paths });
  await mkdir(paths.policyRoot, { recursive: true });
  await cp(sourcePath, paths.policyPath, { force: true });
  return {
    policyPath: paths.policyPath,
    schemaVersion,
    sourcePath,
  };
}

export async function validatePolicy({
  copilotHome = resolveCopilotHome(),
  file,
  packageRoot = getPackageRoot(),
  profile,
} = {}) {
  const paths = getPackagePaths({ copilotHome, packageRoot });
  const sourcePath =
    file || profile
      ? resolvePolicySourcePath({ file, paths, profile })
      : existsSync(paths.policyPath)
        ? paths.policyPath
        : paths.sourcePolicyPath;
  const { schemaVersion } = await validatePolicyFile(sourcePath, { paths });
  return {
    schemaVersion,
    sourcePath,
  };
}

export async function showPolicy({
  copilotHome = resolveCopilotHome(),
  packageRoot = getPackageRoot(),
} = {}) {
  const paths = getPackagePaths({ copilotHome, packageRoot });
  const sourcePath = existsSync(paths.policyPath) ? paths.policyPath : paths.sourcePolicyPath;
  const policy = await readJsonFile(sourcePath);
  return {
    policy,
    source: existsSync(paths.policyPath) ? "user" : "bundled-default",
    sourcePath,
  };
}

async function vendorSdkDependencyTree({ destinationExtensionPath, packageRoot }) {
  const packageRequire = createRequire(join(packageRoot, "package.json"));
  let sdkPackageManifestPath;
  try {
    sdkPackageManifestPath = packageRequire.resolve("@microsoft/agent-governance-sdk/package.json");
  } catch {
    const cliRequire = createRequire(import.meta.url);
    sdkPackageManifestPath = cliRequire.resolve("@microsoft/agent-governance-sdk/package.json", {
      paths: [packageRoot],
    });
  }
  const sdkPackageRoot = dirname(sdkPackageManifestPath);
  const sourceNodeModulesRoot = resolve(sdkPackageRoot, "..", "..");
  const destinationNodeModulesRoot = join(
    destinationExtensionPath,
    "vendor",
    "agent-governance-sdk",
    "node_modules",
  );

  await mkdir(destinationNodeModulesRoot, { recursive: true });
  await copyPackageDependencyTree({
    destinationNodeModulesRoot,
    packageName: "@microsoft/agent-governance-sdk",
    sourceNodeModulesRoot,
    visited: new Set(),
  });
}

function findPackageRoot(startDirectory) {
  let current = resolve(startDirectory);

  while (true) {
    if (existsSync(join(current, "package.json"))) {
      return current;
    }

    const parent = dirname(current);
    if (parent === current) {
      throw new Error(`Could not locate package root above ${startDirectory}.`);
    }
    current = parent;
  }
}

async function copyPackageDependencyTree({
  destinationNodeModulesRoot,
  packageName,
  sourceNodeModulesRoot,
  visited,
}) {
  if (visited.has(packageName)) {
    return;
  }
  visited.add(packageName);

  const sourcePackageRoot = join(sourceNodeModulesRoot, ...packageName.split("/"));
  const sourcePackageJsonPath = join(sourcePackageRoot, "package.json");
  if (!existsSync(sourcePackageJsonPath)) {
    throw new Error(`Missing runtime dependency ${packageName} under ${sourceNodeModulesRoot}.`);
  }

  const destinationPackageRoot = join(destinationNodeModulesRoot, ...packageName.split("/"));
  await mkdir(dirname(destinationPackageRoot), { recursive: true });
  await cp(sourcePackageRoot, destinationPackageRoot, { recursive: true, force: true });

  const manifest = await readJsonFile(sourcePackageJsonPath);
  for (const dependencyName of Object.keys(manifest.dependencies ?? {})) {
    await copyPackageDependencyTree({
      destinationNodeModulesRoot,
      packageName: dependencyName,
      sourceNodeModulesRoot,
      visited,
    });
  }
}

async function getCopilotSettingsStatus(candidates) {
  for (const candidate of candidates) {
    if (!existsSync(candidate)) {
      continue;
    }

    try {
      const parsed = await readJsonFile(candidate, { allowComments: true });
      const enabled =
        parsed?.experimental === true &&
        Array.isArray(parsed?.experimental_flags) &&
        parsed.experimental_flags.includes("EXTENSIONS");

      if (enabled) {
        return { enabled: true, source: candidate };
      }
    } catch {
      return { enabled: false, source: candidate };
    }
  }

  return { enabled: false, source: null };
}

async function readInstallManifest(path) {
  if (!existsSync(path)) {
    return null;
  }
  return readJsonFile(path);
}

async function writeInstallManifest(path, manifest) {
  await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
}

async function readJsonFile(path, { allowComments = false } = {}) {
  let contents = await readFile(path, "utf8");
  if (allowComments) {
    contents = contents.replace(/^\s*\/\/.*$/gm, "");
  }
  return JSON.parse(contents);
}

async function validatePolicyFile(path, { allowBundledProfiles = false, paths } = {}) {
  const policy = await readJsonFile(path);
  if (!policy || typeof policy !== "object" || Array.isArray(policy)) {
    throw new Error(`Policy file at ${path} must contain a JSON object.`);
  }
  const bundledEquivalent =
    allowBundledProfiles || (paths ? await isBundledPolicyEquivalent(path, policy, paths) : false);
  validatePolicyBaseline(policy, { allowBundledProfiles: bundledEquivalent });
  return {
    policy,
    schemaVersion: normalizePolicySchemaVersion(policy.schemaVersion),
  };
}

function resolvePolicySourcePath({ file, paths, profile }) {
  if (file && profile) {
    throw new Error("Specify either --file or --profile, not both.");
  }
  if (!file && !profile) {
    throw new Error("Specify --file <path> or --profile <name>.");
  }

  if (file) {
    const resolved = resolve(String(file));
    if (!existsSync(resolved)) {
      throw new Error(`Policy file not found: ${resolved}`);
    }
    return resolved;
  }

  const normalizedProfile = String(profile).trim().toLowerCase();
  if (!/^[a-z0-9-]+$/.test(normalizedProfile)) {
    throw new Error(
      `Invalid policy profile '${profile}'. Expected one of: strict, balanced, advisory.`,
    );
  }
  const profilePath = join(paths.sourceProfilesRoot, `${normalizedProfile}.json`);
  if (!existsSync(profilePath)) {
    throw new Error(`Unknown policy profile '${profile}'. Expected one of: strict, balanced, advisory.`);
  }
  return profilePath;
}

function validatePolicyBaseline(policy, { allowBundledProfiles }) {
  const mode = String(policy.mode ?? "enforce").toLowerCase();
  const defaultEffect = String(policy.toolPolicies?.defaultEffect ?? "review").toLowerCase();
  const minimumPromptDefenseGrade = String(
    policy.minimumPromptDefenseGrade ?? "B",
  ).toUpperCase();
  const allowedTools = (policy.toolPolicies?.allowedTools ?? []).map(String);
  const scanOutputTools = new Set(
    (policy.scanOutputTools ?? []).map((tool) => String(tool).toLowerCase()),
  );
  const metadataRulePresent = (policy.directResourcePolicies?.urlRules ?? []).some(
    (rule) =>
      String(rule.effect ?? "").toLowerCase() === "deny" &&
      (rule.urlPatterns ?? []).some(patternMatchesMetadataTarget),
  );
  const credentialRulePresent = (policy.directResourcePolicies?.pathRules ?? []).some(
    (rule) =>
      String(rule.effect ?? "").toLowerCase() === "deny" &&
      /(credential-read|secret-read|credential)/i.test(String(rule.id ?? "")),
  );

  if (!allowBundledProfiles && mode !== "enforce") {
    throw new Error("Custom policies must run in enforce mode.");
  }
  if (policy.denyOnPolicyError === false) {
    throw new Error("Policies must set denyOnPolicyError to true.");
  }
  if (!allowBundledProfiles && defaultEffect !== "review") {
    throw new Error("Custom policies must keep toolPolicies.defaultEffect set to review.");
  }
  if (allowedTools.includes("*")) {
    throw new Error("Policies may not wildcard-allow all tools.");
  }
  if (gradeRank(minimumPromptDefenseGrade) < gradeRank("B")) {
    throw new Error("Policies must require a minimum prompt defense grade of B or stronger.");
  }
  if (!metadataRulePresent) {
    throw new Error("Policies must deny cloud metadata endpoint access.");
  }
  if (!credentialRulePresent) {
    throw new Error("Policies must deny direct credential and secret file reads.");
  }
  for (const requiredTool of ["powershell", "bash", "read_powershell", "list_powershell"]) {
    if (!scanOutputTools.has(requiredTool)) {
      throw new Error(`Policies must scan ${requiredTool} output for poisoning attempts.`);
    }
  }
}

function patternMatchesMetadataTarget(pattern) {
  const source = String(pattern?.source ?? "");
  const flags = String(pattern?.flags ?? "");
  let expression;
  try {
    expression = new RegExp(source, flags);
  } catch (error) {
    throw new Error(`Invalid metadata endpoint rule regex: ${source}`);
  }

  return [
    "http://169.254.169.254/latest/meta-data/",
    "https://169.254.169.254/latest/meta-data/",
    "http://100.100.100.200/latest/meta-data/",
    "https://100.100.100.200/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "https://metadata.google.internal/computeMetadata/v1/",
  ].some((candidate) => expression.test(candidate));
}

function isBundledPolicyPath(path, paths) {
  const normalizedPath = normalizePath(path);
  return (
    normalizedPath === normalizePath(paths.sourcePolicyPath) ||
    normalizedPath.startsWith(`${normalizePath(paths.sourceProfilesRoot)}\\`)
  );
}

async function isBundledPolicyEquivalent(path, policy, paths) {
  if (isBundledPolicyPath(path, paths)) {
    return true;
  }

  const bundledCandidates = [paths.sourcePolicyPath];
  const profileName = String(policy.profile ?? "").trim().toLowerCase();
  if (/^[a-z0-9-]+$/.test(profileName)) {
    bundledCandidates.unshift(join(paths.sourceProfilesRoot, `${profileName}.json`));
  }

  const serializedPolicy = canonicalizePolicy(policy);
  for (const candidatePath of bundledCandidates) {
    if (!existsSync(candidatePath)) {
      continue;
    }
    const candidatePolicy = await readJsonFile(candidatePath);
    if (canonicalizePolicy(candidatePolicy) === serializedPolicy) {
      return true;
    }
  }
  return false;
}

function normalizePath(path) {
  return resolve(String(path)).replace(/\//g, "\\").toLowerCase();
}

function canonicalizePolicy(policy) {
  return JSON.stringify(sortJsonValue(policy));
}

function sortJsonValue(value) {
  if (Array.isArray(value)) {
    return value.map(sortJsonValue);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, child]) => [key, sortJsonValue(child)]),
    );
  }
  return value;
}

function gradeRank(grade) {
  return { A: 5, B: 4, C: 3, D: 2, F: 1 }[String(grade).toUpperCase()] ?? 0;
}

function formatDoctorReport(report) {
  const lines = [
    "AGT Copilot CLI doctor",
    "",
    `Copilot home: ${report.copilotHome}`,
    `Extension installed: ${report.extensionInstalled}`,
    `Managed install: ${report.managedInstall}`,
    `Package version: ${report.currentPackageVersion ?? "unknown"}`,
    `Installed version: ${report.installedByVersion ?? "unknown"}`,
    `Vendored SDK present: ${report.vendoredSdkPresent}`,
    `Policy path: ${report.policyPath}`,
    `Policy source: ${report.policySource}`,
    `Policy schema version: ${report.policySchemaVersion ?? "unknown"}`,
    `Policy valid: ${report.policyValid}`,
    `Extensions enabled: ${report.settings.enabled}`,
  ];

  if (report.settings.source) {
    lines.push(`Settings source: ${report.settings.source}`);
  }
  if (report.errors.length) {
    lines.push("", "Errors:");
    lines.push(...report.errors.map((error) => `- ${error}`));
  }
  if (report.warnings.length) {
    lines.push("", "Warnings:");
    lines.push(...report.warnings.map((warning) => `- ${warning}`));
  }
  if (!report.errors.length && !report.warnings.length) {
    lines.push("", "No issues found.");
  }

  return lines.join("\n");
}

function getHelpText() {
  return [
    `${PACKAGE_NAME}`,
    "",
    "Usage:",
    "  agt-copilot install [--copilot-home <path>] [--force-policy]",
    "  agt-copilot update [--copilot-home <path>] [--force-policy] [--replace-unmanaged]",
    "  agt-copilot policy <apply|validate|path|show> [...]",
    "  agt-copilot uninstall [--copilot-home <path>] [--remove-policy]",
    "  agt-copilot doctor [--copilot-home <path>] [--json]",
    "  agt-copilot help",
    "",
    "Notes:",
    "  install copies the packaged Copilot extension into ~/.copilot/extensions/agt-global-policy",
    "  update refreshes an existing AGT-managed install in place",
    "  --replace-unmanaged lets install or update replace a pre-existing unmanaged agt-global-policy extension",
    "  policy apply copies a validated policy file or bundled profile into ~/.copilot/agt/policy.json",
    "  uninstall removes only AGT-managed installs",
    "  doctor validates the install, policy file, vendored SDK, and Copilot extension settings",
    "  if a custom policy is invalid, remove ~/.copilot/agt/policy.json or set AGT_COPILOT_POLICY_PATH to a valid file",
  ].join("\n");
}

function getPolicyHelpText() {
  return [
    `${PACKAGE_NAME} policy`,
    "",
    "Usage:",
    "  agt-copilot policy apply --file <path>",
    "  agt-copilot policy apply --profile <strict|balanced|advisory>",
    "  agt-copilot policy validate [--file <path> | --profile <name>]",
    "  agt-copilot policy path",
    "  agt-copilot policy show",
    "",
    "Notes:",
    "  validate without --file or --profile checks the active user policy, or the bundled default if none is set",
    "  show prints the active user policy, or the bundled default if no user policy exists",
  ].join("\n");
}

function normalizePolicySchemaVersion(value) {
  if (value === undefined || value === null || value === "") {
    return SUPPORTED_POLICY_SCHEMA_VERSION;
  }

  const normalized = Number(value);
  if (!Number.isInteger(normalized) || normalized < 1) {
    throw new Error(`Invalid schemaVersion ${value}.`);
  }
  if (normalized > SUPPORTED_POLICY_SCHEMA_VERSION) {
    throw new Error(
      `Unsupported schemaVersion ${normalized}. This installer supports schemaVersion ${SUPPORTED_POLICY_SCHEMA_VERSION}.`,
    );
  }
  return normalized;
}
