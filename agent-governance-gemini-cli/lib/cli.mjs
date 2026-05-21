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
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";

const PACKAGE_NAME = "@microsoft/agent-governance-gemini-cli";
const EXTENSION_NAME = "agt-global-policy";
const INSTALL_MANIFEST_NAME = ".agt-install-manifest.json";
const SUPPORTED_POLICY_SCHEMA_VERSION = 1;
const VENDORED_RUNTIME_CHECKS = [
  {
    name: "AGT SDK",
    relativePath: join(
      "vendor",
      "agent-governance-sdk",
      "node_modules",
      "@microsoft",
      "agent-governance-sdk",
      "dist",
      "index.js",
    ),
  },
  {
    name: "MCP SDK",
    relativePath: join(
      "vendor",
      "agent-governance-sdk",
      "node_modules",
      "@modelcontextprotocol",
      "sdk",
      "package.json",
    ),
  },
];

export async function runCli(argv = [], io = console) {
  try {
    const parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        file: { type: "string" },
        "force-policy": { type: "boolean" },
        "gemini-home": { type: "string" },
        help: { type: "boolean", short: "h" },
        json: { type: "boolean" },
        profile: { type: "string" },
        "remove-policy": { type: "boolean" },
        "replace-unmanaged": { type: "boolean" },
        version: { type: "boolean", short: "v" },
      },
    });

    const command = (parsed.positionals[0] ?? "help").toLowerCase();
    const geminiHome = resolveGeminiHome(parsed.values["gemini-home"]);

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
        forcePolicy: parsed.values["force-policy"] ?? false,
        geminiHome,
        replaceUnmanaged: parsed.values["replace-unmanaged"] ?? false,
      });
      const verb = command === "update" ? "Updated" : "Installed";
      io.log(`${verb} ${PACKAGE_NAME} at ${result.extensionPath}`);
      if (result.replacedUnmanaged) {
        io.log("Replaced an unmanaged agt-global-policy install because --replace-unmanaged was specified.");
      }
      io.log(`Policy file: ${result.policyPath}`);
      io.log(
        `If a custom policy becomes invalid, remove ${result.policyPath} or point AGT_GEMINI_POLICY_PATH at a valid replacement.`,
      );
      io.log("Hook state is managed inside Gemini CLI. Use /hooks panel or /hooks enable-all to confirm AGT hooks are active.");
      io.log("Restart Gemini CLI to reload the managed extension, hooks, and custom commands.");
      return 0;
    }

    if (command === "policy") {
      const subcommand = (parsed.positionals[1] ?? "help").toLowerCase();
      const packageRoot = getPackageRoot();

      if (subcommand === "apply") {
        const result = await applyPolicy({
          file: parsed.values.file,
          geminiHome,
          packageRoot,
          profile: parsed.values.profile,
        });
        io.log(`Applied policy to ${result.policyPath}`);
        io.log(`Source: ${result.sourcePath}`);
        io.log(`Schema version: ${result.schemaVersion}`);
        io.log("Restart Gemini CLI to reload the updated AGT policy.");
        return 0;
      }

      if (subcommand === "validate") {
        const result = await validatePolicy({
          file: parsed.values.file,
          geminiHome,
          packageRoot,
          profile: parsed.values.profile,
        });
        io.log(`Valid policy: ${result.sourcePath}`);
        io.log(`Schema version: ${result.schemaVersion}`);
        return 0;
      }

      if (subcommand === "path") {
        io.log(getPackagePaths({ geminiHome, packageRoot }).policyPath);
        return 0;
      }

      if (subcommand === "show") {
        const result = await showPolicy({
          geminiHome,
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
        geminiHome,
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
      io.log("Restart Gemini CLI to fully unload the removed AGT extension, hooks, and custom commands.");
      return 0;
    }

    if (command === "doctor") {
      const report = await diagnoseInstall({ geminiHome });
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
  forcePolicy = false,
  geminiHome = resolveGeminiHome(),
  packageRoot = getPackageRoot(),
  replaceUnmanaged = false,
} = {}) {
  const metadata = await readPackageMetadata(packageRoot);
  const paths = getPackagePaths({ geminiHome, packageRoot });
  const settings = await getGeminiSettingsStatus(paths.settingsCandidates);
  const existingManifest = await readInstallManifest(paths.manifestPath);
  const extensionExists = existsSync(paths.extensionPath);
  const shouldSeedPolicy = !existsSync(paths.policyPath);
  const preservedExtensionEnv = extensionExists
    ? await readOptionalTextFile(paths.extensionEnvPath)
    : null;

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
    await vendorRuntimeDependencies({
      destinationExtensionPath: stagedExtensionPath,
      packageLockPath: paths.packageLockPath,
      packageRoot,
    });
    await seedManagedExtensionState({
      extensionEnvPath: join(stagedExtensionPath, ".env"),
      paths,
      preservedExtensionEnv,
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
  geminiHome = resolveGeminiHome(),
  packageRoot = getPackageRoot(),
  removePolicy = false,
} = {}) {
  const paths = getPackagePaths({ geminiHome, packageRoot });
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
  geminiHome = resolveGeminiHome(),
  packageRoot = getPackageRoot(),
} = {}) {
  const paths = getPackagePaths({ geminiHome, packageRoot });
  const metadata = await readPackageMetadata(packageRoot);
  const settings = await getGeminiSettingsStatus(paths.settingsCandidates);
  const manifest = await readInstallManifest(paths.manifestPath);

  const vendoredChecks = Object.fromEntries(
    VENDORED_RUNTIME_CHECKS.map(({ name, relativePath }) => [
      name,
      existsSync(join(paths.extensionPath, relativePath)),
    ]),
  );

  const report = {
    ok: true,
    auditPath: paths.auditPath,
    geminiHome,
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
    geminiManifestPresent: existsSync(join(paths.extensionPath, "gemini-extension.json")),
    hookConfigPresent: existsSync(join(paths.extensionPath, "hooks", "hooks.json")),
    mcpServerPresent: existsSync(join(paths.extensionPath, "mcp", "server.mjs")),
    contextFilePresent: existsSync(join(paths.extensionPath, "GEMINI.md")),
    vendoredRuntimeChecks: vendoredChecks,
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
  if (report.extensionInstalled && !report.geminiManifestPresent) {
    report.ok = false;
    report.errors.push("gemini-extension.json is missing from the installed extension.");
  }
  if (report.extensionInstalled && !report.hookConfigPresent) {
    report.ok = false;
    report.errors.push("hooks/hooks.json is missing from the installed extension.");
  }
  if (report.extensionInstalled && !report.mcpServerPresent) {
    report.ok = false;
    report.errors.push("Bundled MCP server entrypoint is missing from the installed extension.");
  }
  if (report.extensionInstalled && !report.contextFilePresent) {
    report.ok = false;
    report.errors.push("GEMINI.md is missing from the installed extension.");
  }
  for (const [runtimeName, present] of Object.entries(vendoredChecks)) {
    if (report.extensionInstalled && !present) {
      report.ok = false;
      report.errors.push(`Vendored ${runtimeName} is missing from the installed extension.`);
    }
  }
  if (
    report.extensionInstalled &&
    report.installedByVersion &&
    report.currentPackageVersion &&
    report.installedByVersion !== report.currentPackageVersion
  ) {
    report.warnings.push(
      `Installed extension version ${report.installedByVersion} differs from package version ${report.currentPackageVersion}. Run agt-gemini update to refresh the managed install.`,
    );
  }

  if (existsSync(paths.policyPath)) {
    try {
      const policy = await readJsonFile(paths.policyPath);
      report.policySchemaVersion = normalizePolicySchemaVersion(policy?.schemaVersion);
      report.policyValid = true;
    } catch (error) {
      report.warnings.push(
        `User policy could not be parsed or validated: ${error.message} Remove the file or set AGT_GEMINI_POLICY_PATH to a valid policy.`,
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

  if (settings.parseError) {
    report.warnings.push(
      `Gemini user settings at ${settings.source} could not be parsed. Hook state must be confirmed inside Gemini CLI.`,
    );
  }

  return report;
}

export function resolveGeminiHome(override) {
  if (override) {
    return resolve(override);
  }
  if (process.env.GEMINI_CLI_HOME) {
    return join(resolve(process.env.GEMINI_CLI_HOME), ".gemini");
  }
  if (process.env.GEMINI_HOME) {
    return resolve(process.env.GEMINI_HOME);
  }
  return join(homedir(), ".gemini");
}

function getPackageRoot() {
  return resolve(dirname(fileURLToPath(import.meta.url)), "..");
}

function getPackagePaths({ geminiHome, packageRoot }) {
  return {
    geminiHome,
    extensionPath: join(geminiHome, "extensions", EXTENSION_NAME),
    extensionsRoot: join(geminiHome, "extensions"),
    manifestPath: join(geminiHome, "extensions", EXTENSION_NAME, INSTALL_MANIFEST_NAME),
    extensionEnvPath: join(geminiHome, "extensions", EXTENSION_NAME, ".env"),
    auditPath: join(geminiHome, "agt", "audit-log.json"),
    policyPath: join(geminiHome, "agt", "policy.json"),
    policyRoot: join(geminiHome, "agt"),
    packageLockPath: join(packageRoot, "package-lock.json"),
    settingsCandidates: [join(geminiHome, "settings.json")],
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
  file,
  geminiHome = resolveGeminiHome(),
  packageRoot = getPackageRoot(),
  profile,
} = {}) {
  const paths = getPackagePaths({ geminiHome, packageRoot });
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
  file,
  geminiHome = resolveGeminiHome(),
  packageRoot = getPackageRoot(),
  profile,
} = {}) {
  const paths = getPackagePaths({ geminiHome, packageRoot });
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
  geminiHome = resolveGeminiHome(),
  packageRoot = getPackageRoot(),
} = {}) {
  const paths = getPackagePaths({ geminiHome, packageRoot });
  const sourcePath = existsSync(paths.policyPath) ? paths.policyPath : paths.sourcePolicyPath;
  const policy = await readJsonFile(sourcePath);
  return {
    policy,
    source: existsSync(paths.policyPath) ? "user" : "bundled-default",
    sourcePath,
  };
}

async function vendorRuntimeDependencies({ destinationExtensionPath, packageLockPath, packageRoot }) {
  const metadata = await readPackageMetadata(packageRoot);
  const packageLock = await readJsonFile(packageLockPath);
  const sourceNodeModulesRoot = join(packageRoot, "node_modules");
  const destinationNodeModulesRoot = join(
    destinationExtensionPath,
    "vendor",
    "agent-governance-sdk",
    "node_modules",
  );

  await mkdir(destinationNodeModulesRoot, { recursive: true });
  for (const dependencyName of Object.keys(metadata.dependencies ?? {})) {
    await copyPackageDependencyTree({
      destinationNodeModulesRoot,
      packageLock,
      packageName: dependencyName,
      sourceNodeModulesRoot,
      visited: new Set(),
    });
  }
}

async function copyPackageDependencyTree({
  destinationNodeModulesRoot,
  packageLock,
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

  const manifest = await readJsonFile(sourcePackageJsonPath);
  assertPackageMatchesLockfile(packageLock, packageName, manifest.version);

  const destinationPackageRoot = join(destinationNodeModulesRoot, ...packageName.split("/"));
  await mkdir(dirname(destinationPackageRoot), { recursive: true });
  await cp(sourcePackageRoot, destinationPackageRoot, { recursive: true, force: true });

  for (const dependencyName of Object.keys(manifest.dependencies ?? {})) {
    await copyPackageDependencyTree({
      destinationNodeModulesRoot,
      packageLock,
      packageName: dependencyName,
      sourceNodeModulesRoot,
      visited,
    });
  }
}

async function getGeminiSettingsStatus(candidates) {
  for (const candidate of candidates) {
    if (!existsSync(candidate)) {
      continue;
    }

    try {
      await readJsonFile(candidate, { allowComments: true });
      return {
        hookEnablement: "inspect in Gemini CLI (/hooks panel)",
        parseError: null,
        source: candidate,
      };
    } catch {
      return {
        hookEnablement: "inspect in Gemini CLI (/hooks panel)",
        parseError: "Settings file could not be parsed.",
        source: candidate,
      };
    }
  }

  return {
    hookEnablement: "inspect in Gemini CLI (/hooks panel)",
    parseError: null,
    source: null,
  };
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
  if (!scanOutputTools.has("run_shell_command")) {
    throw new Error("Policies must scan run_shell_command output for poisoning attempts.");
  }
}

function patternMatchesMetadataTarget(pattern) {
  const source = String(pattern?.source ?? "");
  const flags = String(pattern?.flags ?? "");
  let expression;
  try {
    expression = new RegExp(source, flags);
  } catch {
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
    "AGT Gemini CLI doctor",
    "",
    `Gemini home: ${report.geminiHome}`,
    `Extension installed: ${report.extensionInstalled}`,
    `Managed install: ${report.managedInstall}`,
    `Package version: ${report.currentPackageVersion ?? "unknown"}`,
    `Installed version: ${report.installedByVersion ?? "unknown"}`,
    `Gemini manifest present: ${report.geminiManifestPresent}`,
    `Hook config present: ${report.hookConfigPresent}`,
    `MCP server present: ${report.mcpServerPresent}`,
    `Context file present: ${report.contextFilePresent}`,
    `Policy path: ${report.policyPath}`,
    `Audit path: ${report.auditPath}`,
    `Policy source: ${report.policySource}`,
    `Policy schema version: ${report.policySchemaVersion ?? "unknown"}`,
    `Policy valid: ${report.policyValid}`,
    `Hook enablement: ${report.settings.hookEnablement}`,
  ];

  if (report.settings.source) {
    lines.push(`User settings source: ${report.settings.source}`);
  }
  if (Object.keys(report.vendoredRuntimeChecks).length) {
    lines.push("", "Vendored runtime:");
    lines.push(
      ...Object.entries(report.vendoredRuntimeChecks).map(
        ([name, present]) => `- ${name}: ${present}`,
      ),
    );
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
    "  agt-gemini install [--gemini-home <path>] [--force-policy]",
    "  agt-gemini update [--gemini-home <path>] [--force-policy] [--replace-unmanaged]",
    "  agt-gemini policy <apply|validate|path|show> [...]",
    "  agt-gemini uninstall [--gemini-home <path>] [--remove-policy]",
    "  agt-gemini doctor [--gemini-home <path>] [--json]",
    "  agt-gemini help",
    "",
    "Notes:",
    "  install copies the packaged Gemini extension into ~/.gemini/extensions/agt-global-policy",
    "  update refreshes an existing AGT-managed install in place",
    "  --replace-unmanaged lets install or update replace a pre-existing unmanaged agt-global-policy extension",
    "  policy apply copies a validated policy file or bundled profile into ~/.gemini/agt/policy.json",
    "  uninstall removes only AGT-managed installs",
    "  doctor validates the install, policy file, bundled MCP server, and vendored runtimes",
    "  if GEMINI_CLI_HOME is set, AGT installs into $GEMINI_CLI_HOME/.gemini",
    "  if a custom policy is invalid, remove ~/.gemini/agt/policy.json or set AGT_GEMINI_POLICY_PATH to a valid file",
  ].join("\n");
}

function assertPackageMatchesLockfile(packageLock, packageName, installedVersion) {
  const packageEntry = packageLock?.packages?.[getLockfilePackageKey(packageName)];
  if (!packageEntry?.version || typeof packageEntry.integrity !== "string") {
    throw new Error(`Missing lockfile metadata for vendored dependency ${packageName}. Run npm ci before packaging.`);
  }
  if (packageEntry.version !== installedVersion) {
    throw new Error(
      `Vendored dependency ${packageName}@${installedVersion} does not match package-lock.json (${packageEntry.version}). Run npm ci before packaging.`,
    );
  }
}

function getLockfilePackageKey(packageName) {
  return `node_modules/${packageName.replace(/\\/g, "/")}`;
}

async function readOptionalTextFile(path) {
  if (!existsSync(path)) {
    return null;
  }
  return readFile(path, "utf8");
}

async function seedManagedExtensionState({ extensionEnvPath, paths, preservedExtensionEnv }) {
  const contents = preservedExtensionEnv ?? buildManagedExtensionEnv(paths);
  await writeFile(extensionEnvPath, contents.endsWith("\n") ? contents : `${contents}\n`, "utf8");
}

function buildManagedExtensionEnv(paths) {
  return [
    `AGT_GEMINI_POLICY_PATH=${JSON.stringify(paths.policyPath)}`,
    `AGT_GEMINI_AUDIT_PATH=${JSON.stringify(paths.auditPath)}`,
  ].join("\n");
}

function getPolicyHelpText() {
  return [
    `${PACKAGE_NAME} policy`,
    "",
    "Usage:",
    "  agt-gemini policy apply --file <path>",
    "  agt-gemini policy apply --profile <strict|balanced|advisory>",
    "  agt-gemini policy validate [--file <path> | --profile <name>]",
    "  agt-gemini policy path",
    "  agt-gemini policy show",
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
