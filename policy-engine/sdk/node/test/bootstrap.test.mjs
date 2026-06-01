import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const assert = require("node:assert/strict");
const test = require("node:test");
const { execFileSync } = require("node:child_process");
const { mkdtempSync, writeFileSync, rmSync, existsSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join, dirname } = require("node:path");
const { fileURLToPath } = require("node:url");
const { createBundledGhcpExtension, resolveBundledOpa } = require("../dist/index.js");

const __dirname = dirname(fileURLToPath(import.meta.url));
const supportManifest = join(__dirname, "..", "..", "..", "examples", "support_agent", "manifest.yaml");

function opaAvailable() {
  try {
    execFileSync("opa", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

// Run body with PATH/ACS_* env saved and restored so tests can't contaminate
// each other (or the rest of the suite) via the discovery globals they probe.
function withCleanEnv(overrides, body) {
  const keys = ["PATH", "ACS_MANIFEST", "ACS_OPA_PATH", "ACS_OPA_NO_BUNDLE"];
  const saved = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  try {
    for (const k of keys) delete process.env[k];
    Object.assign(process.env, overrides);
    return body();
  } finally {
    for (const k of keys) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

test("bootstrap throws a clear error when an explicit manifest path is missing", () => {
  assert.throws(
    () => createBundledGhcpExtension({ manifestPath: join(tmpdir(), "definitely-missing-acs.yaml") }),
    /manifest not found.*options\.manifestPath/,
  );
});

test("bootstrap throws a clear error when ACS_MANIFEST points nowhere", () => {
  withCleanEnv({ ACS_MANIFEST: join(tmpdir(), "missing-from-env.yaml") }, () => {
    assert.throws(() => createBundledGhcpExtension(), /manifest not found.*ACS_MANIFEST/);
  });
});

test("bootstrap throws a clear error when no manifest can be discovered", () => {
  const dir = mkdtempSync(join(tmpdir(), "acs-empty-"));
  try {
    withCleanEnv({}, () => {
      assert.throws(() => createBundledGhcpExtension({ searchFrom: dir }), /could not locate a manifest/);
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("bootstrap discovers a manifest by conventional name walking upward", () => {
  const root = mkdtempSync(join(tmpdir(), "acs-disc-"));
  const nested = join(root, "a", "b");
  require("node:fs").mkdirSync(nested, { recursive: true });
  writeFileSync(join(root, "acs.yaml"), "agent_control_specification_version: 0.3.1-beta\n");
  try {
    // PATH cleared and bundled opa disabled so opa is unresolvable: reaching
    // the opa error proves the manifest was discovered (manifest resolution
    // runs first and would otherwise throw "could not locate").
    withCleanEnv({ PATH: "", ACS_OPA_NO_BUNDLE: "1" }, () => {
      assert.throws(() => createBundledGhcpExtension({ searchFrom: nested }), /'opa' binary/);
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("bootstrap throws a clear opa error when the hint path does not exist", () => {
  withCleanEnv({}, () => {
    assert.throws(
      () => createBundledGhcpExtension({ manifestPath: supportManifest, opaPath: join(tmpdir(), "no-opa-here") }),
      /opa not found at the path provided/,
    );
  });
});

test("bootstrap throws an actionable error when opa is absent and bundling is disabled", () => {
  withCleanEnv({ PATH: "", ACS_OPA_NO_BUNDLE: "1" }, () => {
    assert.throws(() => createBundledGhcpExtension({ manifestPath: supportManifest }), /'opa' binary/);
  });
});

test("resolveBundledOpa finds a vendored binary for the current platform", { skip: !resolveBundledOpa() }, () => {
  const opa = resolveBundledOpa();
  assert.ok(opa, "expected a bundled opa path");
  assert.match(opa, /opa(\.exe)?$/);
});

test("resolveBundledOpa honors ACS_OPA_NO_BUNDLE", () => {
  withCleanEnv({ ACS_OPA_NO_BUNDLE: "1" }, () => {
    assert.equal(resolveBundledOpa(), undefined);
  });
});

test("bootstrap uses the bundled opa with an empty PATH and no hint", { skip: !resolveBundledOpa() }, () => {
  // No system opa on PATH and no opaPath hint: the vendored binary must carry
  // the runtime, proving zero-setup adopters get a working policy engine.
  const bundled = resolveBundledOpa();
  withCleanEnv({ PATH: "" }, () => {
    const result = createBundledGhcpExtension({ manifestPath: supportManifest });
    assert.equal(result.opaPath, bundled);
    assert.ok(result.control);
  });
});

test("bootstrap wires an extension end-to-end when manifest and opa are available", { skip: !(opaAvailable() || resolveBundledOpa()) }, () => {
  const result = createBundledGhcpExtension({ manifestPath: supportManifest });
  assert.equal(result.manifestPath, supportManifest);
  assert.ok(result.control);
  assert.equal(typeof result.extension.onEvent, "function");
  assert.equal(typeof result.extension.hooks.onPreToolUse, "function");
});

test("bootstrap loads credentials from an explicit .env file", { skip: !(opaAvailable() || resolveBundledOpa()) }, () => {
  const dir = mkdtempSync(join(tmpdir(), "acs-env-"));
  const envFile = join(dir, "creds.env");
  const key = `ACS_TEST_VAR_${process.pid}`;
  writeFileSync(envFile, `${key}=loaded-by-bootstrap\n`);
  try {
    assert.equal(process.env[key], undefined);
    createBundledGhcpExtension({ manifestPath: supportManifest, loadEnv: envFile });
    assert.equal(process.env[key], "loaded-by-bootstrap");
  } finally {
    delete process.env[key];
    rmSync(dir, { recursive: true, force: true });
  }
});

test("bootstrap forwards tools and escalate options to the extension", { skip: !(opaAvailable() || resolveBundledOpa()) }, async () => {
  const seen = [];
  const result = createBundledGhcpExtension({
    manifestPath: supportManifest,
    hooks: { tools: ["bash"], logger: (e) => seen.push(e) },
  });
  // A non-governed tool is passed through without evaluation.
  const decision = await result.extension.hooks.onPreToolUse({ toolName: "web-fetch", toolArgs: { url: "x" } }, { sessionId: "s1" });
  assert.equal(decision, undefined);
  assert.ok(seen.some((e) => e.toolName === "web-fetch" && /not governed/.test(e.reason ?? "")));
});
