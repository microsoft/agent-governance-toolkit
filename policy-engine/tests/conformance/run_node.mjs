#!/usr/bin/env node
import { createRequire } from "node:module";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, "../..");
const casesDir = resolve(repo, "tests/conformance/cases");
const output = process.argv.includes("--output")
  ? process.argv[process.argv.indexOf("--output") + 1]
  : resolve(repo, "tests/conformance/results/node.json");

function loadSdk() {
  const entry = resolve(repo, "sdk/node/dist/index.js");
  if (!existsSync(entry)) return undefined;
  return require(entry);
}

function loadCases() {
  const { readdirSync } = require("node:fs");
  return readdirSync(casesDir)
    .filter((name) => name.endsWith(".json"))
    .sort()
    .map((name) => JSON.parse(readFileSync(resolve(casesDir, name), "utf8")));
}

function item(caseDef, status, detail) {
  return { case: caseDef.id, status, detail };
}

function reasonFromError(error) {
  return String(error?.message ?? error).match(/runtime_error:[a-z_]+/)?.[0];
}

function stableJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
}

async function runEvaluate(sdk, caseDef) {
  const annotatorOrder = [];
  const control = sdk.AgentControl.fromNative(
    caseDef.manifest_yaml,
    {
      dispatch(annotatorName) {
        annotatorOrder.push(annotatorName);
        return caseDef.annotator_outputs?.[annotatorName] ?? { ok: true };
      },
    },
    {
      evaluate() {
        if (caseDef.policy_behavior === "error") throw new Error("policy failed");
        return caseDef.policy_response;
      },
    },
  );
  const result = await control.evaluateInterventionPoint(caseDef.intervention_point, caseDef.snapshot, caseDef.mode ?? "enforce");
  const expected = caseDef.expected;
  if (result.verdict.decision !== expected.decision) return item(caseDef, "fail", `decision ${result.verdict.decision}`);
  if (Object.hasOwn(expected, "reason") && result.verdict.reason !== expected.reason) return item(caseDef, "fail", `reason ${result.verdict.reason}`);
  if (Object.hasOwn(expected, "transformed_policy_target")) {
    const actual = result.transformedPolicyTarget === undefined ? null : result.transformedPolicyTarget;
    if (stableJson(actual) !== stableJson(expected.transformed_policy_target)) return item(caseDef, "fail", "transformed target mismatch");
  }
  if (Object.hasOwn(expected, "policy_target") && stableJson(result.policyInput?.policy_target?.value) !== stableJson(expected.policy_target)) {
    return item(caseDef, "fail", "policy target mismatch");
  }
  if (Object.hasOwn(expected, "annotations") && stableJson(result.policyInput?.annotations) !== stableJson(expected.annotations)) {
    return item(caseDef, "fail", "annotations mismatch");
  }
  if (Object.hasOwn(expected, "annotator_order") && JSON.stringify(annotatorOrder) !== JSON.stringify(expected.annotator_order)) {
    return item(caseDef, "fail", `annotator order ${JSON.stringify(annotatorOrder)}`);
  }
  return item(caseDef, "pass");
}

async function runApprovalMismatch(sdk, caseDef) {
  class StubRuntimeClient {
    async evaluateInterventionPoint(request) {
      const policyInput = { intervention_point: request.interventionPoint, snapshot: request.snapshot };
      return {
        verdict: { decision: sdk.Decision.Escalate, reason: "human_review" },
        policyInput,
        actionIdentity: sdk.actionIdentity(policyInput),
      };
    }
  }
  const control = new sdk.AgentControl(new StubRuntimeClient(), (_point, result) => {
    const approved = result.actionIdentity;
    result.policyInput.snapshot.input = "mutated";
    return sdk.ApprovalResolution.allow(approved);
  });
  try {
    await control.run("hi", (input) => input);
  } catch (error) {
    if (error instanceof sdk.AgentControlBlockedError && error.result?.verdict?.reason === caseDef.expected.reason) {
      return item(caseDef, "pass");
    }
    return item(caseDef, "fail", String(error?.message ?? error));
  }
  return item(caseDef, "fail", "approval mismatch did not block");
}

async function runCase(sdk, caseDef) {
  if (caseDef.sdk_support?.node === "skip") return item(caseDef, "skip", "case excludes node");
  if (!sdk && caseDef.operation === "evaluate") return item(caseDef, "skip", "node dist is not built");
  try {
    if (caseDef.operation === "evaluate") return await runEvaluate(sdk, caseDef);
    if (caseDef.operation === "approval_action_mismatch") {
      if (!sdk) return item(caseDef, "skip", "node dist is not built");
      return await runApprovalMismatch(sdk, caseDef);
    }
    return item(caseDef, "skip", `unsupported operation ${caseDef.operation}`);
  } catch (error) {
    const reason = reasonFromError(error);
    if (caseDef.expected?.decision === "deny" && reason === caseDef.expected?.reason) return item(caseDef, "pass");
    return item(caseDef, "error", String(error?.message ?? error));
  }
}

const sdk = loadSdk();
const results = [];
for (const caseDef of loadCases()) results.push(await runCase(sdk, caseDef));
mkdirSync(dirname(output), { recursive: true });
writeFileSync(output, JSON.stringify({ sdk: "node", timestamp: new Date().toISOString(), results }, null, 2) + "\n");
for (const result of results) console.log(`node ${result.status} ${result.case}${result.detail ? `: ${result.detail}` : ""}`);
process.exit(results.every((result) => ["pass", "skip"].includes(result.status)) ? 0 : 1);
