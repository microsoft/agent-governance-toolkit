// Multi-adapter ACS demo (Node SDK) against the comprehensive demo manifest.
import { AgentControl, AgentControlBlockedError } from "../sdk/node/dist/index.js";
import { runModel } from "../sdk/node/dist/src/adapters.js";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const MANIFEST = join(here, "manifest.yaml");

const show = (tag, msg) => console.log(`  ${tag.padEnd(7)} ${msg}`);

async function call(label, fn) {
  try {
    const out = await fn();
    show("ALLOW", `${label} -> ${JSON.stringify(out)}`);
  } catch (e) {
    if (e instanceof AgentControlBlockedError) {
      show("DENY", `${label} -> ${e.result.verdict.decision} (${e.result.verdict.reason})`);
    } else {
      throw e;
    }
  }
}

async function main() {
  process.env.ACS_OPA_PATH ||= process.env.ACS_OPA_PATH || "";
  const control = AgentControl.fromPath(MANIFEST);
  console.log("NODE SDK");

  // --- run: input + output intervention points ---
  console.log("\n[run] generic agent (input/output)");
  await call("benign", async () => (await control.run("hello there", (p) => `answer: ${p}`)).value);
  await call("deny  ", async () => (await control.run("do BLOCKME please", (p) => `answer: ${p}`)).value);
  const r = await control.run("here is my SECRET value", (p) => `used input: ${p}`);
  show("XFORM", `secret input -> ${JSON.stringify(r.value)}`);

  // --- runModel adapter: pre/post model-call points ---
  console.log("\n[runModel] model wrapper (pre/post model)");
  const m = await runModel(control, { prompt: "summarize" }, () => ({ text: "SECRET model output" }));
  show("XFORM", `secret model response -> ${JSON.stringify(m.value)}`);

  // --- runTool: pre/post tool-call points ---
  console.log("\n[runTool] tool wrappers (pre/post tool)");
  await call("echo_tool", async () => (await control.runTool("echo_tool", { text: "ping" }, (a) => ({ result: a.text }))).value);
  await call("danger_tool(name-deny)", async () => (await control.runTool("danger_tool", { text: "x" }, () => ({ result: "x" }))).value);
  const p = await control.runTool("payments_tool", { amount: 10 }, () => ({ result: "SECRET receipt" }));
  show("XFORM", `payments_tool secret result -> ${JSON.stringify(p.value)}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
