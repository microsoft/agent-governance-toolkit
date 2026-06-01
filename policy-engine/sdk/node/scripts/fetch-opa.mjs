#!/usr/bin/env node
// Vendors the Open Policy Agent (`opa`) binary into the per-platform
// `npm/agent-control-specification-opa-*` sub-packages so they can be
// published. Run before `npm publish` of those packages (the binaries are
// gitignored and never committed).
//
// Usage:
//   node scripts/fetch-opa.mjs                # all platforms
//   node scripts/fetch-opa.mjs --platform linux-x64
//   OPA_VERSION=0.70.0 node scripts/fetch-opa.mjs
//
// After downloading, the script prints the sha256 of each binary so the pinned
// CHECKSUMS map below can be kept up to date. When CHECKSUMS has an entry for a
// target, the download is verified against it and the script fails on mismatch.

import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { get } from "node:https";

const VERSION = process.env.OPA_VERSION ?? "0.70.0";
const here = dirname(fileURLToPath(import.meta.url));
const npmDir = join(here, "..", "npm");

// node platform-arch -> { asset on the OPA download host, sub-package, bin name }
const TARGETS = {
  "linux-x64": { asset: "opa_linux_amd64_static", pkg: "agent-control-specification-opa-linux-x64", bin: "opa" },
  "linux-arm64": { asset: "opa_linux_arm64_static", pkg: "agent-control-specification-opa-linux-arm64", bin: "opa" },
  "darwin-x64": { asset: "opa_darwin_amd64", pkg: "agent-control-specification-opa-darwin-x64", bin: "opa" },
  "darwin-arm64": { asset: "opa_darwin_arm64_static", pkg: "agent-control-specification-opa-darwin-arm64", bin: "opa" },
  "win32-x64": { asset: "opa_windows_amd64.exe", pkg: "agent-control-specification-opa-win32-x64", bin: "opa.exe" },
};

const CHECKSUMS = {
  "0.70.0": {
    "linux-x64": "00d114b94fdb1606a48cccdfc73c9ccdc62c38721150131ae578d5ff3df5c084",
    "linux-arm64": "48061407a2d7b0b59440fc3a257e7bb251e9ec62f6ce7b1e45c142263ae24413",
    "darwin-x64": "7827172827c6c7763fd36dd72052c318a6beb18f7b907c5e67d847bb557af1a1",
    "darwin-arm64": "267608fe41dba91fb23e2a69a439cb2a39710b3a069a828c744bd99bb3f94508",
    "win32-x64": "19d00eea60477a8f983c20af690fedcc8da52aef81922e570b27538ca88305a4",
  },
};

function fetch(url, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    get(url, (res) => {
      const status = res.statusCode ?? 0;
      if (status >= 300 && status < 400 && res.headers.location) {
        if (redirectsLeft === 0) {
          reject(new Error(`too many redirects for ${url}`));
          return;
        }
        res.resume();
        const next = new URL(res.headers.location, url).toString();
        resolve(fetch(next, redirectsLeft - 1));
        return;
      }
      if (status !== 200) {
        res.resume();
        reject(new Error(`GET ${url} -> HTTP ${status}`));
        return;
      }
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve(Buffer.concat(chunks)));
      res.on("error", reject);
    }).on("error", reject);
  });
}

async function vendorOne(key) {
  const target = TARGETS[key];
  if (target === undefined) throw new Error(`unknown platform '${key}'. Known: ${Object.keys(TARGETS).join(", ")}`);
  const url = `https://openpolicyagent.org/downloads/v${VERSION}/${target.asset}`;
  process.stdout.write(`fetching ${key} <- ${url}\n`);
  const buf = await fetch(url);
  const digest = createHash("sha256").update(buf).digest("hex");

  const expected = CHECKSUMS[VERSION]?.[key];
  if (expected === undefined) {
    throw new Error(`missing pinned checksum for OPA ${VERSION} ${key}`);
  }
  if (expected !== digest) {
    throw new Error(`checksum mismatch for ${key}: expected ${expected}, got ${digest}`);
  }

  const binDir = join(npmDir, target.pkg, "bin");
  mkdirSync(binDir, { recursive: true });
  const out = join(binDir, target.bin);
  writeFileSync(out, buf);
  if (!key.startsWith("win32")) chmodSync(out, 0o755);
  process.stdout.write(`  wrote ${out} (${buf.length} bytes) sha256=${digest}${expected ? " [verified]" : ""}\n`);
}

async function main() {
  const args = process.argv.slice(2);
  const idx = args.indexOf("--platform");
  const keys = idx === -1 ? Object.keys(TARGETS) : [args[idx + 1]];
  for (const key of keys) {
    await vendorOne(key);
  }
  process.stdout.write(`done (opa v${VERSION}).\n`);
}

main().catch((err) => {
  process.stderr.write(`fetch-opa failed: ${err?.message ?? err}\n`);
  process.exit(1);
});
