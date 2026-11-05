// Banc TS (opnmcp de Yuto) contre Rust (osmcp) : mêmes requêtes MCP stdio contre un faux OPNsense.
// Usage : node bench/bench.mjs [--ts "node dist/index.js"] [--rust rust/target/release/osmcp] [--out bench/results.json]
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { readFileSync, readdirSync, statSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { performance } from "node:perf_hooks";

const arg = (name, def) => { const i = process.argv.indexOf(name); return i > 0 ? process.argv[i + 1] : def; };
const TS_CMD = arg("--ts", "node dist/index.js").split(" ");
const RUST_BIN = arg("--rust", process.platform === "win32" ? "rust/target/release/osmcp.exe" : "rust/target/release/osmcp");
const OUT = arg("--out", "bench/results.json");
const N_LIST = 200, N_CALL = 300;

// Faux pare-feu : répond du JSON à tout, avec une latence nulle (on mesure le serveur MCP, pas le réseau).
const fake = createServer((req, res) => {
  req.resume();
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify({ status: "ok", rows: [], total: 0, rowCount: 0, product_version: "25.7.1" }));
});
await new Promise((r) => fake.listen(0, "127.0.0.1", r));
const FAKE_URL = `http://127.0.0.1:${fake.address().port}`;

const median = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)];
const p95 = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length * 0.95)];

function rssKb(pid) {
  try {
    if (process.platform === "linux") return Number(readFileSync(`/proc/${pid}/status`, "utf8").match(/VmRSS:\s+(\d+)/)[1]);
  } catch {}
  return null;
}

async function measure(label, cmd) {
  const env = { ...process.env, OPNSENSE_URL: FAKE_URL, OPNSENSE_API_KEY: "k", OPNSENSE_API_SECRET: "s", OPNSENSE_TOOLSETS: "all" };
  const t0 = performance.now();
  const child = spawn(cmd[0], cmd.slice(1), { env, stdio: ["pipe", "pipe", "ignore"] });
  const waiting = new Map();
  let buf = "";
  child.stdout.on("data", (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i); buf = buf.slice(i + 1);
      if (!line.trim()) continue;
      const msg = JSON.parse(line);
      waiting.get(msg.id)?.(msg); waiting.delete(msg.id);
    }
  });
  let id = 0;
  const rpc = (method, params) => new Promise((resolve) => {
    const mine = ++id;
    waiting.set(mine, resolve);
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: mine, method, params }) + "\n");
  });

  const init = await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "bench", version: "1" } });
  const startupMs = performance.now() - t0;
  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");

  const list = await rpc("tools/list", {});
  const tools = list.result.tools;
  const lat = [];
  for (let i = 0; i < N_LIST; i++) { const s = performance.now(); await rpc("tools/list", {}); lat.push(performance.now() - s); }

  const probe = tools.find((t) => t.name === "opn_mcp_info");
  const t1 = performance.now();
  for (let i = 0; i < N_CALL; i++) await rpc("tools/call", { name: probe.name, arguments: {} });
  const callsPerSec = N_CALL / ((performance.now() - t1) / 1000);

  // Appels concurrents : 16 en vol à la fois.
  const t2 = performance.now();
  for (let b = 0; b < N_CALL / 16; b++) await Promise.all(Array.from({ length: 16 }, () => rpc("tools/call", { name: probe.name, arguments: {} })));
  const concurrentPerSec = (Math.floor(N_CALL / 16) * 16) / ((performance.now() - t2) / 1000);

  const rss = rssKb(child.pid);
  child.kill();
  return {
    label,
    server: init.result?.serverInfo?.name ?? null,
    tools: tools.length,
    startup_ms: +startupMs.toFixed(1),
    list_median_ms: +median(lat).toFixed(3),
    list_p95_ms: +p95(lat).toFixed(3),
    calls_per_s: Math.round(callsPerSec),
    concurrent_calls_per_s: Math.round(concurrentPerSec),
    rss_mb: rss ? +(rss / 1024).toFixed(1) : null,
  };
}

function loc(dir, ext) {
  let n = 0;
  for (const f of readdirSync(dir)) {
    const p = join(dir, f);
    if (f === "node_modules" || f === "target" || f === "dist") continue;
    const s = statSync(p);
    if (s.isDirectory()) n += loc(p, ext);
    else if (ext.some((e) => f.endsWith(e))) n += readFileSync(p, "utf8").split("\n").length;
  }
  return n;
}

const results = { generated: new Date().toISOString(), node: process.version, platform: `${process.platform}-${process.arch}` };
results.ts = await measure("TypeScript (Yuto)", TS_CMD);
results.ts.loc = loc("src", [".ts"]);
results.ts.size_kb = existsSync("dist") ? Math.round(dirSize("dist") / 1024) : null;
results.rust = existsSync(RUST_BIN) ? await measure("Rust (Toji)", [RUST_BIN]) : null;
if (results.rust) {
  results.rust.loc = loc("rust/src", [".rs"]);
  results.rust.size_kb = Math.round(statSync(RUST_BIN).size / 1024);
}
fake.close();
writeFileSync(OUT, JSON.stringify(results, null, 2) + "\n");
console.log(JSON.stringify(results, null, 2));

function dirSize(d) {
  let n = 0;
  for (const f of readdirSync(d)) { const p = join(d, f); const s = statSync(p); n += s.isDirectory() ? dirSize(p) : s.size; }
  return n;
}
process.exit(0);
