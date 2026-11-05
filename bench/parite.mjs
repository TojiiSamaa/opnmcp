// Compare les outils exposés (noms, annotations, schémas) par le serveur TS et par le serveur Rust.
// Usage : node bench/parite.mjs [--rust chemin] [--writes]
import { spawn } from "node:child_process";

const arg = (n, d) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };
const RUST = arg("--rust", process.platform === "win32" ? "rust/target/release/osmcp.exe" : "rust/target/release/osmcp");

function listTools(cmd, env) {
  return new Promise((resolve, reject) => {
    const c = spawn(cmd[0], cmd.slice(1), { env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "ignore"] });
    let buf = "";
    c.stdout.on("data", (d) => {
      buf += d;
      for (const line of buf.split("\n")) {
        if (!line.trim()) continue;
        try {
          const m = JSON.parse(line);
          if (m.id === 2) { c.kill(); resolve(m.result.tools); }
        } catch {}
      }
    });
    c.on("error", reject);
    const send = (o) => c.stdin.write(JSON.stringify({ jsonrpc: "2.0", ...o }) + "\n");
    send({ id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "parite", version: "1" } } });
    send({ method: "notifications/initialized" });
    send({ id: 2, method: "tools/list", params: {} });
  });
}

const env = { OPNSENSE_URL: "http://127.0.0.1:9", OPNSENSE_API_KEY: "k", OPNSENSE_API_SECRET: "s", OPNSENSE_TOOLSETS: "all", OPNSENSE_ALLOW_WRITES: "true" };
const [ts, rs] = await Promise.all([listTools(["node", "dist/index.js"], env), listTools([RUST], env)]);
const by = (a) => new Map(a.map((t) => [t.name, t]));
const T = by(ts), R = by(rs);
const only = (a, b) => [...a.keys()].filter((k) => !b.has(k)).sort();
const ann = (t) => JSON.stringify([t.annotations?.readOnlyHint ?? null, t.annotations?.destructiveHint ?? null, t.annotations?.idempotentHint ?? null]);
const props = (t) => JSON.stringify(Object.keys(t.inputSchema?.properties ?? {}).sort());
const req = (t) => JSON.stringify([...(t.inputSchema?.required ?? [])].sort());
const diff = (f) => [...T.keys()].filter((k) => R.has(k) && f(T.get(k)) !== f(R.get(k))).sort();

console.log(`TS ${T.size} outils, Rust ${R.size} outils`);
console.log("Seulement TS  :", only(T, R));
console.log("Seulement Rust:", only(R, T));
const dd = { description: diff((t) => t.description), annotations: diff(ann), "champs d'entrée": diff(props), "champs requis": diff(req), titre: diff((t) => t.title ?? t.annotations?.title) };
for (const [k, v] of Object.entries(dd)) console.log(`${k} différents (${v.length})`, v.slice(0, 40));
