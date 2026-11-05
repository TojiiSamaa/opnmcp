// Test différentiel de COMPORTEMENT : serveur TS (dist/index.js) contre serveur Rust (osmcp), sur un faux pare-feu.
// Pour chaque outil (lecture ; écriture en dry_run:true), compare (1) les requêtes HTTP émises, (2) le résultat renvoyé.
// Usage : node bench/differentiel.mjs [--rust chemin] [--only motif] [--json rapport.json] [-v]
import { spawn } from "node:child_process";
import http from "node:http";
import { writeFileSync } from "node:fs";

const arg = (n, d) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };
const RUST = arg("--rust", process.platform === "win32" ? "rust/target/release/osmcp.exe" : "rust/target/release/osmcp");
const ONLY = arg("--only", "");
const JSON_OUT = arg("--json", "");
const VERBOSE = process.argv.includes("-v");
const POOL = 6;

// ---------------------------------------------------------------- faux pare-feu
const U1 = "11111111-1111-4111-8111-111111111111";
const U2 = "22222222-2222-4222-8222-222222222222";
const row = (i) => ({
  uuid: i === 1 ? U1 : U2, name: `item${i}`, description: `Description ${i}`, enabled: "1", interface: "lan", protocol: "TCP", action: "pass",
  source_net: "any", destination_net: "10.0.0.0/24", destination_port: "443", sequence: String(i), hostname: `host${i}`, domain: "example.lan",
  ipaddr: `10.0.0.${i}`, address: `10.0.0.${i}`, type: "host", content: `10.0.0.${i}`, device: "igb1", identifier: "lan", status: "up", label: `label${i}`,
});
const grid = () => ({ rows: [row(1), row(2)], total: 2, rowCount: 2, current: 1 });

const WRAPPERS = ["account", "acl", "action", "alias", "backend", "category", "dot", "frontend", "healthcheck", "host", "instance", "range", "reservation", "route", "rule", "server", "item", "client", "forward", "dnsbl", "blocklist"];
const MODEL = { allowlists: { "a.example": { value: "a.example", selected: 1 }, "b.example": { value: "b.example", selected: 0 } }, enabled: "1", description: "Description 1", name: "item1", hostname: "host1", interface: "lan", type: "host", content: "10.0.0.1", ip: "10.0.0.1", address: "10.0.0.1" };
const XML = '<?xml version="1.0"?><opnsense><system><hostname>fw</hostname><webgui><protocol>https</protocol></webgui><ssh><enabled>enabled</enabled><permitrootlogin>1</permitrootlogin><passwordauth>1</passwordauth></ssh><user><name>root</name><password>$2y$secret-hash</password></user></system><filter><rule><descr>legacy</descr></rule></filter></opnsense>';
const IFACES = { rows: [{ identifier: "lan", device: "igb1", description: "LAN", status: "up", addr4: "10.0.0.1/24", ipv4: [{ ipaddr: "10.0.0.1/24" }] }, { identifier: "wan", device: "igb0", description: "WAN", status: "up", addr4: "203.0.113.2/24", ipv4: [{ ipaddr: "203.0.113.2/24" }] }], total: 2, rowCount: 2, current: 1 };
// Mode « permissif » : tout chemin inconnu répond 200 avec un corps générique, pour atteindre les chemins de succès.
let PERMISSIVE = false;

function fakeReply(method, path) {
  // Les segments finaux (uuid, "this", nombres) sont des paramètres, pas l'action.
  const seg = path.split("/").filter((x, i) => i < 3 || !/^([0-9a-f-]{36}|this|\d+)$/i.test(x));
  const last = seg[seg.length - 1];
  if (path === "core/firmware/status") return [200, { status: "none", product: { product_version: "25.7.1", product_name: "opnsense" } }];
  if (path === "core/firmware/info") return [200, { plugin: [{ name: "os-haproxy", version: "4.0", installed: "1", comment: "proxy" }] }];
  if (path === "core/system/status") return [200, { metadata: { system: { status: 2 } } }];
  if (path.startsWith("core/backup/download")) return [200, XML, "application/xml"];
  if (path.startsWith("core/backup/backups")) return [200, { items: [{ id: "config-1762000000.0001.xml", username: "root@api", description: "x", time: "2026-01-01T00:00:00Z" }, { id: "config-1762000100.0002.xml", username: "root@api", description: "y", time: "2026-01-02T00:00:00Z" }] }];
  if (path === "interfaces/overview/interfaces_info") return [200, IFACES];
  if (path === "firewall/alias_util/aliases") return [200, ["bogons", "lan_hosts"]];
  if (/^(search|list)/.test(last) || /search/.test(last)) return [200, grid()];
  if (/^(get|show)/.test(last)) return [200, { ...MODEL, ...Object.fromEntries(WRAPPERS.map((w) => [w, MODEL])), rows: grid().rows }];
  if (/(apply|reconfigure|savepoint|restart|start|stop|flush|kill)/.test(last)) return [200, { status: "ok", revision: "1762000000.123" }];
  if (PERMISSIVE) return [200, { status: "ok", result: "saved", uuid: U1, rows: [], total: 0, response: "x", data: { a: 1 } }];
  return [404, { errorMessage: "Endpoint not found" }];
}

function startFake() {
  const requests = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const url = new URL(req.url ?? "/", "http://fake");
      const path = url.pathname.replace(/^\/api\//, "");
      const text = Buffer.concat(chunks).toString("utf8");
      let body = text;
      try { body = text ? JSON.parse(text) : null; } catch {}
      const query = [...url.searchParams.entries()].sort().map(([k, v]) => `${k}=${v}`).join("&");
      requests.push({ method: req.method, path, query, body, auth: req.headers.authorization ?? "", ctype: req.headers["content-type"] ?? "", accept: req.headers.accept ?? "" });
      const [status, out, ctype = "application/json"] = fakeReply(req.method, path);
      res.writeHead(status, { "Content-Type": ctype });
      res.end(typeof out === "string" ? out : JSON.stringify(out));
    });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ requests, url: `http://127.0.0.1:${server.address().port}`, close: () => server.close() })));
}

// ---------------------------------------------------------------- client MCP stdio
class Mcp {
  constructor(cmd, env) {
    this.c = spawn(cmd[0], cmd.slice(1), { env: { ...process.env, ...env }, stdio: ["pipe", "pipe", "ignore"] });
    this.pending = new Map(); this.id = 0; this.buf = "";
    this.c.stdout.on("data", (d) => {
      this.buf += d;
      let i;
      while ((i = this.buf.indexOf("\n")) >= 0) {
        const line = this.buf.slice(0, i); this.buf = this.buf.slice(i + 1);
        if (!line.trim()) continue;
        try { const m = JSON.parse(line); if (m.id !== undefined && this.pending.has(m.id)) { this.pending.get(m.id)(m); this.pending.delete(m.id); } } catch {}
      }
    });
  }
  req(method, params, ms = 30000) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => { this.pending.delete(id); reject(new Error(`timeout ${method}`)); }, ms);
      this.pending.set(id, (m) => { clearTimeout(t); resolve(m); });
      this.c.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }
  async init() {
    await this.req("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "diff", version: "1" } });
    this.c.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
  }
  close() { this.c.kill(); }
}

const envFor = (url) => ({ OPNSENSE_URL: url, OPNSENSE_API_KEY: "k", OPNSENSE_API_SECRET: "s", OPNSENSE_TOOLSETS: "all", OPNSENSE_ALLOW_WRITES: "true" });
const IMPLS = { ts: ["node", "dist/index.js"], rust: [RUST] };

// ---------------------------------------------------------------- arguments minimaux déduits du schéma
const PATTERN_CANDIDATES = [U1, "config-1762000000.0001.xml", "ff0000", "firewall/filter/search_rule", "10.0.0.1", "example", "lan", "item1", "abc", "1", "tcp", "example.lan", "00:11:22:33:44:55", "10.0.0.0/24"];
// Surcharges là où le schéma seul ne suffit pas (valeurs fixes plausibles).
const OVERRIDES = {
  opn_describe_model: { path: "firewall/filter/get_rule" },
  opn_kill_states: { address: "10.0.0.1" },
  opn_simulate_firewall_traffic: { interface: "lan" },
  opn_api_read: { path: "firewall/filter/search_rule" },
  opn_api_write: { path: "firewall/filter/add_rule", body: { rule: { description: "x" } } },
};

function genValue(name, s, depth = 0, full = false) {
  if (s.const !== undefined) return s.const;
  if (s.enum) return full ? s.enum[s.enum.length - 1] : s.enum[0];
  if (s.anyOf || s.oneOf) { const alts = s.anyOf ?? s.oneOf; return genValue(name, alts.find((a) => a.type !== "null") ?? alts[0], depth, full); }
  if (s.default !== undefined) return s.default;
  switch (s.type) {
    case "string": {
      if (s.pattern) { const re = new RegExp(s.pattern); const c = PATTERN_CANDIDATES.find((v) => re.test(v)); if (c) return c; }
      if (s.format === "uuid") return U1;
      let v = /uuid/i.test(name) ? U1 : /^path$/.test(name) ? "firewall/filter/search_rule" : /ip|addr|host|network|source|destination/.test(name) ? "10.0.0.1" : /interface/.test(name) ? "lan" : /name|alias/.test(name) ? "item1" : "example";
      if (s.minLength && v.length < s.minLength) v = v.padEnd(s.minLength, "x");
      if (s.maxLength && v.length > s.maxLength) v = v.slice(0, s.maxLength);
      return v;
    }
    case "integer": case "number": {
      let v = s.minimum ?? 1; if (s.exclusiveMinimum !== undefined) v = s.exclusiveMinimum + 1;
      if (name === "port" || /port/.test(name)) v = Math.max(v, 80);
      if (s.maximum !== undefined && v > s.maximum) v = s.maximum;
      return v;
    }
    case "boolean": return true;
    case "array": return depth > 3 ? [] : [genValue(name, s.items ?? { type: "string" }, depth + 1, full)];
    case "object": {
      const out = s.additionalProperties && !s.properties ? { name: "example", description: "x" } : {}; // record libre (champs d'un modèle)
      for (const k of s.required ?? []) out[k] = genValue(k, s.properties?.[k] ?? { type: "string" }, depth + 1, full);
      return out;
    }
    default: return "example";
  }
}

// full=true : TOUS les paramètres optionnels sont renseignés (enum : dernière valeur), pour exercer la construction des requêtes.
function argsFor(t, full) {
  const sch = t.inputSchema ?? {};
  const args = {};
  for (const k of full ? Object.keys(sch.properties ?? {}) : sch.required ?? []) if (k !== "instance" && k !== "dry_run") args[k] = genValue(k, sch.properties[k] ?? { type: "string" }, 0, full);
  if (/^opn_(update|set)_/.test(t.name)) { // un update sans champ est refusé : on en ajoute un
    const props = Object.entries(sch.properties ?? {}).filter(([k]) => !["uuid", "apply", "dry_run", "instance"].includes(k) && !(k in args));
    const pick = props.find(([k]) => k === "description") ?? props.find(([, v]) => ["string", "boolean", "integer", "number"].includes(v.type)) ?? props[0];
    if (pick) args[pick[0]] = genValue(pick[0], pick[1]);
  }
  Object.assign(args, OVERRIDES[t.name]);
  if (t.annotations?.readOnlyHint !== true) args.dry_run = true;
  return args;
}

// ---------------------------------------------------------------- comparaison
const canon = (v) => Array.isArray(v) ? v.map(canon) : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])])) : v;
const reqLine = (r) => `${r.method} ${r.path}${r.query ? "?" + r.query : ""} ${JSON.stringify(canon(r.body))} [ct=${r.ctype}|acc=${r.accept}|auth=${r.auth === "Basic " + Buffer.from("k:s").toString("base64") ? "ok" : r.auth}]`;
// Bruit non déterministe : horodatages, durées, uuid aléatoires.
const NOISE = [[/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?/g, "<TS>"], [/\b1[67]\d{8}(\.\d+)?\b/g, "<EPOCH>"], [/"duration_ms":\d+/g, '"duration_ms":0'], [/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}/g, (m) => (m === U1 || m === U2 ? m : "<UUID>")]];
// Validation des arguments : le SDK TS (zod) et le Rust formulent l'erreur différemment, par construction.
const norm = (s) => (/^MCP error -32602|^\{"error":"Invalid arguments for/.test(s) ? "<INVALID_ARGS>" : NOISE.reduce((a, [re, to]) => a.replace(re, to), s));

function diffJson(a, b, p = "$", out = []) {
  if (JSON.stringify(a) === JSON.stringify(b)) return out;
  if (a && b && typeof a === "object" && typeof b === "object" && Array.isArray(a) === Array.isArray(b)) {
    const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
    for (const k of keys) {
      if (!(k in a)) out.push(`${p}.${k}: absent du TS, Rust=${short(b[k])}`);
      else if (!(k in b)) out.push(`${p}.${k}: absent du Rust, TS=${short(a[k])}`);
      else diffJson(a[k], b[k], `${p}.${k}`, out);
    }
  } else out.push(`${p}: TS=${short(a)} Rust=${short(b)}`);
  return out;
}
const short = (v) => { const s = JSON.stringify(v); return s && s.length > 160 ? s.slice(0, 160) + "…" : s; };

async function runOne(impl, t, args, fake) {
  fake.requests.length = 0;
  const m = new Mcp(IMPLS[impl], envFor(fake.url));
  try {
    await m.init();
    const r = await m.req("tools/call", { name: t.name, arguments: args });
    const res = r.result ?? { isError: true, content: [{ type: "text", text: JSON.stringify(r.error) }], rpcError: true };
    const text = (res.content ?? []).map((c) => c.text ?? "").join("\n");
    // Un appel parallèle encore en vol quand le premier échoue (Promise.all) arrive un peu après la réponse.
    await new Promise((r) => setTimeout(r, 150));
    return { isError: !!res.isError, rpc: !!res.rpcError, text: norm(text), reqs: fake.requests.slice() };
  } catch (e) {
    return { isError: true, text: `HARNESS ${e.message}`, reqs: fake.requests.slice(), harness: true };
  } finally { m.close(); }
}

function compare(t, a, b) {
  const issues = [];
  const la = a.reqs.map(reqLine), lb = b.reqs.map(reqLine);
  const sa = [...la].sort(), sb = [...lb].sort();
  if (JSON.stringify(sa) !== JSON.stringify(sb)) {
    const onlyA = sa.filter((x) => !sb.includes(x)), onlyB = sb.filter((x) => !sa.includes(x));
    issues.push({ kind: "requetes", detail: [...onlyA.map((x) => `TS seulement : ${x}`), ...onlyB.map((x) => `Rust seulement: ${x}`), ...(onlyA.length + onlyB.length === 0 ? [`multiplicité différente TS=${la.length} Rust=${lb.length}`] : [])] });
  } else if (JSON.stringify(la) !== JSON.stringify(lb)) {
    issues.push({ kind: "ordre-requetes", detail: [`TS: ${la.map((x) => x.split(" ").slice(0, 2).join(" ")).join(" | ")}`, `Rust: ${lb.map((x) => x.split(" ").slice(0, 2).join(" ")).join(" | ")}`] });
  }
  if (a.isError !== b.isError) issues.push({ kind: "statut", detail: [`isError TS=${a.isError} Rust=${b.isError}`, `TS: ${short(a.text)}`, `Rust: ${short(b.text)}`] });
  let ja, jb;
  try { ja = JSON.parse(a.text); jb = JSON.parse(b.text); } catch {}
  // Écart TS connu, normalisé : sous Node >= 24, res.socket vaut null à 'end' avec keep-alive, donc le TS ne retient jamais
  // l'adresse locale (client.ts:329) et répond « adresse inconnue » ; le Rust la lit et reconnaît le bouclage 127.0.0.1.
  if (ja?.lockout?.management_path?.source === null && jb?.lockout?.management_path?.source === "127.0.0.1") jb.lockout = ja.lockout;
  if (ja?.management_path?.source === null && jb?.management_path?.source === "127.0.0.1") jb.management_path = ja.management_path, jb.message = ja.message;
  if (ja !== undefined && jb !== undefined) {
    const d = diffJson(ja, jb);
    if (d.length) issues.push({ kind: "resultat", detail: d.slice(0, 12) });
    else if (JSON.stringify(ja) !== JSON.stringify(jb)) {
      let i = 0; const x = JSON.stringify(ja), y = JSON.stringify(jb);
      while (x[i] === y[i]) i++;
      issues.push({ kind: "ordre-cles", detail: ["même contenu, clés dans un autre ordre", `TS:   …${x.slice(Math.max(0, i - 200), i + 400)}`, `Rust: …${y.slice(Math.max(0, i - 200), i + 400)}`] });
    }
  } else if (a.text !== b.text) issues.push({ kind: "texte", detail: [`TS: ${short(a.text)}`, `Rust: ${short(b.text)}`] });
  return issues;
}

// ---------------------------------------------------------------- main
const probe = await startFake();
const lm = new Mcp(IMPLS.ts, envFor(probe.url));
await lm.init();
const tools = (await lm.req("tools/list", {})).result.tools.filter((t) => t.name.includes(ONLY));
lm.close(); probe.close();

const all = [];
for (const [label, permissive, full] of [["404/min", false, false], ["permissif/min", true, false], ["404/full", false, true], ["permissif/full", true, true]]) {
  PERMISSIVE = permissive;
  const queue = [...tools];
  await Promise.all(Array.from({ length: POOL }, async () => {
    const fake = await startFake();
    for (let t; (t = queue.shift()); ) {
      const args = argsFor(t, full);
      const ts = await runOne("ts", t, args, fake);
      const rs = await runOne("rust", t, args, fake);
      const issues = compare(t, ts, rs);
      all.push({ fake: label, tool: t.name, mode: t.annotations?.readOnlyHint ? "lecture" : "dry_run", args, issues, tsError: ts.isError, tsText: VERBOSE ? ts.text : undefined, harness: ts.harness || rs.harness });
    }
    fake.close();
  }));
}

all.sort((x, y) => x.tool.localeCompare(y.tool) || x.fake.localeCompare(y.fake));
const isBad = (r) => r.issues.some((i) => i.kind !== "ordre-requetes");
const bad = all.filter(isBad);
for (const r of all.filter((r) => r.issues.length)) {
  console.log(`\n## ${r.tool} (${r.mode}, faux=${r.fake}) args=${JSON.stringify(r.args)}${isBad(r) ? "" : "  [note seulement]"}`);
  for (const i of r.issues) { console.log(`  [${i.kind}]`); for (const d of i.detail) console.log(`    ${d}`); }
}
if (VERBOSE) for (const r of all) console.log(`${r.tool} (${r.fake}): ${r.tsError ? "ERREUR" : "ok"} ${r.tsText ? short(r.tsText) : ""}`);
// Couverture : un outil est « exercé » s'il a réussi (hors erreur) dans au moins un des deux faux.
const exercised = new Set(all.filter((r) => !r.tsError).map((r) => r.tool));
const names = new Set(all.map((r) => r.tool));
console.log(`\nOutils comparés : ${names.size} (lecture ${[...new Set(all.filter((r) => r.mode === "lecture").map((r) => r.tool))].length}, dry_run ${[...new Set(all.filter((r) => r.mode === "dry_run").map((r) => r.tool))].length}), 2 passes (faux 404 + permissif)`);
console.log(`Passes divergentes : ${bad.length} sur ${all.length} ; outils divergents : ${new Set(bad.map((r) => r.tool)).size}`);
console.log(`Outils sans aucun succès côté TS (comparés seulement sur leur erreur, couverture faible) : ${[...names].filter((n) => !exercised.has(n)).join(", ") || "aucun"}`);
if (all.some((r) => r.harness)) console.log("Incidents de harnais :", all.filter((r) => r.harness).map((r) => r.tool).join(", "));
if (JSON_OUT) writeFileSync(JSON_OUT, JSON.stringify(all, null, 1));
process.exit(bad.length ? 1 : 0);
process.exit(bad.length ? 1 : 0);
