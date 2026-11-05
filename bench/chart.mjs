// Génère bench/chart.svg et le tableau Markdown de bench/results.md à partir de bench/results.json.
import { readFileSync, writeFileSync } from "node:fs";

const r = JSON.parse(readFileSync(process.argv[2] ?? "bench/results.json", "utf8"));
const { ts, rust } = r;
const rows = [
  ["Démarrage (ms)", "startup_ms", true, true],
  ["tools/list médiane (ms)", "list_median_ms", true, true],
  ["tools/list p95 (ms)", "list_p95_ms", true, true],
  ["Appels/s en série", "calls_per_s", false, true],
  ["Appels/s à 16 en vol", "concurrent_calls_per_s", false, true],
  ["Mémoire résidente (Mo)", "rss_mb", true],
  ["Taille livrée (Ko)", "size_kb", true],
]
  .filter(([, k]) => ts[k] != null && (!rust || rust[k] != null));

// Verdict : sur la VITESSE (démarrage, latence, débit). Mémoire et taille restent affichées, sans compter.
const speed = rows.filter((r) => r[3] && rust);
const rustWins = speed.filter(([, k, lower]) => (lower ? rust[k] < ts[k] : rust[k] > ts[k])).length;
let parite = null;
try { parite = JSON.parse(readFileSync("bench/parite.json", "utf8")); } catch {}
const pariteOk = parite && !parite.manquants_rust.length && !parite.en_trop_rust.length && !parite.ecarts;
const verdict = !rust ? "Pas de version Rust à comparer"
  : rustWins === speed.length ? `Toji a gagné : Rust plus rapide sur ${rustWins}/${speed.length} mesures de vitesse`
  : rustWins === 0 ? `Yuto garde la main : TypeScript plus rapide sur ${speed.length}/${speed.length} mesures`
  : `Match nul : Rust devant sur ${rustWins}/${speed.length} mesures de vitesse`;
const win = rust && rustWins === speed.length;
const pariteTxt = parite ? (pariteOk ? `Parité : ${parite.rust}/${parite.ts} outils identiques` : `Parité incomplète : ${parite.manquants_rust.length} outil(s) manquant(s) en Rust, ${parite.ecarts} écart(s)`) : "";

const W = 760, ROW = 74, TOP = 112, H = TOP + rows.length * ROW + 24, LABEL = 200, BAR = W - LABEL - 150;
const C = { ts: "#3178c6", rust: "#d9622b", text: "#1f2328", sub: "#656d76", bg: "#ffffff", line: "#d0d7de" };
const fmt = (v) => (v >= 100 ? Math.round(v).toLocaleString("fr-FR") : String(+v.toFixed(2)));
let y = TOP;
let body = "";
for (const [label, key, lower] of rows) {
  const a = ts[key], b = rust?.[key];
  const max = Math.max(a, b ?? 0) || 1;
  const bar = (v, color, dy, name) => `<rect x="${LABEL}" y="${y + dy}" width="${Math.max(2, (v / max) * BAR)}" height="18" rx="3" fill="${color}"/><text x="${LABEL + (v / max) * BAR + 8}" y="${y + dy + 14}" font-size="13" fill="${C.text}">${fmt(v)} <tspan fill="${C.sub}">${name}</tspan></text>`;
  body += `<text x="24" y="${y + 30}" font-size="14" fill="${C.text}">${label}</text>`;
  body += bar(a, C.ts, 8, "TS");
  if (b != null) {
    body += bar(b, C.rust, 34, "Rust");
    const ratio = lower ? a / b : b / a;
    body += `<text x="${W - 24}" y="${y + 30}" text-anchor="end" font-size="15" font-weight="700" fill="${ratio >= 1 ? C.rust : C.sub}">×${ratio >= 10 ? Math.round(ratio) : ratio.toFixed(1)}</text>`;
  }
  body += `<line x1="24" x2="${W - 24}" y1="${y + ROW - 6}" y2="${y + ROW - 6}" stroke="${C.line}"/>`;
  y += ROW;
}
const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" font-family="-apple-system,Segoe UI,Helvetica,Arial,sans-serif">
<rect width="${W}" height="${H}" rx="10" fill="${C.bg}" stroke="${C.line}"/>
<text x="24" y="34" font-size="18" font-weight="700" fill="${C.text}">opnmcp (TypeScript) contre osmcp (Rust)</text>
<text x="24" y="56" font-size="12" fill="${C.sub}">Mêmes requêtes MCP stdio contre un faux OPNsense · ${r.platform} · Node ${r.node} · ${r.generated.slice(0, 10)}</text>
<rect x="${W - 190}" y="22" width="12" height="12" rx="2" fill="${C.ts}"/><text x="${W - 172}" y="33" font-size="12" fill="${C.text}">TS (Yuto)</text>
<rect x="${W - 100}" y="22" width="12" height="12" rx="2" fill="${C.rust}"/><text x="${W - 82}" y="33" font-size="12" fill="${C.text}">Rust (Toji)</text>
<rect x="24" y="66" width="${W - 48}" height="32" rx="6" fill="${win ? "#fdebe0" : "#eef1f4"}"/><text x="38" y="87" font-size="15" font-weight="700" fill="${win ? C.rust : C.text}">${win ? "🏆 " : ""}${verdict}</text><text x="${W - 38}" y="87" text-anchor="end" font-size="12" fill="${pariteOk ? C.sub : "#cf222e"}">${pariteTxt}</text>
${body}</svg>
`;
writeFileSync("bench/chart.svg", svg);

const cell = (o, k) => (o?.[k] == null ? "n/a" : fmt(o[k]));
const md = `| Mesure | TypeScript | Rust |
|---|---:|---:|
${[...rows.map(([l, k]) => [l, k]), ["Outils exposés", "tools"], ["Lignes de code", "loc"]].map(([l, k]) => `| ${l} | ${cell(ts, k)} | ${cell(rust, k)} |`).join("\n")}
`;
writeFileSync("bench/results.md", `**${win ? "🏆 " : ""}${verdict}**${pariteTxt ? ` · ${pariteTxt}` : ""}

` + md);
console.log(md);
