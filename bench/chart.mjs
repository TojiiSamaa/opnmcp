// Génère bench/chart.svg et bench/results.md à partir de bench/results.json (et bench/parite.json si présent).
import { readFileSync, writeFileSync } from "node:fs";

const r = JSON.parse(readFileSync(process.argv[2] ?? "bench/results.json", "utf8"));
const { ts, rust } = r;
let parite = null;
try { parite = JSON.parse(readFileSync("bench/parite.json", "utf8")); } catch {}

// [libellé, clé, plus petit = meilleur, compte pour la vitesse, unité]
const ALL = [
  ["Démarrage", "startup_ms", true, true, "ms"],
  ["Liste des outils (médiane)", "list_median_ms", true, true, "ms"],
  ["Liste des outils (p95)", "list_p95_ms", true, true, "ms"],
  ["Appels par seconde", "calls_per_s", false, true, "/s"],
  ["Appels par seconde, 16 en parallèle", "concurrent_calls_per_s", false, true, "/s"],
  ["Mémoire", "rss_mb", true, false, "Mo"],
  ["Taille du livrable", "size_kb", true, false, "Ko"],
];
const rows = ALL.filter(([, k]) => ts[k] != null && (!rust || rust[k] != null));
const speed = rows.filter((x) => x[3]);
const ratio = ([, k, lower]) => (lower ? ts[k] / rust[k] : rust[k] / ts[k]); // > 1 : Rust devant
const rustWins = rust ? speed.filter((x) => ratio(x) > 1).length : 0;
const win = rust && rustWins === speed.length;
const pariteOk = parite && !parite.manquants_rust.length && !parite.en_trop_rust.length && !parite.ecarts;
const verdict = !rust ? "Pas de version Rust à comparer"
  : win ? `Toji a gagné : Rust plus rapide sur ${rustWins} mesures de vitesse sur ${speed.length}`
  : rustWins === 0 ? `Yutho garde la main : TypeScript plus rapide sur ${speed.length} mesures sur ${speed.length}`
  : `Match nul : Rust devant sur ${rustWins} mesures de vitesse sur ${speed.length}`;
const pariteTxt = parite ? (pariteOk ? `${parite.rust} outils sur ${parite.ts} identiques` : `Parité incomplète : ${parite.manquants_rust.length} outil(s) manquant(s), ${parite.ecarts} écart(s)`) : "";

const fmt = (v) => (v >= 100 ? Math.round(v).toLocaleString("fr-FR") : String(+v.toFixed(v >= 10 ? 1 : 2)).replace(".", ","));
const times = (x) => `×${x >= 10 ? Math.round(x) : x.toFixed(1).replace(".", ",")}`;
const esc = (t) => String(t).replace(/&/g, "&amp;").replace(/</g, "&lt;");

const W = 820, PAD = 28;
let y = 0;
let out = "";

// En-tête
out += `<text x="${PAD}" y="42" class="h1">TypeScript de Yutho contre Rust de Toji</text>`;
out += `<text x="${PAD}" y="64" class="sub">Mêmes requêtes MCP, même faux pare-feu · ${esc(r.platform)} · Node ${esc(r.node)} · ${r.generated.slice(0, 10)}</text>`;
out += `<g transform="translate(${W - PAD - 210} 28)"><rect width="12" height="12" rx="3" class="ts"/><text x="18" y="11" class="leg">Yutho · TS</text><rect x="100" width="12" height="12" rx="3" class="rs"/><text x="118" y="11" class="leg">Toji · Rust</text></g>`;
y = 84;

// Bandeau verdict
out += `<rect x="${PAD}" y="${y}" width="${W - 2 * PAD}" height="44" rx="10" class="${win ? "banner win" : "banner"}"/>`;
out += `<text x="${PAD + 18}" y="${y + 28}" class="verdict ${win ? "winTxt" : ""}">${win ? "🏆 " : ""}${esc(verdict)}</text>`;
if (pariteTxt) out += `<text x="${W - PAD - 18}" y="${y + 28}" text-anchor="end" class="${pariteOk ? "ok" : "ko"}">${pariteOk ? "✓ " : "⚠ "}${esc(pariteTxt)}</text>`;
y += 64;

// Trois chiffres qui frappent
const heroes = [["startup_ms", "plus vite au démarrage"], ["concurrent_calls_per_s", "de débit en parallèle"], ["rss_mb", "de mémoire en moins"]]
  .map(([k, label]) => [ALL.find((x) => x[1] === k), label]).filter(([a]) => a && rust && ts[a[1]] != null && rust[a[1]] != null);
if (heroes.length) {
  const tw = (W - 2 * PAD - 16 * (heroes.length - 1)) / heroes.length;
  heroes.forEach(([a, label], i) => {
    const x = PAD + i * (tw + 16), q = ratio(a);
    out += `<rect x="${x}" y="${y}" width="${tw}" height="96" rx="12" class="tile"/>`;
    out += `<text x="${x + tw / 2}" y="${y + 52}" text-anchor="middle" class="${q > 1 ? "big rsTxt" : "big tsTxt"}">${times(q > 1 ? q : 1 / q)}</text>`;
    out += `<text x="${x + tw / 2}" y="${y + 78}" text-anchor="middle" class="sub">${q > 1 ? "" : "TS "}${label}</text>`;
  });
  y += 120;
}

// Barres côte à côte, une échelle par mesure
const LABEL = 250, BARX = PAD + LABEL, BARW = W - BARX - PAD - 90;
for (const row of rows) {
  const [label, k, , , unit] = row;
  const a = ts[k], b = rust[k], max = Math.max(a, b) || 1, q = ratio(row);
  out += `<text x="${PAD}" y="${y + 24}" class="lab">${esc(label)}</text>`;
  const bar = (v, cls, dy, who) => {
    const w = Math.max(3, (v / max) * BARW);
    const inside = w > 120;
    return `<rect x="${BARX}" y="${y + dy}" width="${w}" height="20" rx="5" class="${cls}"/>` +
      `<text x="${inside ? BARX + w - 8 : BARX + w + 8}" y="${y + dy + 15}" text-anchor="${inside ? "end" : "start"}" class="${inside ? "val inv" : "val"}">${fmt(v)} ${unit}</text>`;
  };
  out += bar(a, "ts", 6, "TS") + bar(b, "rs", 32, "Rust");
  const rustAhead = q > 1;
  out += `<text x="${W - PAD}" y="${y + 40}" text-anchor="end" class="${rustAhead ? "ratio rsTxt" : "ratio tsTxt"}">${times(rustAhead ? q : 1 / q)}</text>`;
  out += `<text x="${W - PAD}" y="${y + 56}" text-anchor="end" class="sub small">${rustAhead ? "Rust" : "TS"} devant</text>`;
  y += 70;
  out += `<line x1="${PAD}" x2="${W - PAD}" y1="${y - 4}" y2="${y - 4}" class="rule"/>`;
}
y += 12;
out += `<text x="${PAD}" y="${y}" class="sub small">Le verdict ne compte que la vitesse (démarrage, latence, débit). Mémoire et taille sont montrées à part, sans être comptées.</text>`;
const H = y + 22;

const style = `
.bg{fill:#ffffff;stroke:#d0d7de}.h1{font-weight:700;font-size:22px;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;fill:#1f2328}
.sub{font-size:13px;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;fill:#59636e}.small{font-size:11px}
.leg{font-size:12px;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;fill:#1f2328}
.lab{font-weight:600;font-size:14px;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;fill:#1f2328}
.val{font-weight:600;font-size:12px;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;fill:#1f2328}.inv{fill:#ffffff}
.ts{fill:#3178c6}.rs{fill:#d9622b}.tsTxt{fill:#3178c6}.rsTxt{fill:#d9622b}
.big{font-weight:800;font-size:44px;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif}
.ratio{font-weight:800;font-size:22px;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif}
.banner{fill:#eef1f4}.banner.win{fill:#fdebe0}.verdict{font-weight:700;font-size:16px;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;fill:#1f2328}.winTxt{fill:#b4491a}
.tile{fill:#f6f8fa;stroke:#d0d7de}.rule{stroke:#e6e9ed}.ok{font-weight:600;font-size:12px;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;fill:#1a7f37}.ko{font-weight:600;font-size:12px;font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;fill:#cf222e}
@media (prefers-color-scheme: dark){.bg{fill:#0d1117;stroke:#30363d}.h1,.leg,.lab,.val,.verdict{fill:#e6edf3}.inv{fill:#0d1117}.sub{fill:#9198a1}
.banner{fill:#161b22}.banner.win{fill:#3a2216}.winTxt{fill:#ff9a64}.tile{fill:#161b22;stroke:#30363d}.rule{stroke:#21262d}.ts,.tsTxt{fill:#58a6ff}.rs,.rsTxt{fill:#ff8a4c}.ok{fill:#3fb950}.ko{fill:#ff7b72}}`;

const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(verdict)}">
<style>${style}</style>
<rect class="bg" x=".5" y=".5" width="${W - 1}" height="${H - 1}" rx="14"/>
${out}</svg>
`;
writeFileSync("bench/chart.svg", svg);

const cell = (o, k) => (o?.[k] == null ? "n/a" : fmt(o[k]));
const md = `| Mesure | TypeScript (Yutho) | Rust (Toji) |
|---|---:|---:|
${[...rows.map(([l, k]) => [l, k]), ["Outils exposés", "tools"], ["Lignes de code", "loc"]].map(([l, k]) => `| ${l} | ${cell(ts, k)} | ${cell(rust, k)} |`).join("\n")}
`;
writeFileSync("bench/results.md", `**${win ? "🏆 " : ""}${verdict}**${pariteTxt ? ` · ${pariteTxt}` : ""}\n\n` + md);
console.log(md);
