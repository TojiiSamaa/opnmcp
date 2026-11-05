// Génère bench/chart.svg et bench/results.md à partir de bench/results.json (et bench/parite.json si présent).
// Thème « Arasaka » : noir, rouge, angles coupés, monospace en capitales. Aucun logo de marque reproduit.
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
// Rectangle à angles coupés (haut-gauche et bas-droit), c = taille de la coupe
const cut = (x, y, w, h, c, cls) =>
  `<polygon class="${cls}" points="${x + c},${y} ${x + w},${y} ${x + w},${y + h - c} ${x + w - c},${y + h} ${x},${y + h} ${x},${y + c}"/>`;

const W = 820, PAD = 28;
let y = 0;
let out = "";

// En-tête
out += `<rect x="0" y="0" width="${W}" height="6" class="redbar"/>`;
out += `<text x="${PAD}" y="34" class="tag">// BANC DE PERFORMANCE · MCP OPNSENSE</text>`;
out += `<text x="${PAD}" y="66" class="h1">YUTHO <tspan class="vs">VS</tspan> TOJI</text>`;
out += `<text x="${PAD}" y="88" class="sub">TypeScript contre Rust · mêmes requêtes MCP, même faux pare-feu · ${esc(r.platform)} · Node ${esc(r.node)} · ${r.generated.slice(0, 10)}</text>`;
out += `<g transform="translate(${W - PAD - 250} 24)"><rect width="12" height="12" class="ts"/><text x="20" y="11" class="leg">YUTHO · TS</text><rect x="120" width="12" height="12" class="rs"/><text x="140" y="11" class="leg">TOJI · RUST</text></g>`;
y = 106;

// Bandeau verdict
out += cut(PAD, y, W - 2 * PAD, pariteTxt ? 64 : 46, 12, win ? "banner win" : "banner");
out += `<text x="${PAD + (win ? 30 : 22)}" y="${y + 27}" class="verdict ${win ? "winTxt" : ""}">${esc(verdict.toUpperCase())}</text>`;
if (win) out += `<polygon points="${PAD + 8},${y + 15} ${PAD + 18},${y + 21} ${PAD + 8},${y + 27}" class="redbar"/>`;
if (pariteTxt) out += `<text x="${PAD + 30}" y="${y + 50}" class="${pariteOk ? "ok" : "ko"}">${pariteOk ? "✓ " : "⚠ "}${esc(pariteTxt.toUpperCase())}</text>`;
y += pariteTxt ? 86 : 68;

// Trois chiffres qui frappent
const heroes = [["startup_ms", "plus vite au démarrage"], ["concurrent_calls_per_s", "de débit en parallèle"], ["rss_mb", "de mémoire en moins"]]
  .map(([k, label]) => [ALL.find((x) => x[1] === k), label]).filter(([a]) => a && rust && ts[a[1]] != null && rust[a[1]] != null);
if (heroes.length) {
  const tw = (W - 2 * PAD - 16 * (heroes.length - 1)) / heroes.length;
  heroes.forEach(([a, label], i) => {
    const x = PAD + i * (tw + 16), q = ratio(a);
    out += cut(x, y, tw, 100, 14, "tile");
    out += `<rect x="${x}" y="${y + 14}" width="3" height="72" class="redbar"/>`;
    out += `<text x="${x + tw / 2}" y="${y + 55}" text-anchor="middle" class="${q > 1 ? "big rsTxt" : "big tsTxt"}">${times(q > 1 ? q : 1 / q)}</text>`;
    out += `<text x="${x + tw / 2}" y="${y + 82}" text-anchor="middle" class="sub">${q > 1 ? "" : "TS "}${label.toUpperCase()}</text>`;
  });
  y += 124;
}

// Barres côte à côte, une échelle par mesure
const LABEL = 250, BARX = PAD + LABEL, BARW = W - BARX - PAD - 90;
for (const row of rows) {
  const [label, k, , , unit] = row;
  const a = ts[k], b = rust[k], max = Math.max(a, b) || 1, q = ratio(row);
  out += `<text x="${PAD}" y="${y + 24}" class="lab">${esc(label.replace("Appels par seconde", "Appels/s").toUpperCase())}</text>`;
  const bar = (v, cls, dy) => {
    const w = Math.max(3, (v / max) * BARW);
    const inside = w > 120;
    return `<polygon class="${cls}" points="${BARX},${y + dy} ${BARX + w},${y + dy} ${BARX + w - 6},${y + dy + 20} ${BARX},${y + dy + 20}"/>` +
      `<text x="${inside ? BARX + w - 14 : BARX + w + 8}" y="${y + dy + 15}" text-anchor="${inside ? "end" : "start"}" class="${inside ? "val inv" : "val"}">${fmt(v)} ${unit}</text>`;
  };
  out += bar(a, "ts", 6) + bar(b, "rs", 32);
  const rustAhead = q > 1;
  out += `<text x="${W - PAD}" y="${y + 40}" text-anchor="end" class="${rustAhead ? "ratio rsTxt" : "ratio tsTxt"}">${times(rustAhead ? q : 1 / q)}</text>`;
  out += `<text x="${W - PAD}" y="${y + 56}" text-anchor="end" class="sub small">${rustAhead ? "RUST" : "TS"} DEVANT</text>`;
  y += 70;
  out += `<line x1="${PAD}" x2="${W - PAD}" y1="${y - 4}" y2="${y - 4}" class="rule"/>`;
}
y += 12;
out += `<text x="${PAD}" y="${y}" class="sub small">LE VERDICT NE COMPTE QUE LA VITESSE (DÉMARRAGE, LATENCE, DÉBIT). MÉMOIRE ET TAILLE SONT MONTRÉES À PART, SANS ÊTRE COMPTÉES.</text>`;
const H = y + 22;
out += `<rect x="0" y="${H - 6}" width="${W}" height="6" class="redbar"/>`;

const mono = "font-family:Consolas,'Courier New',Menlo,monospace";
const style = `
.bg{fill:#0a0a0b}
.redbar{fill:#e8112d}
.tag{font-size:11px;${mono};fill:#e8112d;letter-spacing:2px}
.h1{font-weight:700;font-size:28px;${mono};fill:#f2f2f2;letter-spacing:3px}.vs{fill:#e8112d}
.sub{font-size:12px;${mono};fill:#8a8a90}.small{font-size:10px}
.leg{font-size:11px;${mono};fill:#d8d8d8;letter-spacing:1px}
.lab{font-weight:700;font-size:12px;${mono};fill:#d8d8d8;letter-spacing:1px}
.val{font-weight:700;font-size:12px;${mono};fill:#f2f2f2}.inv{fill:#0a0a0b}
.ts{fill:#a9adb3}.rs{fill:#e8112d}.tsTxt{fill:#a9adb3}.rsTxt{fill:#ff3b52}
.big{font-weight:700;font-size:46px;${mono}}
.ratio{font-weight:700;font-size:22px;${mono}}
.banner{fill:#141416;stroke:#2c2c30}.banner.win{fill:#2a0a10;stroke:#e8112d}
.verdict{font-weight:700;font-size:13px;${mono};fill:#f2f2f2;letter-spacing:1px}.winTxt{fill:#ff3b52}
.tile{fill:#121214;stroke:#2c2c30}.rule{stroke:#2c2c30}
.ok{font-weight:700;font-size:11px;${mono};fill:#7ee0a0;letter-spacing:1px}.ko{font-weight:700;font-size:11px;${mono};fill:#ff6b6b;letter-spacing:1px}`;

const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(verdict)}">
<defs><pattern id="scan" width="4" height="4" patternUnits="userSpaceOnUse"><rect width="4" height="1" fill="#ffffff" opacity=".035"/></pattern>
<pattern id="grid" width="32" height="32" patternUnits="userSpaceOnUse"><path d="M32 0H0V32" fill="none" stroke="#e8112d" stroke-opacity=".06"/></pattern></defs>
<style>${style}</style>
<rect class="bg" width="${W}" height="${H}"/>
<rect width="${W}" height="${H}" fill="url(#grid)"/>
${out}<rect width="${W}" height="${H}" fill="url(#scan)"/>
</svg>
`;
writeFileSync("bench/chart.svg", svg);

const cell = (o, k) => (o?.[k] == null ? "n/a" : fmt(o[k]));
const md = `| Mesure | TypeScript (Yutho) | Rust (Toji) |
|---|---:|---:|
${[...rows.map(([l, k]) => [l, k]), ["Outils exposés", "tools"], ["Lignes de code", "loc"]].map(([l, k]) => `| ${l} | ${cell(ts, k)} | ${cell(rust, k)} |`).join("\n")}
`;
writeFileSync("bench/results.md", `**${win ? "🏆 " : ""}${verdict}**${pariteTxt ? ` · ${pariteTxt}` : ""}\n\n` + md);
console.log(md);
