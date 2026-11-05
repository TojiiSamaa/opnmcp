#!/usr/bin/env node
/**
 * Generates src/catalog/endpoints.json from the official OPNsense API reference
 * (the csv-tables of opnsense/docs, source/development/api/{core,plugins}/*.rst).
 *
 *   node scripts/build-catalog.mjs              # fetch from GitHub
 *   node scripts/build-catalog.mjs --from DIR   # parse <core|plugins>__<name>.rst files in DIR
 *
 * The HTTP method in the docs is derived by a heuristic and is sometimes wrong
 * (e.g. firewall/filter/toggle_rule_log is documented GET but requires POST), so
 * the catalog is used for discovery only. Access control never trusts it: see
 * src/opnsense/policy.ts.
 */
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const outFile = join(root, 'src', 'catalog', 'endpoints.json');
const REPO = 'opnsense/docs';
const BRANCH = 'master';

async function fetchDocs() {
  const headers = { 'User-Agent': 'osmcp-catalog-builder' };
  const treeRes = await fetch(`https://api.github.com/repos/${REPO}/git/trees/${BRANCH}?recursive=1`, { headers });
  if (!treeRes.ok) throw new Error(`GitHub tree: HTTP ${treeRes.status}`);
  const tree = await treeRes.json();
  const paths = tree.tree
    .filter((t) => t.type === 'blob' && /^source\/development\/api\/(core|plugins)\/[^/]+\.rst$/.test(t.path))
    .map((t) => t.path);
  const docs = [];
  for (let i = 0; i < paths.length; i += 12) {
    const batch = paths.slice(i, i + 12);
    const bodies = await Promise.all(
      batch.map(async (p) => {
        const res = await fetch(`https://raw.githubusercontent.com/${REPO}/${BRANCH}/${p}`, { headers });
        if (!res.ok) throw new Error(`${p}: HTTP ${res.status}`);
        return res.text();
      }),
    );
    batch.forEach((p, j) => {
      const [, kind, name] = /api\/(core|plugins)\/([^/]+)\.rst$/.exec(p);
      docs.push({ kind, name, text: bodies[j] });
    });
  }
  return docs;
}

function readLocalDocs(dir) {
  return readdirSync(dir)
    .filter((f) => /^(core|plugins)__.+\.rst$/.test(f))
    .map((f) => {
      const [, kind, name] = /^(core|plugins)__(.+)\.rst$/.exec(f);
      return { kind, name, text: readFileSync(join(dir, f), 'utf8') };
    });
}

/** Splits a csv-table row: "a","b","c" with no embedded quotes in practice. */
function parseRow(line) {
  const cells = [];
  const re = /"((?:[^"]|"")*)"/g;
  let m;
  while ((m = re.exec(line))) cells.push(m[1].replace(/""/g, '"').trim());
  return cells;
}

function parseDoc({ kind, name, text }) {
  const out = [];
  let controllerFile = null;
  /** Model files appear at the end of a table: attach them to that table's rows. */
  let tableRows = [];
  const flush = () => {
    tableRows = [];
  };
  for (const raw of text.split(/\r?\n/)) {
    const header = /^\.\.\s+csv-table::\s*(.*)$/.exec(raw);
    if (header) {
      flush();
      controllerFile = /\(([A-Za-z0-9_]+\.php)\)/.exec(header[1])?.[1] ?? null;
      continue;
    }
    const line = raw.trim();
    if (!line.startsWith('"')) continue;
    const cells = parseRow(line);
    if (cells.length < 5) continue;
    if (cells[0].includes('<<uses>>')) {
      const model = /<(https?:[^>]+\.xml)>/.exec(cells[4])?.[1];
      if (model) for (const row of tableRows) row.model = model;
      continue;
    }
    const method = /``([A-Z,*]+)``/.exec(cells[0])?.[1];
    if (!method) continue;
    const [module, controller, command] = cells.slice(1, 4);
    if (!/^[a-z0-9_]+$/i.test(module) || !/^[a-z0-9_]+$/i.test(controller) || !/^[a-z0-9_]+$/i.test(command)) continue;
    const row = {
      method,
      path: `${module}/${controller}/${command}`,
      params: cells[4]
        .split(',')
        .map((p) => p.trim())
        .filter(Boolean),
      source: kind === 'core' ? 'core' : `plugin:${name}`,
    };
    if (controllerFile) row.controller = controllerFile;
    tableRows.push(row);
    out.push(row);
  }
  return out;
}

const fromIdx = process.argv.indexOf('--from');
const docs = fromIdx > -1 ? readLocalDocs(process.argv[fromIdx + 1]) : await fetchDocs();

const seen = new Map();
for (const row of docs.flatMap(parseDoc)) {
  // The same path can be documented twice: the base-class table and the concrete one.
  if (!seen.has(row.path)) seen.set(row.path, row);
}
const endpoints = [...seen.values()].sort((a, b) => a.path.localeCompare(b.path));

mkdirSync(dirname(outFile), { recursive: true });
writeFileSync(
  outFile,
  JSON.stringify({
    source: `https://github.com/${REPO} (${BRANCH})`,
    generated: new Date().toISOString().slice(0, 10),
    count: endpoints.length,
    endpoints,
  }) + '\n',
);
console.log(`${endpoints.length} endpoints -> ${outFile}`);
