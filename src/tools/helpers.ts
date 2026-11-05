import { z } from 'zod';
import type { InstanceConfig, ServerConfig } from '../config.js';
import type { ChangeManager, ChangeScope } from '../opnsense/changes.js';
import type { DryRunEntry, OpnsenseClient, RequestOptions } from '../opnsense/client.js';
import { OpnsenseError } from '../opnsense/errors.js';
import { assertApplied, assertWriteOk, compactGrid, flattenModel, isObject, modelFields, searchGrid } from '../opnsense/model.js';

/** Tools are grouped by domain, one file per domain, and can be filtered with OPNSENSE_TOOLSETS. */
export const DOMAINS = ['system', 'network', 'firewall', 'nat', 'dns', 'dhcp', 'vpn', 'services', 'haproxy', 'diagnostics', 'security', 'api'] as const;
export type Domain = (typeof DOMAINS)[number];

/**
 * read: never changes anything, and announces readOnlyHint so that clients can auto-approve it.
 * write: changes something additively or reversibly.
 * destructive: removes something or cuts traffic. Asks a human first when the client can.
 */
export type Access = 'read' | 'write' | 'destructive';

/** Curated view of the client: adds the per-call dry-run, and marks the call as coming from a dedicated tool. */
export class ScopedApi {
  constructor(
    private readonly client: OpnsenseClient,
    private readonly defaults: RequestOptions,
  ) {}

  get(path: string, opts: RequestOptions = {}): Promise<unknown> {
    return this.client.get(path, { ...this.defaults, ...opts });
  }

  post(path: string, body?: unknown, opts: RequestOptions = {}): Promise<unknown> {
    return this.client.post(path, body, { ...this.defaults, ...opts });
  }
}

export interface ToolContext {
  /** For dedicated tools: their paths are written in the code. */
  api: ScopedApi;
  /** For tools that take the path as an argument. Curated-only endpoints stay out of reach. */
  generic: ScopedApi;
  /** The underlying client, for helpers that only read a fixed set of endpoints. */
  client: OpnsenseClient;
  instance: InstanceConfig;
  server: ServerConfig;
  changes: ChangeManager;
  dryRun: boolean;
  dryRunLog: DryRunEntry[];
}

export interface ToolDef {
  name: string;
  title: string;
  description: string;
  domain: Domain;
  access: Access;
  idempotent?: boolean;
  /** The tool reaches beyond the firewall itself (ping, DNS lookup...). */
  openWorld?: boolean;
  /** Other domains that need this tool, for OPNSENSE_TOOLSETS. */
  also?: Domain[];
  input: z.ZodRawShape;
  /** Message for the human, when access is destructive and the client supports elicitation. */
  confirmation?: (args: Record<string, unknown>) => string;
  handler: (args: Record<string, unknown>, ctx: ToolContext) => Promise<unknown>;
}

export function tool<S extends z.ZodRawShape>(def: Omit<ToolDef, 'input' | 'handler' | 'confirmation'> & {
  input: S;
  confirmation?: (args: z.infer<z.ZodObject<S>>) => string;
  handler: (args: z.infer<z.ZodObject<S>>, ctx: ToolContext) => Promise<unknown>;
}): ToolDef {
  return def as unknown as ToolDef;
}

export const paging = {
  search: z.string().optional().describe('Text to look for in any field.'),
  limit: z.number().int().min(1).max(500).optional().describe('Rows per page (default 50, at most 500).'),
  offset: z.number().int().min(0).optional().describe('Rows to skip. Use next_offset from the previous page.'),
};

export const uuid = z.string().regex(/^[0-9a-fA-F-]{36}$/, 'Expected a uuid').describe('Item uuid, from the matching list tool.');

export function requireFields(values: Record<string, unknown>, what: string): void {
  if (Object.keys(values).length === 0) {
    throw new OpnsenseError('invalid_input', `${what}: no field to change was given.`);
  }
}

/** Removes undefined and empty values, so that listings do not spend the context on them. */
export function sparse(row: unknown): unknown {
  if (Array.isArray(row)) return row.map(sparse);
  if (!isObject(row)) return row;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(row)) {
    if (v === '' || v === null || v === undefined) continue;
    if (Array.isArray(v) && v.length === 0) continue;
    out[k] = v;
  }
  return out;
}

/**
 * Runs a firewall write as part of the current change. The baseline is taken before the
 * first write, because afterwards it would already contain the change.
 */
export async function stagedWrite(ctx: ToolContext, scope: ChangeScope, action: string, summary: string, write: () => Promise<unknown>, what: string): Promise<Record<string, unknown>> {
  if (!ctx.dryRun) await ctx.changes.beginIfNeeded();
  try {
    const res = assertWriteOk(await (ctx.dryRun ? write() : ctx.changes.trackWrite(write)), what);
    const entryUuid = typeof res.uuid === 'string' ? res.uuid : undefined;
    if (!ctx.dryRun) ctx.changes.record({ action, scope, summary, ...(entryUuid ? { uuid: entryUuid } : {}) });
    return {
      ...res,
      applied: false,
      next_step: 'Staged, not live yet. When all changes are staged, call opn_apply_firewall_changes.',
      protection: ctx.dryRun ? 'dry-run' : ctx.changes.protectionAvailable(),
    };
  } catch (err) {
    ctx.changes.discardIfEmpty();
    throw err;
  }
}

/** Runs a write to a service that has no rollback timer: it goes live on reconfigure. */
export async function serviceWrite(ctx: ToolContext, write: () => Promise<unknown>, what: string, reconfigure: string[], apply: boolean): Promise<Record<string, unknown>> {
  const before = ctx.dryRun ? undefined : await ctx.changes.latestBackup().catch(() => undefined);
  const res = assertWriteOk(await write(), what);
  const out: Record<string, unknown> = { ...res };
  if (reconfigure.length === 0) {
    // The call itself took effect: there is no separate step.
    out.applied = true;
  } else if (apply) {
    for (const path of reconfigure) assertApplied(await ctx.api.post(path), `${what}: ${path}`);
    out.applied = true;
  } else {
    out.applied = false;
    out.next_step = `Saved, not live yet. Reconfigure with: ${reconfigure.join(', ')}`;
  }
  if (before) out.revert_with = { tool: 'opn_restore_config_backup', backup: before, note: 'This change has no automatic rollback. This backup is the configuration just before it.' };
  return out;
}

export interface CrudSpec {
  domain: Domain;
  singular: string;
  plural: string;
  label: string;
  base: string;
  commands: { search: string; get: string; add?: string; set?: string; del?: string; toggle?: string };
  /** Name of the object wrapping the fields in POST bodies, such as "host" in {"host": {...}}. */
  wrapper: string;
  /** Writable fields. Everything is optional at this level: `required` applies to add. */
  fields?: z.ZodRawShape;
  required?: string[];
  /** Translates tool arguments to model fields. Default: booleans become "1"/"0". */
  toModel?: (args: Record<string, unknown>) => Record<string, unknown>;
  /** Firewall objects are staged and go live through opn_apply_firewall_changes. */
  staged?: ChangeScope;
  /** Service reconfigure endpoints, called after each write unless apply=false. */
  reconfigure?: string[];
  listNote?: string;
  writeNote?: string;
  /** toggle takes "disabled" instead of "enabled". */
  invertedToggle?: boolean;
  /**
   * The toggle endpoint ignores any state it is given and just flips it, so a repeated call
   * would undo itself. With this set, the state is read first: see flipTo.
   */
  toggleFlips?: boolean;
  /** Fields the update tool must receive as well, because the controller misreads their absence. */
  updateRequires?: string[];
  /** Runs after a write, to report anything that keeps the change from having an effect. */
  warnOnWrite?: (ctx: ToolContext) => Promise<string | undefined>;
}

/**
 * For toggle endpoints that take no state: reads the current one, and only flips when it
 * differs, so that asking for the same state twice changes nothing.
 */
export async function flipTo(ctx: ToolContext, getPath: string, wrapper: string, uuid: string, enabled: boolean, what: string, flip: () => Promise<Record<string, unknown>>): Promise<Record<string, unknown>> {
  const res = await ctx.api.get(getPath, { params: [uuid] });
  const item = isObject(res) ? res[wrapper] : undefined;
  if (!isObject(item)) throw new OpnsenseError('not_found', `${what}: the item was not found, so nothing was changed.`, { hint: 'List the items again to get a current uuid.' });
  const current = String(item.enabled ?? '');
  if (current !== '0' && current !== '1') throw new OpnsenseError('bad_response', `${what}: the current state is unreadable, so nothing was changed.`, { details: { enabled: item.enabled ?? null } });
  if ((current === '1') === enabled) return { changed: false, enabled, note: 'Already in this state: nothing was sent.' };
  return { changed: true, enabled, ...(await flip()) };
}

function pickFields(args: Record<string, unknown>, fields: z.ZodRawShape): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(fields)) {
    if (args[key] !== undefined) out[key] = args[key];
  }
  return out;
}

/** Makes an optional field required, keeping its description: unwrap() would lose it. */
function requiredField(field: unknown): z.ZodType {
  const f = field as z.ZodType & { unwrap?: () => z.ZodType };
  const inner = f.unwrap?.() ?? f;
  return f.description ? inner.describe(f.description) : inner;
}

/** The usual list/get/add/update/delete/toggle set for one kind of model item: one tool per request. */
export function crudTools(spec: CrudSpec): ToolDef[] {
  const defs: ToolDef[] = [];
  const { commands: c, base, label, domain } = spec;
  const toModel = spec.toModel ?? modelFields;
  const applyParam: z.ZodRawShape = spec.reconfigure ? { apply: z.boolean().optional().describe('Reconfigure the service right away (default true).') } : {};
  const writeNote = spec.writeNote ? ` ${spec.writeNote}` : spec.staged ? ' Staged: nothing changes until opn_apply_firewall_changes.' : '';

  async function commit(ctx: ToolContext, args: Record<string, unknown>, action: string, summary: string, write: () => Promise<unknown>, what: string) {
    const out = spec.staged ? await stagedWrite(ctx, spec.staged, action, summary, write, what) : await serviceWrite(ctx, write, what, spec.reconfigure ?? [], args.apply !== false && Boolean(spec.reconfigure));
    const warning = await spec.warnOnWrite?.(ctx);
    return warning ? { ...out, warning } : out;
  }

  defs.push(tool({
    name: `opn_list_${spec.plural}`,
    title: `List ${label}s`,
    description: `List ${label}s, with pagination.${spec.listNote ? ` ${spec.listNote}` : ''}`,
    domain,
    access: 'read',
    idempotent: true,
    input: paging,
    handler: async (args, ctx) => {
      const grid = await searchGrid(ctx.api, `${base}/${c.search}`, args);
      return compactGrid(grid);
    },
  }));

  defs.push(tool({
    name: `opn_get_${spec.singular}`,
    title: `Get ${label}`,
    description: `Get every field of one ${label}, by uuid. Enum fields show the selected value.`,
    domain,
    access: 'read',
    idempotent: true,
    input: { uuid },
    handler: async (args, ctx) => {
      const res = await ctx.api.get(`${base}/${c.get}`, { params: [args.uuid] });
      const item = isObject(res) ? res[spec.wrapper] ?? res : res;
      return { uuid: args.uuid, item: flattenModel(item) };
    },
  }));

  if (c.add && spec.fields) {
    const add = c.add;
    const shape: Record<string, z.ZodType> = {};
    for (const [k, v] of Object.entries(spec.fields)) {
      shape[k] = spec.required?.includes(k) ? requiredField(v) : (v as z.ZodType);
    }
    defs.push(tool({
      name: `opn_add_${spec.singular}`,
      title: `Add ${label}`,
      description: `Create a ${label}.${writeNote}`,
      domain,
      access: 'write',
      input: { ...shape, ...applyParam },
      handler: async (args, ctx) => {
        const fields = toModel(pickFields(args, spec.fields!));
        return commit(ctx, args, 'add', `add ${label}: ${JSON.stringify(fields).slice(0, 200)}`, () => ctx.api.post(`${base}/${add}`, { [spec.wrapper]: fields }), `Creating the ${label}`);
      },
    }));
  }

  if (c.set && spec.fields) {
    const set = c.set;
    const updateShape: Record<string, z.ZodType> = {};
    for (const [k, v] of Object.entries(spec.fields)) {
      updateShape[k] = spec.updateRequires?.includes(k) ? requiredField(v) : (v as z.ZodType);
    }
    defs.push(tool({
      name: `opn_update_${spec.singular}`,
      title: `Update ${label}`,
      description: `Change fields of a ${label}. Fields left out keep their value.${writeNote}`,
      domain,
      access: 'write',
      idempotent: true,
      input: { uuid, ...updateShape, ...applyParam },
      handler: async (args, ctx) => {
        const fields = toModel(pickFields(args, spec.fields!));
        requireFields(fields, `Updating the ${label}`);
        return commit(ctx, args, 'update', `update ${label} ${args.uuid}: ${JSON.stringify(fields).slice(0, 200)}`, () => ctx.api.post(`${base}/${set}`, { [spec.wrapper]: fields }, { params: [args.uuid as string] }), `Updating the ${label}`);
      },
    }));
  }

  if (c.del) {
    const del = c.del;
    defs.push(tool({
      name: `opn_delete_${spec.singular}`,
      title: `Delete ${label}`,
      description: `Delete a ${label}.${writeNote}`,
      domain,
      access: 'destructive',
      idempotent: true,
      input: { uuid, ...applyParam },
      confirmation: (args) => `Delete ${label} ${args.uuid}?`,
      handler: async (args, ctx) =>
        commit(ctx, args, 'delete', `delete ${label} ${args.uuid}`, () => ctx.api.post(`${base}/${del}`, undefined, { params: [args.uuid as string] }), `Deleting the ${label}`),
    }));
  }

  if (c.toggle) {
    const toggle = c.toggle;
    defs.push(tool({
      name: `opn_toggle_${spec.singular}`,
      title: `Enable or disable ${label}`,
      description: `Enable or disable a ${label}. The state is explicit: repeating the call changes nothing.${writeNote}`,
      domain,
      access: 'write',
      idempotent: true,
      input: { uuid, enabled: z.boolean().describe('The state wanted.'), ...applyParam },
      handler: async (args, ctx) => {
        const summary = `${args.enabled ? 'enable' : 'disable'} ${label} ${args.uuid}`;
        const params = [args.uuid as string];
        if (spec.toggleFlips) {
          return flipTo(ctx, `${base}/${c.get}`, spec.wrapper, args.uuid as string, args.enabled as boolean, `Changing the ${label}`, () =>
            commit(ctx, args, 'toggle', summary, () => ctx.api.post(`${base}/${toggle}`, undefined, { params }), `Changing the ${label}`));
        }
        const value = (spec.invertedToggle ? !args.enabled : args.enabled) ? '1' : '0';
        return commit(ctx, args, 'toggle', summary, () => ctx.api.post(`${base}/${toggle}`, undefined, { params: [...params, value] }), `Changing the ${label}`);
      },
    }));
  }

  return defs;
}

/** Reads several endpoints where each may be missing or forbidden, and reports which ones were. */
export async function gather<T extends Record<string, () => Promise<unknown>>>(sources: T): Promise<{ data: { [K in keyof T]?: unknown }; unavailable: Record<string, string> }> {
  const keys = Object.keys(sources) as Array<keyof T>;
  const results = await Promise.allSettled(keys.map((k) => sources[k]!()));
  const data: { [K in keyof T]?: unknown } = {};
  const unavailable: Record<string, string> = {};
  results.forEach((r, i) => {
    const key = keys[i]!;
    if (r.status === 'fulfilled') data[key] = r.value;
    else unavailable[String(key)] = r.reason instanceof OpnsenseError ? `${r.reason.type}: ${r.reason.message}` : String(r.reason);
  });
  return { data, unavailable };
}
