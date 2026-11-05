import { OpnsenseError } from './errors.js';

type Obj = Record<string, unknown>;

export function isObject(value: unknown): value is Obj {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isOption(value: unknown): value is { value: unknown; selected: unknown } {
  return isObject(value) && 'selected' in value && 'value' in value;
}

/** An enum field in a model form: {"pass": {"value": "Pass", "selected": 1}, ...}. */
function isOptionMap(value: Obj): boolean {
  const entries = Object.values(value);
  return entries.length > 0 && entries.every(isOption);
}

/** Replaces option maps by the selected keys, comma-separated, as the API expects them back. */
export function flattenModel(node: unknown): unknown {
  if (Array.isArray(node)) return node.map(flattenModel);
  if (!isObject(node)) return node;
  if (isOptionMap(node)) {
    return Object.entries(node)
      .filter(([, o]) => Number((o as { selected: unknown }).selected) === 1)
      .map(([k]) => k)
      .join(',');
  }
  const out: Obj = {};
  for (const [k, v] of Object.entries(node)) out[k] = flattenModel(v);
  return out;
}

export interface FieldDescription {
  current?: unknown;
  options?: Array<{ value: string; label: string }>;
  fields?: Record<string, FieldDescription>;
  options_truncated?: number;
}

const MAX_OPTIONS = 60;

/** Turns a blank model form into a schema: which fields exist and which values they accept. */
export function describeModel(node: unknown): FieldDescription {
  if (isObject(node) && isOptionMap(node)) {
    const entries = Object.entries(node);
    const options = entries.slice(0, MAX_OPTIONS).map(([value, o]) => ({ value, label: String((o as { value: unknown }).value) }));
    const selected = flattenModel(node);
    return {
      ...(selected ? { current: selected } : {}),
      options,
      ...(entries.length > MAX_OPTIONS ? { options_truncated: entries.length - MAX_OPTIONS } : {}),
    };
  }
  if (isObject(node)) {
    const fields: Record<string, FieldDescription> = {};
    for (const [k, v] of Object.entries(node)) fields[k] = describeModel(v);
    return { fields };
  }
  return node === '' || node === null || node === undefined ? {} : { current: node };
}

export interface GridArgs {
  search?: string;
  limit?: number;
  offset?: number;
  /** Extra POST fields, such as show_all or interface on firewall/filter/search_rule. */
  extra?: Obj;
}

export interface GridResult<T = Obj> {
  rows: T[];
  total: number;
  count: number;
  offset: number;
  limit: number;
  has_more: boolean;
  next_offset?: number;
}

export const DEFAULT_LIMIT = 50;
export const MAX_LIMIT = 500;

export function clampLimit(limit: number | undefined): number {
  return Math.min(Math.max(1, Math.trunc(limit ?? DEFAULT_LIMIT)), MAX_LIMIT);
}

export interface PostClient {
  post(path: string, body?: unknown): Promise<unknown>;
}

/** Calls a search endpoint and normalizes the bootgrid envelope into offset pagination. */
export async function searchGrid<T = Obj>(client: PostClient, path: string, args: GridArgs = {}): Promise<GridResult<T>> {
  const limit = clampLimit(args.limit);
  const offset = Math.max(0, Math.trunc(args.offset ?? 0));
  // Pages are aligned on rowCount: an offset that is not a multiple needs a wider read.
  const aligned = offset % limit === 0;
  const rowCount = aligned ? limit : offset + limit;
  const current = aligned ? offset / limit + 1 : 1;
  const raw = await client.post(path, { current, rowCount, searchPhrase: args.search ?? '', sort: {}, ...args.extra });
  return paginate<T>(raw, offset, limit, aligned ? 0 : offset);
}

export function paginate<T = Obj>(raw: unknown, offset: number, limit: number, skip = 0): GridResult<T> {
  const obj = isObject(raw) ? raw : {};
  const rawRows = Array.isArray(raw) ? raw : Array.isArray(obj.rows) ? obj.rows : [];
  const rows = (skip ? rawRows.slice(skip, skip + limit) : rawRows.slice(0, limit)) as T[];
  const total = typeof obj.total === 'number' ? obj.total : typeof obj.rowCount === 'number' && !Array.isArray(raw) ? obj.rowCount : rawRows.length;
  const hasMore = offset + rows.length < total;
  return { rows, total, count: rows.length, offset, limit, has_more: hasMore, ...(hasMore ? { next_offset: offset + rows.length } : {}) };
}

/** Client-side pagination, for endpoints that return everything at once. */
export function paginateArray<T>(items: T[], limit: number | undefined, offset: number | undefined): GridResult<T> {
  const l = clampLimit(limit);
  const o = Math.max(0, Math.trunc(offset ?? 0));
  const rows = items.slice(o, o + l);
  const hasMore = o + rows.length < items.length;
  return { rows, total: items.length, count: rows.length, offset: o, limit: l, has_more: hasMore, ...(hasMore ? { next_offset: o + rows.length } : {}) };
}

/** Reads every page of a search endpoint, for analyses that need the complete set. */
export async function fetchAll<T = Obj>(client: PostClient, path: string, extra?: Obj, maxRows = 20_000): Promise<T[]> {
  const raw = await client.post(path, { current: 1, rowCount: maxRows, searchPhrase: '', sort: {}, ...extra });
  const obj = isObject(raw) ? raw : {};
  return (Array.isArray(raw) ? raw : Array.isArray(obj.rows) ? obj.rows : []) as T[];
}

/** Drops display-only fields so that a listing does not spend the context on them. */
export function compactRow(row: Obj): Obj {
  const out: Obj = {};
  for (const [k, v] of Object.entries(row)) {
    if (k.startsWith('alias_meta_') || k === 'category_colors') continue;
    if (k.startsWith('%')) {
      // Keep the readable label only where it says more than the raw value (a uuid, say).
      const raw = row[k.slice(1)];
      if (typeof v === 'string' && v !== '' && typeof raw === 'string' && /^[0-9a-f-]{36}/i.test(raw)) out[`${k.slice(1)}_label`] = v;
      continue;
    }
    out[k] = v;
  }
  return out;
}

export function compactGrid<T extends GridResult>(grid: T): T {
  return { ...grid, rows: grid.rows.map(compactRow) };
}

/**
 * OPNsense reports validation failures with HTTP 200 and {"result":"failed"}, so a write
 * has to be checked by its content and not by its status code.
 */
export function assertWriteOk(result: unknown, what: string): Obj {
  const obj = isObject(result) ? result : {};
  const status = typeof obj.result === 'string' ? obj.result : typeof obj.status === 'string' ? obj.status : '';
  if (status.toLowerCase() === 'failed' || status.toLowerCase() === 'error' || isObject(obj.validations) || Array.isArray(obj.validations)) {
    const validations = obj.validations;
    throw new OpnsenseError('validation_failed', `${what} was refused by the firewall.`, {
      ...(validations !== undefined ? { details: { validations } } : { details: obj }),
      hint: 'Nothing was changed. Fix the fields listed in validations and try again. opn_describe_model lists the accepted values.',
    });
  }
  // A UserException on the firewall (say, deleting an alias that a rule uses).
  if (typeof obj.errorMessage === 'string') {
    throw new OpnsenseError('validation_failed', `${what} was refused by the firewall: ${obj.errorMessage}`, { details: obj });
  }
  if (status.toLowerCase() === 'not found') {
    throw new OpnsenseError('not_found', `${what}: the item was not found.`, { hint: 'List the items again to get a current uuid.' });
  }
  return obj;
}

const BAD_APPLY = /error|fail/i;

/** Service reconfigure actions answer {"status":"ok"}, or the output of a failed backend call. */
export function assertApplied(result: unknown, what: string, opts: { allowEmpty?: boolean } = {}): Obj {
  const obj = isObject(result) ? result : {};
  if (typeof obj.errorMessage === 'string') {
    throw new OpnsenseError('upstream_error', `${what} did not complete: ${obj.errorMessage}`, { details: obj });
  }
  const raw = obj.status ?? obj.result;
  const status = String(raw ?? '');
  if (status && BAD_APPLY.test(status)) {
    throw new OpnsenseError('upstream_error', `${what} did not complete: ${status.trim()}`, { details: obj });
  }
  // The backend answers with an empty string when it fails or times out.
  if (raw !== undefined && status.trim() === '' && !opts.allowEmpty) {
    throw new OpnsenseError('upstream_error', `${what} did not complete: the firewall backend gave no answer.`, { details: obj });
  }
  return obj;
}

/** For actions that must report success in so many words: anything else, even no error, is a failure. */
export function assertOk(result: unknown, what: string): Obj {
  const obj = isObject(result) ? result : {};
  const status = String(obj.status ?? obj.result ?? '').trim();
  if (status.toLowerCase() !== 'ok') {
    throw new OpnsenseError('upstream_error', `${what} did not report success: ${status || 'the firewall backend gave no answer'}.`, { details: obj });
  }
  return obj;
}

/** Booleans to the "1"/"0" the models expect, leaving undefined fields out. */
export function modelFields(input: Obj): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(input)) {
    if (v === undefined || v === null) continue;
    if (typeof v === 'boolean') out[k] = v ? '1' : '0';
    else if (Array.isArray(v)) out[k] = v.join(',');
    else out[k] = String(v);
  }
  return out;
}
