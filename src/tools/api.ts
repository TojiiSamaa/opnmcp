import { z } from 'zod';
import catalogFile from '../catalog/endpoints.json' with { type: 'json' };
import { OpnsenseError } from '../opnsense/errors.js';
import { describeModel, isObject } from '../opnsense/model.js';
import { decide } from '../opnsense/policy.js';
import { tool, type ToolDef } from './helpers.js';

interface CatalogEntry {
  method: string;
  path: string;
  params?: string[];
  source: string;
  controller?: string;
  model?: string;
}

const path = z
  .string()
  .regex(/^[A-Za-z0-9_.,:/-]+$/, 'Expected a path such as firewall/filter/search_rule')
  .describe('Path below /api, such as firewall/filter/search_rule. Extra segments (a uuid) go at the end.');

const query = z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional().describe('Query string parameters.');
const body = z.record(z.string(), z.unknown()).optional().describe('JSON body, for POST.');

export function apiTools(): ToolDef[] {
  const catalog = (catalogFile as { endpoints: CatalogEntry[] }).endpoints;

  return [
    tool({
      name: 'opn_search_api',
      title: 'Search the OPNsense API',
      description: `Searches the catalog of ${catalog.length} OPNsense endpoints, core and plugins, for what no dedicated tool covers. Each result says how this server treats it: read, write or blocked. Prefer a dedicated tool when one exists. The catalog comes from the documentation: an endpoint may be missing on this firewall, or need a plugin.`,
      domain: 'api',
      access: 'read',
      idempotent: true,
      input: {
        query: z.string().min(2).describe('Words that must all appear in the path, such as "wireguard client" or "vip".'),
        source: z.string().optional().describe('Only "core", or one plugin such as "plugin:haproxy".'),
        limit: z.number().int().min(1).max(200).optional().describe('Results (default 40).'),
      },
      handler: async (args) => {
        const words = args.query.toLowerCase().split(/\s+/).filter(Boolean);
        const hits = catalog.filter((e) => {
          if (args.source && e.source !== args.source) return false;
          const haystack = `${e.path} ${e.source}`.toLowerCase();
          return words.every((w) => haystack.includes(w));
        });
        const limit = args.limit ?? 40;
        return {
          total: hits.length,
          truncated: hits.length > limit,
          results: hits.slice(0, limit).map((e) => {
            const method = e.method.includes('POST') ? 'POST' : 'GET';
            const decision = decide(e.path, method);
            return {
              path: e.path,
              method: e.method,
              params: e.params?.length ? e.params : undefined,
              source: e.source,
              access: decision.blocked ? 'blocked' : decision.access,
              ...(decision.sensitive ? { sensitive: true } : {}),
            };
          }),
        };
      },
    }),
    tool({
      name: 'opn_describe_model',
      title: 'Describe a model',
      description: 'Shows which fields an object accepts, with the allowed values of each enum, as this firewall reports them. Point it at a get endpoint without uuid to get a blank form: firewall/filter/get_rule, unbound/settings/get_host_override. Use this before a write that failed validation.',
      domain: 'api',
      access: 'read',
      idempotent: true,
      input: { path: path.describe('A get endpoint, such as firewall/filter/get_rule.') },
      handler: async (args, ctx) => {
        const res = await ctx.generic.get(args.path);
        if (!isObject(res)) throw new OpnsenseError('bad_response', `${args.path} did not return a model.`, { hint: 'Point this at a get endpoint such as firewall/filter/get_rule.' });
        return { path: args.path, ...describeModel(res) };
      },
    }),
    tool({
      name: 'opn_api_read',
      title: 'Read any API endpoint',
      description: 'Calls an endpoint that only reads, for what no dedicated tool covers. Find it with opn_search_api. Endpoints this server cannot prove to be read-only are refused, whatever the HTTP method: use opn_api_write for those. Secrets are redacted.',
      domain: 'api',
      access: 'read',
      input: {
        path,
        method: z.enum(['GET', 'POST']).optional().describe('Default GET. Search endpoints take POST with paging fields in the body.'),
        query,
        body,
      },
      handler: async (args, ctx) => {
        const opts = args.query ? { query: args.query } : {};
        return wrap(args.method === 'POST' ? await ctx.generic.post(args.path, args.body, opts) : await ctx.generic.get(args.path, opts));
      },
    }),
    tool({
      name: 'opn_api_write',
      title: 'Write to any API endpoint',
      description: 'Calls an endpoint that changes something, for what no dedicated tool covers. Find it with opn_search_api. IMMEDIATE: it is outside the staged change workflow, has no rollback timer and no lockout check, and most endpoints also need their reconfigure call. Blocked endpoints stay blocked. Prefer a dedicated tool whenever one exists.',
      domain: 'api',
      access: 'destructive',
      input: {
        path,
        method: z.enum(['GET', 'POST']).optional().describe('Default POST.'),
        query,
        body,
      },
      confirmation: (args) => `Call ${args.method ?? 'POST'} ${args.path} on the firewall? There is no rollback for this.`,
      handler: async (args, ctx) => {
        const opts = args.query ? { query: args.query } : {};
        return wrap(args.method === 'GET' ? await ctx.generic.get(args.path, opts) : await ctx.generic.post(args.path, args.body, opts));
      },
    }),
  ];
}

/** Some endpoints answer with a bare list or a scalar: the tool result is always an object. */
function wrap(res: unknown): Record<string, unknown> {
  return isObject(res) ? res : { result: res };
}
