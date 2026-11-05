import { isIP } from 'node:net';
import { z } from 'zod';
import { OpnsenseError } from '../opnsense/errors.js';
import { assertApplied, assertWriteOk, compactGrid, flattenModel, isObject, modelFields, searchGrid } from '../opnsense/model.js';
import { crudTools, paging, serviceWrite, tool, uuid, type ToolContext, type ToolDef } from './helpers.js';

const RECONFIGURE = ['unbound/service/reconfigure'];

/** A blocklist change needs the lists to be regenerated before Unbound reloads them. */
const DNSBL_RECONFIGURE = ['unbound/service/dnsbl', 'unbound/service/reconfigure'];

const domainList = z.array(z.string().regex(/^[A-Za-z0-9*._-]+$/, 'Expected a domain name').max(253)).min(1).describe('Domain names.');

const dnsblFields = {
  enabled: z.boolean().optional().describe('Enable this blocklist policy.'),
  type: z.array(z.string()).optional().describe('Predefined list ids to use. opn_describe_model on unbound/settings/get_dnsbl lists them.'),
  lists: z.array(z.string()).optional().describe('URLs of extra blocklists.'),
  allowlists: z.array(z.string()).optional().describe('Domains never to block. opn_add_dnsbl_allowlist keeps what is already there, this replaces it.'),
  blocklists: z.array(z.string()).optional().describe('Domains to block in addition to the lists.'),
  wildcards: z.array(z.string()).optional().describe('Domains to block along with all their subdomains.'),
  source_nets: z.array(z.string()).optional().describe('Networks this policy applies to. Empty means all.'),
  address: z.string().optional().describe('Address to answer with for blocked names. Empty means the default.'),
  nxdomain: z.boolean().optional().describe('Answer NXDOMAIN rather than an address.'),
  cache_ttl: z.number().int().min(0).optional().describe('TTL of block answers, in seconds.'),
  description: z.string().optional().describe('Free-text description.'),
};

function splitList(value: unknown): string[] {
  return String(value ?? '').split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
}

async function readAllowlist(ctx: ToolContext, id: string): Promise<string[]> {
  const res = await ctx.api.get('unbound/settings/get_dnsbl', { params: [id] });
  const form = isObject(res) ? res.blocklist : undefined;
  if (!isObject(form)) throw new OpnsenseError('not_found', `DNSBL policy ${id} was not found.`, { hint: 'opn_list_dnsbl lists the policies.' });
  // A CSVListField comes back as an option map, plain text on older versions as a string.
  return splitList(flattenModel(form.allowlists));
}

function writeAllowlist(ctx: ToolContext, id: string, entries: string[], what: string): Promise<Record<string, unknown>> {
  // These are CSVListFields: a newline would make the whole value fail their per-item mask.
  return serviceWrite(ctx, () => ctx.api.post('unbound/settings/set_dnsbl', { blocklist: { allowlists: entries.join(',') } }, { params: [id] }), what, DNSBL_RECONFIGURE, true);
}

const forwardFields = {
  domain: z.string().optional().describe('Domain to forward. Empty forwards everything.'),
  server: z.string().optional().describe('Address of the upstream server.'),
  port: z.number().int().min(1).max(65535).optional().describe('Upstream port.'),
  forward_tcp_upstream: z.boolean().optional().describe('Use TCP to reach this server.'),
  forward_first: z.boolean().optional().describe('Fall back to direct resolution when the forward fails.'),
  description: z.string().optional().describe('Free-text description.'),
  enabled: z.boolean().optional().describe('Default true on creation.'),
};

export function dnsTools(): ToolDef[] {
  return [
    ...crudTools({
      domain: 'dns',
      singular: 'dns_override',
      plural: 'dns_overrides',
      label: 'DNS host override',
      base: 'unbound/settings',
      commands: { search: 'search_host_override', get: 'get_host_override', add: 'add_host_override', set: 'set_host_override', del: 'del_host_override', toggle: 'toggle_host_override' },
      wrapper: 'host',
      fields: {
        hostname: z.string().optional().describe('Host part. Use * for a wildcard.'),
        domain: z.string().optional().describe('Domain part.'),
        rr: z.enum(['A', 'AAAA', 'MX', 'TXT']).optional().describe('Record type.'),
        server: z.string().optional().describe('Address to answer with, for A and AAAA.'),
        mx: z.string().optional().describe('Mail host, for MX.'),
        mxprio: z.number().int().min(0).optional().describe('Priority, for MX.'),
        txtdata: z.string().optional().describe('Content, for TXT.'),
        ttl: z.number().int().min(0).optional().describe('TTL in seconds.'),
        addptr: z.boolean().optional().describe('Also answer the reverse lookup.'),
        description: z.string().optional().describe('Free-text description.'),
        enabled: z.boolean().optional().describe('Default true on creation.'),
      },
      required: ['domain', 'rr'],
      reconfigure: RECONFIGURE,
      writeNote: 'Goes live when Unbound reconfigures, with no rollback timer.',
    }),
    ...crudTools({
      domain: 'dns',
      singular: 'dns_forward',
      plural: 'dns_forwards',
      label: 'DNS forward',
      base: 'unbound/settings',
      commands: { search: 'search_forward', get: 'get_forward', add: 'add_forward', set: 'set_forward', del: 'del_forward', toggle: 'toggle_forward' },
      wrapper: 'dot',
      fields: forwardFields,
      required: ['server'],
      reconfigure: RECONFIGURE,
      listNote: 'DNS over TLS servers are listed separately: see opn_list_dot_servers.',
      writeNote: 'Goes live when Unbound reconfigures, with no rollback timer. A wrong forward can break name resolution for the whole network.',
    }),
    // Same model as the forwards: the firewall tells them apart by the endpoint used, and each sets the type.
    ...crudTools({
      domain: 'dns',
      singular: 'dot_server',
      plural: 'dot_servers',
      label: 'DNS over TLS server',
      base: 'unbound/settings',
      commands: { search: 'search_dot', get: 'get_dot', add: 'add_dot', set: 'set_dot', del: 'del_dot', toggle: 'toggle_dot' },
      wrapper: 'dot',
      fields: { ...forwardFields, verify: z.string().optional().describe('Name to verify on the certificate of the server.') },
      required: ['server'],
      reconfigure: RECONFIGURE,
      writeNote: 'Goes live when Unbound reconfigures, with no rollback timer. A wrong server can break name resolution for the whole network.',
    }),
    tool({
      name: 'opn_list_dns_host_aliases',
      title: 'List DNS host aliases',
      description: 'Additional names pointing at a DNS host override.',
      domain: 'dns',
      access: 'read',
      idempotent: true,
      input: paging,
      handler: async (args, ctx) => compactGrid(await searchGrid(ctx.api, 'unbound/settings/search_host_alias', args)),
    }),
    tool({
      name: 'opn_list_dns_acls',
      title: 'List DNS access lists',
      description: 'Unbound access lists: which networks may query the resolver.',
      domain: 'dns',
      access: 'read',
      idempotent: true,
      input: paging,
      handler: async (args, ctx) => compactGrid(await searchGrid(ctx.api, 'unbound/settings/search_acl', args)),
    }),
    tool({
      name: 'opn_dns_stats',
      title: 'DNS resolver statistics',
      description: 'Unbound counters: queries, cache hits, answers by type. They restart from zero when Unbound restarts.',
      domain: 'dns',
      access: 'read',
      idempotent: true,
      input: {},
      handler: async (_args, ctx) => ctx.api.get('unbound/diagnostics/stats'),
    }),
    tool({
      name: 'opn_dns_top_domains',
      title: 'Top DNS domains',
      description: 'Query totals and the most queried and most blocked domains. Needs Unbound reporting to be enabled in Reporting > Settings.',
      domain: 'dns',
      access: 'read',
      idempotent: true,
      input: { count: z.number().int().min(1).max(1000).optional().describe('Domains per list (default 10).') },
      handler: async (args, ctx) => ctx.api.get('unbound/overview/totals', { params: [args.count ?? 10] }),
    }),
    tool({
      name: 'opn_dns_query_log',
      title: 'DNS query log',
      description: 'Queries with client, domain, answer and whether they were blocked: the latest 1000, or those of one client over a time window. Needs Unbound reporting to be enabled. No entry does not prove a name was not queried: clients can cache, and other resolvers exist.',
      domain: 'dns',
      access: 'read',
      idempotent: true,
      input: {
        ...paging,
        client: z.string().refine((v) => isIP(v) !== 0, 'Expected an IP address').optional().describe('Only this client IP address.'),
        since_hours: z.number().int().min(1).max(8760).optional().describe('With client: how far back to look, in hours (default 24).'),
      },
      handler: async (args, ctx) => {
        // The firewall ignores client unless it also gets a time window, as JSON integers.
        const now = Math.floor(Date.now() / 1000);
        const extra = args.client ? { client: args.client, timeStart: now - (args.since_hours ?? 24) * 3600, timeEnd: now } : {};
        return compactGrid(await searchGrid(ctx.api, 'unbound/overview/search_queries', { ...args, extra }));
      },
    }),
    tool({
      name: 'opn_reconfigure_unbound',
      title: 'Reconfigure Unbound',
      description: 'Regenerates the Unbound configuration and restarts it: applies changes saved with apply=false. DNS can be briefly unavailable, and the cache is lost.',
      domain: 'dns',
      access: 'write',
      idempotent: true,
      input: {},
      handler: async (_args, ctx) => assertApplied(await ctx.api.post('unbound/service/reconfigure'), 'Reconfiguring Unbound'),
    }),

    // ---- DNS blocklists ----
    tool({
      name: 'opn_list_dnsbl',
      title: 'List DNS blocklists',
      description: 'DNS blocklist policies, with the lists they use and the networks they apply to.',
      domain: 'dns',
      access: 'read',
      idempotent: true,
      input: paging,
      handler: async (args, ctx) => compactGrid(await searchGrid(ctx.api, 'unbound/settings/search_dnsbl', args)),
    }),
    tool({
      name: 'opn_get_dnsbl',
      title: 'Get DNS blocklist',
      description: 'Every field of one DNS blocklist policy, including its allowlist.',
      domain: 'dns',
      access: 'read',
      idempotent: true,
      input: { uuid },
      handler: async (args, ctx) => {
        const res = await ctx.api.get('unbound/settings/get_dnsbl', { params: [args.uuid] });
        return { uuid: args.uuid, blocklist: flattenModel(isObject(res) ? res.blocklist ?? res : res) };
      },
    }),
    tool({
      name: 'opn_test_dnsbl',
      title: 'Test a domain against the blocklists',
      description: 'Checks whether a DNS blocklist would block a domain, and because of which list. Use this before allowlisting.',
      domain: 'dns',
      access: 'read',
      idempotent: true,
      input: {
        domain: z.string().regex(/^[A-Za-z0-9._-]+$/, 'Expected a domain name').describe('Domain to test.'),
        source: z.string().optional().describe('Client address, since policies can apply to some networks only.'),
      },
      handler: async (args, ctx) => ctx.api.post('unbound/diagnostics/test_blocklist', { domain: args.domain, ...(args.source ? { src: args.source } : {}) }),
    }),
    tool({
      name: 'opn_set_dnsbl',
      title: 'Update DNS blocklist',
      description: 'Changes a blocklist policy. Fields left out keep their value; a list given here replaces the existing one. Regenerates the lists and reloads Unbound, which flushes the DNS cache.',
      domain: 'dns',
      access: 'write',
      idempotent: true,
      input: { uuid, ...dnsblFields },
      handler: async (args, ctx) => {
        const { uuid: id, ...rest } = args;
        const fields = modelFields(rest);
        if (Object.keys(fields).length === 0) throw new OpnsenseError('invalid_input', 'Updating the blocklist: no field to change was given.');
        return serviceWrite(ctx, () => ctx.api.post('unbound/settings/set_dnsbl', { blocklist: fields }, { params: [id] }), 'Updating the blocklist', DNSBL_RECONFIGURE, true);
      },
    }),
    tool({
      name: 'opn_add_dnsbl_allowlist',
      title: 'Allow domains in a DNS blocklist',
      description: 'Adds domains to the allowlist of a policy, keeping what is already there. Regenerates the lists and reloads Unbound, which flushes the DNS cache.',
      domain: 'dns',
      access: 'write',
      idempotent: true,
      input: { uuid, domains: domainList },
      handler: async (args, ctx) => {
        const existing = await readAllowlist(ctx, args.uuid);
        const added = args.domains.filter((d) => !existing.includes(d));
        if (added.length === 0) return { status: 'unchanged', added: [], allowlist: existing };
        const merged = [...existing, ...added];
        return { ...(await writeAllowlist(ctx, args.uuid, merged, 'Updating the allowlist')), added, allowlist: merged };
      },
    }),
    tool({
      name: 'opn_remove_dnsbl_allowlist',
      title: 'Remove domains from a DNS allowlist',
      description: 'Removes domains from the allowlist of a policy, so they can be blocked again. Regenerates the lists and reloads Unbound, which flushes the DNS cache.',
      domain: 'dns',
      access: 'destructive',
      idempotent: true,
      input: { uuid, domains: domainList },
      confirmation: (args) => `Remove ${args.domains.join(', ')} from the DNS allowlist?`,
      handler: async (args, ctx) => {
        const existing = await readAllowlist(ctx, args.uuid);
        const kept = existing.filter((d) => !args.domains.includes(d));
        const removed = existing.filter((d) => args.domains.includes(d));
        if (removed.length === 0) return { status: 'unchanged', removed: [], allowlist: existing };
        return { ...(await writeAllowlist(ctx, args.uuid, kept, 'Updating the allowlist')), removed, allowlist: kept };
      },
    }),
    tool({
      name: 'opn_update_dnsbl',
      title: 'Refresh DNS blocklists',
      description: 'Downloads and regenerates the blocklists, then reloads Unbound. This flushes the DNS cache. Changes no setting.',
      domain: 'dns',
      access: 'write',
      idempotent: true,
      openWorld: true,
      input: {},
      handler: async (_args, ctx) => {
        const dnsbl = assertWriteOk(await ctx.api.post('unbound/service/dnsbl', undefined, { timeoutMs: 300_000 }), 'Regenerating the blocklists');
        const service = assertApplied(await ctx.api.post('unbound/service/reconfigure'), 'Reloading Unbound');
        return { dnsbl_status: dnsbl.status ?? dnsbl, service_status: service.status ?? service };
      },
    }),
  ];
}
