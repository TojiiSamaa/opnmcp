import { isIP } from 'node:net';
import { setTimeout as sleep } from 'node:timers/promises';
import { z } from 'zod';
import { OpnsenseError } from '../opnsense/errors.js';
import { assertWriteOk, fetchAll, isObject, paginateArray } from '../opnsense/model.js';
import { matchLiteral } from '../opnsense/simulate.js';
import { gather, tool, type ToolContext, type ToolDef } from './helpers.js';

const hostname = z
  .string()
  .regex(/^[A-Za-z0-9.:_-]+$/, 'Expected a host name or an address')
  .refine((v) => !v.startsWith('-'), 'Expected a host name or an address')
  .describe('Host name or IP address.');

const family = z.enum(['inet', 'inet6']).optional().describe('inet = IPv4 (default), inet6 = IPv6.');
const address = z.string().refine((v) => isIP(v) !== 0, 'Expected an IP address');

const PING_TIMEOUT_MS = 30_000;
const PING_POLL_MS = 1_000;

/**
 * A ping is a job on the firewall: create it, start it, poll the counters, stop and remove it.
 * The model has no packet count, so the job runs until the wanted number of packets went out.
 */
async function runPing(ctx: ToolContext, args: { hostname: string; count: number; family?: 'inet' | 'inet6'; source_address?: string }): Promise<Record<string, unknown>> {
  const settings = {
    hostname: args.hostname,
    ...(args.family ? { fam: args.family === 'inet6' ? 'ip6' : 'ip' } : {}),
    ...(args.source_address ? { source_address: args.source_address } : {}),
  };
  const created = assertWriteOk(await ctx.api.post('diagnostics/ping/set', { ping: { settings } }), 'Creating the ping');
  const jobId = String(created.uuid ?? '');
  if (!jobId) throw new OpnsenseError('bad_response', 'The firewall did not return a ping job id.', { details: created });

  try {
    assertWriteOk(await ctx.api.post('diagnostics/ping/start', undefined, { params: [jobId] }), 'Starting the ping');
    const deadline = Date.now() + PING_TIMEOUT_MS;
    let job: Record<string, unknown> | undefined;
    while (Date.now() < deadline) {
      await sleep(PING_POLL_MS);
      const jobs = await fetchAll<Record<string, unknown>>(ctx.api, 'diagnostics/ping/search_jobs');
      job = jobs.find((j) => String(j.id ?? j.uuid) === jobId);
      if (!job) break;
      if (Number(job.send ?? job.transmitted ?? 0) >= args.count || (job.status && job.status !== 'running')) break;
    }
    return { hostname: args.hostname, ...(job ?? { status: 'finished, no counters returned' }) };
  } finally {
    // Leave no job behind: nothing else stops it. A failure here must not hide the result.
    await ctx.api.post('diagnostics/ping/stop', undefined, { params: [jobId] }).catch(() => undefined);
    await ctx.api.post('diagnostics/ping/remove', undefined, { params: [jobId] }).catch(() => undefined);
  }
}

export function diagnosticsTools(): ToolDef[] {
  return [
    tool({
      name: 'opn_ping',
      title: 'Ping from the firewall',
      description: 'Pings a host from the firewall and returns the counters. Sends packets, but changes nothing on the firewall.',
      domain: 'diagnostics',
      access: 'read',
      openWorld: true,
      input: {
        hostname,
        count: z.number().int().min(1).max(20).optional().describe('Packets to send (default 3).'),
        family,
        source_address: address.optional().describe('Local address to send from.'),
      },
      handler: async (args, ctx) => runPing(ctx, { ...args, count: args.count ?? 3 }),
    }),
    tool({
      name: 'opn_traceroute',
      title: 'Traceroute from the firewall',
      description: 'Traces the path from the firewall to a host. Can take up to a minute.',
      domain: 'diagnostics',
      access: 'read',
      openWorld: true,
      input: {
        hostname,
        protocol: z.enum(['udp', 'icmp']).optional().describe('Default icmp.'),
        family,
        source_address: address.optional().describe('Local address to send from.'),
      },
      handler: async (args, ctx) => {
        const settings = {
          hostname: args.hostname,
          protocol: args.protocol ?? 'icmp',
          ipproto: args.family ?? 'inet',
          ...(args.source_address ? { source_address: args.source_address } : {}),
        };
        return assertWriteOk(await ctx.api.post('diagnostics/traceroute/set', { traceroute: { settings } }, { timeoutMs: 90_000 }), 'The traceroute');
      },
    }),
    tool({
      name: 'opn_dns_lookup',
      title: 'DNS lookup from the firewall',
      description: 'Resolves a name as the firewall sees it, through its own resolver or a given server. Useful to compare with what a client gets.',
      domain: 'diagnostics',
      access: 'read',
      openWorld: true,
      input: { hostname, server: address.optional().describe('IP address of the DNS server to ask. Default: the resolver of the firewall.') },
      handler: async (args, ctx) => {
        const settings = { hostname: args.hostname, ...(args.server ? { server: args.server } : {}) };
        return assertWriteOk(await ctx.api.post('diagnostics/dns_diagnostics/set', { dns: { settings } }, { timeoutMs: 60_000 }), 'The DNS lookup');
      },
    }),
    tool({
      name: 'opn_reverse_dns',
      title: 'Reverse DNS lookup',
      description: 'Finds the names of IP addresses, through the resolver of the firewall.',
      domain: 'diagnostics',
      access: 'read',
      openWorld: true,
      input: { addresses: z.array(address).min(1).max(50).describe('IP addresses.') },
      handler: async (args, ctx) => {
        // PHP reads "address[]" from the query string as a list.
        const query = Object.fromEntries(args.addresses.map((a, i) => [`address[${i}]`, a]));
        return ctx.api.get('diagnostics/dns/reverse_lookup', { query });
      },
    }),
    tool({
      name: 'opn_port_probe',
      title: 'Test a TCP port from the firewall',
      description: 'Tries to open a TCP connection from the firewall to a host and port. Sends packets, but changes nothing on the firewall.',
      domain: 'diagnostics',
      access: 'read',
      openWorld: true,
      input: {
        hostname,
        port: z.number().int().min(1).max(65535).describe('TCP port.'),
        family,
        source_address: address.optional().describe('Local address to connect from.'),
      },
      handler: async (args, ctx) => {
        const settings = {
          hostname: args.hostname,
          port: String(args.port),
          ipproto: args.family ?? 'inet',
          ...(args.source_address ? { source_address: args.source_address } : {}),
        };
        return assertWriteOk(await ctx.api.post('diagnostics/portprobe/set', { portprobe: { settings } }, { timeoutMs: 60_000 }), 'The port probe');
      },
    }),
    tool({
      name: 'opn_investigate_host',
      title: 'Everything known about a host',
      description: 'Brings together what the firewall knows about an IP address: neighbor table, DHCP lease, active connections, aliases containing it, recent log entries and reverse DNS. Sources the API user cannot read are listed under unavailable. Sends a reverse DNS query, nothing else.',
      domain: 'diagnostics',
      access: 'read',
      idempotent: true,
      openWorld: true,
      input: {
        ip: address.describe('IP address to look up.'),
        log_scan: z.number().int().min(100).max(20000).optional().describe('Newest firewall log lines to scan (default 2000).'),
      },
      handler: async (args, ctx) => {
        const ip = args.ip;
        const { data, unavailable } = await gather({
          arp: () => ctx.api.post('diagnostics/interface/search_arp', { current: 1, rowCount: 20, searchPhrase: ip }),
          ndp: () => ctx.api.post('diagnostics/interface/search_ndp', { current: 1, rowCount: 20, searchPhrase: ip }),
          kea_leases: () => ctx.api.post('kea/leases4/search', { current: 1, rowCount: 20, searchPhrase: ip }),
          dnsmasq_leases: () => ctx.api.post('dnsmasq/leases/search', { current: 1, rowCount: 20, searchPhrase: ip }),
          states: () => ctx.api.post('diagnostics/firewall/query_states', { current: 1, rowCount: 50, searchPhrase: ip, sort: {} }),
          aliases: () => ctx.api.post('firewall/alias_util/find_references', { ip: ip.toLowerCase() }),
          reverse_dns: () => ctx.api.get('diagnostics/dns/reverse_lookup', { query: { 'address[0]': ip } }),
          log: () => ctx.api.get('diagnostics/firewall/log', { query: { limit: args.log_scan ?? 2000 } }),
        });

        const rowsOf = (v: unknown) => (isObject(v) && Array.isArray(v.rows) ? (v.rows as Array<Record<string, unknown>>) : []);
        const logRows = (Array.isArray(data.log) ? data.log : rowsOf(data.log)) as Array<Record<string, unknown>>;
        // Exact match: a substring search would also return 10.0.0.10 when asked for 10.0.0.1.
        const matches = (value: unknown) => matchLiteral(ip, String(value ?? '')) === true;
        const log = logRows.filter((r) => matches(r.src) || matches(r.dst));
        const neighbors = [...rowsOf(data.arp), ...rowsOf(data.ndp)].filter((r) => matches(r.ip));
        const leases = [...rowsOf(data.kea_leases).map((r) => ({ source: 'kea', ...r })), ...rowsOf(data.dnsmasq_leases).map((r) => ({ source: 'dnsmasq', ...r }))].filter((r) => {
          const row = r as Record<string, unknown>;
          return matches(row.address ?? row.ip_address ?? row.ip);
        });

        return {
          ip,
          neighbors,
          leases,
          active_connections: rowsOf(data.states).filter((r) => matches(r.src_addr) || matches(r.dst_addr)),
          aliases: isObject(data.aliases) ? data.aliases.matches ?? [] : [],
          reverse_dns: data.reverse_dns ?? null,
          firewall_log: { ...paginateArray(log, 50, 0), scanned: logRows.length },
          unavailable,
          note: 'No log entry does not prove there was no traffic: only rules with logging enabled write to the log.',
        };
      },
    }),
  ];
}
