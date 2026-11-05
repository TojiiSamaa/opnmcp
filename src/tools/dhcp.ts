import { z } from 'zod';
import { OpnsenseError } from '../opnsense/errors.js';
import { assertApplied, compactGrid, fetchAll, paginateArray, searchGrid } from '../opnsense/model.js';
import { crudTools, paging, sparse, tool, type ToolDef } from './helpers.js';

const LEASE_SOURCES = [
  { source: 'kea-dhcp4', path: 'kea/leases4/search' },
  { source: 'kea-dhcp6', path: 'kea/leases6/search' },
  { source: 'dnsmasq', path: 'dnsmasq/leases/search' },
  { source: 'isc-dhcp4', path: 'dhcpv4/leases/search_lease' },
  { source: 'isc-dhcp6', path: 'dhcpv6/leases/search_lease' },
];

const hostFields = {
  host: z.string().optional().describe('Host name.'),
  domain: z.string().optional().describe('Domain.'),
  ip: z.array(z.string()).optional().describe('Addresses of this host.'),
  hwaddr: z.array(z.string()).optional().describe('MAC addresses that get this address over DHCP.'),
  client_id: z.string().optional().describe('DHCP client id.'),
  lease_time: z.number().int().min(0).optional().describe('Lease time in seconds.'),
  ignore: z.boolean().optional().describe('Ignore DHCP requests from this host.'),
  cnames: z.array(z.string()).optional().describe('Extra names for this host.'),
  descr: z.string().optional().describe('Free-text description.'),
};

const rangeFields = {
  interface: z.string().optional().describe('Interface id. Empty means all.'),
  start_addr: z.string().optional().describe('First address, or a prefix for IPv6.'),
  end_addr: z.string().optional().describe('Last address.'),
  prefix_len: z.number().int().min(1).max(64).optional().describe('IPv6 prefix length.'),
  ra_mode: z.string().optional().describe('IPv6 router advertisement mode.'),
  lease_time: z.number().int().min(0).optional().describe('Lease time in seconds.'),
  description: z.string().optional().describe('Free-text description.'),
};

const reservationFields = {
  subnet: z.string().optional().describe('Subnet uuid, from opn_list_kea_subnets.'),
  ip_address: z.string().optional().describe('Address to reserve.'),
  hw_address: z.string().optional().describe('MAC address.'),
  client_id: z.string().optional().describe('DHCP client id, as an alternative to the MAC address.'),
  hostname: z.string().optional().describe('Host name given to the client.'),
  description: z.string().optional().describe('Free-text description.'),
};

export function dhcpTools(): ToolDef[] {
  return [
    tool({
      name: 'opn_list_dhcp_leases',
      title: 'List DHCP leases',
      description: 'Active leases across every DHCP server of the firewall (Kea, Dnsmasq, ISC), each marked with its source. Search by address, MAC or host name. Sources that are not installed are listed under sources_unavailable.',
      domain: 'dhcp',
      access: 'read',
      idempotent: true,
      input: paging,
      handler: async (args, ctx) => {
        const results = await Promise.allSettled(LEASE_SOURCES.map((s) => fetchAll<Record<string, unknown>>(ctx.api, s.path, args.search ? { searchPhrase: args.search } : undefined)));
        const rows: Array<Record<string, unknown>> = [];
        const unavailable: Record<string, string> = {};
        results.forEach((r, i) => {
          const { source } = LEASE_SOURCES[i]!;
          if (r.status === 'fulfilled') rows.push(...r.value.map((row) => ({ source, ...(sparse(row) as Record<string, unknown>) })));
          else unavailable[source] = r.reason instanceof OpnsenseError ? r.reason.type : String(r.reason);
        });
        if (rows.length === 0 && Object.keys(unavailable).length === LEASE_SOURCES.length) {
          throw new OpnsenseError('not_found', 'No DHCP lease source answered.', { details: { sources_unavailable: unavailable }, hint: 'If every source says forbidden, the API user lacks the DHCP privileges.' });
        }
        return { ...paginateArray(rows, args.limit, args.offset), sources_unavailable: unavailable };
      },
    }),
    tool({
      name: 'opn_list_kea_leases',
      title: 'List Kea leases',
      description: 'Leases from the Kea DHCP server, IPv4 by default.',
      domain: 'dhcp',
      access: 'read',
      idempotent: true,
      input: { ...paging, ip_version: z.enum(['4', '6']).optional().describe('Default 4.') },
      handler: async (args, ctx) => compactGrid(await searchGrid(ctx.api, `kea/leases${args.ip_version ?? '4'}/search`, args)),
    }),
    tool({
      name: 'opn_list_dnsmasq_leases',
      title: 'List Dnsmasq leases',
      description: 'Leases from the Dnsmasq DHCP server.',
      domain: 'dhcp',
      access: 'read',
      idempotent: true,
      input: paging,
      handler: async (args, ctx) => compactGrid(await searchGrid(ctx.api, 'dnsmasq/leases/search', args)),
    }),
    ...crudTools({
      domain: 'dhcp',
      singular: 'dnsmasq_range',
      plural: 'dnsmasq_ranges',
      label: 'Dnsmasq DHCP range',
      base: 'dnsmasq/settings',
      commands: { search: 'search_range', get: 'get_range', add: 'add_range', set: 'set_range', del: 'del_range' },
      wrapper: 'range',
      fields: rangeFields,
      required: ['start_addr'],
      reconfigure: ['dnsmasq/service/reconfigure'],
      writeNote: 'Goes live when Dnsmasq reconfigures, with no rollback timer.',
    }),
    ...crudTools({
      domain: 'dhcp',
      singular: 'dnsmasq_host',
      plural: 'dnsmasq_hosts',
      label: 'Dnsmasq host',
      base: 'dnsmasq/settings',
      commands: { search: 'search_host', get: 'get_host', add: 'add_host', set: 'set_host', del: 'del_host' },
      wrapper: 'host',
      fields: hostFields,
      reconfigure: ['dnsmasq/service/reconfigure'],
      listNote: 'A host with a MAC address is a DHCP reservation, and also a DNS entry.',
      writeNote: 'Goes live when Dnsmasq reconfigures, with no rollback timer.',
    }),
    tool({
      name: 'opn_reconfigure_dnsmasq',
      title: 'Reconfigure Dnsmasq',
      description: 'Regenerates the Dnsmasq configuration and restarts it: applies changes saved with apply=false.',
      domain: 'dhcp',
      access: 'write',
      idempotent: true,
      input: {},
      handler: async (_args, ctx) => assertApplied(await ctx.api.post('dnsmasq/service/reconfigure'), 'Reconfiguring Dnsmasq'),
    }),
    tool({
      name: 'opn_list_kea_subnets',
      title: 'List Kea subnets',
      description: 'IPv4 subnets served by Kea, with their pools.',
      domain: 'dhcp',
      access: 'read',
      idempotent: true,
      input: paging,
      handler: async (args, ctx) => compactGrid(await searchGrid(ctx.api, 'kea/dhcpv4/search_subnet', args)),
    }),
    ...crudTools({
      domain: 'dhcp',
      singular: 'kea_reservation',
      plural: 'kea_reservations',
      label: 'Kea IPv4 reservation',
      base: 'kea/dhcpv4',
      commands: { search: 'search_reservation', get: 'get_reservation', add: 'add_reservation', set: 'set_reservation', del: 'del_reservation' },
      wrapper: 'reservation',
      fields: reservationFields,
      required: ['subnet', 'ip_address'],
      reconfigure: ['kea/service/reconfigure'],
      writeNote: 'Goes live when Kea reconfigures, with no rollback timer.',
    }),
    tool({
      name: 'opn_reconfigure_kea',
      title: 'Reconfigure Kea',
      description: 'Regenerates the Kea configuration and restarts it: applies changes saved with apply=false.',
      domain: 'dhcp',
      access: 'write',
      idempotent: true,
      input: {},
      handler: async (_args, ctx) => assertApplied(await ctx.api.post('kea/service/reconfigure'), 'Reconfiguring Kea'),
    }),
  ];
}
