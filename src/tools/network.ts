import { z } from 'zod';
import { compactGrid, fetchAll, isObject, modelFields, paginateArray, searchGrid } from '../opnsense/model.js';
import { crudTools, paging, sparse, tool, type ToolDef } from './helpers.js';

export function networkTools(): ToolDef[] {
  return [
    tool({
      name: 'opn_list_interfaces',
      title: 'List interfaces',
      description: 'All interfaces, mapping configuration ids (opt2) to devices (vlan0.30) and names (DMZ), with state, addresses, gateways and VLAN tag. Call this first when a question spans several tools: rules use ids, logs and states use devices or names.',
      domain: 'network',
      access: 'read',
      idempotent: true,
      input: paging,
      handler: async (args, ctx) => {
        const grid = await searchGrid<Record<string, unknown>>(ctx.api, 'interfaces/overview/interfaces_info', args);
        return {
          ...grid,
          rows: grid.rows.map((r) => sparse({
            identifier: r.identifier,
            device: r.device,
            description: r.description,
            status: r.status,
            enabled: r.enabled,
            link_type: r.link_type,
            link_typev6: r.link_typev6,
            addr4: r.addr4,
            addr6: r.addr6,
            ipv4: r.ipv4,
            ipv6: r.ipv6,
            macaddr: r.macaddr,
            mtu: r.mtu,
            vlan_tag: r.vlan_tag,
            gateways: r.gateways,
            routes: r.routes,
          })),
        };
      },
    }),
    tool({
      name: 'opn_get_interface',
      title: 'Get interface details',
      description: 'Every detail the firewall has about one interface, by device name (from opn_list_interfaces).',
      domain: 'network',
      access: 'read',
      idempotent: true,
      input: { device: z.string().regex(/^[A-Za-z0-9_.:-]+$/).describe('Device name, such as igb0 or vlan0.30.') },
      handler: async (args, ctx) => ctx.api.get('interfaces/overview/get_interface', { params: [args.device] }),
    }),
    tool({
      name: 'opn_interface_stats',
      title: 'Interface statistics',
      description: 'Traffic and error counters per interface, since the interface came up.',
      domain: 'network',
      access: 'read',
      idempotent: true,
      input: {},
      handler: async (_args, ctx) => ctx.api.get('diagnostics/interface/get_interface_statistics'),
    }),
    tool({
      name: 'opn_arp_table',
      title: 'ARP table',
      description: 'IPv4 neighbors: which MAC address and hostname holds which address, on which interface. Search by address, MAC or name.',
      domain: 'network',
      access: 'read',
      idempotent: true,
      input: paging,
      handler: async (args, ctx) => compactGrid(await searchGrid(ctx.api, 'diagnostics/interface/search_arp', args)),
    }),
    tool({
      name: 'opn_ndp_table',
      title: 'NDP table',
      description: 'IPv6 neighbors: which MAC address holds which address, on which interface. Search by address or MAC.',
      domain: 'network',
      access: 'read',
      idempotent: true,
      input: paging,
      handler: async (args, ctx) => compactGrid(await searchGrid(ctx.api, 'diagnostics/interface/search_ndp', args)),
    }),
    tool({
      name: 'opn_routing_table',
      title: 'Routing table',
      description: 'The kernel routing table, as it is now: connected, static and dynamic routes. For what is configured, see opn_list_static_routes.',
      domain: 'network',
      access: 'read',
      idempotent: true,
      input: { ...paging },
      handler: async (args, ctx) => {
        const res = await ctx.api.get('diagnostics/interface/get_routes');
        const rows = (Array.isArray(res) ? res : isObject(res) && Array.isArray(res.rows) ? res.rows : []) as Array<Record<string, unknown>>;
        const q = args.search?.toLowerCase();
        return paginateArray(q ? rows.filter((r) => JSON.stringify(r).toLowerCase().includes(q)) : rows, args.limit, args.offset);
      },
    }),
    tool({
      name: 'opn_ipv6_status',
      title: 'IPv6 status',
      description: 'IPv6 per interface: how it is configured (static, dhcp6, slaac, track6) and the addresses in use.',
      domain: 'network',
      access: 'read',
      idempotent: true,
      input: {},
      handler: async (_args, ctx) => {
        const rows = await fetchAll<Record<string, unknown>>(ctx.api, 'interfaces/overview/interfaces_info');
        const interfaces = rows
          .filter((r) => r.identifier)
          .map((r) => sparse({ identifier: r.identifier, description: r.description, method: r.link_typev6 ?? 'none', address: r.addr6, addresses: r.ipv6 }) as Record<string, unknown>);
        const configured = interfaces.filter((i) => i.method && i.method !== 'none');
        return { interfaces, summary: { total: interfaces.length, with_ipv6: configured.length, without_ipv6: interfaces.length - configured.length } };
      },
    }),
    tool({
      name: 'opn_list_gateways',
      title: 'List configured gateways',
      description: 'Gateways as configured: interface, address, monitoring. For their live state, see opn_gateway_status.',
      domain: 'network',
      access: 'read',
      idempotent: true,
      input: paging,
      handler: async (args, ctx) => compactGrid(await searchGrid(ctx.api, 'routing/settings/search_gateway', args)),
    }),
    tool({
      name: 'opn_list_vlans',
      title: 'List VLANs',
      description: 'Configured VLAN devices, with parent interface and tag.',
      domain: 'network',
      access: 'read',
      idempotent: true,
      input: paging,
      handler: async (args, ctx) => compactGrid(await searchGrid(ctx.api, 'interfaces/vlan_settings/search_item', args)),
    }),
    tool({
      name: 'opn_list_virtual_ips',
      title: 'List virtual IPs',
      description: 'Configured virtual IPs (CARP, IP alias, proxy ARP). For the CARP state, see opn_api_read with diagnostics/interface/get_vip_status.',
      domain: 'network',
      access: 'read',
      idempotent: true,
      input: paging,
      handler: async (args, ctx) => compactGrid(await searchGrid(ctx.api, 'interfaces/vip_settings/search_item', args)),
    }),
    ...crudTools({
      domain: 'network',
      singular: 'static_route',
      plural: 'static_routes',
      label: 'static route',
      base: 'routes/routes',
      commands: { search: 'searchroute', get: 'getroute', add: 'addroute', set: 'setroute', del: 'delroute', toggle: 'toggleroute' },
      wrapper: 'route',
      fields: {
        network: z.string().optional().describe('Destination network, in CIDR form.'),
        gateway: z.string().optional().describe('Gateway name, from opn_list_gateways.'),
        description: z.string().optional().describe('Free-text description.'),
        enabled: z.boolean().optional().describe('Default true on creation.'),
      },
      required: ['network', 'gateway'],
      toModel: (args) => {
        // This model calls the description "descr".
        const { description, ...rest } = args;
        return modelFields({ ...rest, ...(description !== undefined ? { descr: description } : {}) });
      },
      reconfigure: ['routes/routes/reconfigure'],
      writeNote: 'Takes effect on reconfigure, with no rollback timer. A wrong route can cut access to the firewall.',
    }),
  ];
}
