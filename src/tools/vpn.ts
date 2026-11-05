import { z } from 'zod';
import { compactGrid, fetchAll, searchGrid } from '../opnsense/model.js';
import { crudTools, flipTo, gather, paging, serviceWrite, tool, type ToolDef } from './helpers.js';

export function vpnTools(): ToolDef[] {
  return [
    tool({
      name: 'opn_wireguard_status',
      title: 'WireGuard status',
      description: 'WireGuard tunnels and peers as they run now: last handshake, endpoint and traffic. Needs os-wireguard on older firewalls.',
      domain: 'vpn',
      access: 'read',
      idempotent: true,
      input: {},
      handler: async (_args, ctx) => ctx.api.get('wireguard/service/show'),
    }),
    tool({
      name: 'opn_list_wireguard_servers',
      title: 'List WireGuard instances',
      description: 'Configured WireGuard instances (local tunnel ends). Private keys are redacted.',
      domain: 'vpn',
      access: 'read',
      idempotent: true,
      input: paging,
      handler: async (args, ctx) => compactGrid(await searchGrid(ctx.api, 'wireguard/server/search_server', args)),
    }),
    tool({
      name: 'opn_list_wireguard_peers',
      title: 'List WireGuard peers',
      description: 'Configured WireGuard peers. For whether they are connected, see opn_wireguard_status.',
      domain: 'vpn',
      access: 'read',
      idempotent: true,
      input: paging,
      handler: async (args, ctx) => compactGrid(await searchGrid(ctx.api, 'wireguard/client/search_client', args)),
    }),
    tool({
      name: 'opn_toggle_wireguard_peer',
      title: 'Enable or disable WireGuard peer',
      description: 'Enables or disables one WireGuard peer, for example to cut off a lost device. Goes live right away, with no rollback timer. Disabling the peer this server connects through cuts its access.',
      domain: 'vpn',
      access: 'write',
      idempotent: true,
      input: {
        uuid: z.string().regex(/^[0-9a-fA-F-]{36}$/, 'Expected a uuid').describe('Peer uuid, from opn_list_wireguard_peers.'),
        enabled: z.boolean().describe('The state wanted.'),
      },
      // set_client without its servers field would detach the peer from every instance, so use toggle_client, which flips.
      handler: async (args, ctx) =>
        flipTo(ctx, 'wireguard/client/get_client', 'client', args.uuid, args.enabled, 'Changing the peer', () =>
          serviceWrite(ctx, () => ctx.api.post('wireguard/client/toggle_client', undefined, { params: [args.uuid] }), 'Changing the peer', ['wireguard/service/reconfigure'], true)),
    }),
    tool({
      name: 'opn_ipsec_status',
      title: 'IPsec status',
      description: 'IPsec tunnels as they run now: phase 1 and phase 2 state, with the service status.',
      domain: 'vpn',
      access: 'read',
      idempotent: true,
      input: {},
      handler: async (_args, ctx) => {
        const { data, unavailable } = await gather({
          service: () => ctx.api.get('ipsec/service/status'),
          phase1: () => fetchAll<Record<string, unknown>>(ctx.api, 'ipsec/sessions/search_phase1'),
        });
        // search_phase2 answers per tunnel: it takes the name of the phase 1 row.
        const names = ((data.phase1 ?? []) as Array<Record<string, unknown>>).map((row) => String(row.name ?? '')).filter(Boolean);
        const phase2 = await gather(Object.fromEntries(names.map((name) => [name, () => fetchAll(ctx.api, 'ipsec/sessions/search_phase2', { id: name })])));
        const missing = Object.entries(phase2.unavailable).map(([name, why]) => [`phase2:${name}`, why]);
        return { ...data, phase2: phase2.data, unavailable: { ...unavailable, ...Object.fromEntries(missing) } };
      },
    }),
    tool({
      name: 'opn_list_ipsec_connections',
      title: 'List IPsec connections',
      description: 'Configured IPsec connections. For whether they are up, see opn_ipsec_status. Legacy tunnels made on the old IPsec page do not appear here: see opn_get_config_section with section ipsec.',
      domain: 'vpn',
      access: 'read',
      idempotent: true,
      input: paging,
      handler: async (args, ctx) => compactGrid(await searchGrid(ctx.api, 'ipsec/connections/search_connection', args)),
    }),
    tool({
      name: 'opn_openvpn_status',
      title: 'OpenVPN status',
      description: 'OpenVPN as it runs now: connected sessions, with their addresses and traffic, and the routes.',
      domain: 'vpn',
      access: 'read',
      idempotent: true,
      input: {},
      handler: async (_args, ctx) => {
        const { data, unavailable } = await gather({
          sessions: () => fetchAll(ctx.api, 'openvpn/service/search_sessions'),
          routes: () => fetchAll(ctx.api, 'openvpn/service/search_routes'),
        });
        return { ...data, unavailable };
      },
    }),
    ...crudTools({
      domain: 'vpn',
      singular: 'openvpn_instance',
      plural: 'openvpn_instances',
      label: 'OpenVPN instance',
      base: 'openvpn/instances',
      commands: { search: 'search', get: 'get' },
      wrapper: 'instance',
      listNote: 'Legacy instances made on the old OpenVPN pages do not appear here: see opn_get_config_section with section openvpn.',
    }),
  ];
}
