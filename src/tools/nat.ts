import { z } from 'zod';
import { compactGrid, flattenModel, isObject, modelFields, searchGrid } from '../opnsense/model.js';
import { crudTools, paging, tool, type ToolContext, type ToolDef } from './helpers.js';

const addressHelp = 'any, an address, a CIDR, an alias name, an interface network (lan) or address (wanip).';

/**
 * The destination NAT model nests source and destination, and its fields differ from the
 * filter model (target, local-port, descr, an inverted "disabled"), which is easy to get wrong.
 */
const portForwardFields = {
  interface: z.string().optional().describe('Interface the traffic arrives on, usually wan. Comma-separated for several.'),
  ip_protocol: z.enum(['inet', 'inet6']).optional().describe('inet = IPv4, inet6 = IPv6.'),
  protocol: z.string().optional().describe('TCP, UDP, TCP/UDP...'),
  source_net: z.string().optional().describe(`Who may connect: ${addressHelp} Leaving it open exposes the service to everyone.`),
  source_port: z.string().optional().describe('Source port. Rarely needed.'),
  source_not: z.boolean().optional().describe('Invert the source match.'),
  destination_net: z.string().optional().describe(`Address the traffic is sent to: ${addressHelp} Usually wanip.`),
  destination_port: z.string().optional().describe('Public port or range.'),
  destination_not: z.boolean().optional().describe('Invert the destination match.'),
  target: z.string().optional().describe('Internal address or alias to forward to.'),
  target_port: z.string().optional().describe('Internal port. Default: the same as destination_port.'),
  description: z.string().optional().describe('Free-text description.'),
  enabled: z.boolean().optional().describe('Default true on creation.'),
  log: z.boolean().optional().describe('Log matching packets.'),
  pass: z.enum(['', 'pass', 'rule']).optional().describe('Filter rule association: "" = manual, you add the rule yourself; pass = pass matching traffic directly; rule = register a linked filter rule.'),
  natreflection: z.enum(['', 'purenat', 'disable']).optional().describe('NAT reflection for internal clients. "" = system default, purenat = enable.'),
};

function toPortForwardModel(args: Record<string, unknown>): Record<string, unknown> {
  const { source_net, source_port, source_not, destination_net, destination_port, destination_not, target_port, description, enabled, ip_protocol, ...rest } = args;
  const nested = (network: unknown, port: unknown, not: unknown) => {
    const out = modelFields({ network, port, not });
    return Object.keys(out).length ? out : undefined;
  };
  const source = nested(source_net, source_port, source_not);
  const destination = nested(destination_net, destination_port, destination_not);
  return {
    ...modelFields({
      ...rest,
      ...(ip_protocol !== undefined ? { ipprotocol: ip_protocol } : {}),
      ...(target_port !== undefined ? { 'local-port': target_port } : {}),
      ...(description !== undefined ? { descr: description } : {}),
      ...(enabled !== undefined ? { disabled: !enabled } : {}),
    }),
    ...(source ? { source } : {}),
    ...(destination ? { destination } : {}),
  };
}

const outboundFields = {
  interface: z.string().optional().describe('Outgoing interface, usually wan.'),
  ip_protocol: z.enum(['inet', 'inet6']).optional().describe('inet = IPv4, inet6 = IPv6.'),
  protocol: z.string().optional().describe('any, TCP, UDP...'),
  source_net: z.string().optional().describe(`Internal source: ${addressHelp}`),
  source_not: z.boolean().optional().describe('Invert the source match.'),
  source_port: z.string().optional().describe('Source port.'),
  destination_net: z.string().optional().describe(`Destination: ${addressHelp}`),
  destination_not: z.boolean().optional().describe('Invert the destination match.'),
  destination_port: z.string().optional().describe('Destination port.'),
  target: z.string().optional().describe('Address to translate to, for example wanip.'),
  target_port: z.string().optional().describe('Port to translate to.'),
  nonat: z.boolean().optional().describe('Exempt this traffic from NAT.'),
  staticnatport: z.boolean().optional().describe('Keep the source port.'),
  log: z.boolean().optional().describe('Log matching packets.'),
  description: z.string().optional().describe('Free-text description.'),
  enabled: z.boolean().optional().describe('Default true on creation.'),
};

function toOutboundModel(args: Record<string, unknown>): Record<string, unknown> {
  const { ip_protocol, ...rest } = args;
  return modelFields({ ...rest, ...(ip_protocol !== undefined ? { ipprotocol: ip_protocol } : {}) });
}

/** The firewall only loads manual outbound rules in these modes. */
const MANUAL_OUTBOUND_MODES = ['hybrid', 'advanced'];

async function readOutboundMode(ctx: ToolContext): Promise<string> {
  const res = flattenModel(await ctx.api.get('firewall/source_nat/get'));
  const filter = isObject(res) && isObject(res.filter) ? res.filter : {};
  const settings = isObject(filter.settings) ? filter.settings : {};
  const nat = isObject(settings.nat) ? settings.nat : {};
  return String(nat.snat_mode ?? '');
}

export function natTools(): ToolDef[] {
  return [
    ...crudTools({
      domain: 'nat',
      singular: 'nat_rule',
      plural: 'nat_rules',
      label: 'port forward (destination NAT) rule',
      base: 'firewall/d_nat',
      commands: { search: 'search_rule', get: 'get_rule', add: 'add_rule', set: 'set_rule', del: 'del_rule', toggle: 'toggle_rule' },
      wrapper: 'rule',
      fields: portForwardFields,
      required: ['interface', 'protocol', 'destination_port', 'target'],
      toModel: toPortForwardModel,
      invertedToggle: true,
      staged: 'nat',
      listNote: 'Automatic rules have is_automatic=true.',
      writeNote: 'Staged: nothing changes until opn_apply_firewall_changes. A forward also needs traffic to be passed: use the pass field or add a filter rule.',
    }),
    ...crudTools({
      domain: 'nat',
      singular: 'outbound_nat_rule',
      plural: 'outbound_nat_rules',
      label: 'outbound (source NAT) rule',
      base: 'firewall/source_nat',
      commands: { search: 'search_rule', get: 'get_rule', add: 'add_rule', set: 'set_rule', del: 'del_rule', toggle: 'toggle_rule' },
      wrapper: 'rule',
      fields: outboundFields,
      required: ['interface'],
      toModel: toOutboundModel,
      // Same model as the filter rules, so the native savepoint covers it.
      staged: 'filter',
      listNote: 'Manual rules only take effect in hybrid or advanced mode: see opn_get_outbound_nat_mode.',
      warnOnWrite: async (ctx) => {
        // Older firewalls have no such endpoint: stay silent rather than fail a write that worked.
        const mode = await readOutboundMode(ctx).catch(() => '');
        if (!mode || MANUAL_OUTBOUND_MODES.includes(mode)) return undefined;
        return `Outbound NAT is in ${mode} mode, where manual rules are not loaded: this rule has no effect until the mode is hybrid or advanced.`;
      },
    }),
    tool({
      name: 'opn_get_outbound_nat_mode',
      title: 'Outbound NAT mode',
      description: 'How outbound NAT is generated: automatic, hybrid, advanced (manual) or disabled. Manual rules only take effect in hybrid and advanced mode. Not available on older versions.',
      domain: 'nat',
      access: 'read',
      idempotent: true,
      input: {},
      handler: async (_args, ctx) => {
        const mode = await readOutboundMode(ctx);
        return { mode: mode || null, manual_rules_active: mode ? MANUAL_OUTBOUND_MODES.includes(mode) : null };
      },
    }),
    tool({
      name: 'opn_list_one_to_one_nat_rules',
      title: 'List 1:1 NAT rules',
      description: 'List 1:1 NAT rules. To change one, see opn_search_api and opn_api_write.',
      domain: 'nat',
      access: 'read',
      idempotent: true,
      input: paging,
      handler: async (args, ctx) => compactGrid(await searchGrid(ctx.api, 'firewall/one_to_one/search_rule', args)),
    }),
    tool({
      name: 'opn_list_npt_rules',
      title: 'List NPTv6 rules',
      description: 'List NPTv6 (IPv6 prefix translation) rules. To change one, see opn_search_api and opn_api_write.',
      domain: 'nat',
      access: 'read',
      idempotent: true,
      input: paging,
      handler: async (args, ctx) => compactGrid(await searchGrid(ctx.api, 'firewall/npt/search_rule', args)),
    }),
  ];
}
