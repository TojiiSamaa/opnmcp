import { BlockList, isIP, isIPv4 } from 'node:net';
import type { OpnsenseClient } from './client.js';
import { fetchAll, isObject } from './model.js';

/**
 * Offline evaluation of the configured ruleset, with pf semantics: every rule is
 * checked in order, the last match wins, and a quick match stops the evaluation.
 *
 * It answers "would this packet pass, and which rule decides?" without sending any
 * traffic, and it is what the lockout check runs on staged rules, before they go live.
 * Whatever it cannot determine (an unresolvable alias, a schedule) is reported as
 * uncertain and never guessed.
 */
export type Tri = 'yes' | 'no' | 'unknown';

export interface Packet {
  source: string;
  destination: string;
  protocol: string;
  destinationPort?: number;
  sourcePort?: number;
  interface: string;
  direction: 'in' | 'out';
}

export type Rule = Record<string, unknown>;

export interface NetworkContext {
  interfaces: InterfaceInfo[];
  /** For each address being evaluated, the pf tables (aliases) that contain it, lowercase. Absent if the lookup failed. */
  aliasMembership: Map<string, Set<string>>;
  /** Every alias name known to exist, lowercase: not being listed as a member of one of these is a real "no". */
  knownAliases: Set<string>;
  /** Definition of port aliases, by lowercase name. */
  portAliases: Map<string, string[]>;
  /** Interface group name (lowercase) to member identifiers. */
  groups: Map<string, string[]>;
  /** Content of host and network aliases, by lowercase name: what an apply loads, staged changes included. */
  definedAliases?: Map<string, string[]>;
  /** The groups could not be read, so a rule on an interface name not known here may still apply. */
  groupsUnreadable?: boolean;
  /** Interfaces with no assignment, such as most VPN tunnels. */
  unassigned?: InterfaceInfo[];
}

export interface InterfaceInfo {
  identifier: string;
  device: string;
  description: string;
  /** Address with prefix length, such as 192.168.1.1/24. */
  addresses: string[];
}

export interface RuleHit {
  uuid: string;
  description: string;
  action: string;
  interface: string;
  sort_order?: string;
  quick: boolean;
  match: 'definite' | 'possible';
  reason?: string;
  /** The rule also sends the traffic through this gateway (policy routing). */
  gateway?: string;
}

export interface SimulationResult {
  verdict: 'pass' | 'block' | 'reject' | 'none';
  certainty: 'definite' | 'uncertain';
  deciding_rule: RuleHit | null;
  matched_rules: RuleHit[];
  rules_evaluated: number;
  explanation: string;
}

const WELL_KNOWN_PORTS: Record<string, number> = {
  ftp: 21, ssh: 22, telnet: 23, smtp: 25, domain: 53, dns: 53, http: 80, www: 80, kerberos: 88, pop3: 110, ntp: 123,
  imap: 143, snmp: 161, ldap: 389, https: 443, smb: 445, smtps: 465, submission: 587, ldaps: 636, imaps: 993, pop3s: 995,
  mssql: 1433, openvpn: 1194, mysql: 3306, rdp: 3389, postgresql: 5432, vnc: 5900, 'http-alt': 8080,
};

function family(ip: string): 'ipv4' | 'ipv6' {
  return isIPv4(ip) ? 'ipv4' : 'ipv6';
}

/** Matches an address against an IP, a CIDR or a range. Null means the token is none of those. */
export function matchLiteral(token: string, ip: string): boolean | null {
  const t = token.trim();
  if (isIP(t)) {
    const list = new BlockList();
    list.addAddress(t, family(t));
    return list.check(ip, family(ip));
  }
  const cidr = /^(.+)\/(\d{1,3})$/.exec(t);
  if (cidr && isIP(cidr[1]!)) {
    const list = new BlockList();
    const type = family(cidr[1]!);
    const bits = Number(cidr[2]);
    if (bits > (type === 'ipv4' ? 32 : 128)) return null;
    list.addSubnet(cidr[1]!, bits, type);
    return list.check(ip, family(ip));
  }
  const range = /^(.+)-(.+)$/.exec(t);
  if (range && isIP(range[1]!) && isIP(range[2]!) && family(range[1]!) === family(range[2]!)) {
    const list = new BlockList();
    try {
      list.addRange(range[1]!, range[2]!, family(range[1]!));
    } catch {
      return null;
    }
    return list.check(ip, family(ip));
  }
  return null;
}

function str(v: unknown): string {
  return v === undefined || v === null ? '' : String(v);
}

function flag(v: unknown): boolean {
  return v === true || v === 1 || v === '1' || v === 'yes' || v === 'on';
}

function findInterface(token: string, ctx: NetworkContext): InterfaceInfo | undefined {
  const t = token.toLowerCase();
  return ctx.interfaces.find((i) => i.identifier.toLowerCase() === t || i.device.toLowerCase() === t || i.description.toLowerCase() === t);
}

function addressOnly(cidr: string): string {
  return cidr.split('/')[0]!;
}

function matchAddressToken(token: string, ip: string, ctx: NetworkContext): Tri {
  const t = token.trim();
  if (t === '' || t.toLowerCase() === 'any') return 'yes';
  if (t === '(self)' || t.toLowerCase() === 'self' || t.toLowerCase() === 'this firewall') {
    return ctx.interfaces.some((i) => i.addresses.some((a) => addressOnly(a) === ip)) ? 'yes' : 'no';
  }
  const literal = matchLiteral(t, ip);
  if (literal !== null) return literal ? 'yes' : 'no';

  const lower = t.toLowerCase();
  // "wanip" is the address of the interface, "wan" the network behind it.
  if (lower.endsWith('ip')) {
    const iface = findInterface(lower.slice(0, -2), ctx);
    if (iface) return iface.addresses.some((a) => addressOnly(a) === ip) ? 'yes' : 'no';
  }
  const iface = findInterface(lower, ctx);
  if (iface) return iface.addresses.some((a) => matchLiteral(a, ip)) ? 'yes' : 'no';

  const defined = ctx.definedAliases?.get(lower);
  if (defined) return matchDefinedAlias(lower, defined, ip, ctx);
  return liveMembership(lower, ip, ctx);
}

/** What pf holds right now, which leaves out anything staged. */
function liveMembership(name: string, ip: string, ctx: NetworkContext): Tri {
  const membership = ctx.aliasMembership.get(ip);
  if (!membership) return 'unknown';
  if (membership.has(name)) return 'yes';
  return ctx.knownAliases.has(name) ? 'no' : 'unknown';
}

/**
 * The live table would miss a staged edit: adding an address to a block alias, or removing it
 * from a pass alias. So the definition decides, and the table only answers for what the
 * firewall alone can resolve, such as a host name.
 */
function matchDefinedAlias(name: string, entries: string[], ip: string, ctx: NetworkContext, depth = 0): Tri {
  return anyOf(entries.map((entry): Tri => {
    const literal = matchLiteral(entry, ip);
    if (literal !== null) return literal ? 'yes' : 'no';
    const lower = entry.toLowerCase();
    const nested = ctx.definedAliases?.get(lower);
    if (nested && depth < 8) return matchDefinedAlias(lower, nested, ip, ctx, depth + 1);
    return liveMembership(ctx.knownAliases.has(lower) ? lower : name, ip, ctx);
  }));
}

function anyOf(results: Tri[]): Tri {
  if (results.includes('yes')) return 'yes';
  return results.includes('unknown') ? 'unknown' : 'no';
}

function invert(t: Tri): Tri {
  return t === 'yes' ? 'no' : t === 'no' ? 'yes' : 'unknown';
}

/** Automatic rules can list values separated by spaces once their braces are stripped. */
function tokensOf(value: unknown): string[] {
  return str(value).split(/[,\s]+/).filter(Boolean);
}

function hasPortCondition(value: unknown): boolean {
  return tokensOf(value).some((t) => t.toLowerCase() !== 'any');
}

export function matchAddressField(value: unknown, not: unknown, ip: string, ctx: NetworkContext): Tri {
  const tokens = tokensOf(value);
  const result = tokens.length === 0 ? 'yes' : anyOf(tokens.map((t) => matchAddressToken(t, ip, ctx)));
  return flag(not) ? invert(result) : result;
}

function matchPortToken(token: string, port: number, ctx: NetworkContext, depth = 0): Tri {
  const t = token.trim().toLowerCase();
  if (t === '' || t === 'any') return 'yes';
  if (/^\d+$/.test(t)) return Number(t) === port ? 'yes' : 'no';
  const range = /^(\d+)\s*[-:]\s*(\d+)$/.exec(t);
  if (range) return port >= Number(range[1]) && port <= Number(range[2]) ? 'yes' : 'no';
  const known = WELL_KNOWN_PORTS[t];
  if (known !== undefined) return known === port ? 'yes' : 'no';
  const alias = ctx.portAliases.get(t);
  if (alias && depth < 8) return anyOf(alias.map((entry) => matchPortToken(entry, port, ctx, depth + 1)));
  return 'unknown';
}

export function matchPortField(value: unknown, port: number | undefined, ctx: NetworkContext): Tri {
  if (!hasPortCondition(value)) return 'yes';
  const tokens = tokensOf(value);
  if (port === undefined) return 'unknown';
  return anyOf(tokens.map((t) => matchPortToken(t, port, ctx)));
}

function matchProtocol(ruleProtocol: unknown, protocol: string): Tri {
  const rp = str(ruleProtocol).trim().toLowerCase();
  const p = protocol.toLowerCase();
  if (rp === '' || rp === 'any') return 'yes';
  if (rp === 'tcp/udp' || rp === 'tcp,udp') return p === 'tcp' || p === 'udp' ? 'yes' : 'no';
  if ((rp === 'ipv6-icmp' || rp === 'icmpv6' || rp === 'icmp6') && (p === 'ipv6-icmp' || p === 'icmpv6')) return 'yes';
  return rp === p ? 'yes' : 'no';
}

function matchInterface(rule: Rule, packet: Packet, ctx: NetworkContext): Tri {
  const tokens = str(rule.interface).split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  // No interface: a floating rule, which applies everywhere.
  if (tokens.length === 0) return 'yes';
  const target = findInterface(packet.interface, ctx);
  const names = new Set([packet.interface.toLowerCase()]);
  if (target) {
    names.add(target.identifier.toLowerCase());
    names.add(target.device.toLowerCase());
    names.add(target.description.toLowerCase());
  }
  const matched = tokens.some((t) => names.has(t) || (ctx.groups.get(t) ?? []).some((member) => names.has(member.toLowerCase())));
  const result: Tri = matched ? 'yes' : ctx.groupsUnreadable && tokens.some((t) => !findInterface(t, ctx)) ? 'unknown' : 'no';
  return flag(rule.interfacenot) ? invert(result) : result;
}

function isEnabled(rule: Rule): boolean {
  if (rule.enabled === undefined) return !flag(rule.disabled);
  return flag(rule.enabled);
}

function isQuick(rule: Rule): boolean {
  if (rule.quick !== undefined && rule.quick !== '') return flag(rule.quick);
  // Legacy floating rules without the option are not quick; every other kind is.
  return !(rule.floating === 'yes' || rule.floating === true);
}

/** Conditions this offline evaluation does not know the state of. */
function conditionalFields(rule: Rule): string[] {
  const out: string[] = [];
  if (str(rule.sched)) out.push('schedule');
  if (str(rule.tagged)) out.push('tagged');
  if (str(rule['received-on'])) out.push('received-on');
  if (str(rule.tcpflags1) || str(rule.tcpflags2)) out.push('TCP flags');
  if (str(rule.icmptype) || str(rule.icmp6type)) out.push('ICMP type');
  if (str(rule.tos)) out.push('TOS');
  return out;
}

export function matchRule(rule: Rule, packet: Packet, ctx: NetworkContext): { match: Tri; reason?: string } {
  const onInterface = matchInterface(rule, packet, ctx);
  if (onInterface === 'no') return { match: 'no' };

  const direction = str(rule.direction).toLowerCase();
  if (direction && direction !== 'any' && direction !== packet.direction) return { match: 'no' };

  const ipp = str(rule.ipprotocol).toLowerCase();
  const fam = family(packet.source) === 'ipv4' ? 'inet' : 'inet6';
  if (ipp && ipp !== 'inet46' && ipp !== fam) return { match: 'no' };

  const checks: Array<[string, Tri]> = [['interface', onInterface], ['protocol', matchProtocol(rule.protocol, packet.protocol)]];
  const isPortProtocol = ['tcp', 'udp'].includes(packet.protocol.toLowerCase());
  if ((hasPortCondition(rule.source_port) || hasPortCondition(rule.destination_port)) && !isPortProtocol) return { match: 'no' };

  checks.push(['source', matchAddressField(rule.source_net, rule.source_not, packet.source, ctx)]);
  checks.push(['destination', matchAddressField(rule.destination_net, rule.destination_not, packet.destination, ctx)]);
  checks.push(['source port', matchPortField(rule.source_port, packet.sourcePort, ctx)]);
  checks.push(['destination port', matchPortField(rule.destination_port, packet.destinationPort, ctx)]);

  if (checks.some(([, r]) => r === 'no')) return { match: 'no' };
  const unknown = checks.filter(([, r]) => r === 'unknown').map(([name]) => name);
  const conditional = conditionalFields(rule);
  if (unknown.length || conditional.length) {
    const parts = [...(unknown.length ? [`could not resolve: ${unknown.join(', ')}`] : []), ...(conditional.length ? [`depends on: ${conditional.join(', ')}`] : [])];
    return { match: 'unknown', reason: parts.join('; ') };
  }
  return { match: 'yes' };
}

function describeHit(rule: Rule, match: 'definite' | 'possible', reason?: string): RuleHit {
  return {
    uuid: str(rule.uuid),
    description: str(rule.description ?? rule.descr),
    action: str(rule.action).toLowerCase(),
    interface: str(rule.interface),
    ...(str(rule.sort_order) ? { sort_order: str(rule.sort_order) } : {}),
    quick: isQuick(rule),
    match,
    ...(reason ? { reason } : {}),
    ...(str(rule.gateway) ? { gateway: str(rule.gateway) } : {}),
  };
}

export function simulate(rules: Rule[], packet: Packet, ctx: NetworkContext): SimulationResult {
  const enabled = rules.filter(isEnabled);
  const hits: RuleHit[] = [];
  let decided: RuleHit | null = null;

  for (const rule of enabled) {
    const { match, reason } = matchRule(rule, packet, ctx);
    if (match === 'no') continue;
    const action = str(rule.action).toLowerCase();
    if (match === 'unknown') {
      hits.push(describeHit(rule, 'possible', reason));
      continue;
    }
    const hit = describeHit(rule, 'definite');
    hits.push(hit);
    if (action === 'match') continue;
    decided = hit;
    if (hit.quick) break;
  }

  const verdict = decided ? (decided.action as SimulationResult['verdict']) : 'none';
  // A possible match only matters if it could change the outcome.
  const certainty = hits.some((h) => h.match === 'possible' && h.action !== 'match' && h.action !== verdict) ? 'uncertain' : 'definite';

  let explanation: string;
  if (decided) {
    const label = decided.description || decided.uuid || 'unnamed rule';
    explanation = `${verdict} by "${label}"${certainty === 'uncertain' ? ', unless one of the possible matches above it applies' : ''}.`;
  } else if (hits.some((h) => h.match === 'possible')) {
    explanation = 'No rule matches for certain: the outcome depends on the possible matches listed.';
  } else {
    explanation = 'No listed rule matches. OPNsense blocks by default what no rule passes.';
  }
  return { verdict, certainty, deciding_rule: decided, matched_rules: hits.slice(0, 25), rules_evaluated: enabled.length, explanation };
}

export const SIMULATION_LIMITS =
  'Offline estimate from the configuration, which includes staged rules that are not live yet. Existing connections keep their state and are not re-evaluated. Destination NAT happens before filtering, so give the translated destination. Only the requested direction on the given interface is evaluated, and shaping and policy routing are ignored.';

export interface Ruleset {
  rules: Rule[];
  context: NetworkContext;
  /** False on versions whose search_rule omits automatic and legacy rules. */
  complete: boolean;
  warnings: string[];
}

function addressesOf(row: Record<string, unknown>): string[] {
  const out = new Set<string>();
  for (const key of ['addr4', 'addr6']) {
    const v = row[key];
    if (typeof v === 'string' && v) out.add(v);
  }
  for (const key of ['ipv4', 'ipv6']) {
    const list = row[key];
    if (Array.isArray(list)) {
      for (const entry of list) {
        if (isObject(entry) && typeof entry.ipaddr === 'string') out.add(entry.ipaddr);
      }
    }
  }
  // Link-local addresses come with a zone ("fe80::1%igb0"), which address lists do not accept.
  return [...out].map((a) => a.replace(/%[^/]*/, ''));
}

function interfaceInfo(r: Record<string, unknown>): InterfaceInfo {
  return { identifier: str(r.identifier), device: str(r.device), description: str(r.description), addresses: addressesOf(r) };
}


const STATIC_ALIAS_TYPES = new Set(['host', 'network', 'networkgroup']);

/** Loads the configured rules and what is needed to interpret them, except the addresses. */
export async function loadRuleset(client: OpnsenseClient): Promise<Ruleset> {
  const warnings: string[] = [];
  let groupsUnreadable = false;
  const [rules, interfaceRows, aliasRows, groupRows, tables] = await Promise.all([
    fetchAll<Rule>(client, 'firewall/filter/search_rule'),
    fetchAll<Record<string, unknown>>(client, 'interfaces/overview/interfaces_info'),
    fetchAll<Record<string, unknown>>(client, 'firewall/alias/search_item').catch((err: Error) => {
      warnings.push(`Aliases could not be read (${err.message}), so rules using them are uncertain.`);
      return [] as Record<string, unknown>[];
    }),
    fetchAll<Record<string, unknown>>(client, 'firewall/group/search_item').catch((err: Error) => {
      groupsUnreadable = true;
      warnings.push(`Interface groups could not be read (${err.message}), so rules on interfaces not known here count as possible matches.`);
      return [] as Record<string, unknown>[];
    }),
    // Every pf table, including internal ones such as bogons and virusprot.
    client.get('firewall/alias_util/aliases').catch(() => []),
  ]);

  const definedAliases = new Map<string, string[]>();
  const context: NetworkContext = {
    interfaces: interfaceRows.filter((r) => str(r.identifier)).map(interfaceInfo),
    unassigned: interfaceRows.filter((r) => !str(r.identifier)).map(interfaceInfo),
    aliasMembership: new Map(),
    knownAliases: new Set(),
    portAliases: new Map(),
    groups: new Map(),
    definedAliases,
    groupsUnreadable,
  };
  for (const row of aliasRows) {
    const name = str(row.name).toLowerCase();
    const content = str(row.content).split(/[\s,]+/).filter(Boolean);
    context.knownAliases.add(name);
    if (str(row.type) === 'port') context.portAliases.set(name, content);
    // A disabled alias loads no table.
    if (STATIC_ALIAS_TYPES.has(str(row.type))) definedAliases.set(name, row.enabled !== undefined && !flag(row.enabled) ? [] : content);
  }
  if (Array.isArray(tables)) for (const t of tables) context.knownAliases.add(String(t).toLowerCase());
  for (const g of groupRows) {
    context.groups.set(str(g.ifname).toLowerCase(), str(g.members).split(',').map((m) => m.trim()).filter(Boolean));
  }

  const complete = rules.some((r) => r.legacy === true || r.is_automatic === true);
  if (!complete) {
    warnings.push('This firewall returned only MVC rules: automatic and legacy rules are not part of this evaluation, so the real outcome can differ. search_rule includes them on recent OPNsense versions.');
  }
  return { rules, context, complete, warnings };
}

/**
 * Asks pf which tables hold an address, which is cheaper and more exact than downloading
 * every table: bogons alone can hold over a hundred thousand entries.
 */
export async function loadAliasMembership(client: OpnsenseClient, ruleset: Ruleset, addresses: string[]): Promise<void> {
  for (const ip of new Set(addresses)) {
    try {
      const res = await client.post('firewall/alias_util/find_references', { ip: ip.toLowerCase() });
      const matches = isObject(res) && Array.isArray(res.matches) ? res.matches : null;
      if (matches) ruleset.context.aliasMembership.set(ip, new Set(matches.map((m) => String(m).toLowerCase())));
      else ruleset.warnings.push(`The alias lookup for ${ip} returned no usable answer, so rules using aliases are uncertain.`);
    } catch (err) {
      ruleset.warnings.push(`The alias lookup for ${ip} failed (${(err as Error).message}), so rules using aliases are uncertain.`);
    }
  }
}

export function interfaceForAddress(ip: string, interfaces: InterfaceInfo[]): InterfaceInfo | undefined {
  return interfaces.find((i) => i.addresses.some((a) => matchLiteral(a, ip) === true));
}

/** A port forward on the API port takes connections away from the firewall before any filter rule sees them. */
async function findPortForward(client: OpnsenseClient, ruleset: Ruleset, packet: Packet): Promise<{ row: Record<string, unknown>; definite: boolean } | undefined> {
  const rows = await fetchAll<Record<string, unknown>>(client, 'firewall/d_nat/search_rule').catch((err: Error) => {
    ruleset.warnings.push(`Port forwards could not be read (${err.message}), so they were not checked.`);
    return [] as Record<string, unknown>[];
  });
  let possible: { row: Record<string, unknown>; definite: boolean } | undefined;
  for (const row of rows) {
    if (flag(row.disabled) || flag(row.nordr) || flag(row.is_automatic)) continue;
    const { match } = matchRule(
      {
        interface: row.interface,
        ipprotocol: row.ipprotocol,
        protocol: row.protocol,
        source_net: row['source.network'],
        source_not: row['source.not'],
        source_port: row['source.port'],
        destination_net: row['destination.network'],
        destination_not: row['destination.not'],
        destination_port: row['destination.port'],
      },
      packet,
      ruleset.context,
    );
    if (match === 'yes') return { row, definite: true };
    if (match === 'unknown') possible ??= { row, definite: false };
  }
  return possible;
}

export interface LockoutReport {
  risk: 'none' | 'possible' | 'high' | 'unknown';
  management_path: { source: string | null; destination: string | null; port: number; interface: string | null };
  simulation?: SimulationResult;
  message: string;
  warnings: string[];
}

/** Would the configured ruleset still let this server reach the firewall's API? */
export async function checkLockout(client: OpnsenseClient): Promise<LockoutReport> {
  const url = new URL(client.config.url);
  const port = url.port ? Number(url.port) : url.protocol === 'https:' ? 443 : 80;
  const source = client.config.managementSource ?? client.localAddress ?? null;
  const destination = client.remoteAddress ?? (isIP(url.hostname) ? url.hostname : null);
  const path = { source, destination, port, interface: null as string | null };

  if (!source || !destination) {
    return { risk: 'unknown', management_path: path, message: 'The address of this server or of the firewall is not known yet, so the management path could not be checked.', warnings: [] };
  }
  const normalizedSource = source.replace(/^::ffff:/, '');
  const normalizedDestination = destination.replace(/^::ffff:/, '');
  if (normalizedSource === normalizedDestination || normalizedSource === '127.0.0.1' || normalizedSource === '::1') {
    return { risk: 'unknown', management_path: path, message: 'The connection goes through a local address (SSH tunnel or proxy?), so the path the firewall really sees is unknown. Set OPNSENSE_MANAGEMENT_SOURCE to enable this check.', warnings: [] };
  }

  const ruleset = await loadRuleset(client);
  // Without a directly connected source, the traffic enters on the interface the firewall address belongs to.
  const direct = interfaceForAddress(normalizedSource, ruleset.context.interfaces);
  const tunnel = direct ? undefined : interfaceForAddress(normalizedSource, ruleset.context.unassigned ?? []);
  if (tunnel) {
    return { risk: 'unknown', management_path: { ...path, interface: tunnel.device }, message: `This server arrives through ${tunnel.device}, an interface with no assignment (a VPN tunnel?) whose rules cannot be evaluated here, so the management path could not be checked.`, warnings: ruleset.warnings };
  }
  const iface = direct ?? interfaceForAddress(normalizedDestination, ruleset.context.interfaces);
  if (!iface) {
    return { risk: 'unknown', management_path: path, message: 'No interface of the firewall matches the management path, so it could not be checked.', warnings: ruleset.warnings };
  }
  path.interface = iface.identifier;
  if (!direct) ruleset.warnings.push(`${normalizedSource} is not on a network attached to the firewall, so it is assumed to enter on ${iface.identifier}. A VPN or a routed path can enter elsewhere, where other rules apply.`);

  await loadAliasMembership(client, ruleset, [normalizedSource, normalizedDestination]);
  const packet: Packet = { source: normalizedSource, destination: normalizedDestination, protocol: 'tcp', destinationPort: port, interface: iface.identifier, direction: 'in' };
  const simulation = simulate(ruleset.rules, packet, ruleset.context);
  const denied = simulation.verdict === 'block' || simulation.verdict === 'reject' || simulation.verdict === 'none';
  let risk: LockoutReport['risk'];
  let message: string;
  if (denied && simulation.certainty === 'definite' && ruleset.complete) {
    risk = 'high';
    message = `The ruleset would ${simulation.verdict === 'none' ? 'not pass' : simulation.verdict} new connections from this server (${normalizedSource}) to the API (${normalizedDestination}:${port}) on ${iface.identifier}.`;
  } else if (denied || simulation.certainty === 'uncertain') {
    risk = 'possible';
    message = `The ruleset might cut this server off from the API (${normalizedDestination}:${port}). See the possible matches in the simulation.`;
  } else {
    risk = 'none';
    message = `The ruleset keeps the management path open: ${simulation.explanation}`;
    const gateway = simulation.deciding_rule?.gateway;
    if (gateway) {
      risk = 'possible';
      message = `The rule that passes this path also sends its traffic through gateway ${gateway}, which can divert what is meant for the firewall itself.`;
    }
  }
  const forward = await findPortForward(client, ruleset, packet);
  if (forward && (forward.definite || risk === 'none')) {
    risk = forward.definite ? 'high' : 'possible';
    const label = str(forward.row.description ?? forward.row.descr) || str(forward.row.uuid);
    message = `A port forward ("${label}") ${forward.definite ? 'would send' : 'may send'} connections to the API (${normalizedDestination}:${port}) to ${str(forward.row.target) || 'another host'}.`;
  }
  return { risk, management_path: path, simulation, message, warnings: ruleset.warnings };
}
