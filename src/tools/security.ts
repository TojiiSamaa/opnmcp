import { OpnsenseError } from '../opnsense/errors.js';
import { fetchAll, isObject } from '../opnsense/model.js';
import type { Rule } from '../opnsense/simulate.js';
import { analyzeRules } from './firewall.js';
import { tool, type ToolContext, type ToolDef } from './helpers.js';
import { fetchConfigJson } from './shared.js';

type Severity = 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  severity: Severity;
  section: string;
  check: string;
  message: string;
  recommendation?: string;
  [key: string]: unknown;
}

type Check = (ctx: ToolContext) => Promise<Finding[]>;

const DANGEROUS_FORWARD_PORTS: Record<string, string> = {
  '22': 'SSH', '23': 'Telnet', '139': 'NetBIOS', '445': 'SMB', '1433': 'MSSQL', '3306': 'MySQL', '3389': 'RDP',
  '5432': 'PostgreSQL', '5900': 'VNC', '6379': 'Redis', '9200': 'Elasticsearch', '27017': 'MongoDB',
};

/** Words that identify obsolete crypto in an IPsec proposal, compared on whole tokens. */
const WEAK_PROPOSAL = /(^|[-_,\s])(md5|sha1|3des|des|modp768|modp1024|modp1536)($|[-_,\s])/i;

const CERT_WARNING_DAYS = 30;

function on(value: unknown): boolean {
  return value === 1 || value === '1' || value === true;
}

/** Search rows are flattened with dotted keys; other versions nest the same fields. */
function field(row: Record<string, unknown>, group: string, name: string): string {
  const flat = row[`${group}.${name}`];
  if (flat !== undefined) return String(flat);
  const nested = row[group];
  return isObject(nested) && nested[name] !== undefined ? String(nested[name]) : '';
}

const checkFirmware: Check = async (ctx) => {
  const res = await ctx.api.get('core/firmware/status');
  const status = isObject(res) ? res : {};
  const findings: Finding[] = [];
  const add = (severity: Severity, check: string, message: string, recommendation?: string) =>
    findings.push({ severity, section: 'firmware', check, message, ...(recommendation ? { recommendation } : {}) });
  if (status.status === 'update' || status.status === 'upgrade') {
    add('medium', 'updates_available', 'Updates are available.', 'Review the changelog and update from the web interface. This server cannot install updates.');
  }
  if (status.needs_reboot === '1' || status.needs_reboot === 1) add('low', 'reboot_needed', 'A pending update needs a reboot to take effect.');
  if (status.upgrade_major_version) add('info', 'major_upgrade', `A new major version is available: ${String(status.upgrade_major_version)}.`);
  return findings;
};

const checkRules: Check = async (ctx) => {
  const rows = await fetchAll<Rule>(ctx.api, 'firewall/filter/search_rule');
  const statsRes = await ctx.api.get('firewall/filter_util/rule_stats').catch(() => null);
  const stats = isObject(statsRes) && isObject(statsRes.stats) ? statsRes.stats : null;
  const { findings } = analyzeRules(rows, stats) as { findings: Array<Record<string, unknown>> };
  return findings.map((f) => ({ ...f, section: 'firewall_rules' }) as Finding);
};

const checkNat: Check = async (ctx) => {
  const rows = await fetchAll<Record<string, unknown>>(ctx.api, 'firewall/d_nat/search_rule');
  const findings: Finding[] = [];
  for (const row of rows) {
    if (on(row.disabled)) continue;
    const source = field(row, 'source', 'network') || 'any';
    const port = field(row, 'destination', 'port');
    const service = DANGEROUS_FORWARD_PORTS[port];
    if (service && source.toLowerCase() === 'any') {
      findings.push({
        severity: 'high',
        section: 'nat',
        check: 'dangerous_port_forward',
        message: `${service} (port ${port}) is forwarded to ${String(row.target ?? '?')} from any source.`,
        recommendation: 'Restrict the source, or reach this service through a VPN.',
        uuid: row.uuid,
        rule: row.descr,
      });
    }
    const range = /^(\d+)[-:](\d+)$/.exec(port);
    if (range && Number(range[2]) - Number(range[1]) >= 100) {
      findings.push({
        severity: 'medium',
        section: 'nat',
        check: 'broad_port_forward',
        message: `Port range ${port} is forwarded to ${String(row.target ?? '?')}.`,
        uuid: row.uuid,
        rule: row.descr,
      });
    }
  }
  return findings;
};

const checkDns: Check = async (ctx) => {
  const res = await ctx.api.get('unbound/settings/get');
  const general = isObject(res) && isObject(res.unbound) && isObject(res.unbound.general) ? res.unbound.general : null;
  if (!general) throw new OpnsenseError('bad_response', 'Unexpected answer from unbound/settings/get.');
  if (!on(general.enabled)) return [{ severity: 'info', section: 'dns', check: 'unbound_disabled', message: 'Unbound is not enabled, so its checks do not apply.' }];
  return on(general.dnssec)
    ? []
    : [{ severity: 'low', section: 'dns', check: 'dnssec_disabled', message: 'DNSSEC validation is off in Unbound.', recommendation: 'Enable it unless a forwarder breaks it.' }];
};

const checkHardening: Check = async (ctx) => {
  const config = await fetchConfigJson(ctx);
  const findings: Finding[] = [];
  const add = (severity: Severity, check: string, message: string, recommendation?: string) =>
    findings.push({ severity, section: 'system', check, message, ...(recommendation ? { recommendation } : {}) });

  const system = isObject(config.system) ? config.system : {};
  const webgui = isObject(system.webgui) ? system.webgui : {};
  if (webgui.protocol === 'http') add('high', 'webgui_http', 'The web interface uses plain HTTP: credentials and API keys cross the network in clear text.', 'Switch to HTTPS in System > Settings > Administration.');

  const ssh = isObject(system.ssh) ? system.ssh : {};
  if (ssh.enabled === 'enabled') {
    if (on(ssh.permitrootlogin)) add('medium', 'ssh_root_login', 'SSH allows root to log in.', 'Log in as a normal user and use sudo.');
    if (on(ssh.passwordauth)) add('medium', 'ssh_password_auth', 'SSH accepts passwords.', 'Use keys only.');
    if (String(ssh.port ?? '22') === '22') add('info', 'ssh_default_port', 'SSH listens on the default port 22.');
  }

  const legacy = isObject(config.syslog) ? config.syslog : {};
  const opn = isObject(config.OPNsense) ? config.OPNsense : {};
  const syslog = isObject(opn.Syslog) ? opn.Syslog : {};
  const destinations = isObject(syslog.destinations) ? syslog.destinations.destination : undefined;
  const hasDestination = Array.isArray(destinations) ? destinations.length > 0 : isObject(destinations);
  if (!legacy.remoteserver && !legacy.remoteserver2 && !legacy.remoteserver3 && !hasDestination) {
    add('low', 'no_remote_logging', 'Logs stay on the firewall only: an attacker who gets in can erase them.', 'Add a destination in System > Settings > Logging.');
  }
  return findings;
};

const checkServices: Check = async (ctx) => {
  const rows = await fetchAll<Record<string, unknown>>(ctx.api, 'core/service/search');
  return rows
    .filter((s) => String(s.running) === '0')
    .map((s) => ({ severity: 'medium' as const, section: 'services', check: 'service_stopped', message: `${String(s.description ?? s.name)} is enabled but not running.`, service: s.name }));
};

const checkCertificates: Check = async (ctx) => {
  const rows = await fetchAll<Record<string, unknown>>(ctx.api, 'trust/cert/search');
  const findings: Finding[] = [];
  for (const cert of rows) {
    const seconds = Number(cert.valid_to);
    const time = Number.isFinite(seconds) && seconds > 0 ? seconds * 1000 : Date.parse(String(cert.valid_to));
    if (!Number.isFinite(time)) continue;
    const days = Math.floor((time - Date.now()) / 86_400_000);
    if (days < 0) findings.push({ severity: 'high', section: 'certificates', check: 'certificate_expired', message: `Certificate "${String(cert.descr)}" expired ${-days} day(s) ago.`, uuid: cert.uuid });
    else if (days <= CERT_WARNING_DAYS) findings.push({ severity: 'medium', section: 'certificates', check: 'certificate_expiring', message: `Certificate "${String(cert.descr)}" expires in ${days} day(s).`, uuid: cert.uuid });
  }
  return findings;
};

const checkVpn: Check = async (ctx) => {
  const rows = await fetchAll<Record<string, unknown>>(ctx.api, 'ipsec/connections/search_connection');
  return rows
    .filter((c) => WEAK_PROPOSAL.test(String(c.proposals ?? '')))
    .map((c) => ({ severity: 'medium' as const, section: 'vpn', check: 'weak_ipsec_proposal', message: `IPsec connection "${String(c.description ?? c.uuid)}" allows obsolete algorithms: ${String(c.proposals)}.`, uuid: c.uuid }));
};

const checkGateways: Check = async (ctx) => {
  const res = await ctx.api.get('routes/gateway/status');
  const items = isObject(res) && Array.isArray(res.items) ? (res.items as Array<Record<string, unknown>>) : [];
  return items
    .filter((g) => /down|force_down/i.test(String(g.status)))
    .map((g) => ({ severity: 'medium' as const, section: 'gateways', check: 'gateway_down', message: `Gateway ${String(g.name)} is down (${String(g.status_translated ?? g.status)}).` }));
};

const CHECKS: Record<string, Check> = {
  firmware: checkFirmware,
  firewall_rules: checkRules,
  nat: checkNat,
  dns: checkDns,
  system: checkHardening,
  services: checkServices,
  certificates: checkCertificates,
  vpn: checkVpn,
  gateways: checkGateways,
};

const MANUAL_REVIEW = [
  'Who has accounts and API keys, and whether each one is still needed: this server does not read them.',
  'Whether the web interface is reachable only from a management network.',
  'Whether configuration backups are stored off the firewall.',
  'Whether what the rules allow matches what the business needs: only a person can tell.',
];

const ORDER: Record<Severity, number> = { high: 0, medium: 1, low: 2, info: 3 };

export async function runAudit(ctx: ToolContext): Promise<Record<string, unknown>> {
  const names = Object.keys(CHECKS);
  const results = await Promise.allSettled(names.map((n) => CHECKS[n]!(ctx)));
  const findings: Finding[] = [];
  const checked: string[] = [];
  const skipped: Record<string, string> = {};
  results.forEach((r, i) => {
    const name = names[i]!;
    if (r.status === 'fulfilled') {
      checked.push(name);
      findings.push(...r.value);
    } else {
      skipped[name] = r.reason instanceof OpnsenseError ? `${r.reason.type}: ${r.reason.message}` : String(r.reason);
    }
  });
  findings.sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
  const summary = { high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) summary[f.severity]++;
  return {
    summary,
    findings,
    coverage: { checked, skipped },
    manual_review: MANUAL_REVIEW,
    note:
      Object.keys(skipped).length > 0
        ? 'Some sections could not be checked: a clean result covers only the sections under coverage.checked.'
        : 'These are automated checks on the configuration: no finding does not mean the firewall is secure.',
  };
}

export function securityTools(): ToolDef[] {
  return [
    tool({
      name: 'opn_security_audit',
      title: 'Security audit',
      description: 'Checks firmware, firewall rules, port forwards, DNS, system hardening, services, certificates, VPN and gateways, and lists the findings by severity. Sections the API user cannot read are listed under coverage.skipped rather than passed silently. Read-only.',
      domain: 'security',
      access: 'read',
      idempotent: true,
      input: {},
      handler: async (_args, ctx) => runAudit(ctx),
    }),
  ];
}
