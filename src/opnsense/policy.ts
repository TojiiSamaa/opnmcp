import { OpnsenseError } from './errors.js';

/**
 * Access policy, enforced by the HTTP client so that no tool can get around it.
 *
 * The HTTP verb says nothing reliable on OPNsense:
 *  - some GETs change state (redis/service/resetdb, acmeclient/service/reset,
 *    netbird/authentication/down, auth/user/new_otp_seed);
 *  - many POSTs only read (firewall/filter/search_rule, diagnostics/firewall/query_states).
 * So access is decided from the command name, and an unrecognised command counts as
 * a write: the policy fails closed.
 *
 * Matching works on a canonical form. The OPNsense router maps both
 * core/system/re_boot and core/system/reboot to rebootAction (PHP method names are
 * case-insensitive), so comparing raw strings would make the blocklist easy to bypass.
 */
export type Access = 'read' | 'write';

export interface Decision {
  access: Access;
  /** The response can contain secrets that key-based redaction cannot catch. */
  sensitive: boolean;
  blocked?: { reason: string };
}

const SAFE_SEGMENT = /^[A-Za-z0-9_.,:-]+$/;

export function canonicalSegment(segment: string): string {
  return segment.toLowerCase().replaceAll('_', '');
}

/** Rejects anything that could walk the request out of the intended endpoint. */
export function assertSafePath(path: string): string[] {
  const segments = path.split('/');
  if (segments.length < 3) {
    throw new OpnsenseError('invalid_path', `"${path}" is not an API path: expected module/controller/command.`);
  }
  for (const segment of segments) {
    if (!SAFE_SEGMENT.test(segment) || /^\.+$/.test(segment)) {
      throw new OpnsenseError('invalid_path', `Invalid path segment "${segment}" in "${path}".`, {
        hint: 'Path segments may only contain letters, digits and _ . , : -',
      });
    }
  }
  return segments;
}

export function canonicalPath(path: string): string {
  return path.split('/').slice(0, 3).map(canonicalSegment).join('/');
}

function canon(paths: string[]): Map<string, string> {
  return new Map(paths.map((p) => [canonicalPath(p), p]));
}

/** Never reachable, whichever tool asks, unless the operator lists them in OPNSENSE_UNBLOCK. */
const BLOCKED = canon([
  // Power and updates: the firewall would go down with the session that asked for it.
  'core/system/halt',
  'core/system/reboot',
  'core/firmware/poweroff',
  'core/firmware/reboot',
  'core/firmware/update',
  'core/firmware/upgrade',
  'core/firmware/install',
  'core/firmware/reinstall',
  'core/firmware/remove',
  'core/firmware/lock',
  'core/firmware/unlock',
  'core/firmware/resync_plugins',
  'core/firmware/sync_plugins',
  'core/firmware/set',
  // Factory reset and boot environments.
  'core/defaults/factory_defaults',
  'core/defaults/reset',
  'core/snapshots/activate',
  'core/snapshots/del',
  // Accounts and API keys: an agent must not be able to grant itself access.
  'auth/user/add',
  'auth/user/del',
  'auth/user/set',
  'auth/user/upload',
  'auth/user/download',
  'auth/user/add_api_key',
  'auth/user/del_api_key',
  'auth/user/new_otp_seed',
  'auth/group/add',
  'auth/group/del',
  'auth/group/set',
  'auth/priv/set',
  'auth/priv/set_item',
  // A scheduled job can run a configd action, including a reboot or a firmware update.
  'cron/settings/add_job',
  'cron/settings/set_job',
  'cron/settings/set',
  // These drop every connection through the box at once.
  'diagnostics/firewall/flush_states',
  'diagnostics/firewall/flush_sources',
  // Its filter loses "/" and ":" on the way, and "." matches every IPv4 state: opn_kill_states is the way.
  'diagnostics/firewall/kill_states',
  // Irreversibly deletes the legacy rules.
  'firewall/migration/flush',
  'firewall/migration/flush_outbound',
  // Destroys the history the rollback relies on.
  'core/backup/delete_backup',
  // Records network traffic on demand.
  'diagnostics/packet_capture/set',
  'diagnostics/packet_capture/start',
  'diagnostics/packet_capture/download',
  'diagnostics/packet_capture/view',
]);

/** Only reachable through a dedicated tool that adds its own safeguards, never through the generic tools. */
const CURATED_ONLY = canon([
  'core/backup/revert_backup',
  // Lines of config.xml, secrets included, where key-based redaction cannot see them.
  'core/backup/diff',
]);

/** POST endpoints that do not touch the configuration. */
const READ_ONLY_POSTS = canon([
  // These models are mounted ":memory:" on the firewall: nothing is saved to config.xml.
  'diagnostics/ping/set',
  'diagnostics/ping/start',
  'diagnostics/ping/stop',
  'diagnostics/ping/remove',
  'diagnostics/traceroute/set',
  'diagnostics/dns_diagnostics/set',
  'diagnostics/portprobe/set',
  'firewall/alias_util/find_references',
  'unbound/diagnostics/test_blocklist',
  'core/firmware/changelog',
  'core/firmware/details',
  'core/firmware/license',
]);

/**
 * Canonical command prefixes that only read. Short words stay out of this list on purpose:
 * with a "ca" prefix, diagnostics/interface/carp_status (which changes the CARP state) would
 * pass for a read. Those go in READ_COMMANDS below, which is matched exactly.
 */
const READ_PREFIX = /^(get|search|list|show|query|find|count|dump|status|stats|statistics|view)/;

/** Whole commands that only read, taken from an audit of the API catalog. */
const READ_COMMANDS = new Set([
  'accesses', 'accounts', 'aliases', 'backups', 'bfdcounters', 'bfdneighbors', 'bfdstaticroute', 'bfdsummary',
  'bgpneighbors', 'bgpsummary', 'cachestats', 'caddyfile', 'cainfo', 'calist', 'certdiff', 'checkclamav', 'checkredis',
  'chronyauthdata', 'chronysources', 'chronysourcestats', 'chronytracking', 'circuits', 'config', 'configtest',
  'connectionexists', 'counters', 'daily', 'diff', 'dirty', 'errors', 'generalrunningconfig', 'gps', 'hourly', 'index', 'info',
  'interface', 'interfacelist', 'interfacesinfo', 'ip', 'isblocklistenabled', 'isenabled', 'issupported', 'logfilters',
  'macinfo', 'memory', 'meta', 'monthly', 'neighbor', 'net', 'ospfdatabase', 'ospfinterface', 'ospfoverview',
  'ospfv3interface', 'ospfv3overview', 'pending', 'pfstates', 'pfstatistics', 'picture', 'pools', 'powerstatus',
  'productinfofeed', 'providers', 'remoteservice', 'report', 'reverselookup', 'rolling', 'rulestats', 'running',
  'services', 'streams', 'sum', 'swanctl', 'systemdisk', 'systeminformation', 'systemmbuf', 'systemresources',
  'systemswap', 'systemtemperature', 'systemtime', 'tables', 'templates', 'testconfig', 'timeserie', 'tlshandshakes',
  'top', 'totals', 'tree', 'upgradestatus', 'upsstatus', 'userlist', 'version', 'vts', 'yearly', 'zones', 'zoneshow',
  'zonetest',
]);

/** Paths whose command is ambiguous on its own: core/firmware/log takes a "clear" parameter. */
const READ_PATHS = canon(['diagnostics/firewall/log']);

/** Output that key-based redaction cannot make safe: key material, CSV or binary dumps. */
const SENSITIVE_COMMAND = /^(download|export|rawdump|generatefile|keypair|genkeypair|psk|genkey|newotpseed)/;

function explainBlocked(path: string): string {
  return `${path} is blocked: it can take the firewall down, grant access or destroy recovery data.`;
}

export function decide(path: string, method: 'GET' | 'POST', unblocked: readonly string[] = [], curated = false): Decision {
  const canonical = canonicalPath(path);
  const [module, controller, command = ''] = canonical.split('/');

  const unblockedSet = new Set(unblocked.map(canonicalPath));
  if (BLOCKED.has(canonical) && !unblockedSet.has(canonical)) {
    return { access: 'write', sensitive: false, blocked: { reason: explainBlocked(BLOCKED.get(canonical)!) } };
  }
  if (CURATED_ONLY.has(canonical) && !curated && !unblockedSet.has(canonical)) {
    return { access: 'write', sensitive: false, blocked: { reason: `${CURATED_ONLY.get(canonical)} is only available through its dedicated tool.` } };
  }
  // Server-sent event streams never finish, so a tool call would just hang until it times out.
  if (command.startsWith('stream')) {
    return { access: 'read', sensitive: false, blocked: { reason: `${path} is a live event stream, which tool calls cannot consume.` } };
  }

  // Log reads are POST with a dynamic scope: diagnostics/log/<module>/<scope>[/clear|export|live].
  if (module === 'diagnostics' && controller === 'log') {
    const action = path.split('/')[4]?.toLowerCase();
    if (action === 'clear') return { access: 'write', sensitive: false, blocked: { reason: 'Clearing logs is blocked: it destroys evidence.' } };
    if (action === 'live') return { access: 'read', sensitive: false, blocked: { reason: 'Live log streams cannot be consumed by a tool call.' } };
    return { access: 'read', sensitive: false };
  }

  const sensitive = SENSITIVE_COMMAND.test(command);
  if (READ_ONLY_POSTS.has(canonical) || READ_PATHS.has(canonical)) return { access: 'read', sensitive };
  if (sensitive && method === 'GET') return { access: 'read', sensitive };
  if (READ_PREFIX.test(command) || READ_COMMANDS.has(command)) return { access: 'read', sensitive };
  return { access: 'write', sensitive };
}

export interface PolicySubject {
  name: string;
  allowWrites: boolean;
  allowSensitive: boolean;
  dryRun: boolean;
}

export interface AuthorizeOptions {
  /** Set by tools that do their own redaction of a sensitive response (config download). */
  redactedByCaller?: boolean;
  /** Set by dedicated tools, as opposed to the generic opn_api_read and opn_api_write. */
  curated?: boolean;
  /** Set for tools announced as read-only: anything not proven to be a read is refused. */
  readOnly?: boolean;
}

/** Throws unless the call is allowed. Returns the decision for logging and dry-run handling. */
export function authorize(subject: PolicySubject, path: string, method: 'GET' | 'POST', unblocked: readonly string[], opts: AuthorizeOptions = {}): Decision {
  assertSafePath(path);
  const decision = decide(path, method, unblocked, opts.curated ?? false);
  if (decision.blocked) {
    throw new OpnsenseError('blocked_endpoint', decision.blocked.reason, {
      hint: 'Do not retry. A human can do this in the OPNsense web interface, or the operator can list the endpoint in OPNSENSE_UNBLOCK.',
    });
  }
  if (opts.readOnly && decision.access === 'write') {
    throw new OpnsenseError('not_read_only', `${path} is not known to be read-only, so a read tool refuses it: nothing was sent.`, {
      hint: 'If it does change something, opn_api_write is the tool for it, provided writes are enabled. If it only reads and this classification is wrong, a human can check it in the web interface.',
    });
  }
  if (decision.access === 'write' && !subject.allowWrites && !subject.dryRun) {
    throw new OpnsenseError('write_disabled', `Instance "${subject.name}" is read-only: ${path} was not sent.`, {
      hint: 'Do not retry. The operator can enable writes with OPNSENSE_ALLOW_WRITES=true (or allow_writes on the instance), or preview with OPNSENSE_DRY_RUN=true.',
    });
  }
  if (decision.sensitive && !subject.allowSensitive && !opts.redactedByCaller) {
    throw new OpnsenseError('sensitive_disabled', `${path} can return key material or raw exports, which are off by default.`, {
      hint: 'Do not retry. The operator can allow it with OPNSENSE_ALLOW_SENSITIVE=true. To read the configuration, use opn_get_config_section, which redacts secrets.',
    });
  }
  return decision;
}
