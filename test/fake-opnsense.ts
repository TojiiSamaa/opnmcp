import { randomUUID } from 'node:crypto';
import http from 'node:http';
import type { AddressInfo } from 'node:net';

/**
 * A stand-in for the OPNsense API, written from the PHP controllers. It reproduces the
 * behaviours the server depends on: HTTP 200 with result=failed on validation errors, 400 on an
 * empty JSON body, a backup per configuration save, a revert that only rewrites the
 * configuration, and the removal of savepoints in 26.7.
 *
 * It is a model of the API and not a substitute for a real firewall.
 */
export interface RecordedRequest {
  method: string;
  path: string;
  query: URLSearchParams;
  body: unknown;
}

type Row = Record<string, unknown>;
type Handler = (req: RecordedRequest, params: string[]) => unknown;

export interface FakeOptions {
  /** null: the API user cannot read the firmware status, so the version stays unknown. */
  version?: string | null;
  key?: string;
  secret?: string;
  /** Answer anything unknown with a generic reply, instead of 404. */
  permissive?: boolean;
}

export class Reply {
  constructor(
    readonly status: number,
    readonly body: unknown,
    readonly contentType = 'application/json',
  ) {}
}

const GENERIC = { rows: [], total: 0, rowCount: 0, current: 1, status: 'ok', result: 'saved', uuid: '11111111-1111-4111-8111-111111111111' };

const AUTOMATIC_RULE: Row = { uuid: 'auto-1', is_automatic: true, action: 'pass', interface: 'lan', ipprotocol: 'inet46', protocol: 'any', source_net: 'any', destination_net: '(self)', destination_port: '443', quick: '1', enabled: '1', description: 'anti-lockout' };

export class FakeOpnsense {
  readonly requests: RecordedRequest[] = [];
  readonly handlers = new Map<string, Handler>();
  rules: Row[] = [];
  /** What pf is running: the rules as of the last apply. */
  appliedRules: Row[] = [];
  backups: Array<{ id: string; username: string; description: string; time: string; rules: Row[] }> = [];
  aliasTables: Record<string, string[]> = {};
  username = 'root@api';
  connections = 0;
  /** Connections already open keep working, as they do through a pf reload that blocks new ones. */
  refuseNewConnections = false;
  private backupCounter = 0;
  private server?: http.Server;
  url = '';

  constructor(readonly options: FakeOptions = {}) {
    this.rules = [{ ...AUTOMATIC_RULE }];
    this.appliedRules = this.clone(this.rules);
    this.saveRevision('initial');
    this.install();
  }

  get version(): string | null {
    return this.options.version === undefined ? '26.7.8' : this.options.version;
  }

  private get hasSavepoints(): boolean {
    const v = this.version;
    if (!v) return false;
    const [major = 0, minor = 0] = v.split('.').map(Number);
    return major < 26 || (major === 26 && minor < 7);
  }

  private clone<T>(value: T): T {
    return JSON.parse(JSON.stringify(value)) as T;
  }

  /** Config::save() copies the new file to /conf/backup, so the newest backup equals the config. */
  saveRevision(description: string, username = this.username): void {
    this.backupCounter++;
    this.backups.unshift({ id: `config-1762000000.${String(this.backupCounter).padStart(4, '0')}.xml`, username, description, time: new Date().toISOString(), rules: this.clone(this.rules) });
  }

  writes(): RecordedRequest[] {
    return this.requests.filter((r) => r.method === 'POST' && !/search|query|find_references/.test(r.path));
  }

  called(path: string): RecordedRequest[] {
    return this.requests.filter((r) => r.path === path || r.path.startsWith(`${path}/`));
  }

  on(path: string, handler: Handler): void {
    this.handlers.set(path, handler);
  }

  private grid(rows: Row[], req: RecordedRequest): Row {
    const body = (req.body ?? {}) as Row;
    const phrase = String(body.searchPhrase ?? '').toLowerCase();
    const filtered = phrase ? rows.filter((r) => JSON.stringify(r).toLowerCase().includes(phrase)) : rows;
    const rowCount = Number(body.rowCount ?? -1);
    const current = Number(body.current ?? 1);
    const page = rowCount > 0 ? filtered.slice((current - 1) * rowCount, current * rowCount) : filtered;
    return { rows: page, total: filtered.length, rowCount: page.length, current };
  }

  private install(): void {
    const on = this.on.bind(this);

    on('core/firmware/status', () => (this.version === null ? new Reply(403, { message: 'Forbidden' }) : { status: 'none', product: { product_version: this.version } }));
    on('core/system/status', () => ({ metadata: { system: { status: 2 } } }));
    on('core/firmware/info', () => ({ plugin: [{ name: 'os-haproxy', version: '4.0', installed: '1', comment: 'proxy' }, { name: 'os-tor', version: '1.0', installed: '0', comment: 'tor' }] }));

    on('interfaces/overview/interfaces_info', (req) =>
      this.grid(
        [
          { identifier: 'lan', device: 'igb1', description: 'LAN', status: 'up', addr4: '127.0.0.1/8', link_typev6: 'track6', ipv4: [{ ipaddr: '127.0.0.1/8' }] },
          { identifier: 'wan', device: 'igb0', description: 'WAN', status: 'up', addr4: '203.0.113.2/24', ipv4: [{ ipaddr: '203.0.113.2/24' }] },
        ],
        req,
      ));

    on('firewall/filter/search_rule', (req) => this.grid(this.rules, req));
    on('firewall/filter/get_rule', (_req, [id]) => {
      const rule = this.rules.find((r) => r.uuid === id);
      return { rule: rule ?? { action: { pass: { value: 'Pass', selected: 1 }, block: { value: 'Block', selected: 0 } }, description: '' } };
    });
    on('firewall/filter/add_rule', (req) => {
      const rule = ((req.body ?? {}) as { rule?: Row }).rule ?? {};
      if (!['pass', 'block', 'reject'].includes(String(rule.action))) return { result: 'failed', validations: { 'rule.action': 'Option not in list' } };
      const uuid = randomUUID();
      // Automatic rules keep their priority group: new rules land after them.
      this.rules.push({ uuid, enabled: '1', quick: '1', ipprotocol: 'inet', protocol: 'any', source_net: 'any', destination_net: 'any', ...rule });
      this.saveRevision('add rule');
      return { result: 'saved', uuid };
    });
    on('firewall/filter/set_rule', (req, [id]) => {
      const rule = this.rules.find((r) => r.uuid === id);
      if (!rule) return { result: 'failed' };
      Object.assign(rule, ((req.body ?? {}) as { rule?: Row }).rule);
      this.saveRevision('set rule');
      return { result: 'saved' };
    });
    on('firewall/filter/del_rule', (_req, [id]) => {
      const before = this.rules.length;
      this.rules = this.rules.filter((r) => r.uuid !== id);
      if (this.rules.length === before) return { result: 'not found' };
      this.saveRevision('del rule');
      return { result: 'deleted' };
    });
    on('firewall/filter/toggle_rule', (_req, [id, enabled]) => {
      const rule = this.rules.find((r) => r.uuid === id);
      if (!rule) return { result: 'not found' };
      const result = enabled === '1' ? 'Enabled' : 'Disabled';
      // No change, no save: ApiMutableModelControllerBase::toggleBase.
      if (String(rule.enabled) === String(enabled)) return { result, changed: false };
      rule.enabled = enabled;
      this.saveRevision('toggle rule');
      return { result, changed: true };
    });
    on('firewall/filter/move_rule_before', (_req, [id, before]) => {
      const from = this.rules.findIndex((r) => r.uuid === id);
      const to = this.rules.findIndex((r) => r.uuid === before);
      if (from < 0 || to < 0) return { status: 'failed' };
      const [rule] = this.rules.splice(from, 1);
      this.rules.splice(this.rules.findIndex((r) => r.uuid === before), 0, rule!);
      this.saveRevision('move rule');
      return { status: 'ok' };
    });

    on('firewall/filter/savepoint', () => (this.hasSavepoints ? { revision: '1762000000.123', status: 'ok' } : new Reply(404, { message: 'Endpoint not found' })));
    on('firewall/filter/apply', (_req, [revision]) => {
      if (revision && !this.hasSavepoints) return new Reply(404, { message: 'Endpoint not found' });
      this.appliedRules = this.clone(this.rules);
      return { status: 'OK\n' };
    });
    // rollback_cancel.php prints nothing, so a successful cancel has an empty status.
    on('firewall/filter/cancel_rollback', () => (this.hasSavepoints ? { status: '' } : new Reply(404, { message: 'Endpoint not found' })));
    on('firewall/filter/revert', () => {
      if (!this.hasSavepoints) return new Reply(404, { message: 'Endpoint not found' });
      const baseline = this.backups.at(-1);
      this.rules = this.clone(baseline?.rules ?? []);
      this.appliedRules = this.clone(this.rules);
      return { status: 'ok' };
    });

    on('firewall/alias/search_item', (req) => this.grid(Object.keys(this.aliasTables).map((name) => ({ uuid: randomUUID(), name, type: 'host', content: this.aliasTables[name]!.join('\n'), enabled: '1' })), req));
    on('firewall/alias/reconfigure', () => ({ status: 'ok' }));
    on('firewall/alias_util/aliases', () => ['bogons', 'virusprot', ...Object.keys(this.aliasTables)]);
    on('firewall/alias_util/find_references', (req) => {
      const ip = String(((req.body ?? {}) as Row).ip);
      return { status: 'ok', matches: Object.entries(this.aliasTables).filter(([, members]) => members.includes(ip)).map(([name]) => name) };
    });
    on('firewall/group/search_item', (req) => this.grid([], req));
    on('firewall/filter_util/rule_stats', () => ({ status: 'ok', stats: {} }));

    on('core/backup/backups', () => ({ items: this.backups.map(({ id, username, description, time }) => ({ id, username, description, time })) }));
    on('core/backup/revert_backup', (_req, [id]) => {
      const backup = this.backups.find((b) => b.id === id);
      if (!backup) return { status: 'not_found' };
      this.rules = this.clone(backup.rules);
      // It rewrites the configuration and nothing else: pf keeps running the old rules.
      this.saveRevision('revert', this.username);
      return { status: 'reverted' };
    });
    on('core/backup/download', () => new Reply(200, '<?xml version="1.0"?><opnsense><system><hostname>fw</hostname><webgui><protocol>https</protocol></webgui><ssh><enabled>enabled</enabled><permitrootlogin>1</permitrootlogin><passwordauth>1</passwordauth></ssh><user><name>root</name><password>$2y$secret-hash</password></user></system><filter><rule><descr>legacy</descr></rule></filter></opnsense>', 'application/xml'));
  }

  start(): Promise<string> {
    const auth = `Basic ${Buffer.from(`${this.options.key ?? 'key'}:${this.options.secret ?? 'secret'}`).toString('base64')}`;
    this.server = http.createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        const respond = (status: number, body: unknown, contentType = 'application/json') => {
          res.writeHead(status, { 'Content-Type': contentType });
          res.end(typeof body === 'string' ? body : JSON.stringify(body));
        };
        if (req.headers.authorization !== auth) return respond(401, { status: 401, message: 'Authentication Failed' });

        const url = new URL(req.url ?? '/', 'http://fake');
        const path = url.pathname.replace(/^\/api\//, '');
        const text = Buffer.concat(chunks).toString('utf8');
        // The real API rejects a JSON content type with an empty body.
        if (req.method === 'POST' && text === '' && /json/.test(String(req.headers['content-type']))) {
          return respond(400, { errorMessage: 'Invalid JSON syntax' });
        }
        const record: RecordedRequest = { method: req.method ?? 'GET', path, query: url.searchParams, body: text ? JSON.parse(text) : undefined };
        this.requests.push(record);

        const segments = path.split('/');
        const handler = this.handlers.get(segments.slice(0, 3).join('/'));
        if (handler) {
          const out = handler(record, segments.slice(3));
          if (out instanceof Reply) return respond(out.status, out.body, out.contentType);
          return respond(200, out);
        }
        if (this.options.permissive) return respond(200, GENERIC);
        return respond(404, { errorMessage: 'Endpoint not found' });
      });
    });
    this.server.on('connection', (socket) => {
      this.connections++;
      if (this.refuseNewConnections) socket.destroy();
    });
    return new Promise((resolve) => {
      this.server!.listen(0, '127.0.0.1', () => {
        this.url = `http://127.0.0.1:${(this.server!.address() as AddressInfo).port}`;
        resolve(this.url);
      });
    });
  }

  stop(): Promise<void> {
    return new Promise((resolve) => {
      this.server?.closeAllConnections();
      this.server?.close(() => resolve());
    });
  }
}
