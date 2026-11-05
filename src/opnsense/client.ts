import http from 'node:http';
import https from 'node:https';
import { Buffer } from 'node:buffer';
import type { InstanceConfig } from '../config.js';
import { OpnsenseError } from './errors.js';
import { authorize, type AuthorizeOptions, type Decision } from './policy.js';
import { assertNoRedactedValue, redactJson, scrubText } from './redact.js';

export type Method = 'GET' | 'POST';

export interface RequestOptions extends AuthorizeOptions {
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined>;
  /** Extra path segments (uuid, service name...), validated one by one. */
  params?: Array<string | number>;
  /** Return the body as text instead of parsing JSON. */
  text?: boolean;
  /** Keep secrets in the response. Only honoured when the instance allows sensitive data. */
  includeSensitive?: boolean;
  timeoutMs?: number;
  /** Open a new connection: a kept-alive one keeps its pf state through a reload, so it proves nothing about new ones. */
  freshConnection?: boolean;
  /** Simulate this write instead of sending it. */
  dryRun?: boolean;
  /** Filled with the requests a dry run would have sent. */
  dryRunLog?: DryRunEntry[];
}

export interface DryRunEntry {
  method: Method;
  path: string;
  body?: unknown;
}

export interface Capabilities {
  /** Null when the version could not be read (the API user lacks the firmware privilege). */
  version: string | null;
  major: number | null;
  minor: number | null;
  apiStyle: 'snake_case' | 'camelCase';
  /** Native firewall-side rollback timer. Removed upstream in OPNsense 26.7. */
  nativeSavepoints: boolean | null;
}

/** Synthetic identifier returned by simulated creates, so that later steps can still run. */
export const DRY_RUN_UUID = '00000000-0000-4000-8000-000000000000';

const MAX_RETRIES = 2;
const MAX_CONCURRENCY = 4;
const RETRYABLE_STATUS = new Set([502, 503, 504]);
const TLS_ERROR_CODES = /CERT|SSL|TLS|SELF_SIGNED|UNABLE_TO_VERIFY|HOSTNAME|ALTNAME/;

/** snake_case action to camelCase, as firewalls older than 25.7 expect it. */
export function toCamelAction(action: string): string {
  return action.replace(/_([a-zA-Z0-9])/g, (_, c: string) => c.toUpperCase());
}

export function parseVersion(version: string): { major: number; minor: number } | null {
  const m = /^(\d+)\.(\d+)/.exec(version);
  return m ? { major: Number(m[1]), minor: Number(m[2]) } : null;
}

function atLeast(major: number, minor: number, wantMajor: number, wantMinor: number): boolean {
  return major > wantMajor || (major === wantMajor && minor >= wantMinor);
}

interface RawResponse {
  status: number;
  contentType: string;
  body: string;
  localAddress?: string;
  remoteAddress?: string;
}

export class OpnsenseClient {
  private readonly agent: http.Agent;
  private readonly agentOptions: https.AgentOptions;
  private readonly base: URL;
  private readonly authHeader: string;
  private capabilitiesCache?: Capabilities;
  private capabilitiesPromise?: Promise<Capabilities>;
  private active = 0;
  private readonly waiting: Array<() => void> = [];
  /** Last address seen for the connection to the firewall, used by the lockout check. */
  localAddress?: string;
  remoteAddress?: string;

  constructor(
    readonly config: InstanceConfig,
    private readonly unblocked: readonly string[] = [],
    private readonly onWrite?: (entry: { method: Method; path: string; body?: unknown; status: string }) => void,
  ) {
    this.base = new URL(config.url);
    this.authHeader = `Basic ${Buffer.from(`${config.apiKey}:${config.apiSecret}`).toString('base64')}`;
    const options: https.AgentOptions = { keepAlive: true, maxSockets: MAX_CONCURRENCY };
    if (this.base.protocol === 'https:') {
      options.rejectUnauthorized = config.verifySsl;
      if (config.ca) options.ca = config.ca;
      this.agent = new https.Agent(options);
    } else {
      this.agent = new http.Agent(options);
    }
    this.agentOptions = options;
  }

  close(): void {
    this.agent.destroy();
  }

  get(path: string, opts: RequestOptions = {}): Promise<unknown> {
    return this.request('GET', path, opts);
  }

  post(path: string, body?: unknown, opts: RequestOptions = {}): Promise<unknown> {
    return this.request('POST', path, { ...opts, body });
  }

  /** The chokepoint: every call to the firewall goes through here and through the policy. */
  async request(method: Method, path: string, opts: RequestOptions = {}): Promise<unknown> {
    const params = (opts.params ?? []).map(String);
    const fullPath = [path, ...params].join('/');
    const decision = authorize(this.config, fullPath, method, this.unblocked, opts);
    if (opts.body !== undefined) assertNoRedactedValue(opts.body, path);

    if (decision.access === 'write' && (opts.dryRun || this.config.dryRun)) {
      return this.simulateWrite(method, fullPath, opts);
    }

    const capabilities = await this.capabilities();
    let response: RawResponse;
    try {
      response = await this.send(method, this.styledPath(fullPath, capabilities.apiStyle), opts);
    } catch (err) {
      this.auditWrite(decision, method, fullPath, opts.body, `error: ${(err as Error).message}`);
      throw err;
    }
    // Version unknown: 404 on snake_case can mean a firewall older than 25.7.
    if (response.status === 404 && capabilities.version === null && capabilities.apiStyle === 'snake_case') {
      const camel = this.styledPath(fullPath, 'camelCase');
      if (camel !== fullPath) {
        const retried = await this.send(method, camel, opts);
        if (retried.status !== 404) {
          capabilities.apiStyle = 'camelCase';
          response = retried;
        }
      }
    }
    this.auditWrite(decision, method, fullPath, opts.body, String(response.status));
    return this.parse(response, fullPath, method, decision, opts);
  }

  /** Detects the version once. Never throws: an unknown version just means probing later. */
  capabilities(): Promise<Capabilities> {
    if (this.capabilitiesCache) return Promise.resolve(this.capabilitiesCache);
    this.capabilitiesPromise ??= this.detectCapabilities()
      .then((caps) => {
        this.capabilitiesCache = caps;
        return caps;
      })
      .finally(() => {
        this.capabilitiesPromise = undefined;
      });
    return this.capabilitiesPromise;
  }

  /** Called when the savepoint endpoint turned out to be missing on an unknown version. */
  noteNoNativeSavepoints(): void {
    if (this.capabilitiesCache) this.capabilitiesCache.nativeSavepoints = false;
  }

  private async detectCapabilities(): Promise<Capabilities> {
    const unknown: Capabilities = { version: null, major: null, minor: null, apiStyle: 'snake_case', nativeSavepoints: null };
    let response: RawResponse;
    try {
      response = await this.send('GET', 'core/firmware/status', {});
    } catch (err) {
      // Connection and TLS failures concern every call: let the caller see them now.
      if (err instanceof OpnsenseError && ['unreachable', 'timeout', 'tls_error'].includes(err.type)) throw err;
      return unknown;
    }
    if (response.status === 401) this.throwForStatus(response, 'core/firmware/status');
    if (response.status !== 200) return unknown;
    let body: { product?: { product_version?: unknown }; product_version?: unknown };
    try {
      body = JSON.parse(response.body);
    } catch {
      return unknown;
    }
    // OPNsense 26.x nests this under "product"; older versions have it at the top level.
    const version = body.product?.product_version ?? body.product_version;
    if (typeof version !== 'string') return unknown;
    const parsed = parseVersion(version);
    if (!parsed) return { ...unknown, version };
    return {
      version,
      major: parsed.major,
      minor: parsed.minor,
      // ACL patterns are case-sensitive and follow this naming, so a restricted API user
      // gets a 403 with the wrong style even though the router would accept both.
      apiStyle: atLeast(parsed.major, parsed.minor, 25, 7) ? 'snake_case' : 'camelCase',
      nativeSavepoints: !atLeast(parsed.major, parsed.minor, 26, 7),
    };
  }

  private styledPath(path: string, style: Capabilities['apiStyle']): string {
    if (style === 'snake_case') return path;
    const segments = path.split('/');
    // Only the action is renamed: controllers keep their snake_case (firewall/d_nat).
    if (segments[2]) segments[2] = toCamelAction(segments[2]);
    return segments.join('/');
  }

  private simulateWrite(method: Method, path: string, opts: RequestOptions): Record<string, unknown> {
    opts.dryRunLog?.push({ method, path, ...(opts.body !== undefined ? { body: redactJson(opts.body) } : {}) });
    return { result: 'saved', status: 'ok', uuid: DRY_RUN_UUID, dry_run: true };
  }

  private auditWrite(decision: Decision, method: Method, path: string, body: unknown, status: string): void {
    if (decision.access === 'write') this.onWrite?.({ method, path, ...(body !== undefined ? { body: redactJson(body) } : {}), status });
  }

  private parse(response: RawResponse, path: string, method: Method, decision: Decision, opts: RequestOptions): unknown {
    if (response.status < 200 || response.status >= 300) this.throwForStatus(response, path);
    const keepSecrets = opts.includeSensitive === true && this.config.allowSensitive;
    if (opts.text) return keepSecrets || opts.redactedByCaller ? response.body : scrubText(response.body);

    if (/text\/html/i.test(response.contentType) || /^\s*<(!doctype|html)/i.test(response.body)) {
      throw new OpnsenseError('bad_response', `The firewall answered ${path} with an HTML page instead of JSON.`, {
        hint: 'Check OPNSENSE_URL: it should point at the OPNsense web interface, without a reverse proxy login page in front. A session redirect also produces this.',
      });
    }
    let json: unknown;
    try {
      json = response.body === '' ? {} : JSON.parse(response.body);
    } catch {
      // Exports answer with CSV or plain text even without the text option.
      if (decision.sensitive || method === 'GET') return { text: keepSecrets ? response.body : scrubText(response.body) };
      throw new OpnsenseError('bad_response', `The firewall returned invalid JSON for ${path}.`);
    }
    return keepSecrets ? json : redactJson(json);
  }

  private throwForStatus(response: RawResponse, path: string): never {
    const status = response.status;
    let message: string | undefined;
    try {
      const body = JSON.parse(response.body) as { message?: unknown; errorMessage?: unknown };
      const m = body.message ?? body.errorMessage;
      if (typeof m === 'string') message = scrubText(m);
    } catch {
      /* not JSON: the status alone will have to do */
    }
    const detail = message ? ` (${message})` : '';
    switch (status) {
      case 401:
        throw new OpnsenseError('auth_failed', `The firewall rejected the API credentials${detail}.`, {
          status,
          hint: 'Check the API key and secret, and that the user is not disabled. Do not retry with the same credentials.',
        });
      case 403:
        throw new OpnsenseError('forbidden', `The API user has no privilege for ${path}${detail}.`, {
          status,
          hint: 'The credentials are fine: this is a missing privilege on this endpoint. Do not retry. Add the matching privilege to the user in System > Access, or use another tool.',
        });
      case 404:
        throw new OpnsenseError('not_found', `${path} does not exist on this firewall${detail}.`, {
          status,
          hint: 'The plugin that provides it may not be installed (see opn_list_plugins), or this OPNsense version does not have this endpoint. With a uuid, the item may no longer exist.',
        });
      case 400:
        throw new OpnsenseError('bad_request', `The firewall rejected the request to ${path}${detail}.`, { status });
      default:
        throw new OpnsenseError('upstream_error', `The firewall answered ${path} with HTTP ${status}${detail}.`, {
          status,
          ...(status >= 500 ? { hint: 'A server-side error. opn_system_log may tell why.' } : {}),
        });
    }
  }

  private async send(method: Method, path: string, opts: RequestOptions): Promise<RawResponse> {
    await this.acquire();
    try {
      // Only reads are retried: repeating a write that may have gone through is not safe.
      const attempts = method === 'GET' ? MAX_RETRIES + 1 : 1;
      for (let attempt = 1; ; attempt++) {
        try {
          const response = await this.sendOnce(method, path, opts);
          if (attempt < attempts && RETRYABLE_STATUS.has(response.status)) {
            await delay(attempt * 300);
            continue;
          }
          return response;
        } catch (err) {
          const retryable = err instanceof OpnsenseError && (err.type === 'unreachable' || err.type === 'timeout');
          if (attempt >= attempts || !retryable) throw err;
          await delay(attempt * 300);
        }
      }
    } finally {
      this.release();
    }
  }

  private sendOnce(method: Method, path: string, opts: RequestOptions): Promise<RawResponse> {
    const url = new URL(`${this.base.pathname.replace(/\/$/, '')}/api/${path}`, this.base);
    for (const [k, v] of Object.entries(opts.query ?? {})) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }
    const headers: Record<string, string> = { Authorization: this.authHeader, Accept: 'application/json' };
    let payload: string | undefined;
    if (method === 'POST') {
      // A JSON content type with an empty body makes OPNsense answer 400 "Invalid JSON syntax".
      payload = JSON.stringify(opts.body ?? {});
      headers['Content-Type'] = 'application/json';
      headers['Content-Length'] = String(Buffer.byteLength(payload));
    }
    const transport = this.base.protocol === 'https:' ? https : http;
    const timeoutMs = opts.timeoutMs ?? this.config.timeoutMs;
    const single = { ...this.agentOptions, keepAlive: false };
    const oneShot = !opts.freshConnection ? undefined : this.base.protocol === 'https:' ? new https.Agent(single) : new http.Agent(single);

    return new Promise<RawResponse>((resolve, reject) => {
      const req = transport.request(url, { method, headers, agent: oneShot ?? this.agent }, (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('error', (e) => reject(this.networkError(e, path)));
        res.on('end', () => {
          const socket = res.socket;
          if (socket?.localAddress) this.localAddress = socket.localAddress;
          if (socket?.remoteAddress) this.remoteAddress = socket.remoteAddress;
          resolve({
            status: res.statusCode ?? 0,
            contentType: String(res.headers['content-type'] ?? ''),
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      });
      req.setTimeout(timeoutMs, () => {
        req.destroy(new OpnsenseError('timeout', `The firewall did not answer ${path} within ${Math.round(timeoutMs / 1000)} s.`, {
          hint: 'If a firewall change was just applied, it may have cut this connection: see opn_pending_changes.',
        }));
      });
      req.on('error', (e) => reject(this.networkError(e, path)));
      req.on('close', () => oneShot?.destroy());
      if (payload !== undefined) req.write(payload);
      req.end();
    });
  }

  private networkError(err: Error & { code?: string }, path: string): OpnsenseError {
    if (err instanceof OpnsenseError) return err;
    const code = err.code ?? '';
    if (TLS_ERROR_CODES.test(code)) {
      return new OpnsenseError('tls_error', `The TLS certificate of ${this.config.url} was refused (${code}).`, {
        hint: 'OPNsense uses a self-signed certificate by default. Point OPNSENSE_CA_FILE at the certificate to keep verification on, or set OPNSENSE_VERIFY_SSL=false on a trusted network.',
      });
    }
    return new OpnsenseError('unreachable', `Cannot reach the firewall for ${path} (${code || err.message}).`, {
      hint: 'Check the URL and port, and that this host may access the web interface (System > Settings > Administration). If a firewall change was just applied, see opn_pending_changes.',
    });
  }

  private async acquire(): Promise<void> {
    if (this.active < MAX_CONCURRENCY) {
      this.active++;
      return;
    }
    await new Promise<void>((resolve) => this.waiting.push(resolve));
  }

  private release(): void {
    const next = this.waiting.shift();
    if (next) next();
    else this.active--;
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
