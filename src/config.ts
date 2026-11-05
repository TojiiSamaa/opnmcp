import { readFileSync } from 'node:fs';
import { OpnsenseError } from './opnsense/errors.js';

export interface InstanceConfig {
  name: string;
  /** Base URL without trailing slash and without the /api suffix. */
  url: string;
  apiKey: string;
  apiSecret: string;
  verifySsl: boolean;
  /** PEM bundle to trust, for a self-signed firewall certificate with verification kept on. */
  ca?: string;
  allowWrites: boolean;
  allowSensitive: boolean;
  dryRun: boolean;
  description?: string;
  /** Source IP the firewall sees for this server, when NAT or a VPN hides the local address. */
  managementSource?: string;
  timeoutMs: number;
}

export interface ServerConfig {
  instances: Map<string, InstanceConfig>;
  defaultInstance: string;
  /** null means every toolset. */
  toolsets: Set<string> | null;
  rollbackSeconds: number;
  auditLog?: string;
  /** Endpoints the operator explicitly removed from the blocklist. */
  unblocked: string[];
  elicit: boolean;
  maxResponseChars: number;
}

export type Env = Record<string, string | undefined>;

const INSTANCE_NAME = /^[A-Za-z0-9_-]{1,32}$/;
const TRUE_VALUES = new Set(['true', '1', 'yes', 'on']);
const FALSE_VALUES = new Set(['false', '0', 'no', 'off', '']);

function configError(message: string, hint?: string): OpnsenseError {
  return new OpnsenseError('config_error', message, hint ? { hint } : {});
}

/** A typo in a safety flag must stop the server, not silently fall back to a default. */
function parseBool(name: string, value: string | boolean | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  if (typeof value === 'boolean') return value;
  const v = value.trim().toLowerCase();
  if (TRUE_VALUES.has(v)) return true;
  if (FALSE_VALUES.has(v)) return false;
  throw configError(`${name}: "${value}" is not a boolean (use true or false).`);
}

function parseInteger(name: string, value: string | number | undefined, fallback: number, min: number, max: number): number {
  if (value === undefined || value === '') return fallback;
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw configError(`${name}: "${value}" must be an integer between ${min} and ${max}.`);
  }
  return n;
}

function normalizeUrl(raw: string, label: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw configError(`${label}: "${raw}" is not a valid URL.`, 'Example: https://192.168.1.1 or https://fw.example.com:10443');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw configError(`${label}: only http and https URLs are supported.`);
  }
  if (url.username || url.password) {
    throw configError(`${label}: do not put credentials in the URL.`);
  }
  const path = url.pathname.replace(/\/+$/, '').replace(/\/api$/, '');
  return `${url.protocol}//${url.host}${path}`;
}

/** Reads the apikey.txt file OPNsense offers when a key is created (key=... / secret=...). */
function readCredentialsFile(path: string): { apiKey?: string; apiSecret?: string } {
  let text: string;
  try {
    text = readFileSync(path, 'utf8');
  } catch (err) {
    throw configError(`Cannot read credentials file ${path}: ${(err as Error).message}`);
  }
  const out: { apiKey?: string; apiSecret?: string } = {};
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*(key|secret)\s*=\s*(.+?)\s*$/.exec(line);
    if (m?.[1] === 'key') out.apiKey = m[2];
    if (m?.[1] === 'secret') out.apiSecret = m[2];
  }
  return out;
}

function readCa(path: string | undefined): string | undefined {
  if (!path) return undefined;
  try {
    return readFileSync(path, 'utf8');
  } catch (err) {
    throw configError(`Cannot read CA file ${path}: ${(err as Error).message}`);
  }
}

/** Expands ${VAR} so instances.json never has to hold a secret in clear text. */
function expand(value: unknown, env: Env, where: string): unknown {
  if (typeof value !== 'string') return value;
  return value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_, name: string) => {
    const v = env[name];
    if (v === undefined) throw configError(`${where}: environment variable ${name} is not set.`);
    return v;
  });
}

interface RawInstance {
  url?: unknown;
  api_key?: unknown;
  api_secret?: unknown;
  credentials_file?: unknown;
  verify_ssl?: unknown;
  ca_file?: unknown;
  allow_writes?: unknown;
  allow_sensitive?: unknown;
  dry_run?: unknown;
  description?: unknown;
  management_source?: unknown;
  timeout_seconds?: unknown;
}

/** Env is null when the values already come from the environment: they are not templates. */
function buildInstance(name: string, raw: RawInstance, env: Env | null, defaults: { allowWrites: boolean; allowSensitive: boolean; dryRun: boolean; timeoutMs: number }): InstanceConfig {
  if (!INSTANCE_NAME.test(name)) {
    throw configError(`Invalid instance name "${name}": use letters, digits, - and _ (32 characters at most).`);
  }
  const where = `instance "${name}"`;
  const str = (v: unknown) => {
    const expanded = env ? expand(v, env, where) : v;
    return typeof expanded === 'string' && expanded !== '' ? expanded : undefined;
  };
  const urlRaw = str(raw.url);
  if (!urlRaw) throw configError(`${where}: url is required.`);
  const file = str(raw.credentials_file);
  const fromFile = file ? readCredentialsFile(file) : {};
  const apiKey = str(raw.api_key) ?? fromFile.apiKey;
  const apiSecret = str(raw.api_secret) ?? fromFile.apiSecret;
  if (!apiKey || !apiSecret) {
    throw configError(`${where}: API key and secret are required.`, 'Set api_key/api_secret, or credentials_file pointing at the apikey.txt downloaded from OPNsense.');
  }
  const url = normalizeUrl(urlRaw, where);
  const verifySsl = parseBool(`${where} verify_ssl`, str(raw.verify_ssl) ?? (typeof raw.verify_ssl === 'boolean' ? raw.verify_ssl : undefined), true);
  const instance: InstanceConfig = {
    name,
    url,
    apiKey,
    apiSecret,
    verifySsl,
    allowWrites: parseBool(`${where} allow_writes`, typeof raw.allow_writes === 'boolean' ? raw.allow_writes : str(raw.allow_writes), defaults.allowWrites),
    allowSensitive: parseBool(`${where} allow_sensitive`, typeof raw.allow_sensitive === 'boolean' ? raw.allow_sensitive : str(raw.allow_sensitive), defaults.allowSensitive),
    dryRun: parseBool(`${where} dry_run`, typeof raw.dry_run === 'boolean' ? raw.dry_run : str(raw.dry_run), defaults.dryRun),
    timeoutMs: raw.timeout_seconds === undefined ? defaults.timeoutMs : parseInteger(`${where} timeout_seconds`, raw.timeout_seconds as number, 30, 1, 600) * 1000,
  };
  const ca = readCa(str(raw.ca_file));
  if (ca) instance.ca = ca;
  const description = str(raw.description);
  if (description) instance.description = description;
  const managementSource = str(raw.management_source);
  if (managementSource) instance.managementSource = managementSource;
  return instance;
}

export function loadConfig(env: Env = process.env): ServerConfig {
  const defaults = {
    allowWrites: parseBool('OPNSENSE_ALLOW_WRITES', env.OPNSENSE_ALLOW_WRITES, false),
    allowSensitive: parseBool('OPNSENSE_ALLOW_SENSITIVE', env.OPNSENSE_ALLOW_SENSITIVE, false),
    dryRun: parseBool('OPNSENSE_DRY_RUN', env.OPNSENSE_DRY_RUN, false),
    timeoutMs: parseInteger('OPNSENSE_TIMEOUT_SECONDS', env.OPNSENSE_TIMEOUT_SECONDS, 30, 1, 600) * 1000,
  };

  const instances = new Map<string, InstanceConfig>();
  let defaultInstance: string | undefined;

  if (env.OPNSENSE_CONFIG) {
    let parsed: { default?: unknown; instances?: Record<string, RawInstance> };
    try {
      parsed = JSON.parse(readFileSync(env.OPNSENSE_CONFIG, 'utf8'));
    } catch (err) {
      throw configError(`Cannot read OPNSENSE_CONFIG (${env.OPNSENSE_CONFIG}): ${(err as Error).message}`);
    }
    for (const [name, raw] of Object.entries(parsed.instances ?? {})) {
      instances.set(name, buildInstance(name, raw, env, defaults));
    }
    if (instances.size === 0) throw configError('OPNSENSE_CONFIG defines no instances.');
    if (typeof parsed.default === 'string') {
      if (!instances.has(parsed.default)) throw configError(`Default instance "${parsed.default}" is not defined.`);
      defaultInstance = parsed.default;
    }
  } else {
    if (!env.OPNSENSE_URL) {
      throw configError('OPNSENSE_URL is not set.', 'Set OPNSENSE_URL, OPNSENSE_API_KEY and OPNSENSE_API_SECRET, or OPNSENSE_CONFIG for several firewalls.');
    }
    instances.set(
      'default',
      buildInstance(
        'default',
        {
          url: env.OPNSENSE_URL,
          api_key: env.OPNSENSE_API_KEY,
          api_secret: env.OPNSENSE_API_SECRET,
          credentials_file: env.OPNSENSE_API_CREDENTIALS_FILE,
          verify_ssl: env.OPNSENSE_VERIFY_SSL,
          ca_file: env.OPNSENSE_CA_FILE,
          management_source: env.OPNSENSE_MANAGEMENT_SOURCE,
        },
        null,
        defaults,
      ),
    );
  }

  const toolsets = env.OPNSENSE_TOOLSETS
    ? new Set(
        env.OPNSENSE_TOOLSETS.split(',')
          .map((s) => s.trim().toLowerCase())
          .filter(Boolean),
      )
    : null;

  const config: ServerConfig = {
    instances,
    defaultInstance: defaultInstance ?? [...instances.keys()][0]!,
    toolsets,
    rollbackSeconds: parseInteger('OPNSENSE_ROLLBACK_SECONDS', env.OPNSENSE_ROLLBACK_SECONDS, 120, 30, 3600),
    unblocked: (env.OPNSENSE_UNBLOCK ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    elicit: parseBool('OPNSENSE_ELICIT', env.OPNSENSE_ELICIT, true),
    maxResponseChars: parseInteger('OPNSENSE_MAX_RESPONSE_CHARS', env.OPNSENSE_MAX_RESPONSE_CHARS, 120_000, 2_000, 5_000_000),
  };
  if (env.OPNSENSE_AUDIT_LOG) config.auditLog = env.OPNSENSE_AUDIT_LOG;
  return config;
}
