import { XMLBuilder, XMLParser, XMLValidator } from 'fast-xml-parser';
import { OpnsenseError } from './errors.js';

export const REDACTED = '[REDACTED]';

const EXACT = new Set([
  'password',
  'bcrypt-hash',
  'sha512-hash',
  'md5-hash',
  'nt-hash',
  'key',
  'secret',
  'pre-shared-key',
  'privatekey',
  'privkey',
  'certdata',
  'shared_secret',
  'authorizedkeys',
  'otp_seed',
  'tls',
  'keys',
  'keydata',
  'simpin',
  'community',
  'rocommunity',
  'rwcommunity',
  'eab_hmac',
  'basicauthpass',
  'dns_kas_authdata',
  'apikeys',
  'cookie',
]);

const SUBSTRINGS = ['password', 'passwd', 'secret', 'credential', 'token', 'apikey', 'api_key', 'authkey', 'presharedkey', 'pre-shared', 'psk', 'passphrase', 'prv', 'private_key', 'privatekey', 'bindpw', 'hmac'];

/** Keys that match a pattern above but hold no secret. */
const NOT_SECRET = new Set(['passwordauth', 'nopasswd', 'pubkey', 'publickey', 'public-key', 'public_key', 'password_policy_length', 'authtype', 'sortkey', 'ssh_pubkey', 'tokens_max']);

export function isSensitiveKey(key: string): boolean {
  const k = key.toLowerCase();
  if (NOT_SECRET.has(k)) return false;
  if (EXACT.has(k)) return true;
  // otp_seed, and otp_uri, whose secret= parameter is that same seed.
  if (k.startsWith('otp')) return true;
  if (SUBSTRINGS.some((s) => k.includes(s))) return true;
  if (k.endsWith('_pass') || k.endsWith('pw')) return true;
  return k.endsWith('key') && !k.includes('pub') && !k.includes('sort');
}

const PEM_PRIVATE = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g;
/* eslint-disable-next-line no-control-regex */
const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u0080-\u009F]/g;

/**
 * Removes key material from any free text and strips control characters: logs,
 * DHCP hostnames and descriptions can carry attacker-chosen bytes.
 */
export function scrubText(text: string): string {
  return text.replace(PEM_PRIVATE, REDACTED).replace(CONTROL_CHARS, '');
}

/** An enum option in a model form: {"psk": {"value": "Pre-Shared Key", "selected": 0}}. It is not a secret. */
function isModelOption(value: unknown): boolean {
  return typeof value === 'object' && value !== null && !Array.isArray(value) && 'selected' in value && 'value' in value;
}

/** Empty values stay empty, so that "no password set" can still be seen. */
function isEmpty(value: unknown): boolean {
  if (value === null || value === undefined || value === '') return true;
  if (Array.isArray(value)) return value.length === 0;
  return typeof value === 'object' && Object.keys(value).length === 0;
}

export function redactJson<T>(value: T): T {
  if (typeof value === 'string') return scrubText(value) as T;
  if (Array.isArray(value)) return value.map((v) => redactJson(v)) as T;
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = isSensitiveKey(k) && !isEmpty(v) && !isModelOption(v) ? REDACTED : redactJson(v);
    }
    return out as T;
  }
  return value;
}

const ENTITIES: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', '#039': "'", '#39': "'" };

/** OPNsense HTML-escapes every line of a backup diff: the tags only appear once this is undone. */
function decodeEntities(line: string): string {
  return line.replace(/&(amp|lt|gt|quot|#0?39);/g, (_match, name: string) => ENTITIES[name]!);
}

/**
 * Masks secrets in lines of config.xml, such as those of a unified diff. A sensitive element
 * can span several lines (a certificate key, say), so the state carries over from line to line.
 */
export function redactXmlLines(lines: string[]): string[] {
  let openSecret: string | null = null;
  return lines.map((raw) => {
    const line = decodeEntities(raw);
    if (openSecret) {
      if (line.includes(`</${openSecret}>`)) openSecret = null;
      return `${line.slice(0, 1)}${REDACTED}`;
    }
    if (/^(---|\+\+\+|@@)/.test(line)) return scrubText(line);
    // Text before the first tag belongs to a value spanning several lines, which may have started above this hunk.
    const body = `${line.slice(0, 1)}${line.slice(1).replace(/^(\s*)[^<\s][^<]*/, (_match, space: string) => `${space}${REDACTED}`)}`;
    const masked = body.replace(/<([A-Za-z0-9_.:-]+)(\s[^<>]*)?>([^<]*)(<\/\1>)?/g, (match, tag: string, attrs: string | undefined, value: string, close: string | undefined) => {
      if (!isSensitiveKey(tag)) return match;
      if (!close) openSecret = tag;
      return value === '' && close ? match : `<${tag}${attrs ?? ''}>${REDACTED}${close ?? ''}`;
    });
    return scrubText(masked);
  });
}

/** A redacted placeholder must never be written back to the firewall as a real value. */
export function assertNoRedactedValue(value: unknown, path: string): void {
  if (value === REDACTED) {
    throw new OpnsenseError('invalid_input', `The request to ${path} contains the placeholder ${REDACTED}, which would overwrite a real secret.`, {
      hint: 'Leave the field out to keep its current value.',
    });
  }
  if (Array.isArray(value)) value.forEach((v) => assertNoRedactedValue(v, path));
  else if (value && typeof value === 'object') Object.values(value).forEach((v) => assertNoRedactedValue(v, path));
}

const XML_OPTIONS = {
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  preserveOrder: true,
  trimValues: false,
  parseTagValue: false,
  parseAttributeValue: false,
  cdataPropName: '#cdata',
  commentPropName: '#comment',
  processEntities: false,
} as const;

type XmlNode = Record<string, unknown>;

function blankXml(nodes: XmlNode[]): void {
  for (const node of nodes) {
    for (const key of Object.keys(node)) {
      if (key === ':@' || key.startsWith('#') || key.startsWith('?')) {
        if (key === '#text' && typeof node[key] === 'string') node[key] = scrubText(node[key] as string);
        continue;
      }
      const children = node[key] as XmlNode[];
      if (isSensitiveKey(key)) {
        if (children.length > 0) {
          node[key] = [{ '#text': REDACTED }];
          delete node[':@'];
        }
      } else {
        blankXml(children);
      }
    }
  }
}

function parseXmlOrRefuse(xml: string): XmlNode[] {
  // Text that cannot be parsed cannot be redacted, so it must not be passed on.
  if (XMLValidator.validate(xml) !== true) {
    throw new OpnsenseError('bad_response', 'The configuration returned by the firewall is not valid XML, so it cannot be redacted and was not returned.');
  }
  return new XMLParser(XML_OPTIONS).parse(xml) as XmlNode[];
}

/** Blanks every sensitive element of a config.xml, children and attributes included. */
export function redactConfigXml(xml: string): string {
  const tree = parseXmlOrRefuse(xml);
  blankXml(tree);
  return new XMLBuilder({ ...XML_OPTIONS, format: false }).build(tree) as string;
}

/** Parses a config.xml into plain JSON and redacts it. */
export function configXmlToJson(xml: string, redact = true): Record<string, unknown> {
  if (XMLValidator.validate(xml) !== true) {
    throw new OpnsenseError('bad_response', 'The configuration returned by the firewall is not valid XML.');
  }
  const parsed = new XMLParser({ ignoreAttributes: true, parseTagValue: false, parseAttributeValue: false, trimValues: true, processEntities: false }).parse(xml) as Record<string, unknown>;
  const root = (parsed.opnsense ?? parsed.pfsense ?? parsed) as Record<string, unknown>;
  return redact ? redactJson(root) : root;
}
