import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.js';
import { OpnsenseError } from '../src/opnsense/errors.js';
import { assertWriteOk, describeModel, flattenModel } from '../src/opnsense/model.js';
import { assertNoRedactedValue, configXmlToJson, REDACTED, redactConfigXml, redactJson, redactXmlLines, scrubText } from '../src/opnsense/redact.js';

describe('redaction', () => {
  it('masks the TOTP seed, also inside the otpauth link', () => {
    const out = redactJson({ user: { otp_seed: 'JBSWY3DP', otp_uri: 'otpauth://totp/a@b?secret=JBSWY3DP&issuer=OPNsense', name: 'a' } });
    expect(JSON.stringify(out)).not.toContain('JBSWY3DP');
    expect(out.user.name).toBe('a');
  });

  it('masks secrets in the HTML-escaped lines of a real backup diff', () => {
    const out = redactXmlLines([
      '--- /conf/backup/config-1.xml',
      '@@ -1,3 +1,3 @@',
      '-      &lt;password&gt;old&lt;/password&gt;',
      '+      &lt;descr&gt;a &amp;amp; b&lt;/descr&gt;',
    ]);
    expect(out.join(' ')).not.toContain('old');
    expect(out[3]).toBe('+      <descr>a &amp; b</descr>');
    expect(out[0]).toContain('/conf/backup/config-1.xml');
  });

  it('masks what looks like the end of a value that started above the hunk', () => {
    const out = redactXmlLines([' second-line-of-key', ' third-line</prv>', '+      <hostname>fw</hostname>']);
    expect(out.join(' ')).not.toMatch(/second-line|third-line/);
    expect(out[2]).toBe('+      <hostname>fw</hostname>');
  });

  it('masks secrets by field name, at any depth', () => {
    const out = redactJson({ password: 'p', nested: { api_secret: 's', list: [{ privkey: 'k', name: 'keep' }] }, description: 'keep' }) as Record<string, any>;
    expect(out.password).toBe(REDACTED);
    expect(out.nested.api_secret).toBe(REDACTED);
    expect(out.nested.list[0].privkey).toBe(REDACTED);
    expect(out.nested.list[0].name).toBe('keep');
    expect(out.description).toBe('keep');
  });

  it('removes PEM private keys found in free text', () => {
    const out = scrubText('before\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nafter');
    expect(out).not.toContain('abc');
    expect(out).toContain('before');
    expect(out).toContain('after');
  });

  it('refuses to write a redacted value back to the firewall', () => {
    expect(() => assertNoRedactedValue({ rule: { password: REDACTED } }, 'x/y/z')).toThrow();
    expect(() => assertNoRedactedValue({ rule: { description: 'fine' } }, 'x/y/z')).not.toThrow();
  });

  it('masks secrets in config.xml and keeps the rest', () => {
    const xml = '<?xml version="1.0"?><opnsense><system><user><name>root</name><password>$2y$hash</password></user></system></opnsense>';
    const out = redactConfigXml(xml);
    expect(out).not.toContain('$2y$hash');
    expect(out).toContain('<name>root</name>');
  });

  it('refuses XML it cannot parse rather than pass it through', () => {
    expect(() => redactConfigXml('<opnsense><password>secret')).toThrow();
  });

  it('turns config.xml into redacted JSON', () => {
    const json = configXmlToJson('<opnsense><system><hostname>fw</hostname><password>x</password></system></opnsense>') as Record<string, any>;
    expect(json.system.hostname).toBe('fw');
    expect(json.system.password).toBe(REDACTED);
  });
});

describe('model helpers', () => {
  const form = { action: { pass: { value: 'Pass', selected: 1 }, block: { value: 'Block', selected: 0 } }, description: 'x' };

  it('flattens option maps to the selected keys', () => {
    expect(flattenModel(form)).toEqual({ action: 'pass', description: 'x' });
  });

  it('describes accepted values', () => {
    const d = describeModel(form);
    expect(d.fields?.action?.options).toEqual([{ value: 'pass', label: 'Pass' }, { value: 'block', label: 'Block' }]);
    expect(d.fields?.action?.current).toBe('pass');
  });

  it('reads failures out of HTTP 200 answers', () => {
    expect(() => assertWriteOk({ result: 'failed', validations: { 'rule.action': 'bad' } }, 'x')).toThrowError(OpnsenseError);
    expect(() => assertWriteOk({ result: 'not found' }, 'x')).toThrowError(/not found/);
    expect(() => assertWriteOk({ errorMessage: 'alias in use' }, 'x')).toThrowError(/alias in use/);
    expect(assertWriteOk({ result: 'saved', uuid: 'u' }, 'x').uuid).toBe('u');
    expect(assertWriteOk({ result: 'deleted' }, 'x').result).toBe('deleted');
  });
});

describe('configuration', () => {
  const base = { OPNSENSE_URL: 'https://fw.example.com/api/', OPNSENSE_API_KEY: 'k', OPNSENSE_API_SECRET: 's' };

  it('is read-only by default, and normalizes the URL', () => {
    const c = loadConfig(base);
    const i = c.instances.get('default')!;
    expect(i.allowWrites).toBe(false);
    expect(i.url).toBe('https://fw.example.com');
    expect(i.verifySsl).toBe(true);
  });

  it('stops on a typo in a safety flag', () => {
    expect(() => loadConfig({ ...base, OPNSENSE_ALLOW_WRITES: 'ture' })).toThrow(/not a boolean/);
  });

  it('refuses credentials in the URL, and a missing secret', () => {
    expect(() => loadConfig({ ...base, OPNSENSE_URL: 'https://a:b@fw' })).toThrow(/credentials/);
    expect(() => loadConfig({ OPNSENSE_URL: 'https://fw', OPNSENSE_API_KEY: 'k' })).toThrow(/key and secret/);
  });

  it('does not treat an environment secret as a template', () => {
    const c = loadConfig({ ...base, OPNSENSE_API_SECRET: 'abc${NOT_SET}def' });
    expect(c.instances.get('default')!.apiSecret).toBe('abc${NOT_SET}def');
  });

  it('reads several instances, expanding variables', () => {
    const dir = mkdtempSync(join(tmpdir(), 'osmcp-'));
    const file = join(dir, 'instances.json');
    writeFileSync(file, JSON.stringify({ default: 'lab', instances: { lab: { url: 'https://lab', api_key: 'k', api_secret: '${LAB_SECRET}', allow_writes: true }, prod: { url: 'https://prod', api_key: 'k', api_secret: 's' } } }));
    const c = loadConfig({ OPNSENSE_CONFIG: file, LAB_SECRET: 'from-env' });
    expect(c.defaultInstance).toBe('lab');
    expect(c.instances.get('lab')!.apiSecret).toBe('from-env');
    expect(c.instances.get('lab')!.allowWrites).toBe(true);
    expect(c.instances.get('prod')!.allowWrites).toBe(false);
    expect(() => loadConfig({ OPNSENSE_CONFIG: file })).toThrow(/LAB_SECRET/);
  });

  it('reads the apikey.txt that OPNsense offers', () => {
    const dir = mkdtempSync(join(tmpdir(), 'osmcp-'));
    const file = join(dir, 'apikey.txt');
    writeFileSync(file, 'key=abc\nsecret=def\n');
    const c = loadConfig({ OPNSENSE_URL: 'https://fw', OPNSENSE_API_CREDENTIALS_FILE: file });
    expect(c.instances.get('default')!.apiKey).toBe('abc');
    expect(c.instances.get('default')!.apiSecret).toBe('def');
  });
});
