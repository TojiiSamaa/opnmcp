import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { ElicitRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { afterEach, describe, expect, it } from 'vitest';
import catalogFile from '../src/catalog/endpoints.json' with { type: 'json' };
import { loadConfig, type Env } from '../src/config.js';
import { canonicalPath, decide } from '../src/opnsense/policy.js';
import { Runtime } from '../src/runtime.js';
import { createServer, renderResult } from '../src/server.js';
import { FakeOpnsense, Reply, type FakeOptions } from './fake-opnsense.js';

const cleanups: Array<() => Promise<unknown>> = [];

afterEach(async () => {
  // In order: a pending change must still be able to reach the firewall on shutdown.
  for (const cleanup of cleanups.splice(0)) await cleanup().catch(() => undefined);
});

interface Harness {
  fake: FakeOpnsense;
  client: Client;
  runtime: Runtime;
  call: (name: string, args?: Record<string, unknown>) => Promise<{ data: Record<string, any>; isError: boolean }>;
}

async function connect(opts: { fake?: FakeOptions; env?: Env; onElicit?: (message: string) => { action: 'accept' | 'decline' | 'cancel'; content?: Record<string, unknown> } } = {}): Promise<Harness> {
  const fake = new FakeOpnsense(opts.fake);
  await fake.start();
  const config = loadConfig({ OPNSENSE_URL: fake.url, OPNSENSE_API_KEY: 'key', OPNSENSE_API_SECRET: 'secret', OPNSENSE_MANAGEMENT_SOURCE: '198.51.100.7', ...opts.env });
  const runtime = new Runtime(config);
  const server = createServer(runtime);
  const client = new Client({ name: 'test', version: '1' }, { capabilities: opts.onElicit ? { elicitation: { form: {} } } : {} });
  if (opts.onElicit) {
    const handler = opts.onElicit;
    client.setRequestHandler(ElicitRequestSchema, (req) => handler(req.params.message));
  }
  const [a, b] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(a), client.connect(b)]);
  cleanups.push(() => client.close(), () => server.close(), () => runtime.shutdown(), () => fake.stop());
  return {
    fake,
    client,
    runtime,
    call: async (name, args = {}) => {
      const res = (await client.callTool({ name, arguments: args })) as { content: Array<{ text: string }>; isError?: boolean };
      return { data: JSON.parse(res.content[0]!.text), isError: res.isError === true };
    },
  };
}

const WRITES = { OPNSENSE_ALLOW_WRITES: 'true' };

describe('tool list', () => {
  it('has one tool per request, with consistent names and annotations', async () => {
    const { client } = await connect({ env: { ...WRITES, OPNSENSE_TOOLSETS: 'all' } });
    const { tools } = await client.listTools();
    expect(tools.length).toBeGreaterThan(150);
    expect(new Set(tools.map((t) => t.name)).size).toBe(tools.length);
    for (const t of tools) {
      expect(t.name).toMatch(/^opn_[a-z0-9_]+$/);
      expect(t.description?.length, t.name).toBeGreaterThan(15);
      expect(t.annotations?.readOnlyHint, t.name).toBeTypeOf('boolean');
      expect(t.annotations?.destructiveHint, t.name).toBeTypeOf('boolean');
      expect(t.annotations?.idempotentHint, t.name).toBeTypeOf('boolean');
      expect(t.annotations?.openWorldHint, t.name).toBeTypeOf('boolean');
      if (t.annotations?.readOnlyHint) {
        expect(t.annotations.destructiveHint, t.name).toBe(false);
        expect(t.inputSchema.properties, t.name).not.toHaveProperty('dry_run');
      } else {
        expect(t.inputSchema.properties, t.name).toHaveProperty('dry_run');
      }
      // Separate requests: no catch-all "action" or "method" switch between read and write.
      if (t.name !== 'opn_api_read' && t.name !== 'opn_api_write' && t.name !== 'opn_control_service') {
        expect(t.inputSchema.properties ?? {}, t.name).not.toHaveProperty('method');
      }
    }
  });

  it('marks deletions as destructive, and reads as read-only', async () => {
    const { client } = await connect({ env: { ...WRITES, OPNSENSE_TOOLSETS: 'all' } });
    const { tools } = await client.listTools();
    for (const t of tools) {
      if (/^opn_(delete|remove|kill)_/.test(t.name)) expect(t.annotations?.destructiveHint, t.name).toBe(true);
      if (/^opn_(list|get|search)_/.test(t.name)) expect(t.annotations?.readOnlyHint, t.name).toBe(true);
    }
  });

  it('keeps the names lucamarien uses where the function is the same', async () => {
    const { client } = await connect({ env: { ...WRITES, OPNSENSE_TOOLSETS: 'all' } });
    const names = new Set((await client.listTools()).tools.map((t) => t.name));
    const shared = [
      'opn_list_dhcp_leases', 'opn_list_kea_leases', 'opn_list_dnsmasq_leases', 'opn_list_dnsmasq_ranges', 'opn_add_dnsmasq_range', 'opn_update_dnsmasq_range', 'opn_delete_dnsmasq_range', 'opn_reconfigure_dnsmasq',
      'opn_ping', 'opn_traceroute', 'opn_dns_lookup', 'opn_pf_states',
      'opn_list_dns_overrides', 'opn_list_dns_forwards', 'opn_dns_stats', 'opn_reconfigure_unbound', 'opn_add_dns_override', 'opn_update_dns_override', 'opn_delete_dns_override', 'opn_list_dnsbl', 'opn_get_dnsbl', 'opn_set_dnsbl', 'opn_add_dnsbl_allowlist', 'opn_remove_dnsbl_allowlist', 'opn_update_dnsbl',
      'opn_list_firewall_rules', 'opn_list_firewall_aliases', 'opn_firewall_log', 'opn_confirm_changes', 'opn_toggle_firewall_rule', 'opn_add_firewall_rule', 'opn_delete_firewall_rule', 'opn_update_firewall_rule', 'opn_add_alias', 'opn_update_alias', 'opn_delete_alias', 'opn_toggle_alias', 'opn_list_nat_rules', 'opn_add_nat_rule', 'opn_update_nat_rule', 'opn_delete_nat_rule', 'opn_list_firewall_categories', 'opn_add_firewall_category', 'opn_delete_firewall_category', 'opn_set_rule_categories',
      'opn_haproxy_status', 'opn_reconfigure_haproxy', 'opn_haproxy_configtest',
      'opn_interface_stats', 'opn_arp_table', 'opn_ndp_table', 'opn_ipv6_status', 'opn_list_static_routes',
      'opn_security_audit',
      'opn_list_ddns_accounts', 'opn_add_ddns_account', 'opn_update_ddns_account', 'opn_delete_ddns_account', 'opn_reconfigure_ddclient', 'opn_list_acme_certs', 'opn_list_cron_jobs', 'opn_crowdsec_status', 'opn_crowdsec_alerts', 'opn_mdns_repeater_status', 'opn_configure_mdns_repeater',
      'opn_system_status', 'opn_list_services', 'opn_gateway_status', 'opn_download_config', 'opn_scan_config', 'opn_get_config_section', 'opn_mcp_info',
      'opn_wireguard_status', 'opn_ipsec_status', 'opn_openvpn_status',
    ];
    expect(shared.filter((n) => !names.has(n))).toEqual([]);
  });

  it('hides write tools on a read-only server', async () => {
    const { client } = await connect();
    const { tools } = await client.listTools();
    expect(tools.every((t) => t.annotations?.readOnlyHint)).toBe(true);
    expect(tools.map((t) => t.name)).toContain('opn_list_firewall_rules');
    expect(tools.map((t) => t.name)).not.toContain('opn_add_firewall_rule');
  });

  it('loads HAProxy only on request', async () => {
    const off = await connect();
    expect((await off.client.listTools()).tools.some((t) => t.name.includes('haproxy'))).toBe(false);
    const on = await connect({ env: { OPNSENSE_TOOLSETS: 'haproxy' } });
    const names = (await on.client.listTools()).tools.map((t) => t.name);
    expect(names).toContain('opn_haproxy_status');
    expect(names).toContain('opn_mcp_info');
    expect(names).not.toContain('opn_list_firewall_rules');
  });

  it('keeps the change workflow when only NAT is loaded', async () => {
    const { client } = await connect({ env: { ...WRITES, OPNSENSE_TOOLSETS: 'nat' } });
    const names = (await client.listTools()).tools.map((t) => t.name);
    expect(names).toContain('opn_add_nat_rule');
    expect(names).toContain('opn_apply_firewall_changes');
    expect(names).toContain('opn_confirm_changes');
  });

  it('stops on an unknown toolset', async () => {
    await expect(connect({ env: { OPNSENSE_TOOLSETS: 'firewal' } })).rejects.toThrow(/unknown toolset/);
  });
});

describe('every tool, against the API', () => {
  /** Builds valid arguments from the schema of a tool. */
  function argsFor(schema: { properties?: Record<string, any>; required?: string[] }): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const name of schema.required ?? []) out[name] = sample(name, schema.properties?.[name]);
    return out;
  }

  function sample(name: string, prop: any): unknown {
    if (prop?.enum) return prop.enum[0];
    switch (prop?.type) {
      case 'boolean':
        return true;
      case 'number':
      case 'integer':
        return name === 'port' ? 443 : (prop.minimum ?? 1);
      case 'array':
        return [sample(name, prop.items)];
      case 'object':
        return { description: 'x' };
    }
    if (/^(uuid|before_uuid|categories|subnet)$/.test(name)) return '22222222-2222-4222-8222-222222222222';
    if (/^(newer|older|backup)$/.test(name)) return 'config-1762000000.0001.xml';
    if (/^(ip|source|destination|addresses|address)$/.test(name)) return '192.0.2.10';
    if (name === 'hostname' || name === 'domains' || name === 'domain') return 'example.com';
    if (name === 'path') return 'firewall/filter/get_rule';
    if (name === 'query') return 'firewall';
    if (name === 'name') return 'test_name';
    if (name === 'device') return 'igb0';
    return 'x';
  }

  it('calls only endpoints that exist, and survives generic answers', async () => {
    const { client, fake } = await connect({ fake: { permissive: true }, env: { ...WRITES, OPNSENSE_TOOLSETS: 'all', OPNSENSE_ELICIT: 'false' } });
    const { tools } = await client.listTools();
    const failures: string[] = [];
    for (const t of tools) {
      const res = (await client.callTool({ name: t.name, arguments: argsFor(t.inputSchema as any) })) as { content: Array<{ text: string }>; isError?: boolean };
      if (res.isError) {
        const body = res.content[0]!.text;
        // Refusals that the tool is right to make on made-up data.
        if (!/no_pending_change|rollback_blocked|lockout_risk|not_found|validation_failed|invalid_input|upstream_error|bad_response/.test(body)) failures.push(`${t.name}: ${body}`);
      }
    }
    expect(failures).toEqual([]);

    // These controllers exist in the source even though the documentation lumps them together.
    const known = new Set((catalogFile as { endpoints: Array<{ path: string }> }).endpoints.map((e) => canonicalPath(e.path)));
    for (const extra of ['kea/leases4/search', 'kea/leases6/search', 'firewall/filter/savepoint', 'firewall/filter/cancel_rollback', 'firewall/filter/revert', 'firewall/filter/apply', 'firewall/group/search_item', 'firewall/alias_util/aliases', 'unbound/settings/search_dot', 'unbound/settings/get_dot', 'unbound/settings/add_dot', 'unbound/settings/set_dot', 'unbound/settings/del_dot', 'unbound/settings/toggle_dot']) known.add(canonicalPath(extra));
    const unknown = [...new Set(fake.requests.map((r) => canonicalPath(r.path)))].filter((p) => !known.has(p) && !p.startsWith('diagnostics/log/'));
    expect(unknown).toEqual([]);
  }, 60_000);

  it('sends only reads from tools announced as read-only, even with writes enabled', async () => {
    const { client, fake } = await connect({ fake: { permissive: true }, env: { ...WRITES, OPNSENSE_TOOLSETS: 'all', OPNSENSE_ELICIT: 'false' } });
    const { tools } = await client.listTools();
    const offenders: string[] = [];
    for (const t of tools.filter((x) => x.annotations?.readOnlyHint)) {
      fake.requests.length = 0;
      await client.callTool({ name: t.name, arguments: argsFor(t.inputSchema as any) });
      for (const r of fake.requests) {
        const d = decide(r.path, r.method as 'GET' | 'POST', [], true);
        if (d.access !== 'read') offenders.push(`${t.name}: ${r.method} ${r.path}`);
      }
    }
    expect(offenders).toEqual([]);
  }, 60_000);

  it.each(['opn_describe_model', 'opn_api_read'])('does not let %s reach a mutating GET, even with writes enabled', async (name) => {
    const { fake, call } = await connect({ fake: { permissive: true }, env: WRITES });
    fake.requests.length = 0;
    const res = await call(name, { path: 'acmeclient/service/reset' });
    expect(res.isError).toBe(true);
    expect(res.data.error_type).toBe('not_read_only');
    expect(fake.called('acmeclient/service/reset')).toHaveLength(0);
  });

  it('never calls an endpoint that only flips the state without reading it first', async () => {
    const { client, fake } = await connect({ fake: { permissive: true }, env: { ...WRITES, OPNSENSE_TOOLSETS: 'all', OPNSENSE_ELICIT: 'false' } });
    const { tools } = await client.listTools();
    for (const t of tools.filter((x) => /_toggle_/.test(x.name))) {
      await client.callTool({ name: t.name, arguments: { uuid: '22222222-2222-4222-8222-222222222222', enabled: true } });
    }
    const flips = (catalogFile as { endpoints: Array<{ path: string; params?: string[] }> }).endpoints
      .filter((e) => /toggle/.test(e.path) && !(e.params ?? []).some((p) => /enabled|disabled/i.test(p)))
      .map((e) => canonicalPath(e.path));
    const used = fake.requests.map((r) => canonicalPath(r.path)).filter((p) => flips.includes(p));
    expect(used).toEqual([]);
  });
});

describe('read-only mode', () => {
  it('sends nothing to the firewall for a generic write', async () => {
    const { fake, client, call } = await connect();
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name)).not.toContain('opn_api_write');
    fake.requests.length = 0;
    const res = await call('opn_api_read', { path: 'firewall/filter/add_rule', method: 'POST', body: { rule: { action: 'pass' } } });
    expect(res.isError).toBe(true);
    expect(res.data.error_type).toBe('not_read_only');
    expect(fake.called('firewall/filter/add_rule')).toHaveLength(0);
  });

  it('refuses a write tool on a read-only firewall when another one allows writes', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'osmcp-'));
    const fake = new FakeOpnsense();
    await fake.start();
    cleanups.push(() => fake.stop());
    const file = join(dir, 'instances.json');
    writeFileSync(file, JSON.stringify({ default: 'prod', instances: { prod: { url: fake.url, api_key: 'key', api_secret: 'secret' }, lab: { url: fake.url, api_key: 'key', api_secret: 'secret', allow_writes: true } } }));
    const runtime = new Runtime(loadConfig({ OPNSENSE_CONFIG: file }));
    const server = createServer(runtime);
    const client = new Client({ name: 't', version: '1' });
    const [a, b] = InMemoryTransport.createLinkedPair();
    await Promise.all([server.connect(a), client.connect(b)]);
    cleanups.push(() => client.close(), () => server.close(), () => runtime.shutdown());

    const res = (await client.callTool({ name: 'opn_add_firewall_rule', arguments: { action: 'pass', interface: 'lan' } })) as { content: Array<{ text: string }>; isError?: boolean };
    expect(res.isError).toBe(true);
    expect(JSON.parse(res.content[0]!.text).error_type).toBe('write_disabled');
    expect(fake.requests).toHaveLength(0);

    const ok = (await client.callTool({ name: 'opn_add_firewall_rule', arguments: { action: 'pass', interface: 'lan', instance: 'lab' } })) as { isError?: boolean };
    expect(ok.isError).toBeFalsy();
    expect(fake.called('firewall/filter/add_rule')).toHaveLength(1);
  });

  it('blocks a reboot through the generic tools, whatever the spelling', async () => {
    const { fake, call } = await connect({ env: { ...WRITES, OPNSENSE_ELICIT: 'false' } });
    for (const path of ['core/system/reboot', 'core/system/re_boot', 'core/system/REBOOT']) {
      const res = await call('opn_api_write', { path });
      expect(res.isError, path).toBe(true);
      expect(res.data.error_type).toBe('blocked_endpoint');
    }
    expect(fake.called('core/system/reboot')).toHaveLength(0);
    expect(fake.called('core/system/re_boot')).toHaveLength(0);
  });
});

describe('dry run', () => {
  it('sends no write and reports what it would send', async () => {
    const { fake, call } = await connect({ env: WRITES });
    const res = await call('opn_add_firewall_rule', { action: 'pass', interface: 'lan', source_net: '10.0.0.0/8', dry_run: true });
    expect(res.isError).toBe(false);
    expect(res.data.dry_run).toBe(true);
    expect(res.data.would_send[0].path).toBe('firewall/filter/add_rule');
    expect(res.data.would_send[0].body.rule.source_net).toBe('10.0.0.0/8');
    expect(fake.called('firewall/filter/add_rule')).toHaveLength(0);
    expect(fake.called('firewall/filter/savepoint')).toHaveLength(0);
  });

  it('can be the whole mode of the server, without enabling writes', async () => {
    const { fake, client, call } = await connect({ env: { OPNSENSE_DRY_RUN: 'true' } });
    expect((await client.listTools()).tools.map((t) => t.name)).toContain('opn_add_firewall_rule');
    const res = await call('opn_delete_firewall_rule', { uuid: '22222222-2222-4222-8222-222222222222' });
    expect(res.data.dry_run).toBe(true);
    expect(fake.called('firewall/filter/del_rule')).toHaveLength(0);
  });
});

describe('change workflow, end to end', () => {
  it('stages, checks, applies and confirms', async () => {
    const { fake, call } = await connect({ env: WRITES });
    // A rule that passes the management path, so that the lockout check is satisfied.
    const added = await call('opn_add_firewall_rule', { action: 'pass', interface: 'lan', protocol: 'TCP', destination_port: '8080', description: 'web' });
    expect(added.isError).toBe(false);
    expect(added.data.applied).toBe(false);
    expect(added.data.next_step).toMatch(/opn_apply_firewall_changes/);
    expect(fake.appliedRules.some((r) => r.description === 'web')).toBe(false);

    expect((await call('opn_pending_changes')).data.state).toBe('staged');

    const applied = await call('opn_apply_firewall_changes', { ignore_lockout_risk: true });
    expect(applied.isError).toBe(false);
    expect(applied.data.status).toBe('pending_confirmation');
    expect(applied.data.protection).toBe('server-side');
    expect(applied.data.message).toMatch(/runs here, not on the firewall/);
    expect(fake.appliedRules.some((r) => r.description === 'web')).toBe(true);

    expect((await call('opn_confirm_changes')).data.status).toBe('confirmed');
    expect((await call('opn_pending_changes')).data.pending).toBe(false);
  });

  it('returns validation failures, which come with HTTP 200', async () => {
    const { fake, call } = await connect({ env: WRITES });
    fake.on('firewall/filter/add_rule', () => ({ result: 'failed', validations: { 'rule.source_net': 'Invalid network' } }));
    const res = await call('opn_add_firewall_rule', { action: 'pass', interface: 'lan', source_net: 'nonsense' });
    expect(res.isError).toBe(true);
    expect(res.data.error_type).toBe('validation_failed');
    expect(res.data.details.validations['rule.source_net']).toBe('Invalid network');
    // A first write that failed leaves no change behind.
    expect((await call('opn_pending_changes')).data.pending).toBe(false);
  });

  it('rolls back on request', async () => {
    const { fake, call } = await connect({ env: { ...WRITES, OPNSENSE_ELICIT: 'false' } });
    await call('opn_add_firewall_rule', { action: 'pass', interface: 'lan', description: 'oops' });
    await call('opn_apply_firewall_changes', { ignore_lockout_risk: true });
    const res = await call('opn_rollback_changes');
    expect(res.data.status).toBe('rolled_back');
    expect(fake.rules.some((r) => r.description === 'oops')).toBe(false);
    expect(fake.appliedRules.some((r) => r.description === 'oops')).toBe(false);
  });

  it('sends the destination NAT fields the model really has', async () => {
    const { fake, call } = await connect({ fake: { permissive: true }, env: WRITES });
    const res = await call('opn_add_nat_rule', { interface: 'wan', protocol: 'TCP', destination_port: '8443', target: '192.168.1.10', target_port: '443', source_net: '198.51.100.0/24', description: 'web', enabled: true });
    expect(res.isError).toBe(false);
    const rule = (fake.called('firewall/d_nat/add_rule')[0]!.body as { rule: Record<string, any> }).rule;
    expect(rule).toMatchObject({ interface: 'wan', protocol: 'TCP', target: '192.168.1.10', 'local-port': '443', descr: 'web', disabled: '0' });
    expect(rule.destination).toEqual({ port: '8443' });
    expect(rule.source).toEqual({ network: '198.51.100.0/24' });
  });

  it('inverts the state for the NAT toggle, where the parameter means disabled', async () => {
    const { fake, call } = await connect({ fake: { permissive: true }, env: WRITES });
    await call('opn_toggle_nat_rule', { uuid: '22222222-2222-4222-8222-222222222222', enabled: true });
    expect(fake.called('firewall/d_nat/toggle_rule')[0]!.path).toMatch(/\/0$/);
    await call('opn_toggle_firewall_rule', { uuid: '22222222-2222-4222-8222-222222222222', enabled: true });
    expect(fake.called('firewall/filter/toggle_rule')[0]!.path).toMatch(/\/1$/);
  });

  it('reports the alias content as a newline list, and DNSBL allowlists as a comma list', async () => {
    const { fake, call } = await connect({ fake: { permissive: true }, env: WRITES });
    await call('opn_add_alias', { name: 'blocked', type: 'host', content: ['10.0.0.1', '10.0.0.2'] });
    expect((fake.called('firewall/alias/add_item')[0]!.body as any).alias.content).toBe('10.0.0.1\n10.0.0.2');

    fake.on('unbound/settings/get_dnsbl', () => ({ blocklist: { allowlists: { 'a.example': { value: 'a.example', selected: 1 } } } }));
    const res = await call('opn_add_dnsbl_allowlist', { uuid: '22222222-2222-4222-8222-222222222222', domains: ['b.example'] });
    expect(res.data.added).toEqual(['b.example']);
    expect((fake.called('unbound/settings/set_dnsbl')[0]!.body as any).blocklist.allowlists).toBe('a.example,b.example');
    expect(fake.called('unbound/service/dnsbl')).toHaveLength(1);
    expect(fake.called('unbound/service/reconfigure')).toHaveLength(1);
  });

  it('nests diagnostics under settings, as the models require', async () => {
    const { fake, call } = await connect({ fake: { permissive: true } });
    await call('opn_traceroute', { hostname: 'example.com' });
    expect(fake.called('diagnostics/traceroute/set')[0]!.body).toEqual({ traceroute: { settings: { hostname: 'example.com', protocol: 'icmp', ipproto: 'inet' } } });
    await call('opn_dns_lookup', { hostname: 'example.com' });
    expect(fake.called('diagnostics/dns_diagnostics/set')[0]!.body).toEqual({ dns: { settings: { hostname: 'example.com' } } });
    await call('opn_port_probe', { hostname: 'example.com', port: 443 });
    expect((fake.called('diagnostics/portprobe/set')[0]!.body as any).portprobe.settings.port).toBe('443');
  });

  it('runs a ping job from start to cleanup', async () => {
    const { fake, call } = await connect({ fake: { permissive: true } });
    const jobId = '33333333-3333-4333-8333-333333333333';
    fake.on('diagnostics/ping/set', () => ({ result: 'ok', uuid: jobId }));
    fake.on('diagnostics/ping/start', () => ({ status: 'ok' }));
    fake.on('diagnostics/ping/search_jobs', () => ({ rows: [{ id: jobId, status: 'running', send: 3, received: 3, loss: '0%' }], total: 1 }));
    const res = await call('opn_ping', { hostname: 'example.com', count: 3 });
    expect(res.isError).toBe(false);
    expect(res.data.received).toBe(3);
    expect(fake.called('diagnostics/ping/stop')).toHaveLength(1);
    expect(fake.called('diagnostics/ping/remove')).toHaveLength(1);
  });
});

describe('lockout check', () => {
  /** A complete ruleset (it has automatic rules) where the management path is denied. */
  function denyAll(fake: FakeOpnsense): void {
    fake.rules = [
      { uuid: 'auto', is_automatic: true, action: 'pass', interface: 'lan', ipprotocol: 'inet', protocol: 'udp', source_net: 'any', destination_net: 'any', destination_port: '53', quick: '1', enabled: '1' },
      { uuid: 'deny', action: 'block', interface: 'lan', ipprotocol: 'inet46', protocol: 'any', source_net: 'any', destination_net: 'any', quick: '1', enabled: '1', description: 'block everything' },
    ];
  }

  it('refuses to apply a change that cuts the management path', async () => {
    const { fake, call } = await connect({ env: { ...WRITES, OPNSENSE_MANAGEMENT_SOURCE: '127.0.0.2' } });
    await call('opn_add_firewall_rule', { action: 'pass', interface: 'lan', description: 'something' });
    denyAll(fake);
    const res = await call('opn_apply_firewall_changes');
    expect(res.isError).toBe(true);
    expect(res.data.error_type).toBe('lockout_risk');
    expect(res.data.details.lockout.risk).toBe('high');
    expect(fake.called('firewall/filter/apply')).toHaveLength(0);
  });

  it('applies without any flag when the management path stays open', async () => {
    const { fake, call } = await connect({ env: { ...WRITES, OPNSENSE_MANAGEMENT_SOURCE: '127.0.0.2' } });
    const port = new URL(fake.url).port;
    fake.rules = [{ uuid: 'auto', is_automatic: true, action: 'pass', interface: 'lan', ipprotocol: 'inet46', protocol: 'TCP', source_net: 'any', destination_net: '(self)', destination_port: port, quick: '1', enabled: '1', description: 'anti-lockout' }];
    await call('opn_add_firewall_rule', { action: 'block', interface: 'lan', source_net: '10.9.9.9', description: 'block one host' });
    const res = await call('opn_apply_firewall_changes');
    expect(res.isError).toBe(false);
    expect(res.data.lockout_check.risk).toBe('none');
    expect(res.data.status).toBe('pending_confirmation');
    await call('opn_confirm_changes');
  });

  it('lets a human decide otherwise', async () => {
    const { fake, call } = await connect({ env: { ...WRITES, OPNSENSE_MANAGEMENT_SOURCE: '127.0.0.2' } });
    await call('opn_add_firewall_rule', { action: 'pass', interface: 'lan', description: 'something' });
    denyAll(fake);
    const res = await call('opn_apply_firewall_changes', { ignore_lockout_risk: true });
    expect(res.isError).toBe(false);
    expect(res.data.lockout_check.risk).toBe('high');
    expect(fake.called('firewall/filter/apply')).toHaveLength(1);
  });

  it('reports the risk through the preflight, without changing anything', async () => {
    const { fake, call } = await connect({ env: { ...WRITES, OPNSENSE_MANAGEMENT_SOURCE: '127.0.0.2' } });
    denyAll(fake);
    const res = await call('opn_preflight_firewall_changes');
    expect(res.data.lockout.risk).toBe('high');
    expect(res.data.lockout.simulation.deciding_rule.uuid).toBe('deny');
    expect(fake.called('firewall/filter/apply')).toHaveLength(0);
  });

  it('refuses to kill the states of its own connection', async () => {
    const { fake, call } = await connect({ env: { ...WRITES, OPNSENSE_ELICIT: 'false', OPNSENSE_MANAGEMENT_SOURCE: '198.51.100.7' } });
    const res = await call('opn_kill_states', { address: '198.51.100.0/24' });
    expect(res.isError).toBe(true);
    expect(res.data.error_type).toBe('lockout_risk');
    expect(fake.called('diagnostics/firewall/query_states')).toHaveLength(0);

    expect((await call('opn_kill_states', {})).data.error_type).toBe('invalid_input');
    expect((await call('opn_kill_states', { address: '0.0.0.0/0' })).data.error_type).toBe('invalid_input');
  });
});

describe('asking a human', () => {
  it('goes ahead on an explicit yes', async () => {
    const messages: string[] = [];
    const { fake, call } = await connect({ env: WRITES, onElicit: (m) => (messages.push(m), { action: 'accept', content: { confirm: true } }) });
    fake.rules.push({ uuid: '22222222-2222-4222-8222-222222222222', action: 'pass', enabled: '1' });
    const res = await call('opn_delete_firewall_rule', { uuid: '22222222-2222-4222-8222-222222222222' });
    expect(res.isError).toBe(false);
    expect(messages[0]).toMatch(/Delete firewall rule/);
    expect(fake.called('firewall/filter/del_rule')).toHaveLength(1);
  });

  it.each([
    ['decline', { action: 'decline' as const }],
    ['cancel', { action: 'cancel' as const }],
    ['accept without the box ticked', { action: 'accept' as const, content: { confirm: false } }],
  ])('does nothing on %s', async (_label, answer) => {
    const { fake, call } = await connect({ env: WRITES, onElicit: () => answer });
    const res = await call('opn_delete_firewall_rule', { uuid: '22222222-2222-4222-8222-222222222222' });
    expect(res.isError).toBe(true);
    expect(res.data.error_type).toBe('user_cancelled');
    expect(fake.called('firewall/filter/del_rule')).toHaveLength(0);
  });

  it('does not ask for a dry run, or for a plain read', async () => {
    let asked = 0;
    const { call } = await connect({ env: WRITES, onElicit: () => (asked++, { action: 'decline' }) });
    await call('opn_delete_firewall_rule', { uuid: '22222222-2222-4222-8222-222222222222', dry_run: true });
    await call('opn_list_firewall_rules');
    expect(asked).toBe(0);
  });
});

describe('reads', () => {
  it('counts rule kinds and hides automatic rules by default', async () => {
    const { fake, call } = await connect();
    fake.rules.push({ uuid: 'l', legacy: true, action: 'pass', interface: 'LAN' }, { uuid: 'm', action: 'block', interface: 'lan' });
    const res = await call('opn_list_firewall_rules');
    expect(res.data.counts).toEqual({ mvc: 1, legacy: 1, automatic: 1 });
    expect(res.data.rows.map((r: any) => r.uuid)).toEqual(['l', 'm']);
    const all = await call('opn_list_firewall_rules', { include_automatic: true });
    expect(all.data.rows).toHaveLength(3);
  });

  it('redacts secrets in the configuration, and refuses to keep them', async () => {
    const { call } = await connect();
    const xml = await call('opn_download_config');
    expect(xml.data.config).not.toContain('secret-hash');
    expect(xml.data.config).toContain('<hostname>fw</hostname>');
    const section = await call('opn_get_config_section', { section: 'system.user' });
    expect(section.data.data.name).toBe('root');
    expect(section.data.data.password).toBe('[REDACTED]');
    const refused = await call('opn_download_config', { include_sensitive: true });
    expect(refused.data.error_type).toBe('sensitive_disabled');
  });

  it('masks secrets in a configuration diff', async () => {
    const { fake, call } = await connect();
    fake.on('core/backup/diff', () => ({
      items: ['--- a', '-      <password>old-hash</password>', '+      <password>new-hash</password>', '+      <descr>keep this</descr>', '+  <prv>LS0tLS1CRUdJTg', '+  second-line-of-key', '+  </prv>', '+  <hostname>after</hostname>'],
    }));
    const res = await call('opn_diff_config_backups', { newer: 'config-1762000000.0002.xml', older: 'config-1762000000.0001.xml' });
    const text = res.data.diff.join('\n');
    expect(text).not.toContain('old-hash');
    expect(text).not.toContain('new-hash');
    expect(text).not.toContain('LS0tLS1CRUdJTg');
    expect(text).not.toContain('second-line-of-key');
    expect(text).toContain('<descr>keep this</descr>');
    expect(text).toContain('<hostname>after</hostname>');
  });

  it('lists the sections, and says when one does not exist', async () => {
    const { call } = await connect();
    expect((await call('opn_get_config_section')).data.sections).toContain('system');
    expect((await call('opn_get_config_section', { section: 'nope' })).data.error_type).toBe('not_found');
  });

  it('filters the firewall log on exact addresses', async () => {
    const { fake, call } = await connect();
    fake.on('diagnostics/firewall/log', () => [
      { src: '10.0.0.1', dst: '8.8.8.8', dstport: '53', action: 'pass', __digest__: 'x' },
      { src: '10.0.0.10', dst: '8.8.8.8', dstport: '53', action: 'block' },
    ]);
    const res = await call('opn_firewall_log', { source_ip: '10.0.0.1' });
    expect(res.data.rows).toHaveLength(1);
    expect(res.data.rows[0].src).toBe('10.0.0.1');
    expect(res.data.rows[0]).not.toHaveProperty('__digest__');
    expect((await call('opn_firewall_log', { source_ip: '10.0.0.0/24', action: 'block' })).data.rows).toHaveLength(1);
    expect(res.data.note).toMatch(/logging enabled/);
  });

  it('simulates traffic, with staged rules and live alias membership', async () => {
    const { fake, call } = await connect({ env: WRITES });
    fake.aliasTables.trusted = ['127.0.0.5'];
    fake.rules = [
      { uuid: 'auto', is_automatic: true, action: 'pass', interface: 'wan', ipprotocol: 'inet', protocol: 'any', source_net: 'any', destination_net: 'any', quick: '1', enabled: '1' },
      { uuid: 'r1', action: 'pass', interface: 'lan', ipprotocol: 'inet', protocol: 'TCP', source_net: 'trusted', destination_net: 'any', destination_port: '443', quick: '1', enabled: '1', description: 'allow trusted' },
    ];
    const allowed = await call('opn_simulate_firewall_traffic', { source: '127.0.0.5', destination: '8.8.8.8', protocol: 'tcp', destination_port: 443 });
    expect(allowed.data.verdict).toBe('pass');
    expect(allowed.data.interface).toBe('lan');
    expect(allowed.data.deciding_rule.description).toBe('allow trusted');
    expect(allowed.data.certainty).toBe('definite');
    expect((await call('opn_simulate_firewall_traffic', { source: '127.0.0.6', destination: '8.8.8.8', protocol: 'tcp', destination_port: 443 })).data.verdict).toBe('none');
    expect((await call('opn_simulate_firewall_traffic', { source: '192.0.2.99', destination: '8.8.8.8', protocol: 'tcp' })).data.error_type).toBe('invalid_input');
  });

  it('reports what a partial audit could not check', async () => {
    const { fake, call } = await connect();
    fake.on('firewall/d_nat/search_rule', () => new Reply(403, { message: 'Forbidden' }));
    const res = await call('opn_security_audit');
    expect(res.isError).toBe(false);
    expect(res.data.coverage.skipped.nat).toMatch(/forbidden/);
    expect(res.data.coverage.checked).toContain('firewall_rules');
    expect(res.data.coverage.checked).toContain('system');
    expect(res.data.note).toMatch(/could not be checked/);
    const checks = res.data.findings.map((f: any) => f.check);
    expect(checks).toContain('ssh_root_login');
    expect(checks).toContain('ssh_password_auth');
  });

  it('flags a port forward of a dangerous service to anyone', async () => {
    const { fake, call } = await connect();
    fake.on('firewall/d_nat/search_rule', () => ({ rows: [{ uuid: 'n1', 'destination.port': '3389', 'source.network': 'any', target: '192.168.1.5', descr: 'rdp' }, { uuid: 'n2', 'destination.port': '3389', 'source.network': '198.51.100.1', target: '192.168.1.6' }], total: 2 }));
    const res = await call('opn_security_audit');
    const nat = res.data.findings.filter((f: any) => f.section === 'nat');
    expect(nat).toHaveLength(1);
    expect(nat[0].uuid).toBe('n1');
    expect(nat[0].severity).toBe('high');
  });

  it('analyzes shadowed rules', async () => {
    const { fake, call } = await connect();
    fake.rules = [
      { uuid: 'a', action: 'block', interface: 'lan', ipprotocol: 'inet', protocol: 'any', source_net: 'any', destination_net: 'any', quick: '1', enabled: '1', description: 'block all' },
      { uuid: 'b', action: 'pass', interface: 'lan', ipprotocol: 'inet', protocol: 'TCP', source_net: '10.0.0.1', destination_net: 'any', destination_port: '80', quick: '1', enabled: '1', description: 'never reached' },
    ];
    const res = await call('opn_analyze_firewall_rules');
    const hit = res.data.findings.find((f: any) => f.check === 'shadowed_rule');
    expect(hit.uuid).toBe('b');
  });
});

describe('errors that guide the agent', () => {
  it('explains a missing privilege and says not to retry', async () => {
    const { fake, call } = await connect();
    fake.on('routes/gateway/status', () => new Reply(403, { message: 'Forbidden' }));
    const res = await call('opn_gateway_status');
    expect(res.isError).toBe(true);
    expect(res.data.error_type).toBe('forbidden');
    expect(res.data.hint).toMatch(/Do not retry/);
  });

  it('suggests a missing plugin on 404', async () => {
    const { call } = await connect();
    const res = await call('opn_wireguard_status');
    expect(res.data.error_type).toBe('not_found');
    expect(res.data.hint).toMatch(/plugin/);
  });

  it('reports bad credentials', async () => {
    const { call } = await connect({ env: { OPNSENSE_API_SECRET: 'wrong' } });
    const res = await call('opn_gateway_status');
    expect(res.data.error_type).toBe('auth_failed');
  });
});

describe('version handling', () => {
  it('uses camelCase actions before 25.7, for restricted API users', async () => {
    const { fake, call } = await connect({ fake: { version: '24.7.1', permissive: true } });
    await call('opn_arp_table');
    expect(fake.requests.some((r) => r.path === 'diagnostics/interface/searchArp')).toBe(true);
    expect(fake.requests.some((r) => r.path === 'diagnostics/interface/search_arp')).toBe(false);
  });

  it('keeps the snake_case controller names', async () => {
    const { fake, call } = await connect({ fake: { version: '24.7.1', permissive: true } });
    await call('opn_list_nat_rules');
    expect(fake.requests.some((r) => r.path === 'firewall/d_nat/searchRule')).toBe(true);
  });

  it('falls back to camelCase when the version is unknown', async () => {
    const { fake, call } = await connect({ fake: { version: null } });
    fake.on('diagnostics/interface/searchArp', () => ({ rows: [{ ip: '10.0.0.1' }], total: 1 }));
    const res = await call('opn_arp_table');
    expect(res.data.rows).toHaveLength(1);
  });

  it('reports the protection in opn_mcp_info', async () => {
    const recent = await connect();
    expect((await recent.call('opn_mcp_info')).data.firewall_change_protection).toMatch(/^server-side/);
    const old = await connect({ fake: { version: '25.1' } });
    expect((await old.call('opn_mcp_info')).data.firewall_change_protection).toMatch(/^firewall-side/);
  });
});

describe('audit log', () => {
  it('records writes and refusals, without secrets', async () => {
    const file = join(mkdtempSync(join(tmpdir(), 'osmcp-')), 'audit.jsonl');
    const { call } = await connect({ fake: { permissive: true }, env: { ...WRITES, OPNSENSE_AUDIT_LOG: file, OPNSENSE_ELICIT: 'false' } });
    await call('opn_add_ddns_account', { service: 'dyndns2', hostnames: ['a.example'], password: 'hunter2' });
    await call('opn_api_write', { path: 'core/system/reboot' });
    await new Promise((r) => setTimeout(r, 100));
    const text = readFileSync(file, 'utf8');
    const lines = text.trim().split('\n').map((l) => JSON.parse(l) as Record<string, any>);
    expect(text).not.toContain('hunter2');
    expect(lines[0]!.tool).toBe('opn_add_ddns_account');
    expect(lines[0]!.writes.map((w: any) => w.path)).toContain('dyndns/accounts/add_item');
    expect(lines[1]!.tool).toBe('opn_api_write');
    expect(lines[1]!.error_type).toBe('blocked_endpoint');
  });
});

describe('large answers', () => {
  it('cuts rows and says how to continue', () => {
    const rows = Array.from({ length: 1000 }, (_, i) => ({ id: i, text: 'x'.repeat(100) }));
    const out = JSON.parse(renderResult({ rows, total: 1000, count: 1000, offset: 0, limit: 1000, has_more: false }, 5000));
    expect(out.rows.length).toBeGreaterThan(0);
    expect(out.rows.length).toBeLessThan(1000);
    expect(out.has_more).toBe(true);
    expect(out.next_offset).toBe(out.rows.length);
    expect(out.truncated).toMatch(/offset=/);
  });

  it('keeps valid JSON when there is nothing to cut', () => {
    const out = JSON.parse(renderResult({ config: 'x'.repeat(10_000) }, 3000));
    expect(out.truncated).toBe(true);
    expect(out.preview.length).toBeLessThan(3000);
  });
});

describe('resources and prompts', () => {
  it('exposes the interfaces, and the prompts', async () => {
    const { client } = await connect();
    const { resources } = await client.listResources();
    expect(resources.map((r) => r.uri)).toContain('opnsense://default/interfaces');
    const content = await client.readResource({ uri: 'opnsense://default/interfaces' });
    expect(JSON.parse((content.contents[0] as { text: string }).text)[0].identifier).toBe('lan');

    const rules = await client.readResource({ uri: 'opnsense://default/rules' });
    expect(JSON.parse((rules.contents[0] as { text: string }).text)).toEqual([]);

    const { prompts } = await client.listPrompts();
    expect(prompts.map((p) => p.name).sort()).toEqual(['firewall_security_review', 'investigate_host', 'safe_firewall_change', 'troubleshoot_connectivity']);
    const p = await client.getPrompt({ name: 'investigate_host', arguments: { ip: '10.0.0.1' } });
    expect((p.messages[0]!.content as { text: string }).text).toContain('10.0.0.1');
  });
});

describe('requests checked against the OPNsense source', () => {
  const ID = '22222222-2222-4222-8222-222222222222';
  const NO_ELICIT = { ...WRITES, OPNSENSE_ELICIT: 'false' };
  const ALL = { ...NO_ELICIT, OPNSENSE_TOOLSETS: 'all' };
  const schemaOf = async (client: Client, name: string) => (await client.listTools()).tools.find((t) => t.name === name)!.inputSchema as { required?: string[]; properties: Record<string, any> };

  describe('opn_kill_states', () => {
    const rows = [
      { id: 'aa01/c1', src_addr: '10.0.0.1', dst_addr: '8.8.8.8', label: 'rule-a' },
      { id: 'aa02/c1', src_addr: '10.0.0.124', dst_addr: '8.8.8.8', label: 'rule-a-longer' },
      { id: 'aa03/c1', src_addr: '192.168.1.5', dst_addr: '1.1.1.1', nat_addr: '10.0.0.1', label: 'rule-b' },
      { id: 'aa04/c1', src_addr: '198.51.100.7', dst_addr: '127.0.0.1', label: 'rule-a' },
    ];
    const withStates = async (states = rows) => {
      const harness = await connect({ env: NO_ELICIT });
      harness.fake.on('diagnostics/firewall/query_states', () => ({ rows: states, total: states.length }));
      harness.fake.on('diagnostics/firewall/del_state', () => ({ result: 'killed 1 states' }));
      return harness;
    };
    const killed = (fake: FakeOpnsense) => fake.called('diagnostics/firewall/del_state').map((r) => r.path.split('/').slice(3).join('/'));

    it('kills exact matches one by one, and never sends a filter the firewall would rewrite', async () => {
      const { fake, call } = await withStates();
      const res = await call('opn_kill_states', { address: '10.0.0.1/32' });
      expect(res.isError).toBe(false);
      expect(killed(fake)).toEqual(['aa01/c1', 'aa03/c1']);
      expect(res.data.kill_requests_sent).toBe(2);
      expect(fake.called('diagnostics/firewall/query_states')[0]!.body).toMatchObject({ searchPhrase: '10.0.0.1/32' });
      expect(fake.called('diagnostics/firewall/kill_states')).toHaveLength(0);
    });

    it('matches a rule by its exact label, and leaves its own connection alone', async () => {
      const { fake, call } = await withStates();
      // The search of the firewall goes by substring, so it also returns the longer label.
      fake.on('diagnostics/firewall/query_states', () => ({ rows: rows.map((r) => ({ ...r, label: r.label === 'rule-a' ? 'aaaa-bbbb' : 'aaaa-bbbb-cccc' })) }));
      const res = await call('opn_kill_states', { rule_id: 'AAAA-bbbb' });
      expect(killed(fake)).toEqual(['aa01/c1']);
      expect(res.data.skipped_management).toBe(1);
    });

    it('kills its own connection only when told to', async () => {
      const { fake, call } = await withStates([rows[3]!]);
      fake.on('diagnostics/firewall/query_states', () => ({ rows: [{ ...rows[3]!, label: 'abcd' }] }));
      await call('opn_kill_states', { rule_id: 'abcd', include_management: true });
      expect(killed(fake)).toEqual(['aa04/c1']);
    });

    it('refuses, killing nothing, when more states match than allowed', async () => {
      const { fake, call } = await withStates();
      const res = await call('opn_kill_states', { address: '10.0.0.1', max_states: 1 });
      expect(res.data.error_type).toBe('invalid_input');
      expect(killed(fake)).toEqual([]);
    });

    it('stops at the first error, and reports what it did', async () => {
      const { fake, call } = await withStates();
      let count = 0;
      fake.on('diagnostics/firewall/del_state', () => (count++ === 0 ? { result: 'ok' } : new Reply(403, { message: 'no' })));
      const res = await call('opn_kill_states', { address: '10.0.0.1' });
      expect(res.isError).toBe(false);
      expect(res.data.kill_requests_sent).toBe(1);
      expect(res.data.stopped_on_error).toMatch(/privilege/);
    });

    it('only shows what it would send in a dry run', async () => {
      const { fake, call } = await withStates();
      const res = await call('opn_kill_states', { address: '10.0.0.1', dry_run: true });
      expect(killed(fake)).toEqual([]);
      expect(res.data.would_send).toHaveLength(2);
    });
  });

  describe('toggle endpoints that flip', () => {
    it.each([
      ['opn_toggle_wireguard_peer', 'wireguard/client/get_client', 'client', 'wireguard/client/toggle_client'],
      ['opn_toggle_haproxy_frontend', 'haproxy/settings/get_frontend', 'frontend', 'haproxy/settings/toggle_frontend'],
      ['opn_toggle_haproxy_backend', 'haproxy/settings/get_backend', 'backend', 'haproxy/settings/toggle_backend'],
      ['opn_toggle_haproxy_server', 'haproxy/settings/get_server', 'server', 'haproxy/settings/toggle_server'],
      ['opn_toggle_haproxy_action', 'haproxy/settings/get_action', 'action', 'haproxy/settings/toggle_action'],
    ])('%s reads the state first, so that repeating changes nothing', async (name, getPath, wrapper, togglePath) => {
      const { fake, call } = await connect({ fake: { permissive: true }, env: ALL });
      let enabled = '1';
      fake.on(getPath, () => ({ [wrapper]: { enabled } }));
      fake.on(togglePath, () => {
        enabled = enabled === '1' ? '0' : '1';
        return { result: enabled === '1' ? 'Enabled' : 'Disabled', changed: true };
      });

      expect((await call(name, { uuid: ID, enabled: true })).data.changed).toBe(false);
      expect(fake.called(togglePath)).toHaveLength(0);

      expect((await call(name, { uuid: ID, enabled: false })).data.changed).toBe(true);
      expect(enabled).toBe('0');
      expect((await call(name, { uuid: ID, enabled: false })).data.changed).toBe(false);
      expect(enabled).toBe('0');
      expect(fake.called(togglePath).map((r) => r.path)).toEqual([`${togglePath}/${ID}`]);
    });

    it('does not rewrite a WireGuard peer, which would detach it from its instances', async () => {
      const { fake, call } = await connect({ fake: { permissive: true }, env: ALL });
      fake.on('wireguard/client/get_client', () => ({ client: { enabled: '1' } }));
      await call('opn_toggle_wireguard_peer', { uuid: ID, enabled: false });
      expect(fake.called('wireguard/client/set_client')).toHaveLength(0);
      expect(fake.called('wireguard/service/reconfigure')).toHaveLength(1);
    });

    it('changes nothing when the state cannot be read', async () => {
      const { fake, call } = await connect({ fake: { permissive: true }, env: ALL });
      fake.on('wireguard/client/get_client', () => ({ client: {} }));
      expect((await call('opn_toggle_wireguard_peer', { uuid: ID, enabled: false })).data.error_type).toBe('bad_response');
      fake.on('wireguard/client/get_client', () => []);
      expect((await call('opn_toggle_wireguard_peer', { uuid: ID, enabled: false })).data.error_type).toBe('not_found');
      expect(fake.called('wireguard/client/toggle_client')).toHaveLength(0);
    });
  });

  it('keeps DNS over TLS servers apart from forwards', async () => {
    const { client, fake, call } = await connect({ fake: { permissive: true }, env: NO_ELICIT });
    expect((await schemaOf(client, 'opn_add_dns_forward')).properties).not.toHaveProperty('type');
    await call('opn_add_dot_server', { server: '9.9.9.9', verify: 'dns.quad9.net' });
    expect(fake.called('unbound/settings/add_dot')[0]!.body).toEqual({ dot: { server: '9.9.9.9', verify: 'dns.quad9.net' } });
    await call('opn_list_dot_servers');
    expect(fake.called('unbound/settings/search_dot')).toHaveLength(1);
  });

  it('asks for the name when updating a category, which the firewall would otherwise blank in every rule', async () => {
    const { client } = await connect({ env: WRITES });
    expect((await schemaOf(client, 'opn_update_firewall_category')).required).toContain('name');
  });

  it('sends the field names and values of the models', async () => {
    const { client, fake, call } = await connect({ fake: { permissive: true }, env: NO_ELICIT });
    await call('opn_add_ddns_account', { service: 'dyndns2', hostnames: ['a.example', 'b.example'] });
    expect(fake.called('dyndns/accounts/add_item')[0]!.body).toEqual({ account: { service: 'dyndns2', hostnames: 'a.example,b.example' } });
    const nat = await schemaOf(client, 'opn_add_nat_rule');
    expect(nat.properties.pass.enum).toEqual(['', 'pass', 'rule']);
    expect(nat.properties.natreflection.enum).toEqual(['', 'purenat', 'disable']);
    expect((await schemaOf(client, 'opn_add_dnsmasq_range')).properties.prefix_len.maximum).toBe(64);
    expect((await client.callTool({ name: 'opn_dns_lookup', arguments: { hostname: 'example.com', server: 'dns.example' } })).isError).toBe(true);
    expect(fake.called('diagnostics/dns_diagnostics/set')).toHaveLength(0);
  });

  it('warns that an outbound rule does nothing outside hybrid and advanced mode', async () => {
    const { fake, call } = await connect({ fake: { permissive: true }, env: NO_ELICIT });
    const mode = (selected: string) => () => ({ filter: { settings: { nat: { snat_mode: Object.fromEntries(['automatic', 'hybrid', 'advanced', 'disabled'].map((m) => [m, { value: m, selected: m === selected ? 1 : 0 }])) } } } });
    fake.on('firewall/source_nat/get', mode('automatic'));
    expect((await call('opn_add_outbound_nat_rule', { interface: 'wan' })).data.warning).toMatch(/automatic mode/);
    expect((await call('opn_get_outbound_nat_mode')).data).toEqual({ mode: 'automatic', manual_rules_active: false });
    fake.on('firewall/source_nat/get', mode('hybrid'));
    expect((await call('opn_add_outbound_nat_rule', { interface: 'wan' })).data).not.toHaveProperty('warning');
  });

  it('asks for IPsec phase 2 per tunnel', async () => {
    const { fake, call } = await connect({ fake: { permissive: true } });
    fake.on('ipsec/sessions/search_phase1', () => ({ rows: [{ name: 'con1' }, { name: 'con2' }] }));
    fake.on('ipsec/sessions/search_phase2', (req) => ({ rows: [{ tunnel: (req.body as { id: string }).id }] }));
    const res = await call('opn_ipsec_status');
    expect(res.data.phase2).toEqual({ con1: [{ tunnel: 'con1' }], con2: [{ tunnel: 'con2' }] });
  });

  describe('opn_control_service', () => {
    const withServices = async () => {
      const harness = await connect({ env: NO_ELICIT });
      harness.fake.on('core/service/restart', () => ({ result: 'ok' }));
      harness.fake.on('core/service/search', () => ({ rows: [{ name: 'kea-dhcp', id: 'kea-dhcp/v4', running: 1 }, { name: 'kea-dhcp', id: 'kea-dhcp/v6', running: 0 }, { name: 'unbound', id: 'unbound', running: 1 }] }));
      return harness;
    };

    it('takes the id as opn_list_services gives it', async () => {
      const { fake, call } = await withServices();
      expect((await call('opn_control_service', { name: 'kea-dhcp', id: 'kea-dhcp/v4', action: 'restart' })).data.running).toBe(true);
      await call('opn_control_service', { name: 'unbound', id: 'unbound', action: 'restart' });
      expect(fake.called('core/service/restart').map((r) => r.path)).toEqual(['core/service/restart/kea-dhcp/v4', 'core/service/restart/unbound']);
      expect((await call('opn_control_service', { name: 'unbound', id: 'a/b', action: 'restart' })).data.error_type).toBe('invalid_input');
    });

    it('does not take the "ok" of the firewall at its word', async () => {
      const { call } = await withServices();
      expect((await call('opn_control_service', { name: 'nope', action: 'restart' })).data.warning).toMatch(/No service/);
      expect((await call('opn_control_service', { name: 'kea-dhcp', id: 'v6', action: 'restart' })).data.warning).toMatch(/not running/);
    });
  });

  it('gives the DNS query log the time window it needs to honour a client', async () => {
    const { fake, call } = await connect({ fake: { permissive: true } });
    await call('opn_dns_query_log', { client: '10.0.0.5', since_hours: 2 });
    const body = fake.called('unbound/overview/search_queries')[0]!.body as { client: string; timeStart: number; timeEnd: number };
    expect(body.client).toBe('10.0.0.5');
    expect(Number.isInteger(body.timeStart)).toBe(true);
    expect(body.timeEnd - body.timeStart).toBe(7200);
  });

  it('filters the firewall log by interface name, which the log does not contain', async () => {
    const { fake, call } = await connect();
    fake.on('diagnostics/firewall/log', () => [{ src: '10.0.0.1', interface: 'igb1' }, { src: '10.0.0.2', interface: 'igb0' }]);
    fake.on('diagnostics/interface/get_interface_names', () => ({ igb1: 'LAN', igb0: 'WAN' }));
    const res = await call('opn_firewall_log', { interface: 'lan' });
    expect(res.data.rows).toHaveLength(1);
    expect(res.data.rows[0].interface_name).toBe('LAN');
    expect((await call('opn_firewall_log', { interface: 'igb0' })).data.rows[0].src).toBe('10.0.0.2');
  });

  it('finds Kea by its service ids', async () => {
    const { fake, call } = await connect();
    fake.on('core/service/search', () => ({ rows: [{ name: 'kea-dhcp', id: 'kea-dhcp/v4', running: 1 }] }));
    expect((await call('opn_scan_config')).data.dhcp_backend.kea).toBe(true);
  });

  it('keeps backup diffs behind their dedicated tool, and masks their escaped lines', async () => {
    const { fake, call } = await connect();
    fake.on('core/backup/diff', () => ({ items: ['+      &lt;password&gt;hunter2&lt;/password&gt;', '+ rest-of-a-secret', '+      &lt;descr&gt;kept&lt;/descr&gt;'] }));
    const backup = 'config-1762000000.0001.xml';
    const res = await call('opn_diff_config_backups', { newer: backup, older: backup });
    const text = JSON.stringify(res.data.diff);
    expect(text).not.toMatch(/hunter2|rest-of-a-secret/);
    expect(text).toContain('<descr>kept</descr>');
    expect((await call('opn_api_read', { path: `core/backup/diff/this/${backup}/${backup}` })).data.error_type).toBe('blocked_endpoint');
  });

  describe('lockout check', () => {
    const AUTO = { uuid: 'auto', is_automatic: true, action: 'pass', interface: 'wan', ipprotocol: 'inet', protocol: 'any', source_net: 'any', destination_net: 'any', quick: '1', enabled: '1' };
    const rule = (extra: Record<string, unknown>) => ({ uuid: 'r', action: 'pass', interface: 'lan', ipprotocol: 'inet', protocol: 'any', source_net: 'any', destination_net: 'any', quick: '1', enabled: '1', ...extra });
    const risk = async (call: Harness['call']) => (await call('opn_preflight_firewall_changes')).data.lockout;
    const SOURCE = '198.51.100.7';

    it('sees an address staged in a block alias, which the live table does not have yet', async () => {
      const { fake, call } = await connect({ env: WRITES });
      fake.rules = [AUTO, rule({ action: 'block', source_net: 'bad' }), rule({ uuid: 'r2' })];
      fake.aliasTables.bad = [];
      fake.on('firewall/alias/search_item', () => ({ rows: [{ name: 'bad', type: 'host', content: SOURCE, enabled: '1' }] }));
      expect((await risk(call)).risk).toBe('high');
    });

    it('sees an address staged out of a pass alias, which the live table still has', async () => {
      const { fake, call } = await connect({ env: WRITES });
      fake.rules = [AUTO, rule({ source_net: 'good' })];
      fake.aliasTables.good = [SOURCE];
      fake.on('firewall/alias/search_item', () => ({ rows: [{ name: 'good', type: 'host', content: '10.0.0.9', enabled: '1' }] }));
      expect((await risk(call)).risk).toBe('high');
    });

    it('still asks the live table about a host name in an alias', async () => {
      const { fake, call } = await connect({ env: WRITES });
      fake.rules = [AUTO, rule({ source_net: 'good' })];
      fake.aliasTables.good = [SOURCE];
      fake.on('firewall/alias/search_item', () => ({ rows: [{ name: 'good', type: 'host', content: 'admin.example.com', enabled: '1' }] }));
      expect((await risk(call)).risk).toBe('none');
    });

    it('does not ignore a group it could not read', async () => {
      const { fake, call } = await connect({ env: WRITES });
      fake.rules = [AUTO, rule({ action: 'block', interface: 'mygroup' }), rule({ uuid: 'r2' })];
      fake.on('firewall/group/search_item', () => new Reply(403, { message: 'Forbidden' }));
      const report = await risk(call);
      expect(report.risk).toBe('possible');
      expect(report.warnings.join(' ')).toMatch(/groups could not be read/);
    });

    it('does not evaluate the LAN rules for a path through an unassigned VPN interface', async () => {
      const { fake, call } = await connect({ env: WRITES });
      fake.rules = [AUTO, rule({})];
      fake.on('interfaces/overview/interfaces_info', () => ({
        rows: [
          { identifier: 'lan', device: 'igb1', description: 'LAN', addr4: '127.0.0.1/8' },
          { identifier: '', device: 'wg0', description: 'Unassigned Interface', addr4: '198.51.100.1/24' },
        ],
      }));
      expect((await risk(call)).risk).toBe('unknown');
      expect((await call('opn_apply_firewall_changes')).data.error_type).toBe('lockout_risk');
    });

    it('says when it only assumes the interface', async () => {
      const { fake, call } = await connect({ env: WRITES });
      fake.rules = [AUTO, rule({})];
      expect((await risk(call)).warnings.join(' ')).toMatch(/assumed to enter on lan/);
    });

    it('does not trust a pass rule that routes through a gateway', async () => {
      const { fake, call } = await connect({ env: WRITES });
      fake.rules = [AUTO, rule({ gateway: 'WAN_GW' })];
      const report = await risk(call);
      expect(report.risk).toBe('possible');
      expect(report.message).toMatch(/WAN_GW/);
    });

    it('sees a port forward that would take the API port away', async () => {
      const { fake, call } = await connect({ env: WRITES });
      fake.rules = [AUTO, rule({})];
      const port = new URL(fake.url).port;
      const forward = { uuid: 'f', interface: 'lan', protocol: 'TCP', 'destination.network': 'any', 'destination.port': port, target: '10.0.0.50', descr: 'web' };
      fake.on('firewall/d_nat/search_rule', () => ({ rows: [forward] }));
      const report = await risk(call);
      expect(report.risk).toBe('high');
      expect(report.message).toMatch(/10\.0\.0\.50/);

      fake.on('firewall/d_nat/search_rule', () => ({ rows: [{ ...forward, disabled: '1' }, { ...forward, nordr: '1' }, { ...forward, 'destination.port': '1' }] }));
      expect((await risk(call)).risk).toBe('none');
    });

    it('refuses to apply when the check could not run, unless told otherwise', async () => {
      const { fake, call } = await connect({ env: { ...WRITES, OPNSENSE_MANAGEMENT_SOURCE: '' } });
      const res = await call('opn_apply_firewall_changes');
      expect(res.data.error_type).toBe('lockout_risk');
      expect(res.data.hint).toMatch(/OPNSENSE_MANAGEMENT_SOURCE/);
      expect(fake.called('firewall/filter/apply')).toHaveLength(0);
      expect((await call('opn_apply_firewall_changes', { ignore_lockout_risk: true })).data.status).toBe('applied');
    });
  });
});
