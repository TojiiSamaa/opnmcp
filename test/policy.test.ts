import { describe, expect, it } from 'vitest';
import catalogFile from '../src/catalog/endpoints.json' with { type: 'json' };
import { authorize, canonicalPath, decide } from '../src/opnsense/policy.js';

const catalog = (catalogFile as { endpoints: Array<{ method: string; path: string }> }).endpoints;
const readOnly = { name: 't', allowWrites: false, allowSensitive: false, dryRun: false };

describe('blocklist', () => {
  it.each([
    'core/system/reboot',
    'core/system/re_boot',
    'core/system/REBOOT',
    'core/system/halt',
    'core/firmware/update',
    'core/firmware/poweroff',
    'core/defaults/factory_defaults',
    'core/defaults/factoryDefaults',
    'auth/user/add_api_key',
    'auth/user/addApiKey',
    'auth/user/new_otp_seed',
    'diagnostics/firewall/flush_states',
    'diagnostics/firewall/flushStates',
    'firewall/migration/flush',
    'core/backup/delete_backup',
    'diagnostics/packet_capture/start',
  ])('blocks %s whatever its spelling', (path) => {
    expect(decide(path, 'POST').blocked).toBeTruthy();
    expect(decide(path, 'GET').blocked).toBeTruthy();
  });

  it('keeps it blocked with extra path segments', () => {
    expect(decide('core/system/reboot/now', 'POST').blocked).toBeTruthy();
  });

  it('lets the operator unblock an endpoint, by canonical name', () => {
    expect(decide('core/system/re_boot', 'POST', ['core/system/reboot']).blocked).toBeUndefined();
  });

  it.each(['auth/priv/set_item/page-all', 'auth/priv/set', 'cron/settings/add_job', 'cron/settings/set_job/x', 'cron/settings/set', 'diagnostics/firewall/kill_states'])('blocks %s, which reaches what the list forbids by another way', (path) => {
    expect(decide(path, 'POST').blocked).toBeDefined();
  });

  it('keeps raw backup diffs away from the generic tools', () => {
    expect(decide('core/backup/diff/this/a/b', 'GET').blocked).toBeDefined();
    expect(decide('core/backup/diff/this/a/b', 'GET', [], true).blocked).toBeUndefined();
    expect(decide('core/backup/diff/this/a/b', 'GET', [], true).access).toBe('read');
  });

  it('keeps the backup restore away from the generic tools', () => {
    expect(decide('core/backup/revert_backup/x', 'POST', [], false).blocked).toBeTruthy();
    expect(decide('core/backup/revert_backup/x', 'POST', [], true).blocked).toBeUndefined();
  });
});

describe('classification', () => {
  it.each([
    ['redis/service/resetdb', 'GET'],
    ['acmeclient/service/reset', 'GET'],
    ['netbird/authentication/down', 'GET'],
    ['diagnostics/netflow/setconfig', 'GET'],
    ['proxysso/service/deletekeytab', 'GET'],
    ['acmeclient/service/signallcerts', 'GET'],
    ['crowdsec/service/reconfigure', 'GET'],
  ] as const)('treats the mutating GET %s as a write', (path, method) => {
    expect(decide(path, method).access).toBe('write');
  });

  it.each([
    ['firewall/filter/search_rule', 'POST'],
    ['diagnostics/firewall/query_states', 'POST'],
    ['diagnostics/ping/set', 'POST'],
    ['firewall/alias_util/find_references', 'POST'],
    ['diagnostics/firewall/log', 'GET'],
    ['diagnostics/log/core/system', 'POST'],
    ['haproxy/statistics/counters', 'GET'],
  ] as const)('treats the read-only %s as a read', (path, method) => {
    expect(decide(path, method).access).toBe('read');
  });

  it('counts an unknown command as a write', () => {
    expect(decide('foo/bar/do_something', 'GET').access).toBe('write');
  });

  it('does not take carp_status for a read because of a short prefix', () => {
    expect(decide('diagnostics/interface/carp_status', 'POST').access).toBe('write');
  });

  it('refuses clearing logs and live streams', () => {
    expect(decide('diagnostics/log/core/system/clear', 'POST').blocked).toBeTruthy();
    expect(decide('diagnostics/log/core/system/live', 'GET').blocked).toBeTruthy();
  });

  it('marks key material as sensitive', () => {
    expect(decide('wireguard/server/key_pair', 'GET').sensitive).toBe(true);
    expect(decide('trust/cert/raw_dump/x', 'GET').sensitive).toBe(true);
    expect(decide('firewall/filter/search_rule', 'POST').sensitive).toBe(false);
  });

  it('never classifies as read a command with a verb that changes something', () => {
    const verb = /^(add|del|delete|set|toggle|remove|flush|reset|restart|start|stop|reboot|update|upgrade|reconfigure|apply|kill|drop|revert|install|sign|revoke|renew|disconnect|connect)/;
    const wrong = catalog.filter((e) => {
      const command = canonicalPath(e.path).split('/')[2] ?? '';
      if (!verb.test(command)) return false;
      const d = decide(e.path, 'POST');
      return !d.blocked && d.access === 'read';
    });
    const allowed = new Set([
      // Diagnostics mounted :memory: write nothing to the configuration.
      'diagnostics/ping/set', 'diagnostics/ping/start', 'diagnostics/ping/stop', 'diagnostics/ping/remove', 'diagnostics/traceroute/set', 'diagnostics/dns_diagnostics/set', 'diagnostics/portprobe/set',
      // These only look like verbs: one reads a progress log, the other checks that a uuid exists.
      'core/firmware/upgradestatus', 'ipsec/connections/connection_exists',
    ]);
    expect(wrong.map((e) => e.path).filter((p) => !allowed.has(p))).toEqual([]);
  });
});

describe('authorize', () => {
  it('refuses a write on a read-only instance', () => {
    expect(() => authorize(readOnly, 'firewall/filter/add_rule', 'POST', [])).toThrowError(/read-only/);
  });

  it.each(['core/system/../reboot', 'core//system', 'core/system/a b', 'core/system/%2e%2e', 'core/system/a?b=c', 'core'])('rejects the path %s', (path) => {
    expect(() => authorize(readOnly, path, 'GET', [])).toThrow();
  });

  it('refuses sensitive output unless allowed', () => {
    expect(() => authorize(readOnly, 'core/backup/download/this', 'GET', [])).toThrowError(/key material/);
    expect(() => authorize({ ...readOnly, allowSensitive: true }, 'core/backup/download/this', 'GET', [])).not.toThrow();
    expect(() => authorize(readOnly, 'core/backup/download/this', 'GET', [], { redactedByCaller: true })).not.toThrow();
  });
});
