import { afterEach, describe, expect, it, vi } from 'vitest';
import type { InstanceConfig } from '../src/config.js';
import { ChangeManager } from '../src/opnsense/changes.js';
import { OpnsenseClient } from '../src/opnsense/client.js';
import { FakeOpnsense, Reply, type FakeOptions } from './fake-opnsense.js';

const open: FakeOpnsense[] = [];

async function setup(options: FakeOptions = {}) {
  const fake = new FakeOpnsense(options);
  await fake.start();
  open.push(fake);
  const config: InstanceConfig = { name: 't', url: fake.url, apiKey: 'key', apiSecret: 'secret', verifySsl: true, allowWrites: true, allowSensitive: false, dryRun: false, timeoutMs: 5000 };
  const client = new OpnsenseClient(config);
  const notes: string[] = [];
  const changes = new ChangeManager(client, (_level, message) => notes.push(message), { retryIntervalMs: 20 });
  return { fake, client, changes, notes };
}

async function addRule(client: OpnsenseClient, changes: ChangeManager) {
  await changes.beginIfNeeded();
  const res = (await changes.trackWrite(() => client.post('firewall/filter/add_rule', { rule: { action: 'block', interface: 'lan', description: 'new' } }))) as { uuid: string };
  changes.record({ action: 'add', scope: 'filter', summary: 'add', uuid: res.uuid });
  return res.uuid;
}

afterEach(async () => {
  vi.useRealTimers();
  await Promise.all(open.splice(0).map((f) => f.stop()));
});

describe('OPNsense 26.7 and later: rollback by this server', () => {
  it('takes a baseline before the first write', async () => {
    const { fake, client, changes } = await setup();
    const baseline = fake.backups[0]!.id;
    await addRule(client, changes);
    expect(changes.status().baseline_backup).toBe(baseline);
    expect(changes.protectionAvailable()).toBe('server-side');
    // The version is known, so there is no need to ask for an endpoint that 26.7 removed.
    expect(fake.called('firewall/filter/savepoint')).toHaveLength(0);
  });

  it('finds out from the 404 when the version is unknown', async () => {
    const { fake, client, changes } = await setup({ version: null });
    await addRule(client, changes);
    expect(fake.called('firewall/filter/savepoint')).toHaveLength(1);
    expect(changes.protectionAvailable()).toBe('server-side');
    await changes.apply(60);
    expect(fake.called('firewall/filter/apply')[0]!.path).toBe('firewall/filter/apply');
  });

  it('keeps a staged change away from pf until apply', async () => {
    const { fake, client, changes } = await setup();
    await addRule(client, changes);
    expect(fake.appliedRules.some((r) => r.description === 'new')).toBe(false);
    const res = await changes.apply(60);
    expect(res.status).toBe('pending_confirmation');
    expect(res.protection).toBe('server-side');
    expect(res.reachable_after_apply).toBe(true);
    expect(fake.appliedRules.some((r) => r.description === 'new')).toBe(true);
  });

  it('stays in place once confirmed', async () => {
    const { fake, client, changes } = await setup();
    await addRule(client, changes);
    await changes.apply(60);
    const res = await changes.confirm();
    expect(res.status).toBe('confirmed');
    expect(changes.status().pending).toBe(false);
    expect(fake.rules.some((r) => r.description === 'new')).toBe(true);
    expect(fake.called('core/backup/revert_backup')).toHaveLength(0);
  });

  it('restores and reloads when the delay runs out', async () => {
    const { fake, client, changes, notes } = await setup();
    await addRule(client, changes);
    await changes.apply(1);
    await vi.waitFor(() => expect(changes.status().pending).toBe(false), { timeout: 4000, interval: 50 });
    expect(fake.rules.some((r) => r.description === 'new')).toBe(false);
    // revert_backup only rewrites the file: without the reload pf would keep the bad rules.
    expect(fake.appliedRules.some((r) => r.description === 'new')).toBe(false);
    expect(notes.join(' ')).toMatch(/not confirmed in time/);
    expect(changes.drainNotices().join(' ')).toMatch(/not confirmed in time/);
  });

  it('refuses to erase what someone else saved in the meantime, unless forced', async () => {
    const { fake, client, changes } = await setup();
    await addRule(client, changes);
    await changes.apply(60);
    fake.saveRevision('edit in the web interface', 'alice@10.0.0.9');

    await expect(changes.rollback()).rejects.toMatchObject({ type: 'rollback_blocked' });
    expect(changes.status().pending).toBe(true);
    expect(fake.called('core/backup/revert_backup')).toHaveLength(0);

    const forced = await changes.rollback({ force: true });
    expect(forced.status).toBe('rolled_back');
    expect(fake.called('core/backup/revert_backup')).toHaveLength(1);
  });

  it('does not let the timer erase foreign changes either, and says so', async () => {
    const { fake, client, changes, notes } = await setup();
    await addRule(client, changes);
    await changes.apply(1);
    fake.saveRevision('edit in the web interface', 'alice@10.0.0.9');
    await vi.waitFor(() => expect(changes.status().state).toBe('rollback_blocked'), { timeout: 4000, interval: 50 });
    expect(fake.called('core/backup/revert_backup')).toHaveLength(0);
    expect(notes.join(' ')).toMatch(/did not complete/);
  });

  it('retries when the firewall cannot be reached at the deadline', async () => {
    const { fake, client, changes } = await setup();
    await addRule(client, changes);
    await changes.apply(1);
    const original = fake.handlers.get('core/backup/backups')!;
    let failures = 0;
    fake.on('core/backup/backups', (req, params) => {
      if (failures++ < 2) return new Reply(500, { message: 'down' });
      return original(req, params);
    });
    await vi.waitFor(() => expect(changes.status().pending).toBe(false), { timeout: 5000, interval: 25 });
    expect(failures).toBeGreaterThanOrEqual(2);
    expect(fake.rules.some((r) => r.description === 'new')).toBe(false);
  });

  it('rolls an armed change back on shutdown', async () => {
    const { fake, client, changes } = await setup();
    await addRule(client, changes);
    await changes.apply(60);
    await changes.shutdown();
    expect(fake.rules.some((r) => r.description === 'new')).toBe(false);
  });

  it('reloads the aliases when they were part of the change', async () => {
    const { fake, client, changes } = await setup();
    await changes.beginIfNeeded();
    changes.record({ action: 'add', scope: 'alias', summary: 'add alias' });
    await changes.apply(60);
    expect(fake.called('firewall/alias/reconfigure')).toHaveLength(1);
    await changes.rollback();
    expect(fake.called('firewall/alias/reconfigure')).toHaveLength(2);
  });

  it('reports no protection when the API user cannot read backups', async () => {
    const { fake, client, changes } = await setup();
    fake.on('core/backup/backups', () => new Reply(403, { message: 'Forbidden' }));
    await addRule(client, changes);
    expect(changes.protectionAvailable()).toBe('none');
    const res = await changes.apply(60);
    expect(res.status).toBe('applied');
    expect(res.protection).toBe('none');
    expect(changes.status().pending).toBe(false);
  });
});

describe('before 26.7: the rollback timer of the firewall', () => {
  it('uses the native savepoint for filter rules', async () => {
    const { fake, client, changes } = await setup({ version: '25.7.3' });
    await addRule(client, changes);
    expect(changes.protectionAvailable()).toBe('firewall-side');
    const res = await changes.apply(120);
    expect(res.protection).toBe('firewall-side');
    expect(res.rollback_in_seconds).toBeLessThanOrEqual(60);
    expect(fake.called('firewall/filter/apply')[0]!.path).toMatch(/apply\/1762000000\.123$/);
    await changes.confirm();
    expect(fake.called('firewall/filter/cancel_rollback')).toHaveLength(1);
  });

  it('falls back to the backup for what the savepoint does not cover', async () => {
    const { fake, client, changes } = await setup({ version: '25.7.3' });
    await addRule(client, changes);
    changes.record({ action: 'add', scope: 'nat', summary: 'port forward' });
    expect(changes.protectionAvailable()).toBe('server-side');
    await changes.apply(60);
    await changes.rollback();
    expect(fake.called('core/backup/revert_backup')).toHaveLength(1);
    expect(fake.called('firewall/filter/revert')).toHaveLength(0);
  });
});

describe('no pending change', () => {
  it('has nothing to confirm or roll back', async () => {
    const { changes } = await setup();
    await expect(changes.confirm()).rejects.toMatchObject({ type: 'no_pending_change' });
    await expect(changes.rollback()).rejects.toMatchObject({ type: 'no_pending_change' });
  });

  it('refuses to confirm something not applied yet', async () => {
    const { client, changes } = await setup();
    await addRule(client, changes);
    await expect(changes.confirm()).rejects.toMatchObject({ type: 'no_pending_change' });
  });
});

describe('what the firewall really answers', () => {
  it('keeps the timer running when the reload gives no answer, and rolls back', async () => {
    const { fake, client, changes } = await setup();
    await addRule(client, changes);
    const original = fake.handlers.get('firewall/filter/apply')!;
    fake.on('firewall/filter/apply', (req, params) => {
      fake.handlers.set('firewall/filter/apply', original);
      original(req, params);
      // configd returns an empty string when it times out or fails.
      return { status: '' };
    });
    const res = await changes.apply(1);
    expect(res.status).toBe('apply_outcome_unknown');
    expect(changes.status().state).toBe('armed');
    await vi.waitFor(() => expect(changes.status().pending).toBe(false), { timeout: 4000, interval: 50 });
    expect(fake.rules.some((r) => r.description === 'new')).toBe(false);
  });

  it('goes back to staged when the firewall refuses the reload', async () => {
    const { fake, client, changes } = await setup();
    await addRule(client, changes);
    fake.on('firewall/filter/apply', () => new Reply(403, { message: 'Forbidden' }));
    await expect(changes.apply(60)).rejects.toMatchObject({ type: 'forbidden' });
    expect(changes.status().state).toBe('staged');
    expect(changes.status().rollback_in_seconds).toBeNull();
  });

  it('does not call an unknown savepoint a successful revert', async () => {
    const { fake, client, changes } = await setup({ version: '25.7.3' });
    await addRule(client, changes);
    await changes.apply(60);
    fake.on('firewall/filter/revert', () => ({ status: 'unknown (or removed) savepoint' }));
    await expect(changes.rollback()).rejects.toMatchObject({ type: 'upstream_error' });
    expect(changes.status().pending).toBe(true);
  });

  it('accepts the empty answer of a cancelled native timer, and says what it cannot prove', async () => {
    const { client, changes } = await setup({ version: '25.7.3' });
    await addRule(client, changes);
    await changes.apply(60);
    const res = await changes.confirm();
    expect(res.status).toBe('confirmed');
    expect(res.note).toMatch(/does not report/);
  });

  it('probes on a new connection: a kept-alive one survives a reload that blocks new ones', async () => {
    const { fake, client, changes } = await setup();
    await addRule(client, changes);
    const original = fake.handlers.get('firewall/filter/apply')!;
    fake.on('firewall/filter/apply', (req, params) => {
      fake.refuseNewConnections = true;
      return original(req, params);
    });
    const res = await changes.apply(60);
    expect(res.reachable_after_apply).toBe(false);
    expect(res.warning).toMatch(/console/);
    fake.refuseNewConnections = false;
  });
});

describe('what a rollback may erase', () => {
  it('does not take a revision for its own because a write saved nothing', async () => {
    const { fake, client, changes } = await setup();
    await addRule(client, changes);
    fake.saveRevision('edit in the web interface', 'alice@10.0.0.9');
    // A toggle to the state already set saves nothing, so alice would be the newest and oldest name.
    await changes.trackWrite(async () => ({ result: 'Enabled', changed: false }));
    await changes.apply(60);
    await expect(changes.rollback()).rejects.toMatchObject({ type: 'rollback_blocked' });
  });

  it('notices a save under the same account, such as a service write or a person', async () => {
    const { fake, client, changes } = await setup();
    await addRule(client, changes);
    fake.saveRevision('dns override');
    await changes.apply(60);
    await expect(changes.rollback()).rejects.toMatchObject({ type: 'rollback_blocked' });
    expect(fake.called('core/backup/revert_backup')).toHaveLength(0);
  });

  it('keeps retrying after a failed reload, instead of taking its own restore for a foreign save', async () => {
    const { fake, client, changes } = await setup();
    await addRule(client, changes);
    await changes.apply(1);
    const original = fake.handlers.get('firewall/filter/apply')!;
    let failures = 0;
    fake.on('firewall/filter/apply', (req, params) => (failures++ < 1 ? { status: '' } : original(req, params)));
    await vi.waitFor(() => expect(changes.status().pending).toBe(false), { timeout: 5000, interval: 25 });
    expect(fake.called('core/backup/revert_backup').length).toBeGreaterThanOrEqual(2);
  });
});

describe('the order of things', () => {
  it('refuses to confirm while a rollback runs', async () => {
    const { client, changes } = await setup();
    await addRule(client, changes);
    await changes.apply(60);
    const rollback = changes.rollback();
    await expect(changes.confirm()).rejects.toMatchObject({ type: 'change_in_progress' });
    await expect(rollback).resolves.toMatchObject({ status: 'rolled_back' });
    expect(changes.status().pending).toBe(false);
  });

  it('refuses a new write while the last change waits for confirmation', async () => {
    const { client, changes } = await setup();
    await addRule(client, changes);
    await changes.apply(60);
    await expect(changes.beginIfNeeded()).rejects.toMatchObject({ type: 'change_in_progress' });
    await expect(changes.apply(60)).rejects.toMatchObject({ type: 'change_in_progress' });
    await changes.confirm();
    await expect(changes.beginIfNeeded()).resolves.toBeUndefined();
  });

  it('shares one baseline between parallel writes', async () => {
    const { fake, changes } = await setup();
    await Promise.all([changes.beginIfNeeded(), changes.beginIfNeeded()]);
    expect(fake.called('core/backup/backups')).toHaveLength(1);
  });

  it('does not drop a change because a parallel write failed', async () => {
    const { changes } = await setup();
    await changes.beginIfNeeded();
    let finish = () => {};
    const slow = changes.trackWrite(() => new Promise<void>((resolve) => { finish = resolve; }));
    await expect.poll(() => finish.toString()).not.toBe('() => {}');
    await changes.trackWrite(() => Promise.reject(new Error('refused'))).catch(() => changes.discardIfEmpty());
    expect(changes.status().pending).toBe(true);
    finish();
    await slow;
    changes.record({ action: 'add', scope: 'filter', summary: 'add' });
    expect(changes.status().changes).toHaveLength(1);
  });
});
