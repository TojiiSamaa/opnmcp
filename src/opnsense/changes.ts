import { OpnsenseError } from './errors.js';
import type { OpnsenseClient } from './client.js';
import { assertApplied, assertOk, isObject } from './model.js';

/**
 * Safe firewall changes: stage, check, apply, confirm or roll back.
 *
 * OPNsense 26.7 removed the savepoint/apply(revision)/cancelRollback API (core #10411), so
 * the 60-second dead-man's switch is gone upstream. This class provides two protections:
 *
 *  - firewall-side (OPNsense < 26.7): the native timer. It runs on the firewall, so it
 *    still fires if this server loses the connection.
 *  - server-side (26.7+): before the first write we note the latest configuration backup,
 *    which is always identical to the running config because Config::save() copies the
 *    new file to /conf/backup right after writing it. If the change is not confirmed in
 *    time, this process restores that backup and reloads the firewall. It needs a working
 *    connection to do so: the lockout check is what covers the case where the change cuts
 *    this server off, and the tool answers say so plainly.
 */
export type Protection = 'firewall-side' | 'server-side' | 'none';

export type ChangeState = 'staged' | 'armed' | 'rollback_blocked' | 'rollback_failed';

/** What a change touched: the native savepoint only covers the filter model. */
export type ChangeScope = 'filter' | 'nat' | 'alias' | 'other';

export interface ChangeEntry {
  at: string;
  action: string;
  scope: ChangeScope;
  summary: string;
  uuid?: string;
}

interface ChangeSet {
  startedAt: string;
  state: ChangeState;
  entries: ChangeEntry[];
  baselineBackup?: string;
  nativeRevision?: string;
  protection?: Protection;
  armedAt?: string;
  expiresAt?: number;
  lastError?: string;
  timer?: NodeJS.Timeout;
  retries: number;
  /** Revisions saved by the writes of this change: anything else since the baseline is not ours to undo. */
  ownRevisions: Set<string>;
  /** The reload was sent and has not answered yet. */
  applying?: boolean;
  /** Tool calls can run in parallel: one failing must not drop a change another one is still making. */
  writesInFlight: number;
}

export type Notify = (level: 'info' | 'warning' | 'error', message: string) => void;

const NATIVE_TIMER_SECONDS = 60;
/** configd allows a reload 120 s, well over the usual request timeout. */
const RELOAD_TIMEOUT_MS = 130_000;
const RETRY_INTERVAL_MS = 10_000;
const MAX_RETRIES = 18;

interface BackupItem {
  id: string;
  username?: string;
  time?: string;
  description?: string;
}

function isEndpointMissing(err: unknown): boolean {
  return err instanceof OpnsenseError && err.type === 'not_found';
}

/** These prove the request was turned down. After anything else, the reload may have happened. */
function wasRefused(err: unknown): boolean {
  return err instanceof OpnsenseError && ['forbidden', 'not_found', 'bad_request', 'auth_failed', 'blocked_endpoint', 'write_disabled'].includes(err.type);
}

export class ChangeManager {
  private current: ChangeSet | null = null;
  private readonly history: Array<{ at: string; event: string }> = [];
  private readonly noticeQueue: string[] = [];
  private rollbackInFlight: Promise<Record<string, unknown>> | undefined;
  private beginning: Promise<void> | undefined;

  constructor(
    private readonly client: OpnsenseClient,
    private readonly notify: Notify,
    private readonly timing: { retryIntervalMs?: number } = {},
  ) {}

  /** Must run before the first write of a change: the baseline has to predate it. */
  async beginIfNeeded(): Promise<void> {
    if (this.rollbackInFlight) {
      throw new OpnsenseError('change_in_progress', 'A rollback is running, so this was not sent.', { hint: 'See opn_pending_changes, and try again once it has finished.' });
    }
    if (this.current) {
      if (this.current.state === 'staged') return;
      // It would not be part of what was applied, and confirming would call it permanent all the same.
      throw new OpnsenseError('change_in_progress', 'The last firewall change is still waiting to be confirmed or rolled back, so this was not sent.', { hint: 'Call opn_confirm_changes or opn_rollback_changes first. See opn_pending_changes.' });
    }
    // Parallel tool calls must share one baseline.
    this.beginning ??= this.begin().finally(() => {
      this.beginning = undefined;
    });
    return this.beginning;
  }

  private async begin(): Promise<void> {
    const set: ChangeSet = { startedAt: new Date().toISOString(), state: 'staged', entries: [], retries: 0, ownRevisions: new Set(), writesInFlight: 0 };
    const caps = await this.client.capabilities();
    if (caps.nativeSavepoints !== false) {
      try {
        const res = await this.client.post('firewall/filter/savepoint', undefined, { curated: true });
        if (isObject(res) && typeof res.revision === 'string' && res.revision) set.nativeRevision = res.revision;
      } catch (err) {
        if (!isEndpointMissing(err)) throw err;
        this.client.noteNoNativeSavepoints();
      }
    }
    set.baselineBackup = await this.latestBackup();
    this.current = set;
  }

  /**
   * Runs a write of the current change and notes the revisions it saved. A restore replaces the
   * whole configuration, so a rollback has to tell them from everything else saved since the
   * baseline: the name on a revision cannot, since a person can use the same account and address.
   */
  async trackWrite<T>(write: () => Promise<T>): Promise<T> {
    const set = this.current;
    if (!set) return write();
    set.writesInFlight++;
    try {
      if (!set.baselineBackup) return await write();
      const before = await this.latestBackup().catch(() => undefined);
      const result = await write();
      // Without this list the revision counts as someone else's: the rollback stops and asks.
      const items = before ? await this.listBackups().catch(() => [] as BackupItem[]) : [];
      const index = items.findIndex((i) => i.id === before);
      for (const item of index === -1 ? [] : items.slice(0, index)) set.ownRevisions.add(item.id);
      return result;
    } finally {
      set.writesInFlight--;
    }
  }

  record(entry: Omit<ChangeEntry, 'at'>): void {
    this.current?.entries.push({ at: new Date().toISOString(), ...entry });
  }

  /** If the first write of a change failed there is nothing to protect yet. */
  discardIfEmpty(): void {
    if (this.current && this.current.entries.length === 0 && this.current.writesInFlight === 0) this.current = null;
  }

  protectionAvailable(): Protection {
    const set = this.current;
    if (!set) return 'none';
    if (this.canUseNative(set)) return 'firewall-side';
    return set.baselineBackup ? 'server-side' : 'none';
  }

  /** The native revert only restores the filter model, so anything else needs the backup. */
  private canUseNative(set: ChangeSet): boolean {
    return Boolean(set.nativeRevision) && set.entries.every((e) => e.scope === 'filter');
  }

  async apply(rollbackSeconds: number): Promise<Record<string, unknown>> {
    const set = this.current;
    const reload = { curated: true, timeoutMs: RELOAD_TIMEOUT_MS };
    if (!set) {
      assertOk(await this.client.post('firewall/filter/apply', undefined, reload), 'Reloading the firewall');
      return { status: 'applied', protection: 'none', message: 'No change tracked by this server: the firewall was reloaded with its current configuration. Nothing to confirm.' };
    }
    if (this.rollbackInFlight || set.state !== 'staged') {
      throw new OpnsenseError('change_in_progress', 'These changes were already applied: there is nothing new to apply.', { hint: 'Call opn_confirm_changes or opn_rollback_changes. See opn_pending_changes.' });
    }

    const protection = this.protectionAvailable();
    const seconds = protection === 'firewall-side' ? NATIVE_TIMER_SECONDS : rollbackSeconds;
    // The timer starts first: a reload can outlast the request, and the change would then be live with nothing to undo it.
    // The native one starts on the firewall when the request arrives, so ours must not run longer than that.
    if (protection === 'firewall-side') this.arm(set, protection, seconds);
    else if (protection === 'server-side') this.arm(set, protection, RELOAD_TIMEOUT_MS / 1000 + seconds);

    set.applying = true;
    let live = false;
    try {
      await this.trackWrite(async () => {
        if (protection === 'firewall-side') {
          assertOk(await this.client.post('firewall/filter/apply', undefined, { ...reload, params: [set.nativeRevision!] }), 'Applying the changes');
          return;
        }
        if (set.entries.some((e) => e.scope === 'alias')) {
          // This reloads the filter by itself, so from here on the change is live.
          assertApplied(await this.client.post('firewall/alias/reconfigure', undefined, reload), 'Loading the aliases');
          live = true;
        }
        assertOk(await this.client.post('firewall/filter/apply', undefined, reload), 'Applying the changes');
      });
    } catch (err) {
      if (protection === 'none') throw err;
      if (wasRefused(err) && !live) {
        this.disarm(set);
        throw err;
      }
      if (protection === 'server-side') this.arm(set, protection, seconds);
      return {
        status: 'apply_outcome_unknown',
        protection,
        error: (err as Error).message,
        rollback_in_seconds: Math.max(0, Math.round(((set.expiresAt ?? Date.now()) - Date.now()) / 1000)),
        confirm_with: 'opn_confirm_changes',
        rollback_with: 'opn_rollback_changes',
        baseline_backup: set.baselineBackup ?? null,
        message: 'The firewall did not report a successful reload, so the changes may or may not be live. The rollback timer is running: without opn_confirm_changes, the previous configuration comes back.',
      };
    } finally {
      set.applying = false;
    }

    if (protection === 'none') {
      // Applied with no way back: there is nothing left to confirm.
      this.finish(set, 'applied without rollback protection');
      return { status: 'applied', protection: 'none', message: 'The changes are live and permanent. No automatic rollback was possible.' };
    }
    if (this.current !== set) {
      return { status: 'reverted', protection, message: 'The reload took longer than the rollback timer of the firewall, which has reverted the changes.' };
    }
    if (protection === 'server-side') this.arm(set, protection, seconds);

    const reachable = await this.checkReachable();
    const left = Math.max(0, Math.round(((set.expiresAt ?? Date.now()) - Date.now()) / 1000));
    return {
      status: 'pending_confirmation',
      protection,
      reachable_after_apply: reachable,
      rollback_in_seconds: left,
      confirm_with: 'opn_confirm_changes',
      rollback_with: 'opn_rollback_changes',
      baseline_backup: set.baselineBackup ?? null,
      message:
        protection === 'firewall-side'
          ? `The changes are live. The firewall itself reverts them in ${left} s unless opn_confirm_changes is called.`
          : `The changes are live. This server reverts them in ${left} s unless opn_confirm_changes is called. This timer runs here, not on the firewall: it cannot help if the connection to the firewall is lost and stays lost.`,
      ...(reachable ? {} : { warning: this.lockoutMessage(set) }),
    };
  }

  private arm(set: ChangeSet, protection: Protection, seconds: number): void {
    set.protection = protection;
    set.state = 'armed';
    set.armedAt = new Date().toISOString();
    set.expiresAt = Date.now() + seconds * 1000;
    if (set.timer) clearTimeout(set.timer);
    set.timer = setTimeout(() => void this.onDeadline(set), seconds * 1000);
    set.timer.unref();
  }

  private disarm(set: ChangeSet): void {
    if (set.timer) clearTimeout(set.timer);
    set.state = 'staged';
    delete set.timer;
    delete set.protection;
    delete set.armedAt;
    delete set.expiresAt;
  }

  private async onDeadline(set: ChangeSet): Promise<void> {
    if (this.current !== set) return;
    if (set.protection === 'firewall-side') {
      // The firewall has already reverted by itself, there is nothing to send.
      this.finish(set, 'reverted by the firewall timer');
      this.announce('warning', 'The firewall changes were not confirmed in time, and the firewall reverted them.');
      return;
    }
    await this.autoRollback(set);
  }

  private async autoRollback(set: ChangeSet): Promise<void> {
    try {
      await this.rollback({ reason: 'not confirmed in time' });
      this.announce('warning', 'The firewall changes were not confirmed in time, so this server restored the previous configuration.');
    } catch (err) {
      if (this.current !== set) return;
      const blocked = err instanceof OpnsenseError && err.type === 'rollback_blocked';
      if (!blocked && set.retries < MAX_RETRIES) {
        set.retries++;
        set.state = 'rollback_failed';
        set.lastError = (err as Error).message;
        set.timer = setTimeout(() => void this.autoRollback(set), this.timing.retryIntervalMs ?? RETRY_INTERVAL_MS);
        set.timer.unref();
        return;
      }
      set.state = blocked ? 'rollback_blocked' : 'rollback_failed';
      set.lastError = (err as Error).message;
      this.announce('error', `Automatic rollback did not complete: ${(err as Error).message}. The change is still live. ${this.lockoutMessage(set)}`);
    }
  }

  async confirm(): Promise<Record<string, unknown>> {
    const set = this.current;
    if (!set) throw new OpnsenseError('no_pending_change', 'There is no pending firewall change to confirm.');
    if (this.rollbackInFlight) throw new OpnsenseError('change_in_progress', 'A rollback is running, so this change can no longer be confirmed.', { hint: 'See opn_pending_changes for the outcome.' });
    if (set.applying) throw new OpnsenseError('change_in_progress', 'The firewall is still applying this change, so there is nothing to confirm yet.', { hint: 'Wait for the answer of opn_apply_firewall_changes.' });
    if (set.state === 'staged') {
      throw new OpnsenseError('no_pending_change', 'The changes are staged but not applied yet, so there is nothing to confirm.', {
        hint: 'Call opn_apply_firewall_changes first.',
      });
    }
    const native = set.protection === 'firewall-side';
    if (native) {
      // The script behind this prints nothing, whether it worked or not: the answer proves nothing either way.
      assertApplied(await this.client.post('firewall/filter/cancel_rollback', undefined, { curated: true, params: [set.nativeRevision!] }), 'Cancelling the firewall timer', { allowEmpty: true });
      if (this.current !== set) throw new OpnsenseError('no_pending_change', 'The delay ran out in the meantime, and the firewall reverted the changes.');
    }
    const entries = set.entries.length;
    this.finish(set, 'confirmed');
    return {
      status: 'confirmed',
      changes: entries,
      message: 'The changes are permanent.',
      ...(native ? { note: 'The firewall does not report whether its timer was cancelled. Check that the change is still there once the delay has passed.' } : {}),
    };
  }

  /** A timer and a tool call can both ask for this: only one restore may run at a time. */
  rollback(opts: { force?: boolean; reason?: string } = {}): Promise<Record<string, unknown>> {
    this.rollbackInFlight ??= this.runRollback(opts).finally(() => {
      this.rollbackInFlight = undefined;
    });
    return this.rollbackInFlight;
  }

  private async runRollback(opts: { force?: boolean; reason?: string }): Promise<Record<string, unknown>> {
    const set = this.current;
    if (!set) throw new OpnsenseError('no_pending_change', 'There is no pending firewall change to roll back.', {
      hint: 'To go back to an older configuration, use opn_list_config_backups and opn_restore_config_backup.',
    });

    let method: string;
    if (this.canUseNative(set)) {
      assertOk(await this.client.post('firewall/filter/revert', undefined, { curated: true, timeoutMs: RELOAD_TIMEOUT_MS, params: [set.nativeRevision!] }), 'Reverting the firewall changes');
      method = 'native revert';
    } else if (set.baselineBackup) {
      await this.assertNoForeignChanges(set, opts.force === true);
      // Tracked, because a retry must not take this save for someone else's.
      const res = await this.trackWrite(() => this.client.post('core/backup/revert_backup', undefined, { curated: true, params: [set.baselineBackup!] }));
      const status = isObject(res) ? String(res.status ?? '') : '';
      if (status !== 'reverted') {
        throw new OpnsenseError('rollback_failed', `The firewall did not restore backup ${set.baselineBackup} (status: ${status || 'unknown'}).`, { details: res });
      }
      // revert_backup only rewrites config.xml: nothing reaches pf until the reload.
      assertOk(await this.client.post('firewall/filter/apply', undefined, { curated: true, timeoutMs: RELOAD_TIMEOUT_MS }), 'Reloading the firewall');
      if (set.entries.some((e) => e.scope === 'alias')) {
        assertApplied(await this.client.post('firewall/alias/reconfigure', undefined, { curated: true, timeoutMs: RELOAD_TIMEOUT_MS }), 'Reloading the aliases');
      }
      method = 'configuration restore';
    } else {
      throw new OpnsenseError('rollback_failed', 'No baseline is available for this change: it cannot be rolled back automatically.', {
        hint: 'Undo the changes by hand, or use opn_restore_config_backup with a backup from before the change.',
      });
    }
    const undone = set.entries.length;
    this.finish(set, `rolled back (${method})${opts.reason ? `: ${opts.reason}` : ''}`);
    return { status: 'rolled_back', method, changes_undone: undone };
  }

  /**
   * Restoring a backup replaces the whole config.xml, so it would also discard whatever else
   * was saved in the meantime: by a person, or by a service write through this server, which
   * would keep running while its configuration disappears. Only the revisions of this change
   * may go.
   */
  private async assertNoForeignChanges(set: ChangeSet, force: boolean): Promise<void> {
    const items = await this.listBackups();
    const index = items.findIndex((i) => i.id === set.baselineBackup);
    if (index === -1) {
      throw new OpnsenseError('rollback_failed', `Backup ${set.baselineBackup} is no longer on the firewall.`, {
        hint: 'The backup count may be too low for the number of changes. Pick another backup with opn_list_config_backups.',
      });
    }
    const foreign = items.slice(0, index).filter((i) => !set.ownRevisions.has(i.id));
    if (foreign.length > 0 && !force) {
      throw new OpnsenseError('rollback_blocked', `The configuration was also saved outside this change since the baseline (${foreign.length} revision(s)), by someone else or by a service write: restoring it would discard that too.`, {
        details: { revisions: foreign.map((f) => ({ id: f.id, username: f.username, description: f.description })) },
        hint: 'Review the revisions with opn_diff_config_backups, then undo the change by hand or call opn_rollback_changes with force=true.',
      });
    }
  }

  status(): Record<string, unknown> {
    const set = this.current;
    if (!set) return { pending: false, recent: this.history.slice(-5) };
    const remaining = set.expiresAt ? Math.max(0, Math.round((set.expiresAt - Date.now()) / 1000)) : null;
    return {
      pending: true,
      state: set.state,
      started_at: set.startedAt,
      protection: set.protection ?? this.protectionAvailable(),
      rollback_in_seconds: set.state === 'armed' ? remaining : null,
      baseline_backup: set.baselineBackup ?? null,
      native_revision: set.nativeRevision ?? null,
      changes: set.entries,
      ...(set.state === 'staged'
        ? { note: 'Staged changes are saved in the configuration but not live yet. Any later firewall reload, including one started from the web interface, makes them live.' }
        : {}),
      ...(set.lastError ? { last_error: set.lastError, recovery: this.lockoutMessage(set) } : {}),
      recent: this.history.slice(-5),
    };
  }

  /** Called on shutdown: by contract, a change that was never confirmed does not survive. */
  async shutdown(): Promise<void> {
    const set = this.current;
    if (!set) return;
    if (set.state === 'armed' && set.protection === 'server-side') {
      try {
        await this.rollback({ reason: 'server shutting down before confirmation' });
        console.error('[osmcp] unconfirmed firewall change rolled back on shutdown');
      } catch (err) {
        console.error(`[osmcp] could not roll back the unconfirmed change on shutdown: ${(err as Error).message}`);
      }
    } else if (set.state === 'staged') {
      console.error('[osmcp] warning: firewall changes are staged but not applied; the next firewall reload will make them live.');
    }
    if (set.timer) clearTimeout(set.timer);
  }

  /** Messages for the agent about what happened between two tool calls. */
  drainNotices(): string[] {
    return this.noticeQueue.splice(0);
  }

  private announce(level: 'warning' | 'error', message: string): void {
    this.noticeQueue.push(message);
    this.notify(level, message);
  }

  private finish(set: ChangeSet, event: string): void {
    if (set.timer) clearTimeout(set.timer);
    if (this.current === set) this.current = null;
    this.history.push({ at: new Date().toISOString(), event });
  }

  private lockoutMessage(set: ChangeSet): string {
    const backup = set.baselineBackup ? ` Restore backup ${set.baselineBackup}` : ' Restore the last good configuration';
    return `If the firewall stays unreachable, the rollback cannot be sent.${backup} from the console (opnsense-shell, option 13 "Restore a backup") or from any path that still reaches the web interface.`;
  }

  private async checkReachable(): Promise<boolean> {
    try {
      await this.client.get('core/system/status', { timeoutMs: 8_000, freshConnection: true });
      return true;
    } catch (err) {
      // A 403 or 404 still proves that the firewall answered.
      return err instanceof OpnsenseError && !['unreachable', 'timeout', 'tls_error'].includes(err.type);
    }
  }

  private async listBackups(): Promise<BackupItem[]> {
    const res = await this.client.get('core/backup/backups', { params: ['this'] });
    const items = isObject(res) && Array.isArray(res.items) ? res.items : [];
    return items.filter((i): i is BackupItem => isObject(i) && typeof i.id === 'string');
  }

  /** The backup to return to, or undefined when the API user cannot list backups. */
  async latestBackup(): Promise<string | undefined> {
    try {
      return (await this.listBackups())[0]?.id;
    } catch (err) {
      // No privilege on backups is not fatal: it shows up later as "no protection".
      if (err instanceof OpnsenseError && (err.type === 'forbidden' || err.type === 'not_found')) return undefined;
      throw err;
    }
  }
}
