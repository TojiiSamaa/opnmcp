import { AsyncLocalStorage } from 'node:async_hooks';
import { appendFile, appendFileSync } from 'node:fs';
import type { InstanceConfig, ServerConfig } from './config.js';
import { ChangeManager, type Notify } from './opnsense/changes.js';
import { OpnsenseClient, type Method } from './opnsense/client.js';
import { OpnsenseError } from './opnsense/errors.js';

export interface InstanceRuntime {
  config: InstanceConfig;
  client: OpnsenseClient;
  changes: ChangeManager;
}

export interface WriteRecord {
  method: Method;
  path: string;
  body?: unknown;
  status: string;
}

export type AuditEntry = Record<string, unknown>;

const SHUTDOWN_TIMEOUT_MS = 15_000;

/**
 * What outlives a single MCP connection: firewall clients, and the pending changes with
 * their rollback timers. In HTTP mode each request has its own MCP server over this.
 */
export class Runtime {
  readonly instances = new Map<string, InstanceRuntime>();
  private readonly listeners = new Set<Notify>();
  private readonly writeScope = new AsyncLocalStorage<WriteRecord[]>();

  constructor(readonly config: ServerConfig) {
    if (config.auditLog) this.assertAuditWritable(config.auditLog);
    for (const [name, instance] of config.instances) {
      const client = new OpnsenseClient(instance, config.unblocked, (entry) => this.onWrite(name, entry));
      const changes = new ChangeManager(client, (level, message) => this.notify(level, `[${name}] ${message}`));
      this.instances.set(name, { config: instance, client, changes });
    }
  }

  instance(name?: string): InstanceRuntime {
    const key = name ?? this.config.defaultInstance;
    const instance = this.instances.get(key);
    if (!instance) {
      throw new OpnsenseError('invalid_input', `Unknown instance "${key}".`, { hint: `Known instances: ${[...this.instances.keys()].join(', ')}` });
    }
    return instance;
  }

  addListener(listener: Notify): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /** Runs a tool while collecting the requests that change something, for the audit log. */
  collectWrites<T>(writes: WriteRecord[], run: () => Promise<T>): Promise<T> {
    return this.writeScope.run(writes, run);
  }

  audit(entry: AuditEntry): void {
    if (!this.config.auditLog) return;
    appendFile(this.config.auditLog, `${JSON.stringify({ ts: new Date().toISOString(), ...entry })}\n`, (err) => {
      if (err) console.error(`[osmcp] could not write the audit log: ${err.message}`);
    });
  }

  async shutdown(): Promise<void> {
    const timeout = new Promise<void>((resolve) => setTimeout(resolve, SHUTDOWN_TIMEOUT_MS).unref());
    await Promise.race([Promise.allSettled([...this.instances.values()].map((i) => i.changes.shutdown())), timeout]);
    for (const instance of this.instances.values()) instance.client.close();
  }

  private notify(level: 'info' | 'warning' | 'error', message: string): void {
    console.error(`[osmcp] ${level}: ${message}`);
    for (const listener of this.listeners) listener(level, message);
  }

  private onWrite(instance: string, entry: WriteRecord): void {
    const scope = this.writeScope.getStore();
    if (scope) scope.push(entry);
    // Outside a tool call this is the rollback timer acting on its own.
    else this.audit({ instance, tool: '(background)', writes: [entry] });
  }

  /** A log that cannot be written should stop the server now, not fail unnoticed later. */
  private assertAuditWritable(path: string): void {
    try {
      appendFileSync(path, '');
    } catch (err) {
      throw new OpnsenseError('config_error', `OPNSENSE_AUDIT_LOG: cannot write to ${path}: ${(err as Error).message}`);
    }
  }
}
