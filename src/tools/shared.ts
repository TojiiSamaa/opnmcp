import { OpnsenseError } from '../opnsense/errors.js';
import { configXmlToJson, redactConfigXml } from '../opnsense/redact.js';
import type { ToolContext } from './helpers.js';

export interface ConfigOptions {
  /** A specific backup id, otherwise the current configuration. */
  backup?: string;
  includeSensitive?: boolean;
}

function assertSensitiveAllowed(ctx: ToolContext, opts: ConfigOptions): void {
  if (opts.includeSensitive && !ctx.instance.allowSensitive) {
    throw new OpnsenseError('sensitive_disabled', 'include_sensitive requires the operator to set OPNSENSE_ALLOW_SENSITIVE=true.', {
      hint: 'Do not retry. Without it, passwords and keys stay redacted.',
    });
  }
}

async function downloadRaw(ctx: ToolContext, opts: ConfigOptions): Promise<string> {
  const params = opts.backup ? ['this', opts.backup] : ['this'];
  // The raw body leaves the client only because both callers below redact it first.
  const xml = await ctx.api.get('core/backup/download', { params, text: true, redactedByCaller: true });
  return String(xml);
}

export async function fetchConfigXml(ctx: ToolContext, opts: ConfigOptions = {}): Promise<string> {
  assertSensitiveAllowed(ctx, opts);
  const xml = await downloadRaw(ctx, opts);
  return opts.includeSensitive ? xml : redactConfigXml(xml);
}

export async function fetchConfigJson(ctx: ToolContext, opts: ConfigOptions = {}): Promise<Record<string, unknown>> {
  assertSensitiveAllowed(ctx, opts);
  return configXmlToJson(await downloadRaw(ctx, opts), !opts.includeSensitive);
}
