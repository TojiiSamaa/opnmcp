#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { loadConfig } from './config.js';
import { startHttp } from './http.js';
import { OpnsenseError } from './opnsense/errors.js';
import { Runtime } from './runtime.js';
import { createServer, visibleTools } from './server.js';

const HELP = `osmcp: MCP server for OPNsense firewalls

Usage: osmcp [--http] [--host 127.0.0.1] [--port 8765] [--list-tools]

Default transport: stdio. Configuration comes from the environment, see the README.
  OPNSENSE_URL, OPNSENSE_API_KEY, OPNSENSE_API_SECRET   the firewall
  OPNSENSE_ALLOW_WRITES=true                            enable changes (read-only by default)
  OPNSENSE_TOOLSETS=firewall,nat,dns                    load only these domains, or "all"
  OPNSENSE_MCP_TOKEN                                    bearer token for --http
`;

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      http: { type: 'boolean', default: false },
      host: { type: 'string', default: '127.0.0.1' },
      port: { type: 'string', default: '8765' },
      'list-tools': { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
  });
  if (values.help) {
    process.stdout.write(HELP);
    return;
  }

  const runtime = new Runtime(loadConfig());

  if (values['list-tools']) {
    for (const def of visibleTools(runtime)) process.stdout.write(`${def.domain}\t${def.access}\t${def.name}\n`);
    await runtime.shutdown();
    return;
  }

  let stopping = false;
  const stop = () => {
    if (stopping) return;
    stopping = true;
    // An unconfirmed change must not outlive the timer that protects it.
    void runtime.shutdown().finally(() => process.exit(0));
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);

  if (values.http) {
    const port = Number(values.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new OpnsenseError('config_error', `--port: "${values.port}" is not a valid port.`);
    const token = process.env.OPNSENSE_MCP_TOKEN;
    const allowedHosts = (process.env.OPNSENSE_MCP_ALLOWED_HOSTS ?? '').split(',').map((s) => s.trim()).filter(Boolean);
    await startHttp(runtime, { host: values.host, port, allowedHosts, ...(token ? { token } : {}) });
    return;
  }

  // The client closing stdin is how a stdio server is normally told to stop.
  process.stdin.on('close', stop);
  process.stdin.on('end', stop);
  const server = createServer(runtime);
  await server.connect(new StdioServerTransport());
  console.error('[osmcp] ready on stdio');
}

main().catch((err: unknown) => {
  if (err instanceof OpnsenseError) {
    console.error(`[osmcp] ${err.message}${err.hint ? `\n        ${err.hint}` : ''}`);
  } else {
    console.error(`[osmcp] ${(err as Error).stack ?? String(err)}`);
  }
  process.exit(1);
});
