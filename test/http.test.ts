import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.js';
import { startHttp, type HttpOptions } from '../src/http.js';
import { Runtime } from '../src/runtime.js';
import { FakeOpnsense } from './fake-opnsense.js';

const cleanups: Array<() => Promise<unknown> | void> = [];

afterEach(async () => {
  for (const cleanup of cleanups.splice(0)) await cleanup();
});

async function serve(options: Partial<HttpOptions> = {}) {
  const fake = new FakeOpnsense();
  await fake.start();
  const runtime = new Runtime(loadConfig({ OPNSENSE_URL: fake.url, OPNSENSE_API_KEY: 'key', OPNSENSE_API_SECRET: 'secret' }));
  const server = await startHttp(runtime, { host: '127.0.0.1', port: 0, ...options });
  cleanups.push(
    () => new Promise<void>((resolve) => {
      server.closeAllConnections();
      server.close(() => resolve());
    }),
    () => runtime.shutdown(),
    () => fake.stop(),
  );
  return { port: (server.address() as AddressInfo).port, runtime };
}

function request(port: number, opts: { method?: string; path?: string; headers?: Record<string, string>; body?: unknown } = {}): Promise<{ status: number; body: any }> {
  return new Promise((resolve, reject) => {
    const payload = opts.body === undefined ? undefined : JSON.stringify(opts.body);
    const req = http.request(
      { host: '127.0.0.1', port, method: opts.method ?? 'POST', path: opts.path ?? '/mcp', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', ...opts.headers } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let body: unknown = text;
          try {
            body = JSON.parse(text);
          } catch {
            /* not JSON */
          }
          resolve({ status: res.statusCode ?? 0, body });
        });
      },
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

const LIST_TOOLS = { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} };

describe('odd request paths', () => {
  it('answers 404 to "//", which new URL() would throw on, and keeps running', async () => {
    const { port } = await serve();
    const host = { Host: `127.0.0.1:${port}` };
    expect((await request(port, { method: 'GET', path: '//', headers: host })).status).toBe(404);
    expect((await request(port, { method: 'GET', path: '/mcp?x=1', headers: host })).status).toBe(405);
  });
});

describe('HTTP transport', () => {
  it('serves MCP requests without a session', async () => {
    const { port } = await serve();
    const res = await request(port, { body: LIST_TOOLS });
    expect(res.status).toBe(200);
    expect(res.body.result.tools.map((t: { name: string }) => t.name)).toContain('opn_mcp_info');
  });

  it('refuses to listen on the network without a token', async () => {
    const runtime = new Runtime(loadConfig({ OPNSENSE_URL: 'https://192.0.2.1', OPNSENSE_API_KEY: 'k', OPNSENSE_API_SECRET: 's' }));
    cleanups.push(() => runtime.shutdown());
    expect(() => startHttp(runtime, { host: '0.0.0.0', port: 0 })).toThrow(/without a token/);
  });

  it('requires the token when there is one', async () => {
    const { port } = await serve({ token: 'correct-token' });
    expect((await request(port, { body: LIST_TOOLS })).status).toBe(401);
    expect((await request(port, { body: LIST_TOOLS, headers: { Authorization: 'Bearer wrong-token!' } })).status).toBe(401);
    expect((await request(port, { body: LIST_TOOLS, headers: { Authorization: 'Bearer correct-token' } })).status).toBe(200);
  });

  it('refuses a foreign Host header, which is what DNS rebinding looks like', async () => {
    const { port } = await serve();
    const res = await request(port, { body: LIST_TOOLS, headers: { Host: 'evil.example' } });
    expect(res.status).toBe(403);
  });

  it('accepts a Host the operator allowed', async () => {
    const { port } = await serve({ allowedHosts: ['mcp.example.com'] });
    expect((await request(port, { body: LIST_TOOLS, headers: { Host: 'mcp.example.com' } })).status).toBe(200);
  });

  it('only answers POST on /mcp', async () => {
    const { port } = await serve();
    expect((await request(port, { method: 'GET' })).status).toBe(405);
    expect((await request(port, { path: '/other', body: LIST_TOOLS })).status).toBe(404);
  });
});
