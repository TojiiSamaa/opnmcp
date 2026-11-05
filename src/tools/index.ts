import { apiTools } from './api.js';
import { dhcpTools } from './dhcp.js';
import { diagnosticsTools } from './diagnostics.js';
import { dnsTools } from './dns.js';
import { firewallTools } from './firewall.js';
import { haproxyTools } from './haproxy.js';
import type { ToolDef } from './helpers.js';
import { natTools } from './nat.js';
import { networkTools } from './network.js';
import { securityTools } from './security.js';
import { serviceTools } from './services.js';
import { systemTools } from './system.js';
import { vpnTools } from './vpn.js';

/** Every tool, grouped by domain: one tool per request, one file per domain. */
export function allTools(info: () => Record<string, unknown>): ToolDef[] {
  return [
    ...systemTools(info),
    ...networkTools(),
    ...firewallTools(),
    ...natTools(),
    ...dnsTools(),
    ...dhcpTools(),
    ...vpnTools(),
    ...serviceTools(),
    ...haproxyTools(),
    ...diagnosticsTools(),
    ...securityTools(),
    ...apiTools(),
  ];
}
