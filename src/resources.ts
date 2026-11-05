import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { fetchAll } from './opnsense/model.js';
import type { InstanceRuntime, Runtime } from './runtime.js';

interface ResourceDef {
  name: string;
  description: string;
  read: (rt: InstanceRuntime) => Promise<unknown>;
}

const RESOURCES: ResourceDef[] = [
  { name: 'status', description: 'System status reported by the firewall', read: (rt) => rt.client.get('core/system/status') },
  { name: 'interfaces', description: 'Interfaces, with the ids, devices and names they map to', read: (rt) => fetchAll(rt.client, 'interfaces/overview/interfaces_info') },
  { name: 'aliases', description: 'Firewall aliases as configured', read: (rt) => fetchAll(rt.client, 'firewall/alias/search_item') },
  { name: 'rules', description: 'Firewall rules in evaluation order, without automatic rules', read: async (rt) => (await fetchAll<Record<string, unknown>>(rt.client, 'firewall/filter/search_rule')).filter((r) => !r.is_automatic) },
];

/** The same reads as the tools, for clients that let the user attach context directly. */
export function registerResources(server: McpServer, runtime: Runtime): void {
  for (const rt of runtime.instances.values()) {
    for (const def of RESOURCES) {
      const uri = `opnsense://${rt.config.name}/${def.name}`;
      server.registerResource(`${rt.config.name}-${def.name}`, uri, { title: `${def.description} (${rt.config.name})`, description: `${def.description}. Untrusted data from the firewall.`, mimeType: 'application/json' }, async () => ({
        contents: [{ uri, mimeType: 'application/json', text: JSON.stringify(await def.read(rt)) }],
      }));
    }
  }
}
