import { z } from 'zod';
import { assertApplied, modelFields } from '../opnsense/model.js';
import { crudTools, gather, tool, type CrudSpec, type ToolDef } from './helpers.js';

/**
 * HAProxy models have dozens of fields, most of them optional, so these tools take the
 * model fields as they are instead of repeating them here. opn_describe_model lists them.
 */
const fieldsInput = z
  .record(z.string(), z.union([z.string(), z.number(), z.boolean(), z.array(z.string())]))
  .optional()
  .describe('Model fields to set. opn_describe_model with the matching get endpoint lists names and accepted values.');

const HAPROXY = ['haproxy/service/configtest', 'haproxy/service/reconfigure'];

interface Entity {
  singular: string;
  plural: string;
  label: string;
  wrapper: string;
  toggle?: string;
}

const ENTITIES: Entity[] = [
  { singular: 'frontend', plural: 'frontends', label: 'HAProxy frontend', wrapper: 'frontend', toggle: 'toggle_frontend' },
  { singular: 'backend', plural: 'backends', label: 'HAProxy backend', wrapper: 'backend', toggle: 'toggle_backend' },
  { singular: 'server', plural: 'servers', label: 'HAProxy server', wrapper: 'server', toggle: 'toggle_server' },
  { singular: 'action', plural: 'actions', label: 'HAProxy rule', wrapper: 'action', toggle: 'toggle_action' },
  { singular: 'acl', plural: 'acls', label: 'HAProxy condition', wrapper: 'acl' },
  { singular: 'healthcheck', plural: 'healthchecks', label: 'HAProxy health check', wrapper: 'healthcheck' },
];

function entityTools(e: Entity): ToolDef[] {
  const spec: CrudSpec = {
    domain: 'haproxy',
    singular: `haproxy_${e.singular}`,
    plural: `haproxy_${e.plural}`,
    label: e.label,
    base: 'haproxy/settings',
    commands: {
      search: `search_${e.plural}`,
      get: `get_${e.singular}`,
      add: `add_${e.singular}`,
      set: `set_${e.singular}`,
      del: `del_${e.singular}`,
      ...(e.toggle ? { toggle: e.toggle } : {}),
    },
    wrapper: e.wrapper,
    fields: { fields: fieldsInput },
    required: ['fields'],
    toModel: (args) => modelFields((args.fields ?? {}) as Record<string, unknown>),
    reconfigure: HAPROXY,
    writeNote: 'HAProxy reloads right after a valid change, with no rollback timer. The configuration test runs first.',
    // These endpoints all declare $enabled, but none of them passes it on: they flip.
    toggleFlips: true,
  };
  return crudTools(spec);
}

export function haproxyTools(): ToolDef[] {
  return [
    tool({
      name: 'opn_haproxy_status',
      title: 'HAProxy status',
      description: 'Whether HAProxy runs, with its live statistics per frontend, backend and server. Needs the os-haproxy plugin.',
      domain: 'haproxy',
      access: 'read',
      idempotent: true,
      input: {},
      handler: async (_args, ctx) => {
        const { data, unavailable } = await gather({
          service: () => ctx.api.get('haproxy/service/status'),
          info: () => ctx.api.get('haproxy/statistics/info'),
          counters: () => ctx.api.get('haproxy/statistics/counters'),
        });
        return { ...data, unavailable };
      },
    }),
    tool({
      name: 'opn_haproxy_configtest',
      title: 'Test HAProxy configuration',
      description: 'Checks the saved HAProxy configuration without reloading anything.',
      domain: 'haproxy',
      access: 'read',
      idempotent: true,
      input: {},
      handler: async (_args, ctx) => ctx.api.get('haproxy/service/configtest'),
    }),
    tool({
      name: 'opn_reconfigure_haproxy',
      title: 'Reconfigure HAProxy',
      description: 'Reloads HAProxy with the saved configuration: applies changes saved with apply=false.',
      domain: 'haproxy',
      access: 'write',
      idempotent: true,
      input: {},
      handler: async (_args, ctx) => {
        assertApplied(await ctx.api.get('haproxy/service/configtest'), 'Testing the configuration');
        return assertApplied(await ctx.api.post('haproxy/service/reconfigure'), 'Reconfiguring HAProxy');
      },
    }),
    ...ENTITIES.flatMap(entityTools),
  ];
}
