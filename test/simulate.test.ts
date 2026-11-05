import { describe, expect, it } from 'vitest';
import { matchLiteral, matchPortField, simulate, type NetworkContext, type Packet, type Rule } from '../src/opnsense/simulate.js';

const ctx = (over: Partial<NetworkContext> = {}): NetworkContext => ({
  interfaces: [
    { identifier: 'lan', device: 'igb1', description: 'LAN', addresses: ['192.168.1.1/24'] },
    { identifier: 'wan', device: 'igb0', description: 'WAN', addresses: ['203.0.113.2/24'] },
  ],
  aliasMembership: new Map(),
  knownAliases: new Set(),
  portAliases: new Map(),
  groups: new Map(),
  ...over,
});

const packet: Packet = { source: '192.168.1.50', destination: '8.8.8.8', protocol: 'tcp', destinationPort: 443, interface: 'lan', direction: 'in' };
const rule = (over: Rule): Rule => ({ enabled: '1', interface: 'lan', action: 'pass', quick: '1', protocol: 'any', source_net: 'any', destination_net: 'any', ...over });

describe('literal matching', () => {
  it('matches addresses, CIDRs and ranges exactly', () => {
    expect(matchLiteral('10.0.0.1', '10.0.0.1')).toBe(true);
    expect(matchLiteral('10.0.0.1', '10.0.0.10')).toBe(false);
    expect(matchLiteral('10.0.0.0/24', '10.0.0.200')).toBe(true);
    expect(matchLiteral('10.0.0.0/24', '10.0.1.1')).toBe(false);
    expect(matchLiteral('10.0.0.5-10.0.0.9', '10.0.0.7')).toBe(true);
    expect(matchLiteral('2001:db8::/32', '2001:db8::1')).toBe(true);
  });

  it('returns null for something else, so that it is never guessed', () => {
    expect(matchLiteral('myalias', '10.0.0.1')).toBeNull();
    expect(matchLiteral('10.0.0.0/99', '10.0.0.1')).toBeNull();
  });
});

describe('port matching', () => {
  it('handles lists, ranges, names and aliases', () => {
    const c = ctx({ portAliases: new Map([['web', ['80', '443']]]) });
    expect(matchPortField('443', 443, c)).toBe('yes');
    expect(matchPortField('80,443', 443, c)).toBe('yes');
    expect(matchPortField('80 443', 443, c)).toBe('yes');
    expect(matchPortField('1000-2000', 1500, c)).toBe('yes');
    expect(matchPortField('1000:2000', 2500, c)).toBe('no');
    expect(matchPortField('https', 443, c)).toBe('yes');
    expect(matchPortField('web', 443, c)).toBe('yes');
    expect(matchPortField('any', 443, c)).toBe('yes');
    expect(matchPortField('unknown_alias', 443, c)).toBe('unknown');
  });

  it('does not split names on the letter s', () => {
    const c = ctx({ portAliases: new Map([['sshports', ['22']]]) });
    expect(matchPortField('sshports', 22, c)).toBe('yes');
    expect(matchPortField('sshports', 443, c)).toBe('no');
  });
});

describe('pf semantics', () => {
  it('stops at the first quick match', () => {
    const r = simulate([rule({ action: 'block', uuid: 'a' }), rule({ action: 'pass', uuid: 'b' })], packet, ctx());
    expect(r.verdict).toBe('block');
    expect(r.deciding_rule?.uuid).toBe('a');
    expect(r.certainty).toBe('definite');
  });

  it('lets the last match win among non-quick rules', () => {
    const r = simulate([rule({ action: 'block', quick: '0', uuid: 'a' }), rule({ action: 'pass', quick: '0', uuid: 'b' })], packet, ctx());
    expect(r.verdict).toBe('pass');
    expect(r.deciding_rule?.uuid).toBe('b');
  });

  it('skips disabled rules and other interfaces', () => {
    const r = simulate([rule({ action: 'block', enabled: '0' }), rule({ action: 'block', interface: 'wan' }), rule({ action: 'pass', uuid: 'c' })], packet, ctx());
    expect(r.deciding_rule?.uuid).toBe('c');
  });

  it('reports no verdict when nothing matches', () => {
    const r = simulate([rule({ interface: 'wan' })], packet, ctx());
    expect(r.verdict).toBe('none');
    expect(r.explanation).toMatch(/blocks by default/);
  });

  it('honours the source and destination inversion', () => {
    expect(simulate([rule({ source_net: '192.168.1.0/24', source_not: '1' })], packet, ctx()).verdict).toBe('none');
    expect(simulate([rule({ source_net: '10.0.0.0/8', source_not: '1' })], packet, ctx()).verdict).toBe('pass');
  });

  it('treats a port condition as never matching ICMP', () => {
    const r = simulate([rule({ destination_port: '443' })], { ...packet, protocol: 'icmp', destinationPort: undefined }, ctx());
    expect(r.verdict).toBe('none');
  });

  it('separates the interface network from the interface address', () => {
    expect(simulate([rule({ source_net: 'lan' })], packet, ctx()).verdict).toBe('pass');
    expect(simulate([rule({ source_net: 'lanip' })], packet, ctx()).verdict).toBe('none');
    expect(simulate([rule({ source_net: 'lanip' })], { ...packet, source: '192.168.1.1' }, ctx()).verdict).toBe('pass');
  });

  it('applies a floating rule on every interface', () => {
    expect(simulate([rule({ interface: '', action: 'block' })], packet, ctx()).verdict).toBe('block');
  });

  it('resolves interface groups', () => {
    const c = ctx({ groups: new Map([['internal', ['lan']]]) });
    expect(simulate([rule({ interface: 'internal' })], packet, c).verdict).toBe('pass');
  });

  it('filters on the address family', () => {
    expect(simulate([rule({ ipprotocol: 'inet6' })], packet, ctx()).verdict).toBe('none');
    expect(simulate([rule({ ipprotocol: 'inet46' })], packet, ctx()).verdict).toBe('pass');
  });
});

describe('what it cannot know', () => {
  it('is uncertain about an alias it could not resolve', () => {
    const r = simulate([rule({ source_net: 'mystery', action: 'block' }), rule({ action: 'pass' })], packet, ctx());
    expect(r.verdict).toBe('pass');
    expect(r.certainty).toBe('uncertain');
    expect(r.matched_rules[0]?.match).toBe('possible');
  });

  it('resolves an alias through its live table', () => {
    const member = ctx({ aliasMembership: new Map([[packet.source, new Set(['trusted'])]]), knownAliases: new Set(['trusted']) });
    expect(simulate([rule({ source_net: 'trusted' })], packet, member).certainty).toBe('definite');
    expect(simulate([rule({ source_net: 'trusted' })], packet, member).verdict).toBe('pass');

    const notMember = ctx({ aliasMembership: new Map([[packet.source, new Set<string>()]]), knownAliases: new Set(['trusted']) });
    expect(simulate([rule({ source_net: 'trusted' })], packet, notMember).verdict).toBe('none');
  });

  it('is uncertain about a schedule', () => {
    const r = simulate([rule({ sched: 'office', action: 'block' }), rule({ action: 'pass' })], packet, ctx());
    expect(r.certainty).toBe('uncertain');
    expect(r.matched_rules[0]?.reason).toMatch(/schedule/);
  });

  it('stays definite when a possible match would not change the outcome', () => {
    const r = simulate([rule({ source_net: 'mystery', action: 'pass' }), rule({ action: 'pass' })], packet, ctx());
    expect(r.certainty).toBe('definite');
  });
});
