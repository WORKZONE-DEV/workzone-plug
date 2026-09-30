// Fastener rules. Run: node --test tests/js/fasteners.test.mjs
//  Wall anchor:    pull on it and it grips harder.
//  Barbed fitting: slides in one way, can't come back out.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const S = require('../../socket/plug-socket.js');

const ok = async () => ({ status: 200, headers: { get: () => '2' }, text: async () => 'ok' });
const M = { id: 'zone.work.w', name: 'W', version: '1.2.0', permissions: { network: ['api.example.com', 'img.example.com'], events: ['a', 'b'], storage: '1MB', identity: 'public-key' } };

test('wall anchor: each refused request halves the allowance, and it never loosens', () => {
  const g = S.Gate(M, { fetch: ok });
  assert.equal(g.fetchLimit(), 30);
  g.handle({ topic: 'net.fetch', url: 'https://evil.example/' });
  assert.equal(g.fetchLimit(), 15);
  g.handle({ topic: 'net.fetch', url: 'https://evil.example/' });
  g.handle({ topic: 'net.fetch', url: 'http://api.example.com/' });
  assert.equal(g.fetchLimit(), 3);
  for (let i = 0; i < 10; i++) g.handle({ topic: 'net.fetch', url: 'https://api.example.com/' });   // good requests
  assert.ok(g.fetchLimit() <= 3, 'good behaviour afterwards does not loosen it');
  for (let i = 0; i < 10; i++) g.handle({ topic: 'net.fetch', url: 'https://evil.example/' });
  assert.equal(g.fetchLimit(), 1, 'never below 1 (the plug still works, just slowly)');
});

test('wall anchor, other way: a well-behaved plug keeps its full allowance', () => {
  const g = S.Gate(M, { fetch: ok });
  for (let i = 0; i < 30; i++) assert.equal(g.handle({ topic: 'net.fetch', url: 'https://api.example.com/' }).ok, true);
  assert.equal(g.fetchLimit(), 30, 'staying inside the rules never tightens anything');
  assert.equal(g.handle({ topic: 'net.fetch', url: 'https://api.example.com/' }).ok, false, 'the 31st is over the limit');
  assert.equal(g.fetchLimit(), 15, 'and going over the limit counts as pulling');
});

test('barbed fitting: permissions narrow, never widen', () => {
  const g = S.Gate(M, { fetch: ok });
  assert.equal(g.narrow({ network: ['api.example.com'] }), true);
  assert.equal(g.handle({ topic: 'net.fetch', url: 'https://img.example.com/' }).ok, false, 'removed host is gone');
  assert.equal(g.handle({ topic: 'net.fetch', url: 'https://api.example.com/' }).ok, true, 'kept host still works');
  assert.equal(g.narrow({ network: ['api.example.com', 'evil.example'] }), false, 'adding a host is refused');
  assert.equal(g.narrow({ network: ['img.example.com'] }), false, 'putting a removed host back is refused too');
  assert.equal(g.narrow({ events: ['a'] }), true);
  assert.equal(g.handle({ topic: 'event.publish', name: 'b' }).ok, false);
  assert.equal(g.narrow({ storage: '64KB' }), true);
  assert.equal(g.narrow({ storage: '10MB' }), false);
  assert.equal(g.narrow({ storage: null }), true);
  assert.equal(g.handle({ topic: 'storage.set', key: 'k', value: 1 }).ok, false);
  assert.equal(g.narrow({ identity: 'none' }), true);
  assert.equal(g.handle({ topic: 'identity.get' }).ok, false);
  assert.equal(g.narrow({ camera: true }), false, 'unknown permissions cannot be added this way either');
  assert.ok(g.log.some(e => e.topic === 'narrow' && e.verdict === 'refused'), 'widening attempts are logged');
});

test('barbed fitting: after narrowing, the host cannot push a removed event either', () => {
  const g = S.Gate(M, { fetch: ok });
  g.narrow({ events: ['a'] });
  assert.deepEqual(g.events(), ['a']);
});

test('barbed fitting: a plug cannot narrow or widen anything by message', () => {
  const g = S.Gate(M, { fetch: ok });
  assert.equal(g.handle({ topic: 'narrow', network: [] }).ok, false);
  assert.equal(g.handle({ topic: 'permissions.grant', network: ['*'] }).ok, false);
});

test('ratchet: versions only go forward', () => {
  const r = S.Ratchet();
  const A = 'ed25519:' + 'aa'.repeat(32);
  assert.equal(r.accept({ id: 'x.y', version: '1.2.0' }, A), null);
  assert.equal(r.accept({ id: 'x.y', version: '1.2.0' }, A), null, 'same version again is fine');
  assert.equal(r.accept({ id: 'x.y', version: '1.10.0' }, A), null, '1.10 is newer than 1.2 (numbers, not text)');
  assert.match(r.accept({ id: 'x.y', version: '1.9.9' }, A), /older/);
  assert.match(r.accept({ id: 'x.y', version: '0.1.0' }, A), /no rolling back/);
});

test('ratchet: nobody else can slide in under the same name', () => {
  const r = S.Ratchet();
  const A = 'ed25519:' + 'aa'.repeat(32), B = 'ed25519:' + 'bb'.repeat(32);
  r.accept({ id: 'x.y', version: '1.0.0' }, A);
  assert.match(r.accept({ id: 'x.y', version: '9.0.0' }, B), /different author/);
  assert.equal(r.accept({ id: 'other.plug', version: '1.0.0' }, B), null, 'B can still use its own names');
  r.forget('x.y');                       // a human choice, done in the host UI
  assert.equal(r.accept({ id: 'x.y', version: '1.0.0' }, B), null);
});

test('ratchet: a refused check never moves the ratchet', () => {
  const r = S.Ratchet();
  const A = 'ed25519:' + 'aa'.repeat(32), B = 'ed25519:' + 'bb'.repeat(32);
  r.accept({ id: 'x.y', version: '2.0.0' }, A);
  r.accept({ id: 'x.y', version: '5.0.0' }, B);          // refused
  assert.equal(r.accept({ id: 'x.y', version: '3.0.0' }, A), null, 'B\'s refused 5.0.0 did not raise the bar');
});

test('barbed fitting: AI tools can be taken away, never put back', () => {
  const g = S.Gate({ ...M, permissions: { ...M.permissions, ai: ['notes.search'] } }, { fetch: ok });
  assert.equal(g.narrow({ ai: [] }), true, 'the person can untick an AI tool');
  assert.equal(g.narrow({ ai: ['notes.search'] }), false, 'and it cannot come back while running');
  assert.equal(g.narrow({ ai: ['other.tool'] }), false, 'nor can a new one be added');
});

test('powers the person switched off are refused quietly, never counted as misbehaving', () => {
  const g = S.Gate(M, { fetch: ok });
  g.narrow({ events: [] });
  for (let i = 0; i < 30; i++) assert.equal(g.handle({ topic: 'event.publish', name: M.permissions.events[0] }).ok, false);
  assert.equal(g.killed(), null, 'asking for what YOU turned off does not get it pulled');
  assert.ok(g.log.some(e => e.reason === 'you switched this off'), 'and the log says why, plainly');
  for (let i = 0; i < 25; i++) g.handle({ topic: 'event.publish', name: 'never.declared' });
  assert.ok(g.killed(), 'but asking for things it never declared still counts');
});

test('report card: powers you switched off are listed apart and never lower the grade', () => {
  const g = S.Gate(M, { fetch: ok });
  g.narrow({ events: [] });
  g.handle({ topic: 'event.publish', name: M.permissions.events[0] });
  const r = S.report(g);
  assert.equal(r.grade, 'CLEAN', 'your choice is not misbehaviour');
  assert.equal(r.blocked.length, 0);
  assert.equal(r.switchedOff[0].times, 1);
  g.handle({ topic: 'event.publish', name: 'never.declared' });
  assert.equal(S.report(g).grade, 'TRIED THINGS', 'asking for something never declared still counts');
});
