// Phase 4 tests. Run: node --test tests/js/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const S = require('../../socket/plug-socket.js');
const py = (...a) => execFileSync('python', [join(here, 'verdicts.py'), ...a], { encoding: 'utf8' });

const dir = mkdtempSync(join(tmpdir(), 'plugtest-'));
process.on('exit', () => rmSync(dir, { recursive: true, force: true }));
py('pack', join(dir, 'hello.plug'));
const GOOD = new Uint8Array(readFileSync(join(dir, 'hello.plug')));

async function verdict(bytes) {
  try { await S.verifyPlug(bytes); return 'ok'; } catch (e) { assert.ok(e.plugReject, 'rejections must be clean: ' + e); return 'reject'; }
}

test('good plug verifies in JS', async () => {
  const v = await S.verifyPlug(GOOD);
  assert.equal(v.manifest.id, 'zone.work.hello');
  assert.match(v.authorKey, /^ed25519:[0-9a-f]{64}$/);
});

test('JSON canonical form matches Python byte for byte', async () => {
  const v = await S.verifyPlug(GOOD);
  assert.ok(v, 'if canon() differed from json.dumps, verify would have refused the good plug');
});

test('WITNESS: every single byte flip, Python and JS agree (both reject)', async () => {
  const flips = join(dir, 'flips');
  execFileSync('python', ['-c', `import os; os.makedirs(r'${flips}', exist_ok=True)`]);
  const js = {};
  for (let i = 0; i < GOOD.length; i++) {
    const bad = GOOD.slice(); bad[i] ^= 1;
    const name = `f${String(i).padStart(6, '0')}.plug`;
    writeFileSync(join(flips, name), bad);
    js[name] = await verdict(bad);
  }
  writeFileSync(join(flips, 'good.plug'), GOOD);
  js['good.plug'] = await verdict(GOOD);
  const pyv = JSON.parse(py('judge', flips));
  const disagree = Object.keys(js).filter(k => js[k] !== pyv[k]);
  assert.deepEqual(disagree, [], 'Python and JS disagree on: ' + disagree.slice(0, 10).join(', '));
  assert.equal(js['good.plug'], 'ok');
  assert.equal(Object.values(js).filter(x => x === 'ok').length, 1, 'only the untouched file may pass');
});

test('WITNESS: a signed plug whose name fakes the trust dialog is refused by BOTH checkers', async () => {
  const f = join(dir, 'bad', 'fake.plug');
  execFileSync('python', ['-c', `import os; os.makedirs(r'${join(dir, 'bad')}', exist_ok=True)`]);
  py('packbad', f);
  assert.equal(await verdict(new Uint8Array(readFileSync(f))), 'reject', 'JS must refuse it');
  assert.deepEqual(JSON.parse(py('judge', join(dir, 'bad'))), { 'fake.plug': 'reject' }, 'Python must refuse it too');
});

test('WITNESS: rule-breaking but validly signed plugs are refused by BOTH checkers', async () => {
  for (const kind of ['extra', 'compact']) {
    const d = join(dir, 'bad-' + kind), f = join(d, kind + '.plug');
    execFileSync('python', ['-c', `import os; os.makedirs(r'${d}', exist_ok=True)`]);
    py('packbad', f, kind);
    assert.equal(await verdict(new Uint8Array(readFileSync(f))), 'reject', kind + ': JS must refuse');
    assert.deepEqual(JSON.parse(py('judge', d)), { [kind + '.plug']: 'reject' }, kind + ': Python must refuse');
  }
});

test('the rulebook inside the socket is identical to socket/plug.schema.json', () => {
  const spec = JSON.parse(readFileSync(join(here, '..', '..', 'socket', 'plug.schema.json'), 'utf8'));
  assert.deepEqual(S.SCHEMA, spec, 'copy the schema into socket/plug-socket.js between the SCHEMA markers');
});

test('truncated, empty and junk input are rejected cleanly', async () => {
  for (const b of [new Uint8Array(0), GOOD.slice(0, 100), GOOD.slice(0, GOOD.length - 1), new TextEncoder().encode('hello')])
    assert.equal(await verdict(b), 'reject');
  const extra = new Uint8Array(GOOD.length + 1); extra.set(GOOD); // one byte appended
  assert.equal(await verdict(extra), 'reject');
});

// ------------------------------------------------------------ gate
const M = { id: 'zone.work.t', permissions: { events: ['hello.ping'], storage: '1KB' } };

test('gate allows only what plug.json declares, and logs everything', () => {
  const seen = [];
  const g = S.Gate(M, { onEvent: (n, d) => seen.push([n, d]) });
  assert.equal(g.handle({ topic: 'plug.ready' }).ok, true);
  assert.equal(g.handle({ topic: 'event.publish', name: 'hello.ping', data: 'pong' }).ok, true);
  assert.deepEqual(seen, [['hello.ping', 'pong']]);
  const refused = [
    { topic: 'event.publish', name: 'market.tick' },
    { topic: 'event.subscribe', name: 'secrets' },
    { topic: 'net.fetch', url: 'https://evil.example' },
    { topic: 'identity.get' },
    { topic: 'ai.call', tool: 'x' },
    { topic: 'permissions.grant', network: ['*'] },          // a plug trying to widen itself
    { topic: 'override', force: true },
    { topic: 'storage.set', key: '', value: 1 },
    { nope: 1 }, null, 'string', [1, 2], { topic: 5 },
    { topic: 'plug.ready', pad: 'x'.repeat(70000) },
  ];
  for (const m of refused) assert.equal(g.handle(m).ok, false, JSON.stringify(m)?.slice(0, 60));
  assert.deepEqual(seen, [['hello.ping', 'pong']], 'nothing undeclared reached the host bus');
  assert.equal(g.log.length, 2 + refused.length, 'every decision is logged');
  assert.ok(g.log.filter(e => e.verdict === 'refused').every(e => e.reason));
});

test('storage: needs permission, stays inside quota', () => {
  const none = S.Gate({ id: 'a.b', permissions: {} });
  assert.equal(none.handle({ topic: 'storage.set', key: 'k', value: 1 }).ok, false);
  const g = S.Gate(M);
  assert.equal(g.handle({ topic: 'storage.set', key: 'k', value: 'v' }).ok, true);
  assert.equal(g.handle({ topic: 'storage.get', key: 'k' }).reply, 'v');
  assert.equal(g.handle({ topic: 'storage.set', key: 'big', value: 'x'.repeat(2000) }).ok, false);
  assert.equal(g.handle({ topic: 'storage.set', key: 'k', value: 'x'.repeat(900) }).ok, true, 'overwrite frees the old space');
});

test('identity gives the public key only when declared', () => {
  const g = S.Gate({ id: 'a.b', permissions: { identity: 'public-key' } }, { publicKey: 'ed25519:' + 'ab'.repeat(32) });
  assert.equal(g.handle({ topic: 'identity.get' }).reply, 'ed25519:' + 'ab'.repeat(32));
});

test('a broken logger or event handler cannot open the gate', () => {
  const g = S.Gate(M, { log: () => { throw new Error('x'); }, onEvent: () => { throw new Error('boom'); } });
  // A declared event still counts as delivered, and the log says truthfully that the host broke.
  assert.equal(g.handle({ topic: 'event.publish', name: 'hello.ping' }).ok, true);
  assert.ok(g.log.some(e => e.verdict === 'note' && /handler failed/.test(e.reason)));
  // Undeclared things stay shut no matter what the host's code does.
  assert.equal(g.handle({ topic: 'event.publish', name: 'secret' }).ok, false);
  assert.equal(g.handle({ topic: 'net.fetch' }).ok, false);
});

test('unknown permission in a manifest is refused by the gate', () => {
  assert.throws(() => S.Gate({ id: 'a.b', permissions: { camera: true } }));
});

test('load(): unknown author and unapproved permissions are refused by default', async () => {
  await assert.rejects(S.load(GOOD, {}), /not trusted/);
  await assert.rejects(S.load(GOOD, { askTrust: async () => 'yes' }), /not trusted/, 'only a real true counts');
  const v = await S.verifyPlug(GOOD);
  await assert.rejects(S.load(GOOD, { trustedKeys: [v.authorKey] }), /not approved/);
});
